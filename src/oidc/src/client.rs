// Copyright (C) 2025 Mike Sauh
//
// This file is part of ExposedObserve, a modified fork of OpenObserve.
//
// OpenObserve is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// Original project: https://github.com/openobserve/openobserve
//
// This file is NOT part of the original OpenObserve codebase.
// It was created independently to add OIDC authentication and claim-based authorization.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::str::FromStr;

use actix_session::SessionExt;
use actix_web::{
    HttpRequest, HttpResponse, Result, error::ErrorInternalServerError, http::StatusCode, web,
};
use log::error;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, CsrfToken, IdTokenVerifier, Nonce, NonceVerifier,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RefreshToken, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreJsonWebKey, CoreProviderMetadata},
    url::Url,
};
use tokio::sync::OnceCell;

use crate::{
    config::{self, OidcConfig},
    cookies::clear_all_auth_cookies,
    errors::{self, AuthError, error_message_formatter},
    http::get_http_client,
    models::{
        self, AuthTokens, AuthorizationState, CallbackState, CustomClient, CustomToken,
        CustomTokenResponse, UserInfo,
    },
    session::{extract_auth_state, insert_auth_state, log_session_contents, update_tokens},
};

pub async fn logout(req: HttpRequest) -> Result<HttpResponse> {
    let mut response_builder = HttpResponse::Ok();
    clear_all_auth_cookies(&mut response_builder);
    req.get_session().purge();
    Ok(response_builder.finish())
}

pub async fn login(req: HttpRequest) -> Result<HttpResponse> {
    req.get_session().clear();
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_state, nonce) = match create_authorize_url(pkce_challenge).await {
        Ok(res) => res,
        Err(e) => {
            return Ok(ErrorInternalServerError(e.to_string()).error_response());
        }
    };

    let session = &req.get_session();
    let auth_state = AuthorizationState {
        pkce_verifier: pkce_verifier.into_secret(),
        csrf_state: csrf_state.into_secret(),
        nonce: nonce.secret().to_owned(),
    };
    match insert_auth_state(session, auth_state) {
        Ok(()) => Ok(HttpResponse::SeeOther()
            .insert_header(("Location", auth_url.as_str()))
            .finish()),
        Err(err) => {
            let msg = error_message_formatter(&err, "Failed to make redirect response");
            error!("{msg}");
            session.clear();
            Ok(HttpResponse::InternalServerError().body(err.to_string()))
        }
    }
}

pub async fn retrieve_user_info(req: HttpRequest) -> Result<UserInfo, errors::AuthError> {
    log::debug!("Starting OIDC callback user info retrieval");
    let callback_state: web::Query<CallbackState> =
        web::Query::<CallbackState>::from_query(req.query_string()).map_err(|err| {
            log::error!("Failed to parse callback query parameters: {}", err);
            AuthError::from_error(
                err,
                Some("Failed to parse CallbackState".to_owned()),
                StatusCode::UNAUTHORIZED,
            )
        })?;
    log::debug!("Successfully parsed callback state: code={}, state={}", callback_state.code.len(), callback_state.state.len());

    let auth_state = extract_auth_state(&req.get_session()).map_err(|err| {
        log::error!("Failed to extract auth state from session: {}", err);
        err
    })?;
    log::debug!("Successfully extracted auth state from session");

    let pkce_verifier = PkceCodeVerifier::new(auth_state.pkce_verifier.clone());
    let state = callback_state.state.clone();
    if state != auth_state.csrf_state {
        log::error!("CSRF state mismatch: expected={}, received={}", auth_state.csrf_state, state);
        return Err(errors::AuthError::new(
            "Invalid state",
            StatusCode::UNAUTHORIZED,
        ));
    }
    log::debug!("CSRF state validation passed");

    let code = callback_state.code.clone();
    let client = &create_oidc_client().await.map_err(|err| {
        log::error!("Failed to create OIDC client: {}", err);
        err
    })?;
    log::debug!("Successfully created OIDC client");

    let response = exchange_code(code, pkce_verifier, &client).await.map_err(|err| {
        log::error!("Failed to exchange authorization code for tokens: {}", err);
        err
    })?;
    log::debug!("Successfully exchanged authorization code for tokens");

    let token_verifier: IdTokenVerifier<'_, CoreJsonWebKey> = client.id_token_verifier();
    match process_token_response(token_verifier, &Nonce::new(auth_state.nonce), response) {
        Ok(res) => {
            log::debug!("Successfully processed token response for user: {}", res.0.email);
            update_tokens(&req, &res.1).map_err(|err| {
                log::error!("Failed to update tokens in session: {}", err);
                err
            })?;
            log::debug!("Successfully updated tokens in session");
            log_session_contents(&req);
            Ok(res.0)
        }
        Err(e) => {
            log::error!("Failed to process token response: {}", e);
            Err(e)
        }
    }
}

pub async fn exchange_refresh_token(
    tokens: AuthTokens,
) -> Result<(UserInfo, AuthTokens), errors::AuthError> {
    let refresh_token = &RefreshToken::new(tokens.refresh_token);
    let async_http_client = get_http_client().await;
    let oidc_client = create_oidc_client().await?;
    let token_verifier: IdTokenVerifier<'_, CoreJsonWebKey> = oidc_client.id_token_verifier();
    let response = oidc_client
        .exchange_refresh_token(refresh_token)?
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            AuthError::from_error(
                e,
                Some("Failed to exchange refresh token".to_owned()),
                StatusCode::UNAUTHORIZED,
            )
        })?;
    let nonce_verifier = models::empty_nonce_verifier();
    process_token_response(token_verifier, nonce_verifier, response)
}

pub async fn try_to_verify_token(token: &String) -> Option<UserInfo> {
    let oidc_client = create_oidc_client().await.ok()?;
    let token_verifier: IdTokenVerifier<'_, CoreJsonWebKey> = oidc_client.id_token_verifier();
    verify_token(token, &token_verifier)
        .inspect_err(|e| error!("Failed to verify token\n{}", e))
        .ok()
}

fn verify_token<'a>(
    token: &'a String,
    token_verifier: &'a IdTokenVerifier<'a, CoreJsonWebKey>,
) -> Result<UserInfo, AuthError> {
    let token = CustomToken::from_str(token).map_err(|e| {
        return AuthError::from_error(e, None, StatusCode::UNAUTHORIZED);
    })?;
    let claims = token
        .claims(token_verifier, models::empty_nonce_verifier())
        .map_err(|e| {
            return AuthError::from_error(e, None, StatusCode::UNAUTHORIZED);
        })?;
    Ok(UserInfo::from_claims(claims))
}

fn process_token_response<T: NonceVerifier>(
    token_verifier: IdTokenVerifier<'_, CoreJsonWebKey>,
    nonce_verifier: T,
    response: CustomTokenResponse,
) -> Result<(UserInfo, AuthTokens), errors::AuthError> {
    let id_token: &CustomToken = response.id_token().ok_or(errors::AuthError::new(
        "Id token not found",
        StatusCode::UNAUTHORIZED,
    ))?;
    let claims = id_token.claims(&token_verifier, nonce_verifier)?;
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            response.access_token(),
            id_token.signing_alg()?,
            id_token.signing_key(&token_verifier)?,
        )?;
        if actual_access_token_hash != *expected_access_token_hash {
            return Err(errors::AuthError::new(
                "Invalid access token hash",
                StatusCode::UNAUTHORIZED,
            ));
        }
    }
    let id_token_str = id_token.to_string();
    let access_token_str = response.access_token().secret().clone();
    let refresh_token_str = response
        .refresh_token()
        .map(|rt| rt.secret().to_owned())
        .unwrap_or_default();
    let expires_in = match response
        .extra_fields()
        .extra_fields()
        .refresh_token_expires_in()
    {
        Some(duration) => Some(duration),
        None => response.expires_in(),
    };
    Ok((
        UserInfo::from_claims(claims),
        AuthTokens {
            expires_in,
            access_token: access_token_str,
            refresh_token: refresh_token_str,
            id_token: id_token_str,
        },
    ))
}

static OIDC_CLIENT: OnceCell<Result<CustomClient, AuthError>> = OnceCell::const_new();

async fn get_static_oidc_client() -> &'static Result<CustomClient, AuthError> {
    OIDC_CLIENT.get_or_init(init_oidc_client).await
}

async fn init_oidc_client() -> Result<CustomClient, AuthError> {
    create_oidc_client().await
}

pub(crate) async fn create_oidc_metadata(
    config: &OidcConfig,
) -> Result<CoreProviderMetadata, AuthError> {
    let issuer_url = config.issuer_url.clone();
    let http_client = get_http_client().await;
    match openidconnect::ProviderMetadata::discover_async(issuer_url, http_client).await {
        Ok(metadata) => Ok(metadata),
        Err(e) => Err(AuthError::to_internal_error(
            e,
            Some("Failed to discover OpenID Connect provider".to_owned()),
        )),
    }
}

async fn create_oidc_client() -> Result<CustomClient, AuthError> {
    let config = config::get_oidc_config();
    let client: CustomClient = CustomClient::from_provider_metadata(
        create_oidc_metadata(&config).await?,
        config.client_id.clone(),
        config.client_secret.clone(),
    )
    .set_redirect_uri(config.redirect_url.clone());
    Ok(client)
}

async fn exchange_code(
    code: String,
    pkce_verifier: PkceCodeVerifier,
    client: &CustomClient,
) -> Result<CustomTokenResponse, errors::AuthError> {
    let async_http_client = get_http_client().await;

    let token_response: CustomTokenResponse = client
        .exchange_code(AuthorizationCode::new(code))
        .map(|req| req.set_pkce_verifier(pkce_verifier))
        .map_err(|err| {
            AuthError::from_error(
                err,
                Some("Exchange code request setup error".to_owned()),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?
        .request_async(async_http_client)
        .await
        .map_err(|err| {
            AuthError::from_error(
                err,
                Some("Exchange code request execution error".to_owned()),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?;

    Ok(token_response)
}

async fn create_authorize_url(
    pkce_challenge: PkceCodeChallenge,
) -> Result<(Url, CsrfToken, Nonce), &'static AuthError> {
    let client = get_static_oidc_client().await;
    match client {
        Ok(c) => Ok(c
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use std::sync::Once;

    use actix_session::{SessionMiddleware, SessionStatus, storage::CookieSessionStore};
    use actix_web::{
        App, HttpServer,
        cookie::Key,
        dev::{Server, ServiceFactory, ServiceRequest, ServiceResponse},
        test::TestRequest,
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::JwkSet};
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey};
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    static INIT: Once = Once::new();

        fn generate_keys(uri: &String) -> (JwkSet, String) {
        let private_key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();

        let encoding_key =
            EncodingKey::from_rsa_der(&private_key.to_pkcs1_der().unwrap().as_bytes());

        let header = Header {
            alg: Algorithm::RS256,
            kid: None,
            ..Default::default()
        };

        let claims = json!({
            "sub": "citizen",
                "aud": "client",
                "nbf": "1762941467",
                "azp": "client",
                "iss": format!("{uri}/default"),
                "groups": [
                    "foo",
                    "bar"
                ],
                "exp": 2147483647,
                "iat": 1762941467,
                "jti": "c2a5bf31-29aa-41f6-b101-ae5eeb09164c",
                "tid": "default",
                "email": "citizen@foo.bar"
        });

        let id_token = encode(&header, &claims, &encoding_key).unwrap();
        let jwk_item = jsonwebtoken::jwk::Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).unwrap();
        let jwk_set: JwkSet = JwkSet{ keys: vec![jwk_item] };
        (jwk_set, id_token)
    }

    fn get_well_known_response(uri: &String) -> Value {
        json!({
          "issuer" : format!("{uri}/default"),
          "authorization_endpoint" : format!("{uri}/default/authorize"),
          "end_session_endpoint" : format!("{uri}/default/endsession"),
          "revocation_endpoint" : format!("{uri}/default/revoke"),
          "token_endpoint" : format!("{uri}/default/token"),
          "userinfo_endpoint" : format!("{uri}/default/userinfo"),
          "jwks_uri" : format!("{uri}/default/jwks"),
          "introspection_endpoint" : format!("{uri}/default/introspect"),
          "response_types_supported" : [ "code", "none", "id_token", "token" ],
          "response_modes_supported" : [ "query", "fragment", "form_post" ],
          "subject_types_supported" : [ "public" ],
          "id_token_signing_alg_values_supported" : [ "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" ],
          "code_challenge_methods_supported" : [ "plain", "S256" ]
        })
    }

    fn setup_logging() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .try_init();
    }

    pub(crate) fn create_app() -> App<
        impl ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = actix_web::Error,
            InitError = (),
        >,
    > {
        let private_key = Key::generate();
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                private_key.clone(),
            ))
            .service(web::resource("/auth/login").to(login))
            .service(web::resource("/auth/redirect").to(|req| async move {
                match retrieve_user_info(req).await {
                    Ok(res) => Ok(HttpResponse::build(StatusCode::OK).json(res)),
                    Err(err) => Err(err),
                }
            }))
    }

    pub(crate) async fn run_http_server(service_port: u16) -> Option<Server> {
        let result = HttpServer::new(move || create_app()).bind(("0.0.0.0", service_port));
        match result {
            Ok(srv) => Some(srv.run()),
            Err(err) => {
                let error_message = error_message_formatter(&err, "Failed to create server");
                error!("{error_message}");
                None
            }
        }
    }

    #[tokio::test]
    async fn logout_test() {
        setup_logging();
        let request = TestRequest::get().to_http_request();
        let session = request.get_session();
        session.insert("foo", "bar").unwrap();

        let logout = logout(request).await;

        assert!(logout.is_ok());
        assert!(!session.contains_key("foo"));
        assert!(session.status() == SessionStatus::Purged);
    }

    #[tokio::test]
    async fn validate_token_test() {
        setup_logging();

        let mock_server = MockServer::start().await;
        let uri = &mock_server.uri();

        let test_config = config::OidcConfig::new(
            "client".to_string(),
            Some("secret".to_string()),
            format!("{}/default", uri),
            format!("{}/redirect", uri),
            format!("{}/callback", uri),
            Some(true), // insecure
            None, None, None, None, None, None, None, None, None, None, None, None, None
        );
        config::set_test_config(test_config);

        let (jwks, id_token) = generate_keys(&uri);
        let well_known_response = get_well_known_response(&uri);

        Mock::given(method("GET"))
            .and(path(format!("/default/.well-known/openid-configuration")))
            .respond_with(ResponseTemplate::new(200).set_body_json(well_known_response))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/default/jwks")))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&mock_server)
            .await;

        let user_info = try_to_verify_token(&id_token).await;

        assert!(user_info.is_some());
        let user = user_info.unwrap();
        assert_eq!(user.sub, "citizen");
        assert_eq!(user.email, "citizen@foo.bar".to_string());

        config::clear_test_config();
    }
}
