// Copyright (C) 2026 Mike Sauh
//
// This file is part of ExposedObserve, a modified fork of OpenObserve.
//
// OpenObserve is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// Original project: https://github.com/openobserve/openobserve
//
// This file was created independently to add OIDC authentication and claim-based authorization.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use openidconnect::{
    AccessTokenHash, AuthorizationCode, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, ProviderMetadata, RefreshToken, Scope, TokenResponse,
    UserInfoUrl,
    core::{CoreAuthenticationFlow, CoreJsonWebKey, CoreProviderMetadata},
};
use serde_json::Value;
use tokio::sync::OnceCell;

use crate::{
    config::OidcConfig,
    errors::AuthError,
    http::get_http_client,
    models::{AuthTokens, AuthorizationState, CustomClient, CustomToken, UserInfo},
};

/// Lazily-resolved provider metadata. Wrapped in `Mutex<Option<...>>` so tests
/// can reset it via `reset_metadata_cache_for_tests`.
type MetadataSlot = Option<Result<Arc<CoreProviderMetadata>, Arc<AuthError>>>;
static METADATA: OnceCell<Mutex<MetadataSlot>> = OnceCell::const_new();

/// `openidconnect` client with a configured `redirect_uri` and the project's
/// custom claims / extra-token-fields wiring.
pub type OidcClient = CustomClient;

/// Discover the OIDC provider metadata for the configured issuer and cache it.
pub async fn create_oidc_metadata(cfg: &OidcConfig) -> Result<CoreProviderMetadata, AuthError> {
    let client = get_http_client().await;
    let issuer: IssuerUrl = cfg.issuer_url.clone();
    ProviderMetadata::discover_async(issuer, client)
        .await
        .map_err(|err| {
            log::error!("OIDC discover failed: {err:?}");
            AuthError::internal("discovering OIDC provider metadata", err)
        })
}

/// Build an `OidcClient` from the cached metadata and the configured credentials.
pub async fn create_oidc_client() -> Result<OidcClient, AuthError> {
    let cfg = crate::config::get_oidc_config();
    let metadata = get_oidc_metadata(&cfg).await?;
    let builder = CustomClient::from_provider_metadata(
        metadata,
        cfg.client_id.clone(),
        cfg.client_secret.clone(),
    )
    .set_redirect_uri(cfg.redirect_url.clone());
    Ok(builder)
}

async fn get_oidc_metadata(cfg: &OidcConfig) -> Result<CoreProviderMetadata, AuthError> {
    let cell = METADATA.get_or_init(|| async { Mutex::new(None) }).await;
    // Read the cache under a short-lived lock and drop the guard before any
    // `await`. The lock is sync, so holding it across `create_oidc_metadata`'s
    // network round-trip would tie up an executor thread and trip
    // `clippy::await_holding_lock`.
    let cached: MetadataSlot = cell.lock().expect("metadata mutex poisoned").clone();
    if let Some(snapshot) = cached {
        return materialise_metadata(Some(snapshot));
    }
    let fresh = create_oidc_metadata(cfg)
        .await
        .map(Arc::new)
        .map_err(Arc::new);
    *cell.lock().expect("metadata mutex poisoned") = Some(fresh.clone());
    materialise_metadata(Some(fresh))
}

fn materialise_metadata(cached: MetadataSlot) -> Result<CoreProviderMetadata, AuthError> {
    match cached {
        Some(Ok(meta)) => Ok((*meta).clone()),
        Some(Err(err)) => Err(AuthError::internal("cached OIDC metadata", err)),
        None => Err(AuthError::internal(
            "cached OIDC metadata missing",
            std::io::Error::other("metadata slot was empty after init"),
        )),
    }
}

/// Test helper: clear the cached provider metadata so a subsequent call
/// re-runs discovery. Exposed only for integration tests that need to retry
/// discovery against different mock issuers.
#[doc(hidden)]
pub async fn reset_metadata_cache_for_tests() {
    if let Some(cell) = METADATA.get() {
        *cell.lock().expect("metadata mutex poisoned") = None;
    }
}

/// Build a fresh `AuthorizationState` for an outgoing OIDC login, together
/// with the matching PKCE challenge. The caller is expected to store the
/// returned `AuthorizationState` in the session and pass the challenge
/// straight into `build_authorization_url`.
pub fn create_authorization_state() -> (AuthorizationState, PkceCodeChallenge) {
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let csrf = CsrfToken::new_random();
    let nonce = Nonce::new_random();
    let state = AuthorizationState {
        pkce_verifier: verifier.into_secret(),
        csrf_state: csrf.into_secret(),
        nonce: nonce.secret().to_owned(),
    };
    (state, challenge)
}

/// Build the authorization URL the user should be redirected to in order to
/// start the OIDC login. The caller must pair this with the `state` that was
/// already stored in the session (the CSRF token echoed back by the provider
/// is verified on callback).
pub async fn build_authorization_url(
    state: &AuthorizationState,
    challenge: &PkceCodeChallenge,
) -> Result<url::Url, AuthError> {
    let client = create_oidc_client().await?;
    let csrf_secret = state.csrf_state.clone();
    let nonce_secret = state.nonce.clone();
    let url = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            move || CsrfToken::new(csrf_secret.clone()),
            move || Nonce::new(nonce_secret.clone()),
        )
        .add_scope(Scope::new("openid".to_string()))
        .set_pkce_challenge(challenge.clone())
        .url();
    Ok(url.0)
}

/// Exchange the authorization `code` from the OIDC callback for tokens,
/// verify the `id_token`, and produce a `UserInfo` + `AuthTokens` pair.
///
/// `state` must be the same `AuthorizationState` that was stored when
/// initiating the login (it carries the PKCE verifier, CSRF, and nonce).
pub async fn exchange_authorization_code(
    code: &str,
    state: &AuthorizationState,
) -> Result<(UserInfo, AuthTokens), AuthError> {
    let client = create_oidc_client().await?;
    let response = exchange_code(code, state, &client).await?;
    let verifier = client.id_token_verifier();
    let expected_nonce = state.nonce.clone();
    process_token_response(verifier, move |actual| actual == expected_nonce, response)
}

/// Refresh the access/refresh tokens using the stored `refresh_token`.
/// Verifies the new `id_token` and returns the new user/tokens pair.
pub async fn exchange_refresh_token(
    tokens: &AuthTokens,
) -> Result<(UserInfo, AuthTokens), AuthError> {
    if tokens.refresh_token.is_empty() {
        return Err(AuthError::internal_msg("refresh token is empty"));
    }
    let client = create_oidc_client().await?;
    let refresh = RefreshToken::new(tokens.refresh_token.clone());
    let http = get_http_client().await;
    let response = client
        .exchange_refresh_token(&refresh)
        .map_err(|err| AuthError::internal("building refresh token request", err))?
        .request_async(http)
        .await
        .map_err(|err| AuthError::internal("executing refresh token request", err))?;
    let verifier = client.id_token_verifier();
    // On refresh the nonce is rotated by the provider; skip strict check.
    process_token_response(verifier, |_| true, response)
}

/// Verify a previously-issued `id_token` against the provider's JWKS and
/// return the contained `UserInfo`. Does not perform token exchange.
pub async fn try_to_verify_token(id_token: &str) -> Result<UserInfo, AuthError> {
    let client = create_oidc_client().await?;
    let verifier = client.id_token_verifier();
    let token = CustomToken::from_str(id_token)
        .map_err(|err| AuthError::internal("parsing id_token", err))?;
    let claims = token
        .claims(&verifier, crate::models::empty_nonce_verifier())
        .map_err(|err| AuthError::internal("verifying id_token claims", err))?;
    Ok(UserInfo::from_claims(claims))
}

/// Verify an `id_token`, falling back to a refresh-token grant when the
/// token has expired. Returns the (possibly refreshed) `UserInfo` along
/// with a possibly-rotated `AuthTokens` set. When no refresh is needed,
/// the returned `AuthTokens` is identical to the input.
pub async fn verify_with_refresh(tokens: &AuthTokens) -> Result<(UserInfo, AuthTokens), AuthError> {
    match try_to_verify_token(&tokens.id_token).await {
        Ok(user_info) => Ok((user_info, tokens.clone())),
        Err(_) if !tokens.refresh_token.is_empty() => {
            log::info!("OIDC id_token expired; exchanging refresh_token");
            exchange_refresh_token(tokens).await
        }
        Err(e) => Err(e),
    }
}

/// Hit the OIDC `userinfo` endpoint with the given `access_token` and return
/// the JSON body. Useful for providers whose `id_token` is minimal and which
/// rely on `/userinfo` for identity claims.
pub async fn retrieve_user_info_from_endpoint(
    access_token: &str,
    userinfo_url: &str,
) -> Result<Value, AuthError> {
    let http = get_http_client().await;
    // Reject malformed URLs early so we don't pass garbage to reqwest.
    let _ = UserInfoUrl::new(userinfo_url.to_owned())
        .map_err(|err| AuthError::internal("invalid userinfo URL", err))?;
    let resp = http
        .get(userinfo_url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|err| AuthError::internal("userinfo request failed", err))?;
    if !resp.status().is_success() {
        return Err(AuthError::internal(
            "userinfo endpoint returned non-2xx",
            std::io::Error::other(format!("status {}", resp.status())),
        ));
    }
    resp.json::<Value>()
        .await
        .map_err(|err| AuthError::internal("decoding userinfo response", err))
}

async fn exchange_code(
    code: &str,
    state: &AuthorizationState,
    client: &OidcClient,
) -> Result<crate::models::CustomTokenResponse, AuthError> {
    let http = get_http_client().await;
    let verifier = PkceCodeVerifier::new(state.pkce_verifier.clone());
    let auth_code = AuthorizationCode::new(code.to_owned());
    let response = client
        .exchange_code(auth_code)
        .map_err(|err| AuthError::internal("building code exchange request", err))?
        .set_pkce_verifier(verifier)
        .request_async(http)
        .await
        .map_err(|err| AuthError::internal("executing code exchange request", err))?;
    Ok(response)
}

fn process_token_response(
    verifier: openidconnect::IdTokenVerifier<'_, CoreJsonWebKey>,
    nonce_check: impl Fn(&str) -> bool,
    response: crate::models::CustomTokenResponse,
) -> Result<(UserInfo, AuthTokens), AuthError> {
    let id_token: &CustomToken = response
        .id_token()
        .ok_or_else(|| AuthError::internal_msg("id_token missing in token response"))?;
    let claims = id_token
        .claims(&verifier, crate::models::empty_nonce_verifier())
        .map_err(|err| AuthError::internal("verifying id_token", err))?;
    let actual_nonce = claims.nonce().map(|n| n.secret().as_str()).unwrap_or("");
    if !nonce_check(actual_nonce) {
        return Err(AuthError::internal_msg(
            "id_token nonce did not match expected",
        ));
    }
    if let Some(expected) = claims.access_token_hash() {
        let alg = id_token
            .signing_alg()
            .map_err(|err| AuthError::internal("reading id_token signing alg", err))?;
        let key = id_token
            .signing_key(&verifier)
            .map_err(|err| AuthError::internal("resolving id_token signing key", err))?;
        let actual = AccessTokenHash::from_token(response.access_token(), alg, key)
            .map_err(|err| AuthError::internal("computing access_token hash", err))?;
        if actual != *expected {
            return Err(AuthError::internal_msg("access_token hash mismatch"));
        }
    }
    let id_token_str = id_token.to_string();
    let access_token_str = response.access_token().secret().to_owned();
    let refresh_token_str = response
        .refresh_token()
        .map(|rt| rt.secret().to_owned())
        .unwrap_or_default();
    let expires_in = response
        .extra_fields()
        .extra_fields()
        .refresh_token_expires_in()
        .or_else(|| response.expires_in());
    let user = UserInfo::from_claims(claims);
    let tokens = AuthTokens {
        expires_in,
        access_token: access_token_str,
        refresh_token: refresh_token_str,
        id_token: id_token_str,
    };
    Ok((user, tokens))
}
