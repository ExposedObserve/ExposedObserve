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

use actix_session::{
    Session, SessionExt, SessionInsertError, SessionMiddleware,
    config::CookieContentSecurity,
    storage::{CookieSessionStore, RedisSessionStore, SessionStore},
};
use actix_web::{HttpRequest, cookie::Key, http::StatusCode};
use base64::Engine;
use log::error;

use crate::{
    config::{
        self, AUTH_STATE, AUTH_TOKENS_COOKIE, AUTH_TOKENS_SESSION_KEY, OIDC_SESSION_FLAG, SessionConfig, get_oidc_config
    },
    errors::AuthError,
    models::{AuthTokens, AuthorizationState},
};

/// Enum representing the type of session store to use for OIDC sessions.
///
/// This enum wraps the underlying session store implementations from actix-session,
/// providing a unified interface for different storage backends.
pub enum OidcSessionStore {
    /// Cookie-based session storage using client-side cookies.
    Cookie(CookieSessionStore),
    /// Redis-based session storage for server-side session management.
    Redis(RedisSessionStore),
}

/// Creates and returns the appropriate session store based on the current OIDC configuration.
///
/// This function reads the session configuration and instantiates either a cookie-based
/// or Redis-based session store depending on the configured `session_store_type`.
/// For Redis stores, it will attempt to connect to the Redis instance specified in the config.
///
/// # Returns
/// * `OidcSessionStore` - The configured session store wrapped in the enum
///
/// # Panics
/// Panics if Redis is configured but the connection fails or Redis URL is missing.
pub async fn get_session_store() -> OidcSessionStore {
    let session_config = &get_oidc_config().session_config;
    match session_config.session_store_type {
        config::SessionStoreType::Cookie => OidcSessionStore::Cookie(CookieSessionStore::default()),
        config::SessionStoreType::Redis => {
            let redis_store = get_redis_session_store(session_config).await;
            OidcSessionStore::Redis(redis_store)
        }
    }
}

/// Creates a Redis session store from the provided session configuration.
///
/// This function attempts to establish a connection to the Redis instance
/// specified in the configuration. If the connection fails or the Redis URL
/// is not provided, the function will panic with an error message.
///
/// # Arguments
/// * `session_config` - The session configuration containing Redis connection details
///
/// # Returns
/// * `RedisSessionStore` - A configured Redis session store
///
/// # Panics
/// Panics if Redis URL is missing from config or if connection to Redis fails.
pub async fn get_redis_session_store(session_config: &SessionConfig) -> RedisSessionStore {
    let redis_url = session_config.redis_url.as_ref().expect(
            "Redis URL must be provided in OIDC session config when using Redis session store",
        );
    RedisSessionStore::new(redis_url)
        .await
        .inspect_err(|e| error!("Failed to create Redis session store: {}", e))
        .unwrap()
}

/// Creates a session middleware configured for Redis session storage.
///
/// This function builds a `SessionMiddleware` with the provided Redis store
/// and applies all session configuration settings from the OIDC config,
/// including cookie security, session lifecycle, and other session parameters.
///
/// # Arguments
/// * `store` - The Redis session store to use
///
/// # Returns
/// * `SessionMiddleware<RedisSessionStore>` - Configured session middleware
pub fn get_redis_session_middleware(store: RedisSessionStore) -> SessionMiddleware<RedisSessionStore> {
    session_middleware(store, &get_oidc_config().session_config)
}

/// Creates a session middleware configured for cookie-based session storage.
///
/// This function builds a `SessionMiddleware` with a default cookie store
/// and applies all session configuration settings from the OIDC config,
/// including cookie security, session lifecycle, and other session parameters.
///
/// # Returns
/// * `SessionMiddleware<CookieSessionStore>` - Configured session middleware
pub fn get_cookie_session_middleware() -> SessionMiddleware<CookieSessionStore> {
    session_middleware(CookieSessionStore::default(), &get_oidc_config().session_config)
}

fn session_middleware<S: SessionStore>(
    store: S,
    config: &config::SessionConfig,
) -> SessionMiddleware<S> {
    let cookie_content_security = match config.cookie_config.secure {
        true => CookieContentSecurity::Private,
        false => CookieContentSecurity::Signed,
    };
    SessionMiddleware::builder(store, Key::from(&config.cookie_key))
        .cookie_name(config.cookie_name.clone())
        .cookie_secure(config.cookie_config.secure)
        .session_lifecycle(config.session_lifecycle.clone())
        .cookie_same_site(config.cookie_config.same_site)
        .cookie_content_security(cookie_content_security)
        .cookie_http_only(config.cookie_config.secure)
        .build()
}

/// Retrieves authentication tokens from the client-side cookie.
///
/// This function extracts and decodes the base64-encoded AuthTokens stored
/// in the "auth_tokens" cookie for client-side authentication token storage.
/// Returns None if the cookie doesn't exist or decoding/deserialization fails.
pub fn get_tokens(req: &HttpRequest) -> Option<AuthTokens> {
    let cookie = req.cookie(AUTH_TOKENS_COOKIE)?;
    let cookie_value = cookie.value();
    let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(cookie_value)
        .inspect_err(|e| error!("Tokens decoding error\n{}", e))
        .ok()?;
    serde_json::from_slice::<AuthTokens>(&decoded)
        .inspect_err(|e| error!("Tokens deserializing error\n{}", e))
        .ok()
}

/// Retrieves authentication tokens stored in the server-side session.
///
/// This is used for server-side session storage as an alternative to
/// client-side cookie storage. Returns None if session doesn't contain tokens.
pub fn get_session_tokens(req: &HttpRequest) -> Option<AuthTokens> {
    req.get_session()
        .get::<AuthTokens>(AUTH_TOKENS_SESSION_KEY)
        .ok()?
}

/// Updates the session with new authentication tokens.
///
/// Sets the "oidc" flag to indicate OIDC authentication is active
/// and stores the tokens in the session storage. Renews the session
/// to reset the expiration time.
///
/// # Arguments
/// * `req` - The HTTP request containing the session
/// * `auth_tokens` - The authentication tokens to store
///
/// # Returns
/// * `Result<(), SessionInsertError>` - Success or insertion error
pub(crate) fn update_tokens(
    req: &HttpRequest,
    auth_tokens: &AuthTokens,
) -> Result<(), SessionInsertError> {
    let session: Session = req.get_session();
    session.insert(OIDC_SESSION_FLAG, true)?;
    session.insert(AUTH_TOKENS_SESSION_KEY, auth_tokens)?;
    session.renew();
    Ok(())
}

/// Stores the OAuth authorization state in the session.
///
/// This state is generated during the OIDC authorization flow initiation
/// and must be validated upon callback to prevent CSRF attacks.
/// The session is renewed to prevent expiration during the auth flow.
///
/// # Arguments
/// * `session` - The Actix session to store the state in
/// * `auth_state` - The authorization state containing PKCE, CSRF token, and nonce
///
/// # Returns
/// * `Result<(), SessionInsertError>` - Success or insertion error
pub(crate) fn insert_auth_state(
    session: &Session,
    auth_state: AuthorizationState,
) -> Result<(), SessionInsertError> {
    session.insert(AUTH_STATE, auth_state)?;
    session.renew();
    Ok(())
}

/// Retrieves and removes the authorization state from the session.
///
/// Used during the OIDC callback processing to validate the state
/// and extract the PKCE verifier, nonce, and CSRF token.
/// The state is removed to prevent reuse and ensure single-use.
///
/// # Arguments
/// * `session` - The Actix session containing the state
///
/// # Returns
/// * `Result<AuthorizationState, AuthError>` - The extracted auth state or error
pub(crate) fn extract_auth_state(session: &Session) -> Result<AuthorizationState, AuthError> {
    match session.remove_as::<AuthorizationState>(AUTH_STATE) {
        Some(res) => match res {
            Ok(auth_state) => {
                session.renew();
                Ok(auth_state)
            }
            Err(_err) => Err(AuthError::new(
                "Failed to deserialize AuthorizationState",
                StatusCode::UNAUTHORIZED,
            )),
        },
        None => Err(AuthError::new(
            "AuthorizationState not found",
            StatusCode::UNAUTHORIZED,
        )),
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{cookie, test::TestRequest};

    use super::*;

    #[test]
    fn test_get_session_tokens_none_when_missing() {
        let req = TestRequest::default().to_http_request();
        let result = get_session_tokens(&req);
        assert!(result.is_none());
    }

    #[test]
    fn test_insert_extract_auth_state() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        let test_state = AuthorizationState {
            pkce_verifier: "test_verifier".into(),
            csrf_state: "test_csrf".into(),
            nonce: "test_nonce".into(),
        };

        // Insert state
        let insert_result = insert_auth_state(&session, test_state.clone());
        assert!(insert_result.is_ok());

        // Extract state
        let extract_result = extract_auth_state(&session);
        assert!(extract_result.is_ok());

        let extracted = extract_result.unwrap();
        assert_eq!(extracted.pkce_verifier, test_state.pkce_verifier);
        assert_eq!(extracted.csrf_state, test_state.csrf_state);
        assert_eq!(extracted.nonce, test_state.nonce);
    }

    #[test]
    fn test_extract_auth_state_not_found() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        let result = extract_auth_state(&session);
        assert!(result.is_err());

        // Test the error response contains expected content
        let err = result.unwrap_err();
        assert_eq!(err.status_code, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_get_tokens_success() {
        let expected_tokens = AuthTokens {
            expires_in: Some(std::time::Duration::from_secs(3600)),
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            id_token: "id".into(),
        };

        let json = serde_json::to_string(&expected_tokens).unwrap();
        let encoded: String = base64::engine::general_purpose::STANDARD_NO_PAD.encode(json);

        let req = TestRequest::default()
            .cookie(cookie::Cookie::new("auth_tokens", encoded))
            .to_http_request();

        let result = get_tokens(&req);
        assert!(result.is_some());

        let tokens = result.unwrap();
        assert_eq!(tokens.access_token, expected_tokens.access_token);
        assert_eq!(tokens.refresh_token, expected_tokens.refresh_token);
        assert_eq!(tokens.id_token, expected_tokens.id_token);
        assert_eq!(tokens.expires_in, expected_tokens.expires_in);
    }

    #[test]
    fn test_get_tokens_no_cookie() {
        let req = TestRequest::default().to_http_request();
        let result = get_tokens(&req);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_tokens_invalid_base64() {
        let req = TestRequest::default()
            .cookie(cookie::Cookie::new("auth_tokens", "invalid_base64"))
            .to_http_request();

        let result = get_tokens(&req);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_tokens_invalid_json() {
        let encoded: String =
            base64::engine::general_purpose::STANDARD_NO_PAD.encode("invalid json");
        let req = TestRequest::default()
            .cookie(cookie::Cookie::new("auth_tokens", encoded))
            .to_http_request();

        let result = get_tokens(&req);
        assert!(result.is_none());
    }

    #[test]
    fn test_update_tokens() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        let test_tokens = AuthTokens {
            expires_in: Some(std::time::Duration::from_secs(3600)),
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            id_token: "id".into(),
        };

        let result = update_tokens(&req, &test_tokens);
        assert!(result.is_ok());

        let stored = session.get::<AuthTokens>(AUTH_TOKENS_SESSION_KEY);
        assert!(stored.is_ok());

        let retrieved = stored.unwrap();
        assert!(retrieved.is_some());

        let tokens = retrieved.unwrap();
        assert_eq!(tokens.access_token, test_tokens.access_token);
        assert_eq!(tokens.refresh_token, "refresh");
        assert_eq!(tokens.id_token, "id");
    }

    #[test]
    fn test_extract_auth_state_deserialization_error() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        // Manually insert invalid data that can't be deserialized as AuthorizationState
        let invalid_data = "invalid json";
        session.insert(AUTH_STATE, invalid_data).unwrap();

        let result = extract_auth_state(&session);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.status_code, StatusCode::UNAUTHORIZED);
        assert!(err.message.as_ref().unwrap().contains("Failed to deserialize"));
    }

    #[test]
    fn test_get_session_tokens_with_invalid_data() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        // Insert invalid data for tokens
        session.insert(AUTH_TOKENS_SESSION_KEY, "invalid data").unwrap();

        let result = get_session_tokens(&req);
        assert!(result.is_none());
    }
}
