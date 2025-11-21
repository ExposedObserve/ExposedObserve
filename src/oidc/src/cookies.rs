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

use actix_web::{
    HttpResponseBuilder,
    cookie::{Cookie, time::Duration},
};
use base64::Engine;

use crate::{
    config::{self, AUTH_TOKENS_COOKIE, CookieConfig, OidcConfig},
    models::AuthTokens,
};

/// Creates a secure authentication cookie containing the base64-encoded AuthTokens.
///
/// This function serializes the AuthTokens to JSON, encodes it with base64,
/// and creates a secure cookie with appropriate security settings.
/// The cookie expiration is set based on the token's expires_in field.
///
/// # Arguments
/// * `auth_tokens` - The authentication tokens to store in the cookie
///
/// # Returns
/// * `Cookie<'static>` - The configured authentication cookie
pub fn make_auth_cookie(auth_tokens: &AuthTokens, config: &CookieConfig) -> Cookie<'static> {
    let json_string = serde_json::to_string(&auth_tokens).unwrap();
    let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(json_string.as_str());
    let duration = auth_tokens
        .expires_in
        .map(|d| Duration::seconds_f64(d.as_secs_f64()));
    build_cookie(AUTH_TOKENS_COOKIE, encoded, config, duration)
}

/// Convenience function to create a cookie with the OIDC configuration settings.
///
/// # Arguments
/// * `name` - Cookie name
/// * `secret` - Cookie value
/// * `duration` - Optional custom duration, otherwise uses config default
///
/// # Returns
/// * `Cookie<'static>` - The configured cookie
pub fn make_cookie(
    name: &'static str,
    secret: String,
    duration: Option<Duration>,
    config: &OidcConfig,
) -> Cookie<'static> {
    build_cookie(name, secret, &config.session_config.cookie_config, duration)
}

// TODO: Consider removing the config parameter and making this function pure
/// Internal function to build a cookie with provided OIDC configuration.
///
/// Creates a secure cookie with proper settings for the OIDC environment.
/// All cookies are http_only, set path to "/", and configured for security.
///
/// # Arguments
/// * `name` - Cookie name
/// * `secret` - Cookie value
/// * `config` - OIDC configuration for cookie security settings
/// * `duration` - Optional duration, defaults to config.cookie_max_age
///
/// # Returns
/// * `Cookie<'static>` - The configured cookie
pub(crate) fn build_cookie(
    name: &'static str,
    secret: String,
    config: &CookieConfig,
    duration: Option<Duration>,
) -> Cookie<'static> {
    let max_age = match duration {
        Some(dur) => dur,
        None => config.cookie_max_age,
    };
    actix_web::cookie::Cookie::build(name, secret)
        .path("/")
        .same_site(config.same_site)
        .secure(config.secure)
        .http_only(true)
        .max_age(max_age)
        .finish()
}

/// Clears authentication-related cookies from the response.
///
/// This function adds "expire immediately" cookies to clear any existing
/// auth tokens from the client. Currently only clears the main auth_tokens cookie
/// since other auth data is stored in server-side sessions.
///
/// # Arguments
/// * `response_builder` - The HTTP response builder to add expiration cookies to
pub(crate) fn clear_all_auth_cookies(response_builder: &mut HttpResponseBuilder) {
    let config = config::get_oidc_config();
    // Only clear the main auth_tokens cookie since other data (PKCE, nonce, etc.) is in sessions
    response_builder.cookie(clear_cookie(AUTH_TOKENS_COOKIE, &config));
}

/// Creates an expiration cookie to clear a named cookie from the client.
///
/// This function creates a cookie with empty value and zero max-age
/// to instruct the client to delete any existing cookie of that name.
///
/// # Arguments
/// * `name` - Name of the cookie to clear
/// * `config` - OIDC configuration for cookie security settings
///
/// # Returns
/// * `Cookie<'static>` - Expiration cookie for the named cookie
fn clear_cookie(name: &'static str, config: &OidcConfig) -> Cookie<'static> {
    actix_web::cookie::Cookie::build(name, "")
        .path("/")
        .same_site(config.session_config.cookie_config.same_site)
        .secure(config.session_config.cookie_config.secure)
        .http_only(true)
        .max_age(Duration::seconds(0))
        .finish()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use actix_web::{
        cookie::{SameSite, time::Duration as CookieDuration},
        http::StatusCode,
    };

    use super::*;
    use crate::config::{
        OIDC_COOKIE_MAX_AGE_SEC_DEFAULT_VALUE,
        OIDC_COOKIE_SAME_SITE_DEFAULT_VALUE, get_oidc_config,
    };

    #[test]
    fn test_make_auth_cookie() {
        let tokens = AuthTokens {
            expires_in: Some(Duration::from_secs(3600)),
            access_token: "test_access".to_string(),
            refresh_token: "test_refresh".to_string(),
            id_token: "test_id".to_string(),
        };
        let config = CookieConfig {
            secure: false,
            same_site: OIDC_COOKIE_SAME_SITE_DEFAULT_VALUE,
            cookie_max_age: config::convert_duration(OIDC_COOKIE_MAX_AGE_SEC_DEFAULT_VALUE),
        };
        let cookie = make_auth_cookie(&tokens, &config);

        assert_eq!(cookie.name(), "auth_tokens");
        assert!(!cookie.secure().unwrap()); // Should be secure based on config
        assert!(cookie.http_only().unwrap()); // Should always be http_only
    }

    #[test]
    fn test_make_cookie() {
        let config = &config::CookieConfig::default();
        let cookie = build_cookie("test_name", "test_value".into(), config, None);
        assert_eq!(cookie.name(), "test_name");
        assert_eq!(cookie.value(), "test_value");
        assert!(cookie.http_only().unwrap());
    }

    #[test]
    fn test_build_cookie() {
        let config = CookieConfig {
            secure: true,
            same_site: SameSite::Strict,
            cookie_max_age: CookieDuration::hours(1),
        };

        let cookie = build_cookie("test", "secret".into(), &config, None);
        assert_eq!(cookie.name(), "test");
        assert_eq!(cookie.value(), "secret");
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true)); // since insecure false
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.max_age(), Some(CookieDuration::hours(1)));
    }

    #[test]
    fn test_build_cookie_with_custom_duration() {
        let config = CookieConfig {
            secure: false,
            same_site: SameSite::Lax,
            cookie_max_age: CookieDuration::hours(1),
        };

        let custom_duration = CookieDuration::minutes(30);
        let cookie = build_cookie("test", "secret".into(), &config, Some(custom_duration));
        assert_eq!(cookie.max_age(), Some(custom_duration));
    }

    #[test]
    fn test_clear_all_auth_cookies() {
        let mut builder = actix_web::HttpResponseBuilder::new(StatusCode::OK);
        clear_all_auth_cookies(&mut builder);

        let response = builder.finish();
        let cookies: Vec<_> = response.cookies().collect();

        assert_eq!(cookies.len(), 1);
        let cookie = &cookies[0];
        assert_eq!(cookie.name(), "auth_tokens");
        assert_eq!(cookie.value().trim(), ""); // value is ""
        assert_eq!(cookie.max_age(), Some(CookieDuration::seconds(0)));
        assert_eq!(cookie.http_only(), Some(true));
    }

    #[test]
    fn test_clear_cookie_creation() {
        let config = get_oidc_config();

        let cookie = clear_cookie("test_cookie", &config);
        assert_eq!(cookie.name(), "test_cookie");
        assert_eq!(cookie.value(), "");
        assert_eq!(
            cookie.max_age(),
            Some(actix_web::cookie::time::Duration::seconds(0))
        );
        assert!(cookie.http_only().unwrap());
    }
}
