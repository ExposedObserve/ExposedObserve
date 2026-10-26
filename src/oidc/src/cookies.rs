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

use axum_extra::extract::CookieJar;
use base64::Engine as _;
use cookie::Cookie;
#[cfg(test)]
use cookie::SameSite;
use http::HeaderValue;
use serde::de::DeserializeOwned;
use time::Duration;

use crate::{
    config::{AUTH_STATE_COOKIE, CookieConfig, OidcConfig, get_oidc_config},
    errors::AuthError,
    models::{AuthTokens, AuthorizationState},
};

// /// Build a session cookie for the OIDC flow with the configured security flags.
// pub fn make_cookie(name: &'static str, value: String, config: &OidcConfig) -> Cookie<'static> {
//     build_cookie(name, value, &config.cookie_config, None)
// }

/// Internal helper that takes a `CookieConfig` directly. Useful for tests.
fn build_cookie(
    name: &'static str,
    value: String,
    config: &CookieConfig,
    max_age_override: Option<Duration>,
) -> Cookie<'static> {
    let max_age = max_age_override.unwrap_or(config.cookie_max_age);
    Cookie::build((name, value))
        .path("/")
        .same_site(config.same_site)
        .secure(config.secure)
        .http_only(true)
        .max_age(max_age)
        .into()
}

fn cookie_to_header(cookie: Cookie<'static>) -> Result<HeaderValue, AuthError> {
    axum::http::HeaderValue::from_str(&cookie.encoded().to_string())
        .map_err(|err| AuthError::BadRequest(err.to_string()))
}

fn read_cookie<T: DeserializeOwned>(jar: CookieJar, name: &str) -> Option<T> {
    let cookie_value: &str = jar.get(name)?.value();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(cookie_value)
        .ok()?;
    let json = String::from_utf8(decoded).ok()?;
    serde_json::from_str(&json).ok()
}

pub fn build_state_cookie(state: &AuthorizationState) -> Result<Cookie<'static>, AuthError> {
    let config = get_oidc_config();
    let json = serde_json::to_string(state)
        .map_err(|e| AuthError::internal("Failed to serialize AuthorizationState", e))?;
    let value = base64::engine::general_purpose::STANDARD.encode(json);
    if value.len() > 4096 {
        return Err(AuthError::internal_msg(
            "Cookie size exceeds 4KB browser limit",
        ));
    }
    let cookie = build_cookie(
        AUTH_STATE_COOKIE,
        value,
        &config.cookie_config,
        Some(time::Duration::minutes(5)),
    );
    Ok(cookie)
}

pub fn read_state_cookie(jar: CookieJar) -> Option<AuthorizationState> {
    read_cookie::<AuthorizationState>(jar, AUTH_STATE_COOKIE)
}

pub fn clear_state_cookie() -> Result<HeaderValue, AuthError> {
    let config = get_oidc_config();
    let cookie = build_cookie(
        AUTH_STATE_COOKIE,
        "".into(),
        &config.cookie_config,
        Some(time::Duration::milliseconds(0)),
    );
    cookie_to_header(cookie)
}

pub fn build_auth_cookie(
    name: &'static str,
    tokens: &AuthTokens,
) -> Result<HeaderValue, AuthError> {
    let config = &get_oidc_config().cookie_config;
    let json = serde_json::to_string(tokens)
        .map_err(|e| AuthError::internal("Failed to serialize AuthTokens", e))?;
    let value = base64::engine::general_purpose::STANDARD.encode(json);
    if value.len() > 4096 {
        return Err(AuthError::internal_msg(
            "Cookie size exceeds 4KB browser limit",
        ));
    }

    cookie_to_header(build_cookie(name, value, config, None))
}

pub fn clear_auth_cookie(name: &'static str) -> Result<HeaderValue, AuthError> {
    let config: std::sync::Arc<OidcConfig> = get_oidc_config();
    let cookie = build_cookie(
        name,
        "".into(),
        &config.cookie_config,
        Some(time::Duration::milliseconds(0)),
    );
    cookie_to_header(cookie)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::config::{HttpClientConfig, SessionConfig};

    fn build_cfg(same_site: SameSite) -> OidcConfig {
        OidcConfig::new(
            "test",
            None,
            "https://example.com",
            "https://example.com/cb",
            "https://example.com/cb",
            HttpClientConfig::default(),
            CookieConfig {
                cookie_name: "foo".into(),
                secure: true,
                same_site,
                cookie_max_age: time::Duration::seconds(60),
            },
            SessionConfig {
                ..SessionConfig::default()
            },
            "groups",
            "^(?<org>.*)$",
            Some("sub"),
            Some("email"),
            HashSet::new(),
        )
        .expect("config must build")
    }

    #[test]
    fn build_cookie_sets_security_flags() {
        let cfg = build_cfg(SameSite::Strict);
        let cookie = build_cookie("sid", "value".into(), &cfg.cookie_config, None);
        assert_eq!(cookie.name(), "sid");
        assert_eq!(cookie.value(), "value");
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.path(), Some("/"));
    }

    #[test]
    fn build_cookie_respects_max_age_override() {
        let cfg = build_cfg(SameSite::Lax);
        let override_duration = time::Duration::seconds(15);
        let cookie = build_cookie(
            "sid",
            "value".into(),
            &cfg.cookie_config,
            Some(override_duration),
        );
        assert_eq!(cookie.max_age(), Some(override_duration));
    }
}
