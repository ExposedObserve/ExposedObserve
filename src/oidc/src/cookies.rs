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

use actix_web::
    cookie::{Cookie, time::Duration}
;

use crate::
    config::{CookieConfig, OidcConfig}
;

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

#[cfg(test)]
mod tests {

    use actix_web::
        cookie::{SameSite, time::Duration as CookieDuration}
    ;

    use super::*;
    use crate::config::{self, get_oidc_config};

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
}
