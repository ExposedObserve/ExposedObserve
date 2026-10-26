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

use std::{collections::HashSet, env, sync::Arc, time::Duration as StdDuration};

use arc_swap::ArcSwap;
use base64::Engine;
use cookie::SameSite;
use log::error;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};
use regex::Regex;
use time::Duration as CookieDuration;

use crate::errors::AuthError;

pub static OIDC_ISSUER_URL: &str = "OIDC_ISSUER_URL";
pub static OIDC_REDIRECT_URL: &str = "OIDC_REDIRECT_URL";
pub static OIDC_CLIENT_ID: &str = "OIDC_CLIENT_ID";
pub static OIDC_CLIENT_SECRET: &str = "OIDC_CLIENT_SECRET";
pub static OIDC_TIMEOUT: &str = "OIDC_TIMEOUT";
pub static OIDC_CONNECT_TIMEOUT: &str = "OIDC_CONNECT_TIMEOUT";
pub static OIDC_POOL_IDLE_TIMEOUT: &str = "OIDC_POOL_IDLE_TIMEOUT";
pub static OIDC_POOL_MAX_IDLE_PER_HOST: &str = "OIDC_POOL_MAX_IDLE_PER_HOST";
pub static OIDC_INSECURE: &str = "OIDC_INSECURE";
pub static OIDC_COOKIE_SAME_SITE: &str = "OIDC_COOKIE_SAME_SITE";
pub static OIDC_COOKIE_MAX_AGE_SEC: &str = "OIDC_COOKIE_MAX_AGE_SEC";
pub static OIDC_COOKIE_NAME: &str = "OIDC_COOKIE_NAME";
pub static OIDC_SESSION_NAME: &str = "OIDC_SESSION_NAME";
pub static OIDC_SESSION_KEY: &str = "OIDC_SESSION_KEY";
pub static OIDC_CALLBACK_URL: &str = "OIDC_CALLBACK_URL";
pub static OIDC_ORG_CLAIM: &str = "OIDC_ORG_CLAIM";
pub static OIDC_ORG_CLAIM_PATTERN: &str = "OIDC_ORG_CLAIM_PATTERN";
pub static OIDC_SUBJECT_CLAIM: &str = "OIDC_SUBJECT_CLAIM";
pub static OIDC_EMAIL_CLAIM: &str = "OIDC_EMAIL_CLAIM";
pub static OIDC_ORG_BLACKLIST: &str = "OIDC_ORG_BLACKLIST";
pub static OIDC_REDIS_URL: &str = "OIDC_REDIS_URL";
pub static OIDC_REDIS_USERNAME: &str = "OIDC_REDIS_USERNAME";
pub static OIDC_REDIS_PASSWORD: &str = "OIDC_REDIS_PASSWORD";
pub static OIDC_REDIS_DB: &str = "OIDC_REDIS_DB";
pub static OIDC_REDIS_TLS: &str = "OIDC_REDIS_TLS";
pub static OIDC_REDIS_TLS_SERVER_NAME: &str = "OIDC_REDIS_TLS_SERVER_NAME";
pub static OIDC_REDIS_POOL_SIZE: &str = "OIDC_REDIS_POOL_SIZE";
pub static OIDC_REDIS_CONNECT_TIMEOUT: &str = "OIDC_REDIS_CONNECT_TIMEOUT";
pub static OIDC_REDIS_RECONNECT_DELAY_MAX: &str = "OIDC_REDIS_RECONNECT_DELAY_MAX";
pub static OIDC_REDIS_KEY_PREFIX: &str = "OIDC_REDIS_KEY_PREFIX";

pub static ORG_CAPTURE_GROUP: &str = "org";
pub static ROLE_CAPTURE_GROUP: &str = "role";
pub static AUTH_STATE_COOKIE: &str = "auth_state";
pub static SESSION_AUTH_TOKENS_KEY: &str = "auth_tokens";

const OIDC_TIMEOUT_DEFAULT_VALUE: StdDuration = StdDuration::from_secs(10);
const OIDC_CONNECT_TIMEOUT_DEFAULT_VALUE: StdDuration = StdDuration::from_secs(5);
const OIDC_POOL_IDLE_TIMEOUT_DEFAULT_VALUE: StdDuration = StdDuration::from_secs(60);
const OIDC_COOKIE_MAX_AGE_SEC_DEFAULT_VALUE: StdDuration = StdDuration::from_secs(3600);
const OIDC_POOL_MAX_IDLE_PER_HOST_DEFAULT_VALUE: usize = 10;
const OIDC_REDIS_POOL_SIZE_DEFAULT_VALUE: usize = 4;
const OIDC_REDIS_CONNECT_TIMEOUT_DEFAULT_VALUE: StdDuration = StdDuration::from_secs(5);
const OIDC_REDIS_RECONNECT_DELAY_MAX_DEFAULT_VALUE: StdDuration = StdDuration::from_secs(60);
const OIDC_REDIS_KEY_PREFIX_DEFAULT_VALUE: &str = "o2-oidc:session:";
const OIDC_INSECURE_DEFAULT_VALUE: bool = false;
const OIDC_COOKIE_SAME_SITE_DEFAULT_VALUE: SameSite = SameSite::Lax;
// const OIDC_SESSION_NAME_DEFAULT_VALUE: &str = "_Host-eo-auth";
const OIDC_SESSION_KEY_DEFAULT_VALUE: [u8; 64] = [0; 64];
const OIDC_ORG_CLAIM_DEFAULT_VALUE: &str = "groups";
const OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE: &str = "^(?<org>.*)$";

#[derive(Clone, Debug)]
pub struct CookieConfig {
    pub cookie_name: String,
    pub secure: bool,
    pub same_site: SameSite,
    pub cookie_max_age: CookieDuration,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            cookie_name: "".to_string(),
            secure: !OIDC_INSECURE_DEFAULT_VALUE,
            same_site: OIDC_COOKIE_SAME_SITE_DEFAULT_VALUE,
            cookie_max_age: std_duration_to_cookie(OIDC_COOKIE_MAX_AGE_SEC_DEFAULT_VALUE),
        }
    }
}

/// Redis connection settings for the session store.
///
/// Credentials and TLS have their own fields rather than living in the URL so
/// a password can be sourced from a secret store without URL-encoding rules,
/// and so TLS can be turned on independently of the scheme.
#[derive(Clone, Debug)]
pub struct RedisConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub database: Option<u32>,
    pub tls: bool,
    pub tls_server_name: Option<String>,
    pub pool_size: usize,
    pub connect_timeout: StdDuration,
    pub reconnect_delay_max: StdDuration,
    pub key_prefix: String,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            username: None,
            password: None,
            database: None,
            tls: false,
            tls_server_name: None,
            pool_size: OIDC_REDIS_POOL_SIZE_DEFAULT_VALUE,
            connect_timeout: OIDC_REDIS_CONNECT_TIMEOUT_DEFAULT_VALUE,
            reconnect_delay_max: OIDC_REDIS_RECONNECT_DELAY_MAX_DEFAULT_VALUE,
            key_prefix: OIDC_REDIS_KEY_PREFIX_DEFAULT_VALUE.to_string(),
        }
    }
}

impl RedisConfig {
    pub fn is_enabled(&self) -> bool {
        !self.url.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub session_name: String,
    pub session_key: Vec<u8>,
    pub redis: RedisConfig,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            session_name: "".to_string(),
            session_key: OIDC_SESSION_KEY_DEFAULT_VALUE.to_vec(),
            redis: RedisConfig::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpClientConfig {
    pub insecure: bool,
    pub timeout: StdDuration,
    pub connect_timeout: StdDuration,
    pub pool_idle_timeout: StdDuration,
    pub pool_max_idle_per_host: usize,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            insecure: OIDC_INSECURE_DEFAULT_VALUE,
            timeout: OIDC_TIMEOUT_DEFAULT_VALUE,
            connect_timeout: OIDC_CONNECT_TIMEOUT_DEFAULT_VALUE,
            pool_idle_timeout: OIDC_POOL_IDLE_TIMEOUT_DEFAULT_VALUE,
            pool_max_idle_per_host: OIDC_POOL_MAX_IDLE_PER_HOST_DEFAULT_VALUE,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub client_id: ClientId,
    pub client_secret: Option<ClientSecret>,
    pub issuer_url: IssuerUrl,
    pub redirect_url: RedirectUrl,
    pub callback_url: String,
    pub http_client_config: HttpClientConfig,
    pub cookie_config: CookieConfig,
    pub session_config: SessionConfig,
    pub org_claim: String,
    pub org_claim_pattern: Regex,
    pub subject_claim: Option<String>,
    pub email_claim: Option<String>,
    pub org_blacklist: HashSet<String>,
}

impl OidcConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_id: &str,
        client_secret: Option<&str>,
        issuer: &str,
        redirect_url: &str,
        callback_url: &str,
        http_client_config: HttpClientConfig,
        cookie_config: CookieConfig,
        session_config: SessionConfig,
        org_claim: &str,
        org_claim_pattern: &str,
        subject_claim: Option<&str>,
        email_claim: Option<&str>,
        org_blacklist: HashSet<String>,
    ) -> Result<Self, AuthError> {
        let pattern = Regex::new(org_claim_pattern)
            .map_err(|err| AuthError::internal("compiling org claim pattern", err))?;
        // SameSite=None requires Secure=true per RFC 6265 bis.
        let mut cookie_config = cookie_config;
        if cookie_config.same_site == SameSite::None {
            cookie_config.secure = true;
        }
        Ok(Self {
            client_id: ClientId::new(client_id.to_owned()),
            client_secret: client_secret.map(|s| ClientSecret::new(s.to_owned())),
            issuer_url: IssuerUrl::new(issuer.to_owned())
                .map_err(|e| AuthError::internal("invalid OIDC_ISSUER_URL", e))?,
            redirect_url: RedirectUrl::new(redirect_url.to_owned())
                .map_err(|e| AuthError::internal("invalid OIDC_REDIRECT_URL", e))?,
            callback_url: callback_url.to_owned(),
            http_client_config,
            cookie_config,
            session_config,
            org_claim: org_claim.to_owned(),
            org_claim_pattern: pattern,
            subject_claim: subject_claim.map(|s| s.to_owned()),
            email_claim: email_claim.map(|s| s.to_owned()),
            org_blacklist,
        })
    }

    /// `true` when the running process was configured for a real OIDC
    /// provider, i.e. `OIDC_ISSUER_URL` differs from the placeholder
    /// used by `build_default_config`. The login page uses this to
    /// decide whether to render the OIDC button.
    pub fn is_enabled(&self) -> bool {
        !self.issuer_url.url().as_str().is_empty()
            && self.issuer_url.url().host_str() != Some("example.com")
    }
}

static CONFIG: once_cell::sync::Lazy<ArcSwap<OidcConfig>> =
    once_cell::sync::Lazy::new(|| ArcSwap::from_pointee(build_default_config()));

pub fn get_oidc_config() -> Arc<OidcConfig> {
    CONFIG.load_full()
}

/// Replace the cached config. Called from `init()` after parsing
/// `OIDC_*` env vars. The replacement is atomic via `ArcSwap`,
/// so in-flight `get_oidc_config()` readers see either the old
/// or the new config, never a half-initialised one.
pub fn set_config(cfg: OidcConfig) {
    CONFIG.store(Arc::new(cfg));
}

fn build_default_config() -> OidcConfig {
    OidcConfig::new(
        "oidc-client",
        None,
        "https://example.com",
        "https://example.com/callback",
        "https://example.com/callback",
        HttpClientConfig::default(),
        CookieConfig::default(),
        SessionConfig::default(),
        OIDC_ORG_CLAIM_DEFAULT_VALUE,
        OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE,
        Some("sub"),
        Some("email"),
        HashSet::new(),
    )
    .expect("default config must be valid")
}

/// Parse the OIDC config from process environment variables. Used by `init()`.
pub fn load_config_from_env() -> Result<OidcConfig, AuthError> {
    let _ = dotenvy::dotenv();

    let client_id = env::var(OIDC_CLIENT_ID).unwrap_or_else(|_| "oidc-client".into());
    let client_secret = env::var(OIDC_CLIENT_SECRET).ok();
    let issuer_url = env::var(OIDC_ISSUER_URL).unwrap_or_else(|_| "https://example.com".into());
    let redirect_url =
        env::var(OIDC_REDIRECT_URL).unwrap_or_else(|_| "https://example.com/callback".into());
    let callback_url = env::var(OIDC_CALLBACK_URL).unwrap_or_else(|_| redirect_url.clone());

    let org_claim =
        env::var(OIDC_ORG_CLAIM).unwrap_or_else(|_| OIDC_ORG_CLAIM_DEFAULT_VALUE.to_string());
    let org_claim_pattern = env::var(OIDC_ORG_CLAIM_PATTERN)
        .unwrap_or_else(|_| OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE.to_string());
    let subject_claim = env::var(OIDC_SUBJECT_CLAIM).ok().filter(|s| !s.is_empty());
    let email_claim = env::var(OIDC_EMAIL_CLAIM).ok().filter(|s| !s.is_empty());

    let org_blacklist = env::var(OIDC_ORG_BLACKLIST)
        .ok()
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_owned())
                .filter(|p| !p.is_empty())
                .collect::<HashSet<String>>()
        })
        .unwrap_or_default();

    let http_client_config = HttpClientConfig {
        insecure: parse_env_or(OIDC_INSECURE, OIDC_INSECURE_DEFAULT_VALUE, |s| {
            s.parse::<bool>().map_err(|e| e.to_string())
        }),
        timeout: StdDuration::from_secs(parse_env_or(
            OIDC_TIMEOUT,
            OIDC_TIMEOUT_DEFAULT_VALUE.as_secs(),
            |s| s.parse::<u64>().map_err(|e| e.to_string()),
        )),
        connect_timeout: StdDuration::from_secs(parse_env_or(
            OIDC_CONNECT_TIMEOUT,
            OIDC_CONNECT_TIMEOUT_DEFAULT_VALUE.as_secs(),
            |s| s.parse::<u64>().map_err(|e| e.to_string()),
        )),
        pool_idle_timeout: StdDuration::from_secs(parse_env_or(
            OIDC_POOL_IDLE_TIMEOUT,
            OIDC_POOL_IDLE_TIMEOUT_DEFAULT_VALUE.as_secs(),
            |s| s.parse::<u64>().map_err(|e| e.to_string()),
        )),
        pool_max_idle_per_host: parse_env_or(
            OIDC_POOL_MAX_IDLE_PER_HOST,
            OIDC_POOL_MAX_IDLE_PER_HOST_DEFAULT_VALUE,
            |s| s.parse::<usize>().map_err(|e| e.to_string()),
        ),
    };

    let same_site = parse_env_or(
        OIDC_COOKIE_SAME_SITE,
        OIDC_COOKIE_SAME_SITE_DEFAULT_VALUE,
        |s| match s.to_ascii_lowercase().as_str() {
            "strict" => Ok(SameSite::Strict),
            "lax" => Ok(SameSite::Lax),
            "none" => Ok(SameSite::None),
            other => Err(format!("unknown SameSite value: {other}")),
        },
    );

    let max_age_secs = parse_env_or(
        OIDC_COOKIE_MAX_AGE_SEC,
        OIDC_COOKIE_MAX_AGE_SEC_DEFAULT_VALUE.as_secs(),
        |s| s.parse::<u64>().map_err(|e| e.to_string()),
    );
    let cookie_max_age = std_duration_to_cookie(StdDuration::from_secs(max_age_secs));

    let cookie_name = env::var(OIDC_COOKIE_NAME).unwrap_or_else(|_| "".to_string());
    let session_name = env::var(OIDC_SESSION_NAME).unwrap_or_else(|_| "".to_string());
    let session_key = env::var(OIDC_SESSION_KEY)
        .ok()
        .and_then(|v| {
            base64::engine::general_purpose::STANDARD
                .decode(v.trim())
                .ok()
        })
        .unwrap_or_else(|| OIDC_SESSION_KEY_DEFAULT_VALUE.to_vec());

    let session_config = SessionConfig {
        session_name,
        session_key,
        redis: load_redis_config_from_env(),
    };

    let cookie_config = CookieConfig {
        cookie_name,
        secure: !http_client_config.insecure,
        same_site,
        cookie_max_age,
    };

    OidcConfig::new(
        &client_id,
        client_secret.as_deref(),
        &issuer_url,
        &redirect_url,
        &callback_url,
        http_client_config,
        cookie_config,
        session_config,
        &org_claim,
        &org_claim_pattern,
        subject_claim.as_deref(),
        email_claim.as_deref(),
        org_blacklist,
    )
}

fn parse_env_or<T, F>(name: &str, default: T, parse: F) -> T
where
    F: FnOnce(&str) -> Result<T, String>,
{
    match env::var(name) {
        Ok(v) => match parse(&v) {
            Ok(parsed) => parsed,
            Err(err) => {
                error!("env {name} parse error: {err} (using default)");
                default
            }
        },
        Err(_) => default,
    }
}

fn parse_env_bool(name: &str, default: bool) -> bool {
    parse_env_or(name, default, |s| match s.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        other => Err(format!("expected a boolean, got `{other}`")),
    })
}

fn parse_env_secs(name: &str, default: StdDuration) -> StdDuration {
    parse_env_or(name, default, |s| {
        s.parse::<u64>()
            .map(StdDuration::from_secs)
            .map_err(|e| e.to_string())
    })
}

fn load_redis_config_from_env() -> RedisConfig {
    let url = env::var(OIDC_REDIS_URL).unwrap_or_default();
    // `rediss://` implies TLS, so it is the default rather than an override.
    let tls = parse_env_bool(OIDC_REDIS_TLS, url.starts_with("rediss://"));
    RedisConfig {
        url,
        username: env::var(OIDC_REDIS_USERNAME).ok().filter(|v| !v.is_empty()),
        password: env::var(OIDC_REDIS_PASSWORD).ok().filter(|v| !v.is_empty()),
        database: parse_env_or(OIDC_REDIS_DB, None, |s| {
            s.parse::<u32>().map(Some).map_err(|e| e.to_string())
        }),
        tls,
        tls_server_name: env::var(OIDC_REDIS_TLS_SERVER_NAME)
            .ok()
            .filter(|v| !v.is_empty()),
        pool_size: parse_env_or(
            OIDC_REDIS_POOL_SIZE,
            OIDC_REDIS_POOL_SIZE_DEFAULT_VALUE,
            |s| s.parse::<usize>().map_err(|e| e.to_string()),
        ),
        connect_timeout: parse_env_secs(
            OIDC_REDIS_CONNECT_TIMEOUT,
            OIDC_REDIS_CONNECT_TIMEOUT_DEFAULT_VALUE,
        ),
        reconnect_delay_max: parse_env_secs(
            OIDC_REDIS_RECONNECT_DELAY_MAX,
            OIDC_REDIS_RECONNECT_DELAY_MAX_DEFAULT_VALUE,
        ),
        key_prefix: env::var(OIDC_REDIS_KEY_PREFIX)
            .unwrap_or_else(|_| OIDC_REDIS_KEY_PREFIX_DEFAULT_VALUE.to_string()),
    }
}

fn std_duration_to_cookie(d: StdDuration) -> CookieDuration {
    let whole = d.as_secs() as i64;
    let nanos = d.subsec_nanos() as i32;
    CookieDuration::new(whole, nanos)
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    #[test]
    fn default_config_is_loadable() {
        let cfg = get_oidc_config();
        assert_eq!(cfg.org_claim, OIDC_ORG_CLAIM_DEFAULT_VALUE);
        assert_eq!(cfg.subject_claim.as_deref(), Some("sub"));
        assert_eq!(cfg.email_claim.as_deref(), Some("email"));
    }

    #[test]
    fn same_site_none_forces_secure() {
        let cfg = OidcConfig::new(
            "test",
            None,
            "https://example.com",
            "https://example.com/cb",
            "https://example.com/cb",
            HttpClientConfig {
                insecure: true,
                ..Default::default()
            },
            CookieConfig {
                cookie_name: "foo".into(),
                secure: false,
                same_site: SameSite::None,
                cookie_max_age: std_duration_to_cookie(StdDuration::from_secs(60)),
            },
            SessionConfig {
                ..Default::default()
            },
            OIDC_ORG_CLAIM_DEFAULT_VALUE,
            OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE,
            Some("sub"),
            Some("email"),
            HashSet::new(),
        )
        .expect("config must build");
        assert!(cfg.cookie_config.secure);
    }

    #[test]
    fn std_duration_to_cookie_preserves_seconds() {
        let d = std_duration_to_cookie(StdDuration::from_secs(120));
        assert_eq!(d.whole_seconds(), 120);
    }

    #[test]
    fn std_duration_to_cookie_keeps_nanos_component() {
        let d = std_duration_to_cookie(StdDuration::new(45, 500));
        assert_eq!(d.whole_seconds(), 45);
        assert_eq!(d.subsec_nanoseconds(), 500);
    }

    #[test]
    fn invalid_org_pattern_is_rejected() {
        let err = OidcConfig::new(
            "test",
            None,
            "https://example.com",
            "https://example.com/cb",
            "https://example.com/cb",
            HttpClientConfig::default(),
            CookieConfig::default(),
            SessionConfig::default(),
            "groups",
            // Unclosed capture group: the regex engine rejects this outright.
            "^(?<org>.*$",
            Some("sub"),
            Some("email"),
            HashSet::new(),
        )
        .expect_err("an uncompilable org pattern must not build a config");
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn invalid_issuer_url_is_rejected() {
        let err = OidcConfig::new(
            "test",
            None,
            "not-a-url",
            "https://example.com/cb",
            "https://example.com/cb",
            HttpClientConfig::default(),
            CookieConfig::default(),
            SessionConfig::default(),
            OIDC_ORG_CLAIM_DEFAULT_VALUE,
            OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE,
            Some("sub"),
            Some("email"),
            HashSet::new(),
        )
        .expect_err("a non-URL issuer must not build a config");
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn is_enabled_is_false_for_placeholder_issuer() {
        // The login page keys the OIDC button off this, so the placeholder
        // issuer used before `init()` must read as disabled.
        assert!(!build_default_config().is_enabled());

        let enabled = OidcConfig::new(
            "test",
            None,
            "https://accounts.example.org",
            "https://example.com/cb",
            "https://example.com/cb",
            HttpClientConfig::default(),
            CookieConfig::default(),
            SessionConfig::default(),
            OIDC_ORG_CLAIM_DEFAULT_VALUE,
            OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE,
            Some("sub"),
            Some("email"),
            HashSet::new(),
        )
        .expect("config must build");
        assert!(enabled.is_enabled());
    }
}
