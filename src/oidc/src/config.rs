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

use std::{collections::HashSet, env, str::FromStr, sync::Arc, time::Duration as StdDuration};

use arc_swap::ArcSwap;
use config::meta::user::UserRole;
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
pub static OIDC_LOGOUT_URL: &str = "OIDC_LOGOUT_URL";
pub static OIDC_ENABLE_RP_LOGOUT: &str = "OIDC_ENABLE_RP_LOGOUT";
pub static OIDC_LOGOUT_REDIRECT_URL: &str = "OIDC_LOGOUT_REDIRECT_URL";
pub static OIDC_ORG_CLAIM: &str = "OIDC_ORG_CLAIM";
pub static OIDC_ORG_CLAIM_PATTERN: &str = "OIDC_ORG_CLAIM_PATTERN";
pub static OIDC_DEFAULT_ROLE: &str = "OIDC_DEFAULT_ROLE";
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
const OIDC_ORG_CLAIM_DEFAULT_VALUE: &str = "groups";
const OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE: &str = "^(?<org>.*)$";
const OIDC_DEFAULT_ROLE_DEFAULT_VALUE: &str = "user";
// The SPA landing path the provider sends the browser back to after the logout.
const OIDC_LOGOUT_REDIRECT_URL_DEFAULT_VALUE: &str = "/web/";

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
    pub redis: RedisConfig,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            session_name: "".to_string(),
            redis: RedisConfig::default(),
        }
    }
}

/// Where the OIDC session lives.
///
/// Derived from the existing configuration rather than a separate knob: a
/// session name means "the session lives on the server", and the Redis URL
/// then decides whether that server is Redis or the shared meta store.
///
/// Both variants are shared between the nodes of a cluster, so there is no
/// configuration that leaves a session stranded in one process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStoreKind {
    /// Session row in the shared meta store. Visible to every node.
    Db,
    /// Session in Redis. Shared, but needs an external Redis.
    Redis,
}

impl SessionStoreKind {
    /// The store implied by the configuration.
    ///
    /// A session name is what makes the session server-side at all; without
    /// one the tokens ride in a self-contained cookie and no store is involved.
    pub fn from_config(cfg: &SessionConfig) -> Option<Self> {
        if cfg.session_name.is_empty() {
            return None;
        }
        if cfg.redis.is_enabled() {
            Some(SessionStoreKind::Redis)
        } else {
            Some(SessionStoreKind::Db)
        }
    }

    /// `true` when the store is backed by `tower-sessions`.
    pub fn uses_tower_sessions(self) -> bool {
        matches!(self, SessionStoreKind::Redis)
    }

    /// `true` when the session is only visible to the process that created it.
    ///
    /// Always `false`: every store is shared, so no configuration can strand a
    /// session in one node of a cluster.
    pub fn is_process_local(self) -> bool {
        false
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
    pub logout_url: Option<String>,
    pub logout_redirect_url: String,
    /// Whether a logout also ends the session at the identity provider.
    ///
    /// Off by default: the provider may share one session across the
    /// applications of a realm, so ending it can sign the operator out of the
    /// other ones too.
    pub rp_logout_enabled: bool,
    pub http_client_config: HttpClientConfig,
    pub cookie_config: CookieConfig,
    pub session_config: SessionConfig,
    pub org_claim: String,
    pub org_claim_pattern: Regex,
    pub default_role: UserRole,
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
        logout_url: Option<&str>,
        http_client_config: HttpClientConfig,
        cookie_config: CookieConfig,
        session_config: SessionConfig,
        org_claim: &str,
        org_claim_pattern: &str,
        default_role: &str,
        subject_claim: Option<&str>,
        email_claim: Option<&str>,
        org_blacklist: HashSet<String>,
    ) -> Result<Self, AuthError> {
        let pattern = Regex::new(org_claim_pattern)
            .map_err(|err| AuthError::config(format!("invalid OIDC_ORG_CLAIM_PATTERN: {err}")))?;
        if !UserRole::is_valid_role(default_role) {
            return Err(AuthError::config(format!(
                "invalid OIDC_DEFAULT_ROLE `{default_role}`"
            )));
        }
        // SameSite=None requires Secure=true per RFC 6265 bis.
        let mut cookie_config = cookie_config;
        if cookie_config.same_site == SameSite::None {
            cookie_config.secure = true;
        }
        Ok(Self {
            client_id: ClientId::new(client_id.to_owned()),
            client_secret: client_secret.map(|s| ClientSecret::new(s.to_owned())),
            issuer_url: IssuerUrl::new(issuer.to_owned())
                .map_err(|e| AuthError::config(format!("invalid OIDC_ISSUER_URL: {e}")))?,
            redirect_url: RedirectUrl::new(redirect_url.to_owned())
                .map_err(|e| AuthError::config(format!("invalid OIDC_REDIRECT_URL: {e}")))?,
            callback_url: callback_url.to_owned(),
            logout_url: logout_url
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .map(|url| url.to_owned()),
            logout_redirect_url: OIDC_LOGOUT_REDIRECT_URL_DEFAULT_VALUE.to_owned(),
            rp_logout_enabled: false,
            http_client_config,
            cookie_config,
            session_config,
            org_claim: org_claim.to_owned(),
            org_claim_pattern: pattern,
            default_role: UserRole::from_str(default_role).unwrap_or(UserRole::User),
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

    /// Set the URL the provider sends the browser back to after the logout.
    ///
    /// The value may be absolute (`https://eo.example.com/web/`) or a path
    /// (`/web/`); a path is resolved against the origin of the registered
    /// redirect URL, because some providers (Keycloak) reject a relative
    /// `post_logout_redirect_uri`.
    pub fn with_logout_redirect_url(mut self, logout_redirect_url: &str) -> Self {
        let trimmed = logout_redirect_url.trim();
        if !trimmed.is_empty() {
            self.logout_redirect_url = trimmed.to_owned();
        }
        self
    }

    /// Whether a logout also ends the session at the identity provider.
    pub fn with_rp_logout(mut self, enabled: bool) -> Self {
        self.rp_logout_enabled = enabled;
        self
    }

    /// The absolute `post_logout_redirect_uri` for the provider.
    ///
    /// An absolute configured value is used as is; a relative one is joined
    /// onto the origin of the registered redirect URL.
    pub fn post_logout_redirect_uri(&self) -> String {
        let target = self.logout_redirect_url.trim();
        if target.is_empty() {
            return OIDC_LOGOUT_REDIRECT_URL_DEFAULT_VALUE.to_owned();
        }
        if url::Url::parse(target).is_ok_and(|url| url.has_host()) {
            return target.to_owned();
        }
        match url::Url::parse(self.redirect_url.as_str()) {
            Ok(base) => match base.join(target) {
                Ok(joined) => joined.to_string(),
                Err(_) => target.to_owned(),
            },
            Err(_) => target.to_owned(),
        }
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
        None,
        HttpClientConfig::default(),
        CookieConfig::default(),
        SessionConfig::default(),
        OIDC_ORG_CLAIM_DEFAULT_VALUE,
        OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE,
        OIDC_DEFAULT_ROLE_DEFAULT_VALUE,
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
    let logout_url = env::var(OIDC_LOGOUT_URL)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let logout_redirect_url = env::var(OIDC_LOGOUT_REDIRECT_URL)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| OIDC_LOGOUT_REDIRECT_URL_DEFAULT_VALUE.to_owned());
    let rp_logout_enabled = env::var(OIDC_ENABLE_RP_LOGOUT)
        .ok()
        .map(|v| v.trim().to_lowercase())
        .map(|v| v == "true" || v == "1" || v == "yes" || v == "on")
        .unwrap_or(false);

    let org_claim =
        env::var(OIDC_ORG_CLAIM).unwrap_or_else(|_| OIDC_ORG_CLAIM_DEFAULT_VALUE.to_string());
    let org_claim_pattern = env::var(OIDC_ORG_CLAIM_PATTERN)
        .unwrap_or_else(|_| OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE.to_string());
    let default_role = env::var(OIDC_DEFAULT_ROLE)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| OIDC_DEFAULT_ROLE_DEFAULT_VALUE.to_string());
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

    let session_config = SessionConfig {
        session_name,
        redis: load_redis_config_from_env(),
    };

    let cookie_config = CookieConfig {
        cookie_name,
        secure: !http_client_config.insecure,
        same_site,
        cookie_max_age,
    };

    let cfg = OidcConfig::new(
        &client_id,
        client_secret.as_deref(),
        &issuer_url,
        &redirect_url,
        &callback_url,
        logout_url.as_deref(),
        http_client_config,
        cookie_config,
        session_config,
        &org_claim,
        &org_claim_pattern,
        &default_role,
        subject_claim.as_deref(),
        email_claim.as_deref(),
        org_blacklist,
    )?
    .with_logout_redirect_url(&logout_redirect_url)
    .with_rp_logout(rp_logout_enabled);
    Ok(cfg)
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
    use serial_test::serial;

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
            None,
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
            OIDC_DEFAULT_ROLE_DEFAULT_VALUE,
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
            None,
            HttpClientConfig::default(),
            CookieConfig::default(),
            SessionConfig::default(),
            "groups",
            // Unclosed capture group: the regex engine rejects this outright.
            "^(?<org>.*$",
            OIDC_DEFAULT_ROLE_DEFAULT_VALUE,
            Some("sub"),
            Some("email"),
            HashSet::new(),
        )
        .expect_err("an uncompilable org pattern must not build a config");
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn invalid_default_role_is_rejected() {
        let err = OidcConfig::new(
            "test",
            None,
            "https://example.com",
            "https://example.com/cb",
            "https://example.com/cb",
            None,
            HttpClientConfig::default(),
            CookieConfig::default(),
            SessionConfig::default(),
            OIDC_ORG_CLAIM_DEFAULT_VALUE,
            OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE,
            "wizard",
            Some("sub"),
            Some("email"),
            HashSet::new(),
        )
        .expect_err("an unknown default role must not build a config");
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            err.is_config(),
            "an unknown default role is a configuration error, not a transient one"
        );
    }

    #[test]
    #[serial]
    fn an_invalid_default_role_from_the_env_is_a_config_error() {
        // The start-up path reads the role from the environment: a typo there
        // has to stop the node instead of silently downgrading every user.
        let previous = std::env::var(OIDC_DEFAULT_ROLE).ok();
        unsafe { std::env::set_var(OIDC_DEFAULT_ROLE, "wizard") };
        let err = load_config_from_env().expect_err("an unknown default role must be rejected");
        match previous {
            Some(value) => unsafe { std::env::set_var(OIDC_DEFAULT_ROLE, value) },
            None => unsafe { std::env::remove_var(OIDC_DEFAULT_ROLE) },
        }
        assert!(
            err.is_config(),
            "an invalid OIDC_DEFAULT_ROLE has to surface as a configuration error"
        );
        assert!(err.to_string().contains("OIDC_DEFAULT_ROLE"));
    }

    #[test]
    #[serial]
    fn a_valid_default_role_from_the_env_builds_a_config() {
        let previous = std::env::var(OIDC_DEFAULT_ROLE).ok();
        unsafe { std::env::set_var(OIDC_DEFAULT_ROLE, "editor") };
        let cfg = load_config_from_env().expect("a known role must build a config");
        match previous {
            Some(value) => unsafe { std::env::set_var(OIDC_DEFAULT_ROLE, value) },
            None => unsafe { std::env::remove_var(OIDC_DEFAULT_ROLE) },
        }
        assert_eq!(cfg.default_role, UserRole::Editor);
    }

    #[test]
    fn default_role_defaults_to_user() {
        let cfg = build_default_config();
        assert_eq!(cfg.default_role, UserRole::User);
    }

    fn config_with_logout_redirect(logout_redirect_url: &str) -> OidcConfig {
        build_default_config().with_logout_redirect_url(logout_redirect_url)
    }

    #[test]
    fn logout_redirect_defaults_to_the_spa_root() {
        // The default must not point at the callback: the callback demands a
        // state cookie the logout round trip never carries.
        let cfg = build_default_config();
        assert_eq!(cfg.logout_redirect_url, "/web/");
        assert_eq!(
            cfg.post_logout_redirect_uri(),
            "https://example.com/web/",
            "the relative default is resolved against the redirect URL origin"
        );
    }

    #[test]
    fn an_absolute_logout_redirect_is_used_as_is() {
        let cfg = config_with_logout_redirect("https://eo.example.com/logged-out");
        assert_eq!(
            cfg.post_logout_redirect_uri(),
            "https://eo.example.com/logged-out"
        );
    }

    #[test]
    fn a_relative_logout_redirect_is_resolved_against_the_redirect_origin() {
        let cfg = config_with_logout_redirect("/web/");
        assert_eq!(cfg.post_logout_redirect_uri(), "https://example.com/web/");
    }

    #[test]
    fn an_empty_logout_redirect_falls_back_to_the_default() {
        let cfg = config_with_logout_redirect("   ");
        assert_eq!(cfg.logout_redirect_url, "/web/");
        assert_eq!(cfg.post_logout_redirect_uri(), "https://example.com/web/");
    }

    #[test]
    fn the_logout_redirect_never_lands_on_the_callback() {
        let cfg = build_default_config();
        assert!(
            !cfg.post_logout_redirect_uri()
                .contains("/auth/sso/callback"),
            "the post-logout redirect must not point at the OIDC callback"
        );
    }

    #[test]
    fn a_relative_logout_redirect_replaces_the_redirect_path() {
        // A deployment behind a base URI keeps the base path.
        let cfg = OidcConfig::new(
            "test",
            None,
            "https://example.com",
            "https://example.com/openobserve/auth/sso/callback",
            "https://example.com/openobserve/auth/sso/callback",
            None,
            HttpClientConfig::default(),
            CookieConfig::default(),
            SessionConfig::default(),
            OIDC_ORG_CLAIM_DEFAULT_VALUE,
            OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE,
            OIDC_DEFAULT_ROLE_DEFAULT_VALUE,
            Some("sub"),
            Some("email"),
            HashSet::new(),
        )
        .expect("config must build")
        .with_logout_redirect_url("/openobserve/web/");
        assert_eq!(
            cfg.post_logout_redirect_uri(),
            "https://example.com/openobserve/web/"
        );
    }

    #[test]
    fn invalid_issuer_url_is_rejected() {
        let err = OidcConfig::new(
            "test",
            None,
            "not-a-url",
            "https://example.com/cb",
            "https://example.com/cb",
            None,
            HttpClientConfig::default(),
            CookieConfig::default(),
            SessionConfig::default(),
            OIDC_ORG_CLAIM_DEFAULT_VALUE,
            OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE,
            OIDC_DEFAULT_ROLE_DEFAULT_VALUE,
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
            None,
            HttpClientConfig::default(),
            CookieConfig::default(),
            SessionConfig::default(),
            OIDC_ORG_CLAIM_DEFAULT_VALUE,
            OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE,
            OIDC_DEFAULT_ROLE_DEFAULT_VALUE,
            Some("sub"),
            Some("email"),
            HashSet::new(),
        )
        .expect("config must build");
        assert!(enabled.is_enabled());
    }

    fn session_config(session_name: &str, redis_url: &str) -> SessionConfig {
        SessionConfig {
            session_name: session_name.to_string(),
            redis: RedisConfig {
                url: redis_url.to_string(),
                ..RedisConfig::default()
            },
        }
    }

    #[test]
    fn no_session_name_means_no_server_side_store() {
        // Without a session name the tokens ride in a self-contained cookie,
        // so there is no store to pick.
        assert_eq!(SessionStoreKind::from_config(&session_config("", "")), None);
    }

    #[test]
    fn a_session_name_without_redis_selects_the_shared_meta_store() {
        // The meta store is shared by every node, so it is the only backend
        // that works in a cluster without an external dependency.
        assert_eq!(
            SessionStoreKind::from_config(&session_config("oidc_sid", "")),
            Some(SessionStoreKind::Db)
        );
    }

    #[test]
    fn a_redis_url_selects_the_redis_store() {
        assert_eq!(
            SessionStoreKind::from_config(&session_config("oidc_sid", "redis://redis:6379")),
            Some(SessionStoreKind::Redis)
        );
    }

    #[test]
    fn only_the_meta_store_works_without_tower_sessions() {
        assert!(!SessionStoreKind::Db.uses_tower_sessions());
        assert!(SessionStoreKind::Redis.uses_tower_sessions());
    }

    #[test]
    fn every_store_is_shared_between_cluster_nodes() {
        // No configuration may leave a session stranded in one process: a
        // request proxied to a peer node would not resolve it.
        for kind in [SessionStoreKind::Db, SessionStoreKind::Redis] {
            assert!(
                !kind.is_process_local(),
                "{kind:?} must be shared between the nodes of a cluster"
            );
        }
    }
}
