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

#[cfg(test)]
use std::cell::RefCell;
use std::{
    collections::HashSet,
    env,
    io::{self, Error},
    sync::Arc,
};

use actix_session::config::{BrowserSession, PersistentSession, SessionLifecycle};
use actix_web::cookie::SameSite;
use arc_swap::ArcSwap;
use base64::Engine;
use dotenvy::dotenv;
use log::{error, info};
use once_cell::sync::Lazy;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};
use regex::Regex;

use crate::errors::{error_message_formatter, handle_env_error};

/// Enum to specify how environment variables should be parsed.
///
/// - `Required`: Fails the application if the variable is missing.
#[derive(Clone)]
enum EnvParseMode {
    Required,
    Optional(String),
    /// `StrictNone`: Returns None if missing, no default applied.
    StrictNone,
}

/// Environment variable name for OIDC issuer URL.
pub(crate) static OIDC_ISSUER_URL: &str = "OIDC_ISSUER_URL";
/// Environment variable name for OIDC redirect URL after authentication.
pub(crate) static OIDC_REDIRECT_URL: &str = "OIDC_REDIRECT_URL";
/// Environment variable name for OIDC client ID.
pub(crate) static OIDC_CLIENT_ID: &str = "OIDC_CLIENT_ID";
/// Environment variable name for OIDC client secret (sensitive).
pub(crate) static OIDC_CLIENT_SECRET: &str = "OIDC_CLIENT_SECRET";
/// Environment variable name for HTTP request timeout in seconds.
pub(crate) static OIDC_TIMEOUT: &str = "OIDC_TIMEOUT";
/// Environment variable name for HTTP connection timeout in seconds.
pub(crate) static OIDC_CONNECT_TIMEOUT: &str = "OIDC_CONNECT_TIMEOUT";
/// Environment variable name for HTTP pool idle timeout in seconds.
pub(crate) static OIDC_POOL_IDLE_TIMEOUT: &str = "OIDC_POOL_IDLE_TIMEOUT";
/// Environment variable name for maximum idle connections per host.
pub(crate) static OIDC_POOL_MAX_IDLE_PER_HOST: &str = "OIDC_POOL_MAX_IDLE_PER_HOST";
/// Environment variable name for allowing insecure TLS connections.
pub(crate) static OIDC_INSECURE: &str = "OIDC_INSECURE";
/// Environment variable name for SameSite cookie attribute.
pub(crate) static OIDC_COOKIE_SAME_SITE: &str = "OIDC_COOKIE_SAME_SITE";
/// Environment variable name for cookie maximum age in seconds.
pub(crate) static OIDC_COOKIE_MAX_AGE_SEC: &str = "OIDC_COOKIE_MAX_AGE_SEC";
/// Environment variable name for session cookie name.
pub(crate) static OIDC_SESSION_NAME: &str = "OIDC_SESSION_NAME";
/// Environment variable name for session signing key (base64 encoded).
pub(crate) static OIDC_SESSION_KEY: &str = "OIDC_SESSION_KEY";
/// Environment variable name for session lifecycle policy.
pub(crate) static OIDC_SESSION_LIFECYCLE: &str = "OIDC_SESSION_LIFECYCLE";
/// Environment variable name for application callback URL.
pub(crate) static OIDC_CALLBACK_URL: &str = "OIDC_CALLBACK_URL";
/// Environment variable name for organization/groups claim name.
pub(crate) static OIDC_ORG_CLAIM: &str = "OIDC_ORG_CLAIM";
/// Environment variable name for organization claim regex pattern.
pub(crate) static OIDC_ORG_CLAIM_PATTERN: &str = "OIDC_ORG_CLAIM_PATTERN";
/// Environment variable name for subject/user identifier claim name.
pub(crate) static OIDC_SUBJECT_CLAIM: &str = "OIDC_SUBJECT_CLAIM";
/// Environment variable name for email claim name.
pub(crate) static OIDC_EMAIL_CLAIM: &str = "OIDC_EMAIL_CLAIM";
/// Environment variable name for organization blacklist (comma-separated).
pub(crate) static OIDC_ORG_BLACKLIST: &str = "OIDC_ORG_BLACKLIST";
/// Environment variable name for session store type (cookie or redis).
pub(crate) static OIDC_SESSION_STORE: &str = "OIDC_SESSION_STORE";
/// Environment variable name for Redis URL for session storage.
pub(crate) static OIDC_REDIS_URL: &str = "OIDC_REDIS_URL";

static SENSITIVE_ENVS: Lazy<HashSet<&str>> = Lazy::new(|| HashSet::from([OIDC_CLIENT_SECRET]));

// Capture group names for claim mapping
pub(crate) static ORG_CAPTURE_GROUP: &str = "org";
pub(crate) static ROLE_CAPTURE_GROUP: &str = "role";
pub(crate) static AUTH_STATE: &str = "auth_state";
pub(crate) static AUTH_TOKENS_COOKIE: &str = "auth_tokens";
pub(crate) static AUTH_TOKENS_SESSION_KEY: &str = "auth_tokens";
pub(crate) static OIDC_SESSION_FLAG: &str = "oidc";

pub(crate) static OIDC_TIMEOUT_DEFAULT_VALUE: std::time::Duration =
    std::time::Duration::from_secs(10);
pub(crate) static OIDC_CONNECT_TIMEOUT_DEFAULT_VALUE: std::time::Duration =
    std::time::Duration::from_secs(5);
pub(crate) static OIDC_POOL_IDLE_TIMEOUT_DEFAULT_VALUE: std::time::Duration =
    std::time::Duration::from_secs(60);
pub(crate) static OIDC_COOKIE_MAX_AGE_SEC_DEFAULT_VALUE: std::time::Duration =
    std::time::Duration::from_secs(3600);
pub(crate) static OIDC_POOL_MAX_IDLE_PER_HOST_DEFAULT_VALUE: usize = 10;
pub(crate) static OIDC_INSECURE_DEFAULT_VALUE: bool = false;
pub(crate) static OIDC_COOKIE_SAME_SITE_DEFAULT_VALUE: SameSite = SameSite::Lax;
pub(crate) static OIDC_SESSION_NAME_DEFAULT_VALUE: &str = "_Host-eo-auth";
pub(crate) static OIDC_SESSION_KEY_DEFAULT_VALUE: [u8; 64] = [0; 64];
pub(crate) static OIDC_SESSION_LIFECYCLE_DEFAULT_VALUE: Lazy<SessionLifecycle> =
    Lazy::new(|| SessionLifecycle::BrowserSession(BrowserSession::default()));
pub(crate) static OIDC_ORG_CLAIM_DEFAULT_VALUE: &str = "groups";
pub(crate) static OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE: Lazy<Regex> = Lazy::new(|| {
    Regex::new("^(?<org>.*)$")
        .inspect_err(|err| {
            handle_env_error(&err, OIDC_ORG_CLAIM_PATTERN);
            unreachable!()
        })
        .unwrap()
});

/// Session store type for choosing between cookie and Redis storage.
#[derive(Clone, Debug, PartialEq)]
pub enum SessionStoreType {
    Cookie,
    Redis,
}

/// Cookie configuration parameters.
/// These are used for configuring secure cookie settings.
#[derive(Clone)]
pub struct CookieConfig {
    /// When true, disables secure cookie flags.
    pub secure: bool,
    /// SameSite attribute for cookies and sessions.
    pub same_site: SameSite,
    /// Maximum age for authentication cookies.
    pub cookie_max_age: actix_web::cookie::time::Duration,
}

impl Default for CookieConfig {
    fn default() -> Self {
        CookieConfig {
            secure: !OIDC_INSECURE_DEFAULT_VALUE,
            same_site: OIDC_COOKIE_SAME_SITE_DEFAULT_VALUE,
            cookie_max_age: convert_duration(OIDC_COOKIE_MAX_AGE_SEC_DEFAULT_VALUE),
        }
    }
}

/// Session configuration parameters.
/// These are used for configuring the Actix Web session middleware.
#[derive(Clone)]
pub struct SessionConfig {
    pub cookie_config: CookieConfig,
    /// Name of the session cookie.
    pub cookie_name: String,
    /// Key for session signing (currently using a fixed insecure key).
    pub cookie_key: Vec<u8>,
    /// Session lifecycle policy.
    pub session_lifecycle: SessionLifecycle,
    /// Type of session store (Cookie or Redis).
    pub session_store_type: SessionStoreType,
    /// Redis URL for Redis session store (required if session_store_type is Redis).
    pub redis_url: Option<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            cookie_config: CookieConfig::default(),
            cookie_name: OIDC_SESSION_NAME_DEFAULT_VALUE.to_string(),
            cookie_key: OIDC_SESSION_KEY_DEFAULT_VALUE.to_vec(),
            session_lifecycle: OIDC_SESSION_LIFECYCLE_DEFAULT_VALUE.clone(),
            session_store_type: SessionStoreType::Cookie,
            redis_url: None,
        }
    }
}

/// HTTP client configuration parameters.
/// These are used for configuring the underlying reqwest HTTP client.
#[derive(Clone)]
pub struct HttpClientConfig {
    /// Whether to allow insecure connections (e.g., for development).
    pub insecure: bool,
    /// Timeout for HTTP requests.
    pub timeout: std::time::Duration,
    /// Connection timeout.
    pub connect_timeout: std::time::Duration,
    /// Pool idle timeout for HTTP connections.
    pub pool_idle_timeout: std::time::Duration,
    /// Maximum idle connections per host.
    pub pool_max_idle_per_host: usize,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        HttpClientConfig {
            insecure: OIDC_INSECURE_DEFAULT_VALUE,
            timeout: OIDC_TIMEOUT_DEFAULT_VALUE,
            connect_timeout: OIDC_CONNECT_TIMEOUT_DEFAULT_VALUE,
            pool_idle_timeout: OIDC_POOL_IDLE_TIMEOUT_DEFAULT_VALUE,
            pool_max_idle_per_host: OIDC_POOL_MAX_IDLE_PER_HOST_DEFAULT_VALUE,
        }
    }
}

/// Configuration for OpenID Connect authentication.
/// This struct holds all necessary parameters for OIDC setup, loaded from environment variables.
/// It is initialized once and cached using a singleton pattern.
pub struct OidcConfig {
    /// The client ID provided by the OIDC provider.
    pub client_id: ClientId,
    /// The client secret for authenticating with the OIDC provider.
    pub client_secret: Option<ClientSecret>,
    /// The issuer URL of the OIDC provider.
    pub issuer_url: IssuerUrl,
    /// The redirect URL after successful authentication.
    pub redirect_url: RedirectUrl,
    /// Callback URL for the application.
    pub callback_url: String,
    /// HTTP client configuration parameters.
    pub http_client_config: HttpClientConfig,
    /// Session configuration parameters.
    pub session_config: SessionConfig,
    /// Claim name for organization/groups.
    pub org_claim: String,
    /// Regex pattern to extract organization from the claim.
    pub org_claim_pattern: Regex,
    /// Optional claim name for subject (user identifier).
    pub subject_claim: Option<String>,
    /// Optional claim name for email.
    pub email_claim: Option<String>,
    /// Set of organization names to exclude from user orgs.
    pub org_blacklist: HashSet<String>,
}

static OIDC_CONFIG: Lazy<ArcSwap<OidcConfig>> = Lazy::new(|| {
    ArcSwap::from_pointee(OidcConfig::from_env().expect("Failed to load configuration"))
});

// Thread-local test configuration for isolated testing
#[cfg(test)]
thread_local! {
    static TEST_CONFIG: RefCell<Option<Arc<OidcConfig>>> = RefCell::new(None);
}

pub fn get_oidc_config() -> Arc<OidcConfig> {
    #[cfg(test)]
    {
        // Check thread-local first for test isolation
        let test_config = TEST_CONFIG.with(|config| config.borrow().clone());
        if let Some(config) = test_config {
            return config;
        }
    }

    // Fallback to global config
    OIDC_CONFIG.load().clone()
}

// Test helper functions for thread-local config management
#[cfg(test)]
pub fn set_test_config(config: OidcConfig) {
    TEST_CONFIG.with(|test_config| {
        *test_config.borrow_mut() = Some(Arc::new(config));
    });
}

#[cfg(test)]
pub fn clear_test_config() {
    TEST_CONFIG.with(|test_config| {
        *test_config.borrow_mut() = None;
    });
}

pub fn refresh_oidc_config() -> Result<(), anyhow::Error> {
    OIDC_CONFIG.store(Arc::new(
        OidcConfig::from_env().expect("Failed to load configuration"),
    ));
    Ok(())
}

impl OidcConfig {
    #[cfg(test)]
    pub(crate) fn new(
        client_id: String,
        client_secret: Option<String>,
        issuer_url: String,
        redirect_url: String,
        callback_url: String,
        insecure: Option<bool>,
        timeout: Option<std::time::Duration>,
        connect_timeout: Option<std::time::Duration>,
        pool_idle_timeout: Option<std::time::Duration>,
        pool_max_idle_per_host: Option<usize>,
        same_site: Option<SameSite>,
        cookie_max_age: Option<std::time::Duration>,
        session_name: Option<String>,
        session_key: Option<Vec<u8>>,
        session_lifecycle: Option<SessionLifecycle>,
        org_claim: Option<String>,
        org_claim_pattern: Option<Regex>,
        subject_claim: Option<String>,
        email_claim: Option<String>,
    ) -> Self {
        let insecure = insecure.unwrap_or(OIDC_INSECURE_DEFAULT_VALUE);
        let http_client_config = HttpClientConfig {
            insecure,
            timeout: timeout.unwrap_or(OIDC_TIMEOUT_DEFAULT_VALUE),
            connect_timeout: connect_timeout.unwrap_or(OIDC_CONNECT_TIMEOUT_DEFAULT_VALUE),
            pool_idle_timeout: pool_idle_timeout.unwrap_or(OIDC_POOL_IDLE_TIMEOUT_DEFAULT_VALUE),
            pool_max_idle_per_host: pool_max_idle_per_host
                .unwrap_or(OIDC_POOL_MAX_IDLE_PER_HOST_DEFAULT_VALUE),
        };

        // SameSite=None requires Secure=true according to browser specs
        let resolved_same_site = same_site.unwrap_or(OIDC_COOKIE_SAME_SITE_DEFAULT_VALUE);
        let secure = if resolved_same_site == SameSite::None { true } else { !insecure };
        let cookie_config = CookieConfig {
            secure,
            same_site: resolved_same_site,
            cookie_max_age: cookie_max_age
                .map(convert_duration)
                .unwrap_or(convert_duration(OIDC_COOKIE_MAX_AGE_SEC_DEFAULT_VALUE)),
        };

        let session_config = SessionConfig {
            cookie_config,
            cookie_name: session_name.unwrap_or(OIDC_SESSION_NAME_DEFAULT_VALUE.to_string()),
            cookie_key: session_key.unwrap_or(OIDC_SESSION_KEY_DEFAULT_VALUE.to_vec()),
            session_lifecycle: session_lifecycle
                .unwrap_or(OIDC_SESSION_LIFECYCLE_DEFAULT_VALUE.clone()),
            session_store_type: SessionStoreType::Cookie,
            redis_url: None,
        };

        OidcConfig {
            client_id: ClientId::new(client_id),
            client_secret: client_secret.map(ClientSecret::new),
            issuer_url: IssuerUrl::new(issuer_url).unwrap(),
            redirect_url: RedirectUrl::new(redirect_url).unwrap(),
            callback_url,
            http_client_config,
            session_config,
            org_claim: org_claim.unwrap_or(String::from(OIDC_ORG_CLAIM_DEFAULT_VALUE)),
            org_claim_pattern: org_claim_pattern
                .unwrap_or(OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE.to_owned()),
            subject_claim,
            email_claim,
            org_blacklist: HashSet::new(), // Default empty blacklist for test method
        }
    }

    fn from_env() -> Result<Self, env::VarError> {
        dotenv().ok();

        let client_id = ClientId::new(parse_required_env(OIDC_CLIENT_ID));
        let client_secret = parse_env(OIDC_CLIENT_SECRET, EnvParseMode::StrictNone).map(ClientSecret::new);
        let issuer_url = parse_url::<IssuerUrl>(OIDC_ISSUER_URL);
        let redirect_url = parse_url::<RedirectUrl>(OIDC_REDIRECT_URL);
        let callback_url = parse_required_env(OIDC_CALLBACK_URL);

        let timeout = std::time::Duration::parse_env(OIDC_TIMEOUT, OIDC_TIMEOUT_DEFAULT_VALUE);
        let connect_timeout = std::time::Duration::parse_env(
            OIDC_CONNECT_TIMEOUT,
            OIDC_CONNECT_TIMEOUT_DEFAULT_VALUE,
        );
        let pool_idle_timeout = std::time::Duration::parse_env(
            OIDC_POOL_IDLE_TIMEOUT,
            OIDC_POOL_IDLE_TIMEOUT_DEFAULT_VALUE,
        );
        let pool_max_idle_per_host = parse_typed_env(
            OIDC_POOL_MAX_IDLE_PER_HOST,
            |val| val.parse::<usize>(),
            OIDC_POOL_MAX_IDLE_PER_HOST_DEFAULT_VALUE,
        );
        let insecure = parse_typed_env(
            OIDC_INSECURE,
            |val| val.parse::<bool>(),
            OIDC_INSECURE_DEFAULT_VALUE,
        );
        let same_site = parse_same_site_env();
        let cookie_max_age = actix_web::cookie::time::Duration::parse_env(
            OIDC_COOKIE_MAX_AGE_SEC,
            OIDC_COOKIE_MAX_AGE_SEC_DEFAULT_VALUE,
        );

        let cookie_name = parse_optional_env(OIDC_SESSION_NAME, OIDC_SESSION_NAME_DEFAULT_VALUE);
        let cookie_key = parse_typed_env(
            OIDC_SESSION_KEY,
            |val| base64::engine::general_purpose::STANDARD_NO_PAD.decode(val),
            OIDC_SESSION_KEY_DEFAULT_VALUE.to_vec(),
        );
        let session_lifecycle = parse_session_lifecycle_env();
        let session_store_type = parse_session_store_env();
        let redis_url = if session_store_type == SessionStoreType::Redis {
            Some(parse_required_env(OIDC_REDIS_URL))
        } else {
            None
        };

        let org_claim = parse_optional_env(OIDC_ORG_CLAIM, OIDC_ORG_CLAIM_DEFAULT_VALUE);
        let org_claim_pattern = parse_regex_env(
            OIDC_ORG_CLAIM_PATTERN,
            OIDC_ORG_CLAIM_PATTERN_DEFAULT_VALUE.to_owned(),
        );
        let subject_claim = parse_env(OIDC_SUBJECT_CLAIM, EnvParseMode::StrictNone);
        let email_claim = parse_env(OIDC_EMAIL_CLAIM, EnvParseMode::StrictNone);
        let org_blacklist = parse_typed_env(
            OIDC_ORG_BLACKLIST,
            |val| -> Result<HashSet<String>, std::io::Error> {
                Ok(val.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<HashSet<String>>())
            },
            HashSet::new(),
        );

        let http_client_config = HttpClientConfig {
            insecure,
            timeout,
            connect_timeout,
            pool_idle_timeout,
            pool_max_idle_per_host,
        };

        // SameSite=None requires Secure=true according to browser specs
        let secure = if same_site == SameSite::None { true } else { !insecure };
        let cookie_config = CookieConfig {
            secure,
            same_site,
            cookie_max_age,
        };

        let session_config = SessionConfig {
            cookie_config,
            cookie_name,
            cookie_key,
            session_lifecycle,
            session_store_type,
            redis_url,
        };

        Ok(Self {
            client_id,
            client_secret,
            issuer_url,
            redirect_url,
            callback_url,
            http_client_config,
            session_config,
            org_claim,
            org_claim_pattern,
            subject_claim,
            email_claim,
            org_blacklist,
        })
    }
}

fn parse_session_lifecycle_env() -> SessionLifecycle {
    let default = OIDC_SESSION_LIFECYCLE_DEFAULT_VALUE.clone();
    match parse_env(OIDC_SESSION_LIFECYCLE, EnvParseMode::StrictNone) {
        None => default,
        Some(val) => match session_lifecycle(&val) {
            Ok(session_lifecycle) => session_lifecycle,
            Err(err) => {
                log_env_parsing_error(&err, OIDC_SESSION_LIFECYCLE, val);
                default
            }
        },
    }
}

fn session_lifecycle(input: &str) -> Result<SessionLifecycle, Box<Error>> {
    let result = match input.to_lowercase().as_str() {
        "browser" => Ok(SessionLifecycle::BrowserSession(BrowserSession::default())),
        "persistent" => Ok(SessionLifecycle::PersistentSession(PersistentSession::default())),
        &_ => Err(Box::new(io::Error::other(format!(
            "Unknown param: {}",
            input
        )))),
    };
    result
}

fn parse_same_site_env() -> SameSite {
    match parse_env(OIDC_COOKIE_SAME_SITE, EnvParseMode::StrictNone) {
        None => OIDC_COOKIE_SAME_SITE_DEFAULT_VALUE,
        Some(val) => match same_site(&val) {
            Ok(same_site) => same_site,
            Err(err) => {
                log_env_parsing_error(&err, OIDC_COOKIE_SAME_SITE, val);
                OIDC_COOKIE_SAME_SITE_DEFAULT_VALUE
            }
        },
    }
}

fn parse_session_store_env() -> SessionStoreType {
    match parse_env(OIDC_SESSION_STORE, EnvParseMode::StrictNone) {
        None => SessionStoreType::Cookie,
        Some(val) => match val.to_lowercase().as_str() {
            "cookie" => SessionStoreType::Cookie,
            "redis" => SessionStoreType::Redis,
            _ => {
                log_env_parsing_error(
                    &std::io::Error::other(format!("Unknown session store type: {}", val)),
                    OIDC_SESSION_STORE,
                    val,
                );
                SessionStoreType::Cookie
            }
        },
    }
}

fn same_site(input: &str) -> Result<SameSite, Box<Error>> {
    let result = match input.to_lowercase().as_str() {
        "strict" => Ok(SameSite::Strict),
        "none" => Ok(SameSite::None),
        "lax" => Ok(SameSite::Lax),
        &_ => Err(Box::new(io::Error::other(format!(
            "Unknown param: {}",
            input
        )))),
    };
    result
}

fn parse_typed_env<T, E, F>(env: &str, parser: F, default: T) -> T
where
    F: Fn(&str) -> Result<T, E>,
    E: std::error::Error,
{
    match parse_env(env, EnvParseMode::StrictNone) {
        Some(val) => parser(&val)
            .inspect_err(|err| {
                log_env_parsing_error(err, env, val);
            })
            .unwrap_or(default),
        None => default,
    }
}

fn parse_env(env: &str, mode: EnvParseMode) -> Option<String> {
    match env::var(env) {
        Ok(value) => Some(value),
        Err(err) => match mode {
            EnvParseMode::Required => {
                handle_env_error(&err, env);
                unreachable!()
            }
            EnvParseMode::Optional(_default) => Some(_default),
            EnvParseMode::StrictNone => None,
        },
    }
}

fn parse_required_env(env: &str) -> String {
    parse_env(env, EnvParseMode::Required).unwrap()
}

fn parse_optional_env(env: &str, default: &str) -> String {
    parse_env(env, EnvParseMode::Optional(default.to_string())).unwrap()
}

fn parse_regex_env(env: &str, default: regex::Regex) -> Regex {
    match parse_env(env, EnvParseMode::StrictNone) {
        None => default,
        Some(str) => match Regex::new(&str) {
            Ok(re) => re,
            Err(err) => {
                handle_env_error(&err, env);
                unreachable!()
            }
        },
    }
}

trait UrlWrapper: Sized {
    fn parse(s: String) -> Self;
}

impl UrlWrapper for IssuerUrl {
    fn parse(s: String) -> Self {
        match IssuerUrl::new(s) {
            Ok(url) => url,
            Err(err) => {
                handle_env_error(&err, OIDC_ISSUER_URL);
                unreachable!()
            }
        }
    }
}

impl UrlWrapper for RedirectUrl {
    fn parse(s: String) -> Self {
        match RedirectUrl::new(s) {
            Ok(url) => url,
            Err(err) => {
                handle_env_error(&err, OIDC_REDIRECT_URL);
                unreachable!()
            }
        }
    }
}

fn parse_url<T: UrlWrapper>(env: &str) -> T {
    let s = parse_required_env(env);
    T::parse(s)
}

trait ParseDurationEnv {
    fn parse_env(env: &str, default: std::time::Duration) -> Self;
}

impl ParseDurationEnv for actix_web::cookie::time::Duration {
    fn parse_env(env: &str, default: std::time::Duration) -> Self {
        let duration = std::time::Duration::parse_env(env, default);
        actix_web::cookie::time::Duration::seconds_f64(duration.as_secs_f64())
    }
}

pub(crate) fn convert_duration(duration: std::time::Duration) -> actix_web::cookie::time::Duration {
    actix_web::cookie::time::Duration::seconds_f64(duration.as_secs_f64())
}

impl ParseDurationEnv for std::time::Duration {
    fn parse_env(env: &str, default: Self) -> Self {
        let var = env::var(env);
        match var {
            Ok(val) => {
                match val
                    .parse::<u64>()
                    .and_then(|secs| Ok(std::time::Duration::from_secs(secs)))
                {
                    Ok(d) => d,
                    Err(err) => {
                        log_env_parsing_error(&err, env, val);
                        default
                    }
                }
            }
            Err(_) => {
                info!(
                    "Environment variable '{}' is unset. Using default value.",
                    env
                );
                default
            }
        }
    }
}

fn log_env_parsing_error<T: std::error::Error>(err: &T, env: &str, val: String) {
    let log_val = if SENSITIVE_ENVS.contains(env) {
        "[MASKED]"
    } else {
        &val
    };
    let msg = error_message_formatter(
        err,
        &format!(
            "Failed to process environment variable: {env}={log_val}. Default value will be used."
        ),
    );
    error!("{msg}");
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;
    
    fn setup_logging() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .try_init();
    }

    #[test]
    fn test_same_site_strict() {
        assert_eq!(same_site("strict").unwrap(), SameSite::Strict);
    }

    #[test]
    fn test_same_site_none() {
        assert_eq!(same_site("none").unwrap(), SameSite::None);
    }

    #[test]
    fn test_same_site_lax() {
        assert_eq!(same_site("lax").unwrap(), SameSite::Lax);
    }

    #[test]
    fn test_same_site_invalid() {
        assert!(same_site("invalid").is_err());
    }

    #[test]
    fn test_parse_same_site_env_present() {
        unsafe {
            std::env::set_var("OIDC_COOKIE_SAME_SITE", "none");
        }
        assert_eq!(parse_same_site_env(), SameSite::None);
        unsafe {
            std::env::remove_var("OIDC_COOKIE_SAME_SITE");
        }
    }

    #[test]
    fn test_parse_same_site_env_missing() {
        unsafe {
            std::env::remove_var(OIDC_COOKIE_SAME_SITE);
        }
        assert_eq!(parse_same_site_env(), OIDC_COOKIE_SAME_SITE_DEFAULT_VALUE);
    }

    #[test]
    fn test_parse_same_site_env_invalid() {
        setup_logging();
        unsafe {
            std::env::set_var("OIDC_COOKIE_SAME_SITE", "invalid");
        }
        assert_eq!(parse_same_site_env(), OIDC_COOKIE_SAME_SITE_DEFAULT_VALUE);
        unsafe {
            std::env::remove_var("OIDC_COOKIE_SAME_SITE");
        }
    }

    #[test]
    fn test_parse_optional_env_present() {
        unsafe {
            std::env::set_var("TEST_OPT", "value");
        }
        assert_eq!(parse_optional_env("TEST_OPT", "default"), "value");
        unsafe {
            std::env::remove_var("TEST_OPT");
        }
    }

    #[test]
    fn test_parse_optional_env_missing() {
        assert_eq!(parse_optional_env("MISSING_OPT", "default"), "default");
    }

    #[test]
    fn test_parse_env_strict_none_present() {
        unsafe {
            std::env::set_var("TEST_STRICT", "val");
        }
        assert_eq!(
            parse_env("TEST_STRICT", EnvParseMode::StrictNone),
            Some("val".to_string())
        );
        unsafe {
            std::env::remove_var("TEST_STRICT");
        }
    }

    #[test]
    fn test_parse_env_strict_none_missing() {
        assert_eq!(parse_env("MISSING_STRICT", EnvParseMode::StrictNone), None);
    }

    #[test]
    fn test_parse_env_optional_present() {
        unsafe {
            std::env::set_var("TEST_OPT_ENV", "val");
        }
        assert_eq!(
            parse_env("TEST_OPT_ENV", EnvParseMode::Optional("def".to_string())),
            Some("val".to_string())
        );
        unsafe {
            std::env::remove_var("TEST_OPT_ENV");
        }
    }

    #[test]
    fn test_parse_env_optional_missing() {
        assert_eq!(
            parse_env("MISSING_OPT_ENV", EnvParseMode::Optional("def".to_string())),
            Some("def".to_string())
        );
    }

    #[test]
    fn test_parse_regex_env_present() {
        let default = regex::Regex::new(".*").unwrap();
        unsafe {
            std::env::set_var("OIDC_ORG_CLAIM_PATTERN", "[0-9]+");
        }
        let re = parse_regex_env("OIDC_ORG_CLAIM_PATTERN", default);
        assert!(re.is_match("123"));
        unsafe {
            std::env::remove_var("OIDC_ORG_CLAIM_PATTERN");
        }
    }

    #[test]
    fn test_parse_regex_env_missing() {
        let default = regex::Regex::new(".*").unwrap();
        let re = parse_regex_env("MISSING_REGEX", default.clone());
        assert_eq!(re.as_str(), default.as_str());
    }

    #[test]
    fn test_parse_typed_env_present() {
        unsafe {
            std::env::set_var("TEST_INT", "42");
        }
        assert_eq!(parse_typed_env("TEST_INT", |s| s.parse::<usize>(), 0), 42);
        unsafe {
            std::env::remove_var("TEST_INT");
        }
    }

    #[test]
    fn test_parse_typed_env_missing() {
        assert_eq!(
            parse_typed_env("MISSING_INT", |s| s.parse::<usize>(), 10),
            10
        );
    }

    #[test]
    fn test_session_lifecycle_browser() {
        assert!(matches!(
            session_lifecycle("browser").unwrap(),
            SessionLifecycle::BrowserSession(_)
        ));
    }

    #[test]
    fn test_session_lifecycle_persistent() {
        assert!(matches!(
            session_lifecycle("persistent").unwrap(),
            SessionLifecycle::PersistentSession(_)
        ));
    }

    #[test]
    fn test_session_lifecycle_case_insensitive() {
        assert!(matches!(
            session_lifecycle("BROWSER").unwrap(),
            SessionLifecycle::BrowserSession(_)
        ));
        assert!(matches!(
            session_lifecycle("PERSISTENT").unwrap(),
            SessionLifecycle::PersistentSession(_)
        ));
    }

    #[test]
    fn test_session_lifecycle_invalid() {
        assert!(session_lifecycle("invalid").is_err());
    }

    #[test]
    fn test_parse_session_lifecycle_env_present() {
        unsafe {
            std::env::remove_var("OIDC_SESSION_LIFECYCLE");
            std::env::set_var("OIDC_SESSION_LIFECYCLE", "persistent");
        }
        assert!(matches!(
            parse_session_lifecycle_env(),
            SessionLifecycle::PersistentSession(_)
        ));
        unsafe {
            std::env::remove_var("OIDC_SESSION_LIFECYCLE");
        }
    }

    #[test]
    fn test_parse_session_lifecycle_env_missing() {
        // Ensure the env var is not set for this test
        unsafe {
            std::env::remove_var("OIDC_SESSION_LIFECYCLE");
        }
        assert!(matches!(
            parse_session_lifecycle_env(),
            SessionLifecycle::BrowserSession(_)
        ));
    }

    #[test]
    fn test_parse_session_lifecycle_env_invalid() {
        setup_logging();
        unsafe {
            std::env::set_var("OIDC_SESSION_LIFECYCLE", "invalid");
        }
        assert!(matches!(
            parse_session_lifecycle_env(),
            SessionLifecycle::BrowserSession(_)
        ));
        unsafe {
            std::env::remove_var("OIDC_SESSION_LIFECYCLE");
        }
    }

    #[test]
    fn test_cookie_config_default() {
        let config = CookieConfig::default();
        assert_eq!(config.secure, true);
        assert_eq!(config.same_site, SameSite::Lax);
        assert_eq!(
            config.cookie_max_age,
            convert_duration(OIDC_COOKIE_MAX_AGE_SEC_DEFAULT_VALUE)
        );
    }

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.cookie_name, OIDC_SESSION_NAME_DEFAULT_VALUE);
        assert_eq!(config.cookie_key, OIDC_SESSION_KEY_DEFAULT_VALUE.to_vec());
        assert!(matches!(
            config.session_lifecycle,
            SessionLifecycle::BrowserSession(_)
        ));
    }

    #[test]
    fn test_http_client_config_default() {
        let config = HttpClientConfig::default();
        assert_eq!(config.insecure, OIDC_INSECURE_DEFAULT_VALUE);
        assert_eq!(config.timeout, OIDC_TIMEOUT_DEFAULT_VALUE);
        assert_eq!(config.connect_timeout, OIDC_CONNECT_TIMEOUT_DEFAULT_VALUE);
        assert_eq!(config.pool_idle_timeout, OIDC_POOL_IDLE_TIMEOUT_DEFAULT_VALUE);
        assert_eq!(config.pool_max_idle_per_host, OIDC_POOL_MAX_IDLE_PER_HOST_DEFAULT_VALUE);
    }

    #[test]
    fn test_convert_duration() {
        let std_duration = std::time::Duration::from_secs(123);
        let cookie_duration = convert_duration(std_duration);
        assert_eq!(cookie_duration.whole_seconds(), 123);
    }

    #[test]
    fn test_get_oidc_config_returns_instance() {
        // This test assumes from_env() will succeed with defaults or env vars
        // In real usage, environment variables should be set
        let _config = get_oidc_config();
        // Just verify it returns something without panicking
    }

    #[test]
    fn test_refresh_oidc_config() {
        // Note: This test may interfere with other tests that use the global config
        // In a real scenario, you'd want to set up proper env vars
        let result = refresh_oidc_config();
        assert!(result.is_ok());
    }

    #[test]
    fn test_oidc_config_from_env_with_minimal_vars() {
        // Save original env vars
        let orig_client_id = std::env::var(OIDC_CLIENT_ID).ok();
        let orig_client_secret = std::env::var(OIDC_CLIENT_SECRET).ok();
        let orig_issuer_url = std::env::var(OIDC_ISSUER_URL).ok();
        let orig_redirect_url = std::env::var(OIDC_REDIRECT_URL).ok();
        let orig_callback_url = std::env::var(OIDC_CALLBACK_URL).ok();

        // Set minimal required env vars for from_env() to succeed
        // Also override .env values to test defaults
        unsafe {
            std::env::set_var(OIDC_CLIENT_ID, "test-client-id");
            std::env::set_var(OIDC_CLIENT_SECRET, "test-client-secret");
            std::env::set_var(OIDC_ISSUER_URL, "https://example.com");
            std::env::set_var(OIDC_REDIRECT_URL, "https://example.com/callback");
            std::env::set_var(OIDC_CALLBACK_URL, "https://example.com/app-callback");
            std::env::set_var(OIDC_INSECURE, "false"); // Override .env value
        }

        // Test from_env() parsing
        let result = OidcConfig::from_env();
        assert!(result.is_ok());
        let config = result.unwrap();

        assert_eq!(config.client_id.as_str(), "test-client-id");
        assert_eq!(config.client_secret.as_ref().unwrap().secret(), "test-client-secret");
        assert_eq!(config.issuer_url.as_str(), "https://example.com");
        assert_eq!(config.redirect_url.as_str(), "https://example.com/callback");
        assert_eq!(config.callback_url, "https://example.com/app-callback");

        // Verify defaults are applied
        assert_eq!(config.http_client_config.insecure, OIDC_INSECURE_DEFAULT_VALUE);
        assert_eq!(config.session_config.cookie_name, OIDC_SESSION_NAME_DEFAULT_VALUE);
        assert!(matches!(
            config.session_config.session_lifecycle,
            SessionLifecycle::BrowserSession(_)
        ));

        // Restore original env vars
        match orig_client_id {
            Some(val) => unsafe { std::env::set_var(OIDC_CLIENT_ID, val) },
            None => unsafe { std::env::remove_var(OIDC_CLIENT_ID) },
        }
        match orig_client_secret {
            Some(val) => unsafe { std::env::set_var(OIDC_CLIENT_SECRET, val) },
            None => unsafe { std::env::remove_var(OIDC_CLIENT_SECRET) },
        }
        match orig_issuer_url {
            Some(val) => unsafe { std::env::set_var(OIDC_ISSUER_URL, val) },
            None => unsafe { std::env::remove_var(OIDC_ISSUER_URL) },
        }
        match orig_redirect_url {
            Some(val) => unsafe { std::env::set_var(OIDC_REDIRECT_URL, val) },
            None => unsafe { std::env::remove_var(OIDC_REDIRECT_URL) },
        }
        match orig_callback_url {
            Some(val) => unsafe { std::env::set_var(OIDC_CALLBACK_URL, val) },
            None => unsafe { std::env::remove_var(OIDC_CALLBACK_URL) },
        }
    }

    #[test]
    fn test_parse_typed_env_invalid() {
        setup_logging();
        unsafe {
            std::env::set_var("TEST_INT_INVALID", "not_a_number");
        }
        assert_eq!(
            parse_typed_env("TEST_INT_INVALID", |s| s.parse::<usize>(), 20),
            20
        );
        unsafe {
            std::env::remove_var("TEST_INT_INVALID");
        }
    }

    #[test]
    fn test_same_site_none_forces_secure() {
        // Test that SameSite::None automatically sets secure=true
        let config = OidcConfig::new(
            "test".to_string(),
            Some("secret".to_string()),
            "https://example.com".to_string(),
            "https://example.com/callback".to_string(),
            "https://example.com/callback".to_string(),
            Some(true), // insecure=true, but SameSite::None should override
            None, None, None, None,
            Some(SameSite::None), // SameSite::None
            None, None, None, None, None, None, None, None
        );

        // Should be secure=true despite insecure=true
        assert_eq!(config.session_config.cookie_config.secure, true);
        assert_eq!(config.session_config.cookie_config.same_site, SameSite::None);
    }

    #[test]
    fn test_thread_local_config_isolation() {
        // Создаём тестовый конфиг с кастомными настройками
        let test_config = OidcConfig::new(
            "thread-local-client".to_string(),
            Some("thread-local-secret".to_string()),
            "https://thread-local.example.com".to_string(),
            "https://thread-local.example.com/callback".to_string(),
            "https://thread-local.example.com/app".to_string(),
            Some(true), // insecure: true для теста
            Some(std::time::Duration::from_secs(30)), // custom timeout
            None, None, None, None, None, None, None, None, None, None, None, None
        );

        // Устанавливаем в thread-local
        set_test_config(test_config);

        // Проверяем, что get_oidc_config() возвращает наш тестовый конфиг
        let retrieved_config = get_oidc_config();
        assert_eq!(retrieved_config.client_id.as_str(), "thread-local-client");
        assert_eq!(retrieved_config.client_secret.as_ref().unwrap().secret(), "thread-local-secret");
        assert_eq!(retrieved_config.http_client_config.insecure, true);
        assert_eq!(retrieved_config.http_client_config.timeout, std::time::Duration::from_secs(30));

        // Очищаем thread-local конфиг
        clear_test_config();

        // Теперь get_oidc_config() должен вернуться к глобальному конфигу
        let global_config = get_oidc_config();
        // Мы не знаем точно что в глобальном конфиге, но он должен быть другим
        assert_ne!(global_config.client_id.as_str(), "thread-local-client");
    }
}
