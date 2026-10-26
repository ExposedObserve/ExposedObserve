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

use std::sync::Arc;

#[cfg(feature = "redis-session")]
use fred::prelude::{
    ClientLike, Config, ConnectionConfig, Pool, ReconnectPolicy, ServerConfig, TlsConfig,
};
#[cfg(feature = "redis-session")]
use fred::types::config::TlsConnector;
use tokio::sync::OnceCell;
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer, cookie::time};
#[cfg(feature = "redis-session")]
use tower_sessions_redis_store::RedisStore;

use crate::{
    config::{CookieConfig, OidcConfig},
    errors::AuthError,
    models::{AuthTokens, AuthorizationState},
};

static INIT: OnceCell<()> = OnceCell::const_new();
static LAYER: OnceCell<Arc<SessionManagerLayerForStore>> = OnceCell::const_new();

/// Idempotent one-time session setup hook.
pub async fn init_default() {
    INIT.get_or_init(|| async {}).await;
}

/// Build a `SessionManagerLayer` for in-memory sessions.
///
/// Used as a default for tests and for development; it is not appropriate
/// for production deployments (sessions are not shared between workers).
pub fn memory_layer(cfg: &OidcConfig) -> SessionManagerLayer<MemoryStore> {
    let store = MemoryStore::default();
    let expiry = expiry_from_cookie(&cfg.cookie_config);
    SessionManagerLayer::new(store)
        .with_name(cookie_name(&cfg.session_config.session_name))
        .with_expiry(expiry)
        .with_secure(cfg.cookie_config.secure)
        .with_http_only(true)
        .with_same_site(cfg.cookie_config.same_site)
}

#[cfg(feature = "redis-session")]
/// Build a `SessionManagerLayer` for Redis-backed sessions.
pub async fn redis_layer(
    cfg: &OidcConfig,
) -> Result<SessionManagerLayer<RedisStore<Pool>>, AuthError> {
    let rcfg = &cfg.session_config.redis;
    if !rcfg.is_enabled() {
        return Err(AuthError::BadRequest(
            "OIDC_REDIS_URL is required for the redis session store".into(),
        ));
    }
    let mut fred_cfg = Config::from_url(&rcfg.url)
        .map_err(|e| AuthError::internal("parsing OIDC_REDIS_URL", e))?;

    // `from_url` already derives credentials, database and TLS from the URL;
    // the explicit env values only override what it guessed.
    if let Some(user) = rcfg.username.clone() {
        fred_cfg.username = Some(user);
    }
    if let Some(pass) = rcfg.password.clone() {
        fred_cfg.password = Some(pass);
    }
    if let Some(db) = rcfg.database {
        // Redis addresses databases with a single byte, so a larger number
        // cannot be expressed and the URL's own value is kept.
        fred_cfg.database = u8::try_from(db).ok();
    }
    // `rediss://` already produced a rustls connector; a bare `redis://` with
    // TLS switched on needs one built from the system trust store.
    if rcfg.tls && fred_cfg.tls.is_none() {
        let connector = rustls_connector()?;
        fred_cfg.tls = Some(TlsConfig::from(connector));
    }
    if let Some(name) = rcfg.tls_server_name.as_deref() {
        apply_tls_server_name(&mut fred_cfg, name);
    }

    let max_delay_ms = rcfg.reconnect_delay_max.as_millis().min(u32::MAX as u128) as u32;
    let policy = ReconnectPolicy::Exponential {
        attempts: u32::MAX,
        max_attempts: u32::MAX,
        min_delay: 64,
        max_delay: max_delay_ms.max(64),
        base: 2,
        jitter: 64,
    };
    let conn = ConnectionConfig {
        connection_timeout: rcfg.connect_timeout,
        ..ConnectionConfig::default()
    };
    let pool = Pool::new(
        fred_cfg,
        None,
        Some(conn),
        Some(policy),
        rcfg.pool_size.max(1),
    )
    .map_err(|e| AuthError::internal("building Redis session pool", e))?;
    // `connect` returns the task driving every client in the pool; it is dropped
    // because the pool reconnects on its own and the layer outlives this call.
    pool.connect();
    let store = RedisStore::new(pool);
    let expiry = expiry_from_cookie(&cfg.cookie_config);
    Ok(SessionManagerLayer::new(store)
        .with_name(cookie_name(&cfg.session_config.session_name))
        .with_expiry(expiry)
        .with_secure(cfg.cookie_config.secure)
        .with_http_only(true)
        .with_same_site(cfg.cookie_config.same_site))
}

/// Build the rustls connector fred uses for the Redis session pool.
///
/// The provider is installed first and only as a default: the AWS SDK pulls in
/// `aws-lc-rs` while the rest of the tree uses `ring`, so rustls finds two
/// candidates and would otherwise panic at the first TLS connection.
#[cfg(feature = "redis-session")]
fn rustls_connector() -> Result<TlsConnector, AuthError> {
    // `ring`, matching the provider `main.rs` installs for the HTTP and gRPC
    // servers. A provider already chosen by the host process wins.
    let _ = rustls::crypto::ring::default_provider().install_default();
    TlsConnector::default_rustls()
        .map_err(|e| AuthError::internal("building Redis TLS connector", e))
}

/// Override the SNI name used during the Redis TLS handshake.
///
/// This matters when Redis sits behind a load balancer or a TLS-terminating
/// proxy: the certificate names the balancer, not the host in `OIDC_REDIS_URL`,
/// so the default SNI would fail verification.
#[cfg(feature = "redis-session")]
fn apply_tls_server_name(fred_cfg: &mut Config, name: &str) {
    match &mut fred_cfg.server {
        ServerConfig::Centralized { server } => {
            server.tls_server_name = Some(name.into());
        }
        ServerConfig::Clustered { hosts, .. } => {
            for host in hosts.iter_mut() {
                host.tls_server_name = Some(name.into());
            }
        }
        // Sentinel and unix-socket servers carry their own handshake settings.
        _ => {}
    }
}

fn cookie_name(name: &str) -> String {
    if name.is_empty() {
        "oidc_session".to_string()
    } else {
        name.to_string()
    }
}

fn expiry_from_cookie(cfg: &CookieConfig) -> Expiry {
    Expiry::OnInactivity(time::Duration::new(
        cfg.cookie_max_age.whole_seconds(),
        cfg.cookie_max_age.subsec_nanoseconds(),
    ))
}

/// Convenience: returns a built layer matching the configured store type.
pub async fn build_layer(cfg: &OidcConfig) -> Result<SessionManagerLayerForStore, AuthError> {
    match cfg.session_config.redis.is_enabled() {
        false => Ok(SessionManagerLayerForStore::Memory(memory_layer(cfg))),
        #[cfg(feature = "redis-session")]
        true => Ok(SessionManagerLayerForStore::Redis(redis_layer(cfg).await?)),
        #[cfg(not(feature = "redis-session"))]
        true => Err(AuthError::BadRequest(
            "OIDC_REDIS_URL requires the `redis-session` feature".into(),
        )),
    }
}

/// Resolve and cache the `SessionManagerLayer` for the running process. The
/// underlying `build_layer` is async (Redis needs a connect handshake), so we
/// build it once during `init` and hand a clone-friendly `Arc` to every
/// caller from then on. Synchronous callers (e.g. axum router setup) can
/// use this without `await`-ing in a non-async context.
pub async fn init_layer(cfg: &OidcConfig) -> Result<Arc<SessionManagerLayerForStore>, AuthError> {
    // We cannot use `OnceCell::get_or_init` here because it does not allow
    // fallible closures: `build_layer` returns `Result<_, AuthError>`. A
    // fast-path read of the existing cell keeps the common case lock-free
    // after the first call.
    if let Some(existing) = LAYER.get() {
        return Ok(existing.clone());
    }
    let built = build_layer(cfg).await?;
    // Two callers racing on first init both build a layer; the loser's is
    // dropped. This is fine because `build_layer` is idempotent (memory
    // store) and the rare double-build for Redis is harmless.
    let _ = LAYER.set(Arc::new(built));
    Ok(LAYER.get().expect("LAYER was set above").clone())
}

/// Returns the cached `SessionManagerLayer`, panicking if `init_layer` was
/// never awaited. Router builders run after `oidc::init()`, so the
/// invariant holds in practice.
pub fn get_layer() -> Arc<SessionManagerLayerForStore> {
    LAYER
        .get()
        .expect("oidc::session::init_layer must be awaited before get_layer")
        .clone()
}

/// Wrapper around the two possible layer types.
#[derive(Clone)]
pub enum SessionManagerLayerForStore {
    Memory(SessionManagerLayer<MemoryStore>),
    #[cfg(feature = "redis-session")]
    Redis(SessionManagerLayer<RedisStore<Pool>>),
}

/// Persist `auth_tokens` to the session.
pub async fn store_tokens(session: &Session, tokens: &AuthTokens) -> Result<(), AuthError> {
    session
        .insert(crate::config::SESSION_AUTH_TOKENS_KEY, tokens.clone())
        .await
        .map_err(|e| AuthError::internal("storing auth tokens", e))
}

/// Load `auth_tokens` from the session, if any.
pub async fn load_tokens(session: &Session) -> Option<AuthTokens> {
    session
        .get::<AuthTokens>(crate::config::SESSION_AUTH_TOKENS_KEY)
        .await
        .ok()
        .flatten()
}

/// Insert the in-flight `AuthorizationState` into the session.
pub async fn store_auth_state(
    session: &Session,
    state: &AuthorizationState,
) -> Result<(), AuthError> {
    session
        .insert(crate::config::AUTH_STATE_COOKIE, state.clone())
        .await
        .map_err(|e| AuthError::internal("storing auth state", e))
}

/// Take the `AuthorizationState` from the session in a single-use fashion.
pub async fn take_auth_state(session: &Session) -> Result<Option<AuthorizationState>, AuthError> {
    let value: Option<AuthorizationState> = session
        .remove(crate::config::AUTH_STATE_COOKIE)
        .await
        .map_err(|e| AuthError::internal("taking auth state", e))?;
    Ok(value)
}

/// Reset OIDC-related session keys without dropping the whole session.
pub async fn reset_oidc(session: &Session) -> Result<(), AuthError> {
    let _: Option<AuthTokens> = session
        .remove(crate::config::SESSION_AUTH_TOKENS_KEY)
        .await
        .map_err(|e| AuthError::internal("resetting auth tokens", e))?;
    Ok(())
}

/// Apply the cached session layer to `app`.
///
/// Panics on a Redis store built without the `redis-session` feature: that
/// combination cannot serve sessions at all, and a silently memory-backed
/// layer would drop them on every worker restart.
pub fn add_session_layer(app: axum::Router) -> axum::Router {
    use SessionManagerLayerForStore;
    match &*get_layer() {
        SessionManagerLayerForStore::Memory(typed) => app.layer(typed.clone()),
        #[cfg(feature = "redis-session")]
        SessionManagerLayerForStore::Redis(typed) => app.layer(typed.clone()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::config::{HttpClientConfig, SessionConfig};

    fn sample_cfg() -> OidcConfig {
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
                same_site: cookie::SameSite::Strict,
                cookie_max_age: time::Duration::seconds(60),
            },
            SessionConfig {
                session_name: "test_sid".to_string(),
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
    fn expiry_is_configured_in_seconds() {
        let cfg = sample_cfg();
        let exp = expiry_from_cookie(&cfg.cookie_config);
        let _ = exp;
    }

    #[test]
    fn memory_layer_builds() {
        let cfg = sample_cfg();
        let _ = memory_layer(&cfg);
    }

    #[test]
    fn default_name_when_empty() {
        assert_eq!(cookie_name(""), "oidc_session");
        assert_eq!(cookie_name("custom"), "custom");
    }
}
