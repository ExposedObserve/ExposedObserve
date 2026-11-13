// Copyright (C) 2026 Mike Sauh
//
// This file is part of ExposedObserve, a modified fork of OpenObserve.
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

//! Token persistence backend for OIDC.
//!
//! The active store is selected at startup and exposed as a global
//! `OnceCell<Box<dyn TokenStore + Send + Sync>>`. Store methods take only the
//! request `Parts` — no other state to thread through.
//!
//! The selection follows the existing configuration:
//!
//! - `OIDC_SESSION_NAME` set, `OIDC_REDIS_URL` set — Redis, shared between nodes.
//! - `OIDC_SESSION_NAME` set, no `OIDC_REDIS_URL` — the shared meta store, which every node of a
//!   cluster reads.
//! - neither set — a self-contained cookie, which needs no server-side store.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::{HeaderValue, request::Parts};
use axum_extra::extract::cookie::CookieJar;
use once_cell::sync::Lazy;

use super::session;
use crate::{
    config::{OidcConfig, SessionStoreKind, get_oidc_config},
    cookies,
    errors::AuthError,
    models::AuthTokens,
    session::SessionManagerLayerForStore,
};

#[async_trait]
pub trait TokenStore: Send + Sync {
    async fn store_tokens(
        &self,
        parts: &Parts,
        tokens: &AuthTokens,
    ) -> Result<Option<HeaderValue>, AuthError>;
    async fn load_tokens(&self, parts: &Parts) -> Option<AuthTokens>;
    async fn has_oidc_flag(&self, parts: &Parts) -> bool;
    async fn reset_oidc(&self, parts: &Parts) -> Result<Option<HeaderValue>, AuthError>;
    fn need_session(&self) -> bool;
    fn get_layer(&self) -> Option<Arc<SessionManagerLayerForStore>>;
    /// `true` when only the process that created the session can resolve it.
    fn is_process_local(&self) -> bool;
    /// Human-readable store name, for start-up diagnostics.
    fn kind(&self) -> &'static str;
}

pub struct CookieTokenStore {
    cookie_name: String,
}

impl CookieTokenStore {
    pub fn new(cfg: Arc<OidcConfig>) -> Self {
        Self {
            cookie_name: cfg.cookie_config.cookie_name.clone(),
        }
    }
}

#[async_trait]
impl TokenStore for CookieTokenStore {
    async fn store_tokens(
        &self,
        _: &Parts,
        tokens: &AuthTokens,
    ) -> Result<Option<HeaderValue>, AuthError> {
        let cookie_name: &'static str = Box::leak(self.cookie_name.clone().into_boxed_str());
        let header = cookies::build_auth_cookie(cookie_name, tokens).await?;
        Ok(Some(header))
    }

    async fn load_tokens(&self, parts: &Parts) -> Option<AuthTokens> {
        let jar = CookieJar::from_headers(&parts.headers);
        cookies::read_auth_cookie(jar, &self.cookie_name).await
    }

    async fn has_oidc_flag(&self, parts: &Parts) -> bool {
        let jar = CookieJar::from_headers(&parts.headers);
        jar.get(&self.cookie_name).is_some()
    }

    async fn reset_oidc(&self, _: &Parts) -> Result<Option<HeaderValue>, AuthError> {
        let cookie_name: &'static str = Box::leak(self.cookie_name.clone().into_boxed_str());
        let header = cookies::clear_auth_cookie(cookie_name)?;
        Ok(Some(header))
    }

    fn get_layer(&self) -> Option<Arc<SessionManagerLayerForStore>> {
        None
    }

    fn need_session(&self) -> bool {
        false
    }

    fn is_process_local(&self) -> bool {
        false
    }

    fn kind(&self) -> &'static str {
        "cookie"
    }
}

pub struct SessionTokenStore {
    session_name: String,
}

impl SessionTokenStore {
    pub fn new(cfg: Arc<OidcConfig>) -> Self {
        Self {
            session_name: cfg.session_config.session_name.clone(),
        }
    }
}

#[async_trait]
impl TokenStore for SessionTokenStore {
    async fn store_tokens(
        &self,
        parts: &Parts,
        tokens: &AuthTokens,
    ) -> Result<Option<HeaderValue>, AuthError> {
        let Some(session) = parts.extensions.get::<tower_sessions::Session>() else {
            return Ok(None);
        };
        match session::store_tokens(session, tokens).await {
            Ok(()) => Ok(None),
            Err(err) => Err(err),
        }
    }

    async fn load_tokens(&self, parts: &Parts) -> Option<AuthTokens> {
        let session = parts.extensions.get::<tower_sessions::Session>()?;
        let tokens = session::load_tokens(session).await?;
        // An entry without an id_token cannot be verified, so treat it as
        // "no OIDC session" rather than failing the request.
        if tokens.id_token.is_empty() {
            return None;
        }
        Some(tokens)
    }

    async fn has_oidc_flag(&self, parts: &Parts) -> bool {
        let jar = CookieJar::from_headers(&parts.headers);
        jar.get(&self.session_name).is_some()
    }

    async fn reset_oidc(&self, parts: &Parts) -> Result<Option<HeaderValue>, AuthError> {
        let Some(session) = parts.extensions.get::<tower_sessions::Session>() else {
            return Ok(None);
        };
        session::reset_oidc(session).await?;
        return Ok(None);
    }

    fn get_layer(&self) -> Option<Arc<SessionManagerLayerForStore>> {
        Some(session::get_layer())
    }

    fn need_session(&self) -> bool {
        true
    }

    fn is_process_local(&self) -> bool {
        false
    }

    fn kind(&self) -> &'static str {
        "redis"
    }
}

/// Session stored in the shared meta store: the cookie carries the session id
/// and the tokens live in the `sessions` table, which every node can read.
///
/// This is the only store that works in a cluster without an external
/// dependency: the meta store is already shared, and the coordinator
/// broadcasts invalidation to all nodes.
pub struct DbTokenStore {
    cookie_name: String,
    /// `Cookie::build` wants a `'static` name, so it is leaked once here
    /// rather than on every request.
    static_cookie_name: &'static str,
}

impl DbTokenStore {
    pub fn new(cfg: Arc<OidcConfig>) -> Self {
        // The session name doubles as the cookie name here: it is what
        // `OIDC_SESSION_NAME` configures, and the cookie has to carry the id
        // that names the row.
        let cookie_name = cfg.session_config.session_name.clone();
        let static_cookie_name = Box::leak(cookie_name.clone().into_boxed_str());
        Self {
            cookie_name,
            static_cookie_name,
        }
    }

    /// A fresh session id. The `oidc_` prefix keeps these rows apart from the
    /// Dex sessions the enterprise build writes to the same table.
    fn new_session_id() -> String {
        format!("oidc_{}", config::ider::uuid())
    }

    /// The session id in the request's cookies, if any.
    fn session_id(&self, parts: &Parts) -> Option<String> {
        let jar = CookieJar::from_headers(&parts.headers);
        jar.get(&self.cookie_name)
            .map(|cookie| cookie.value().to_string())
    }
}

#[async_trait]
impl TokenStore for DbTokenStore {
    async fn store_tokens(
        &self,
        parts: &Parts,
        tokens: &AuthTokens,
    ) -> Result<Option<HeaderValue>, AuthError> {
        // A refresh keeps the session it already has: the browser's cookie
        // still points at that row, and minting a new id would orphan the old
        // row until it expires.
        let session_id = self.session_id(parts).unwrap_or_else(Self::new_session_id);
        let expires_at = tokens
            .expires_in
            .map(|ttl| chrono::Utc::now().timestamp() + ttl.as_secs() as i64)
            .unwrap_or_else(|| {
                chrono::Utc::now().timestamp()
                    + get_oidc_config()
                        .cookie_config
                        .cookie_max_age
                        .whole_seconds()
            });
        let payload = serde_json::to_string(tokens)
            .map_err(|e| AuthError::internal("serializing OIDC auth tokens", e))?;
        db::session::set_with_expiry(&session_id, &payload, expires_at)
            .await
            .map_err(|e| AuthError::internal("storing OIDC session", e))?;

        let header = cookies::build_session_cookie(self.static_cookie_name, &session_id)?;
        Ok(Some(header))
    }

    async fn load_tokens(&self, parts: &Parts) -> Option<AuthTokens> {
        let session_id = self.session_id(parts)?;
        // A missing or expired session is not an error here: the caller treats
        // `None` as "no OIDC session" and falls back to the native auth path.
        let payload = db::session::get(&session_id).await.ok()?;
        serde_json::from_str(&payload).ok()
    }

    async fn has_oidc_flag(&self, parts: &Parts) -> bool {
        self.session_id(parts).is_some()
    }

    async fn reset_oidc(&self, parts: &Parts) -> Result<Option<HeaderValue>, AuthError> {
        if let Some(session_id) = self.session_id(parts)
            && let Err(e) = db::session::delete(&session_id).await
        {
            log::error!("Failed to delete OIDC session {session_id}: {e}");
        }
        let header = cookies::clear_auth_cookie(self.static_cookie_name)?;
        Ok(Some(header))
    }

    fn need_session(&self) -> bool {
        false
    }

    fn get_layer(&self) -> Option<Arc<SessionManagerLayerForStore>> {
        None
    }

    fn is_process_local(&self) -> bool {
        false
    }

    fn kind(&self) -> &'static str {
        "db"
    }
}

pub static OIDC_STORE: Lazy<Arc<dyn TokenStore>> = Lazy::new(|| {
    let config = super::config::get_oidc_config();

    match SessionStoreKind::from_config(&config.session_config) {
        // A session name without a Redis URL means the shared meta store: the
        // only backend every node of a cluster can resolve.
        Some(SessionStoreKind::Db) => Arc::new(DbTokenStore::new(config)),
        Some(SessionStoreKind::Redis) => Arc::new(SessionTokenStore::new(config)),
        None if !config.cookie_config.cookie_name.is_empty() => {
            Arc::new(CookieTokenStore::new(config))
        }
        None => {
            panic!(
                "Failed to initialize TokenStore: neither OIDC_SESSION_NAME nor OIDC_COOKIE_NAME is configured"
            )
        }
    }
});
