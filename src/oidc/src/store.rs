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
//! The active store is selected at startup based on the presence of
//! `OIDC_SESSION_NAME` and exposed as a global `OnceCell<Box<dyn
//! TokenStore + Send + Sync>>`. Store methods take only the request
//! `Parts` — no other state to thread through.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::{HeaderValue, request::Parts};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine as _;
use once_cell::sync::Lazy;
use serde::de::DeserializeOwned;

use super::session;
use crate::{
    config::OidcConfig, cookies, errors::AuthError, models::AuthTokens,
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
        let header = cookies::build_auth_cookie(cookie_name, tokens)?;
        Ok(Some(header))
    }

    async fn load_tokens(&self, parts: &Parts) -> Option<AuthTokens> {
        let jar = CookieJar::from_headers(&parts.headers);
        read_cookie::<AuthTokens>(jar, &self.cookie_name)
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
}

pub fn read_cookie<T: DeserializeOwned>(jar: CookieJar, name: &str) -> Option<T> {
    let cookie_value: &str = jar.get(name)?.value();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(cookie_value)
        .ok()?;
    let json = String::from_utf8(decoded).ok()?;
    serde_json::from_str(&json).ok()
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
}

pub static OIDC_STORE: Lazy<Arc<dyn TokenStore>> = Lazy::new(|| {
    let config = super::config::get_oidc_config();

    if !config.session_config.session_name.is_empty() {
        Arc::new(SessionTokenStore::new(config))
    } else if !config.cookie_config.cookie_name.is_empty() {
        Arc::new(CookieTokenStore::new(config))
    } else {
        panic!(
            "Failed to initialize TokenStore: neither OIDC_SESSION_NAME nor OIDC_COOKIE_NAME is configured"
        )
    }
});
