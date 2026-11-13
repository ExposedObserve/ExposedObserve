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

//! OIDC authentication crate.
//!
//! This crate is a pure domain library: it does not depend on any HTTP framework
//! types. HTTP integration is the caller's responsibility; the crate exposes
//! `tower_sessions::Session` as its only session abstraction.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod client;
pub mod config;
pub mod cookies;
pub mod errors;
pub mod ext_users;
pub mod handlers;
pub mod http;
pub mod keys;
pub mod models;
pub mod session;
pub mod store;

pub use config::OidcConfig;
pub use errors::AuthError;
pub use models::UserInfo;

/// Initialize the OIDC subsystem.
///
/// Loads the OIDC config, builds the shared HTTP client, resolves the OIDC
/// provider metadata and prepares the cached `tower-sessions` layer. Must
/// be called once at process start, before any router builder that mounts
/// OIDC routes.
///
/// A configuration error (an invalid role, a broken session key) stops the
/// process: the operator has to fix the setting, and a node that keeps
/// running with it authorises requests wrongly. A provider that cannot be
/// reached only disables the OIDC login, so the node keeps serving the
/// native one.
pub async fn init() -> Result<(), anyhow::Error> {
    // Read OIDC_* env vars (via dotenvy) and swap the static config
    // before any other subsystem grabs a reference. Without this,
    // the cached default `https://example.com` issuer would survive
    // every call and discovery would 404.
    let cfg = config::load_config_from_env()?;
    config::set_config(cfg);
    let cfg = config::get_oidc_config();
    let _client = http::get_http_client().await;
    if let Err(err) = client::create_oidc_metadata(&cfg).await {
        if err.is_config() {
            return Err(err.into());
        }
        // The provider is down or misconfigured: OIDC simply stays
        // unavailable, the native login keeps working.
        log::error!("OIDC discovery failed, the OIDC login stays disabled: {err}");
    }
    session::init_default().await;
    // The `tower-sessions` layer only backs the Redis store; the shared
    // meta-store backend keeps the session in the database instead.
    if config::SessionStoreKind::from_config(&cfg.session_config)
        .is_some_and(|kind| kind.uses_tower_sessions())
    {
        let _layer = session::init_layer(&cfg).await?;
    }
    Ok(())
}
