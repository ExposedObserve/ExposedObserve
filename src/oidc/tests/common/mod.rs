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

//! Shared fixtures for the OIDC integration tests.
//!
//! Every test that reaches the network or the process-global config must go
//! through [`install_config`]: the library reads its settings from the
//! `ArcSwap` in `oidc::config`, so a locally-built `OidcConfig` is ignored
//! unless it is installed there first.

// Each integration binary compiles `common/mod.rs` separately and uses a
// different slice of it, so unused helpers here are expected, not a bug.
#![allow(dead_code)]

use std::collections::HashSet;

use oidc::config::{CookieConfig, HttpClientConfig, OidcConfig, RedisConfig, SessionConfig};

/// Redirect URI registered with the provider under test.
pub const REDIRECT_URL: &str = "http://127.0.0.1:9999/auth/sso/callback";

/// Client id used across the suite.
pub const CLIENT_ID: &str = "oss-test-client";

/// Build a config pointing at `issuer`, install it globally, and return it.
///
/// Installing is the whole point: `oidc::client` resolves the issuer through
/// `oidc::config::get_oidc_config()`, so a config that is only passed around
/// locally still makes discovery hit the default `https://example.com`.
pub fn install_config(issuer: &str, org_claim_pattern: &str) -> OidcConfig {
    let cfg = build_config(issuer, org_claim_pattern);
    oidc::config::set_config(cfg.clone());
    cfg
}

/// Same as [`install_config`], but also sets a cookie name so the
/// process-global `OIDC_STORE` resolves to the cookie backend.
pub fn install_named_store_config(issuer: &str, cookie_name: &str) -> OidcConfig {
    let cfg = OidcConfig {
        cookie_config: CookieConfig {
            cookie_name: cookie_name.to_string(),
            ..CookieConfig::default()
        },
        ..build_config(issuer, "^(?<org>org:(?<role>\\w+))$")
    };
    oidc::config::set_config(cfg.clone());
    cfg
}

/// Construct a config without touching global state.
pub fn build_config(issuer: &str, org_claim_pattern: &str) -> OidcConfig {
    OidcConfig::new(
        CLIENT_ID,
        None,
        issuer,
        REDIRECT_URL,
        REDIRECT_URL,
        HttpClientConfig::default(),
        CookieConfig::default(),
        SessionConfig::default(),
        "groups",
        org_claim_pattern,
        Some("sub"),
        Some("email"),
        HashSet::new(),
    )
    .expect("config must build")
}

/// Build a config whose session store is Redis, without touching global state.
///
/// `url` alone is enough to enable the store; every other field stays at its
/// default so a test only sets what it actually cares about.
pub fn build_redis_config(url: &str) -> OidcConfig {
    OidcConfig {
        session_config: SessionConfig {
            redis: RedisConfig {
                url: url.to_string(),
                ..RedisConfig::default()
            },
            ..SessionConfig::default()
        },
        ..build_config("https://example.com", "^(?<org>org:(?<role>\\w+))$")
    }
}

/// Minimal `.well-known/openid-configuration` document for a mock provider.
///
/// `issuer` must match the URL discovery was requested from, otherwise
/// `openidconnect` rejects the document outright.
pub mod discovery {
    use serde_json::Value;

    pub fn document(issuer: &str) -> Value {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "userinfo_endpoint": format!("{issuer}/userinfo"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })
    }

    /// Empty JWKS: enough for discovery to finish, not enough to verify a token.
    pub fn empty_jwks() -> Value {
        serde_json::json!({ "keys": [] })
    }
}
