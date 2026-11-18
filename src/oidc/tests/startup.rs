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
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Start-up behaviour of the OIDC subsystem.
//!
//! A configuration mistake has to stop the node: it would authorise requests
//! with the wrong rules. A provider that cannot be reached must not: the
//! node still serves the native login.

mod common;

use serial_test::serial;

/// The value `OIDC_DEFAULT_ROLE` had before the test changed it.
fn take_env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Put the previous value of `name` back, or remove the variable again.
fn restore_env_var(name: &str, previous: Option<String>) {
    match previous {
        Some(previous) => unsafe { std::env::set_var(name, previous) },
        None => unsafe { std::env::remove_var(name) },
    }
}

#[test]
#[serial]
fn an_invalid_default_role_is_a_configuration_error() {
    let previous = take_env_var("OIDC_DEFAULT_ROLE");
    unsafe { std::env::set_var("OIDC_DEFAULT_ROLE", "wizard") };
    let err = oidc::config::load_config_from_env()
        .expect_err("an unknown default role must not produce a config");
    restore_env_var("OIDC_DEFAULT_ROLE", previous);
    assert!(
        err.is_config(),
        "an invalid OIDC_DEFAULT_ROLE has to be a configuration error, \
         otherwise the node keeps running with the wrong rules"
    );
    assert!(err.to_string().contains("OIDC_DEFAULT_ROLE"));
}

#[test]
#[serial]
fn a_valid_default_role_produces_a_config() {
    let previous = take_env_var("OIDC_DEFAULT_ROLE");
    unsafe { std::env::set_var("OIDC_DEFAULT_ROLE", "editor") };
    let cfg = oidc::config::load_config_from_env().expect("a known role must build a config");
    restore_env_var("OIDC_DEFAULT_ROLE", previous);
    assert_eq!(cfg.default_role, config::meta::user::UserRole::Editor);
}

#[test]
#[serial]
fn an_invalid_org_claim_pattern_is_a_configuration_error() {
    let previous = take_env_var("OIDC_ORG_CLAIM_PATTERN");
    unsafe { std::env::set_var("OIDC_ORG_CLAIM_PATTERN", "^(?<org>.*$") };
    let err = oidc::config::load_config_from_env()
        .expect_err("an uncompilable pattern must not produce a config");
    restore_env_var("OIDC_ORG_CLAIM_PATTERN", previous);
    assert!(
        err.is_config(),
        "an uncompilable OIDC_ORG_CLAIM_PATTERN has to be a configuration error"
    );
}

#[tokio::test]
#[serial]
async fn an_invalid_session_key_is_a_configuration_error() {
    // A key that does not decode to 64 bytes can never seal a cookie.
    let previous = take_env_var("OIDC_SESSION_KEY");
    unsafe { std::env::set_var("OIDC_SESSION_KEY", "not-base64!!") };
    let err = oidc::keys::session_key()
        .await
        .expect_err("a broken key must not be accepted");
    restore_env_var("OIDC_SESSION_KEY", previous);
    assert!(
        err.is_config(),
        "a broken OIDC_SESSION_KEY has to be a configuration error"
    );
}

#[tokio::test]
#[serial]
async fn a_provider_that_cannot_be_reached_is_not_a_configuration_error() {
    // The issuer points at a port nothing listens on: the OIDC login stays
    // unavailable, the node keeps running.
    let previous = take_env_var("OIDC_ISSUER_URL");
    unsafe { std::env::set_var("OIDC_ISSUER_URL", "http://127.0.0.1:1/oidc") };
    let cfg = oidc::config::load_config_from_env().expect("the config itself is valid");
    oidc::config::set_config(cfg.clone());
    let err = oidc::client::create_oidc_metadata(&cfg)
        .await
        .expect_err("discovery against a dead issuer must fail");
    restore_env_var("OIDC_ISSUER_URL", previous);
    assert!(
        !err.is_config(),
        "an unreachable provider is a transient failure, not a configuration one"
    );
}
