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

//! The URL the browser is sent to after the logout.
//!
//! The provider sends it back to `post_logout_redirect_uri`. Pointing that at
//! the OIDC callback made the browser land on a 400, because the callback
//! demands a state cookie the logout round trip never carries.

mod common;

use std::collections::HashSet;

use oidc::config::{OidcConfig, get_oidc_config};
use serial_test::serial;

/// A config whose callback URL is the OIDC callback route, the case that
/// used to send the browser to the 400.
fn config_with_callback_url(callback_url: &str) -> OidcConfig {
    OidcConfig::new(
        common::CLIENT_ID,
        None,
        "https://accounts.example.org",
        common::REDIRECT_URL,
        callback_url,
        None,
        oidc::config::HttpClientConfig::default(),
        oidc::config::CookieConfig::default(),
        oidc::config::SessionConfig::default(),
        "groups",
        "^(?<org>.*)$",
        "user",
        None,
        Some("sub"),
        Some("email"),
        HashSet::new(),
    )
    .expect("config must build")
}

#[test]
#[serial]
fn the_logout_redirect_never_points_at_the_callback() {
    oidc::config::set_config(config_with_callback_url(common::REDIRECT_URL));
    let redirect = get_oidc_config().post_logout_redirect_uri();
    assert!(
        !redirect.contains("/auth/sso/callback"),
        "the post-logout redirect must not point at the OIDC callback: {redirect}"
    );
    assert!(
        redirect.ends_with("/web/"),
        "the post-logout redirect must land on the SPA: {redirect}"
    );
}

#[test]
#[serial]
fn the_logout_redirect_ignores_the_callback_url() {
    // A callback URL that is a valid SPA path stays out of the logout
    // redirect: the two are separate settings.
    oidc::config::set_config(config_with_callback_url("https://eo.example.com/web/cb"));
    let redirect = get_oidc_config().post_logout_redirect_uri();
    assert!(!redirect.contains("/web/cb"));
    assert!(redirect.ends_with("/web/"));
}

#[test]
#[serial]
fn a_configured_logout_redirect_wins() {
    let cfg = config_with_callback_url(common::REDIRECT_URL)
        .with_logout_redirect_url("https://eo.example.com/signed-out");
    oidc::config::set_config(cfg);
    let redirect = get_oidc_config().post_logout_redirect_uri();
    assert_eq!(redirect, "https://eo.example.com/signed-out");
}
