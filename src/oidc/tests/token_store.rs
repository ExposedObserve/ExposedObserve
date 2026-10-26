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

//! Token-store and cookie round-trip tests.
//!
//! These cover the `store`/`cookies` pair, which had no tests at all: the
//! cookie backend is the default in production (the session backend needs
//! `OIDC_SESSION_NAME` set), so a break here logs every user out.

mod common;

use axum::http::{Request, request::Parts};
use base64::Engine as _;
use oidc::models::{AuthTokens, AuthorizationState};
use serial_test::serial;

/// Issuer is irrelevant for the cookie backend, but `OIDC_STORE` refuses to
/// initialise unless one of the store names is configured.
const ISSUER: &str = "https://example.com";

fn tokens() -> AuthTokens {
    AuthTokens {
        access_token: "access-value".into(),
        refresh_token: "refresh-value".into(),
        id_token: "id-value".into(),
        expires_in: None,
    }
}

/// Request parts carrying a single cookie header.
fn request_with_cookie(header: &str) -> Parts {
    Request::builder()
        .uri("/")
        .header("cookie", header)
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

/// The `name=value` pair of a `Set-Cookie` header, as a request echoes it.
fn cookie_pair(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .expect("Set-Cookie must carry a pair")
        .to_string()
}

fn jar_with(header: &str) -> axum_extra::extract::CookieJar {
    axum_extra::extract::CookieJar::from_headers(&request_with_cookie(header).headers)
}

/// Install the cookie-backed token store under the given cookie name.
fn install_cookie_store(cookie_name: &str) {
    oidc::config::set_config(common::install_named_store_config(ISSUER, cookie_name).clone());
}

#[tokio::test]
#[serial]
async fn cookie_store_round_trips_tokens() {
    install_cookie_store("oidc_tokens");
    let store = &*oidc::store::OIDC_STORE;

    let set_cookie = store
        .store_tokens(&request_with_cookie("x=1"), &tokens())
        .await
        .expect("storing tokens must succeed")
        .expect("cookie store must emit a header");
    let set_cookie = set_cookie.to_str().expect("header must be ascii");

    let loaded = store
        .load_tokens(&request_with_cookie(&cookie_pair(set_cookie)))
        .await
        .expect("tokens must decode back");
    assert_eq!(loaded.access_token, "access-value");
    assert_eq!(loaded.refresh_token, "refresh-value");
    assert_eq!(loaded.id_token, "id-value");
}

#[tokio::test]
#[serial]
async fn cookie_store_reports_flag_only_when_cookie_present() {
    install_cookie_store("oidc_tokens");
    let store = &*oidc::store::OIDC_STORE;

    assert!(!store.has_oidc_flag(&request_with_cookie("x=1")).await);

    let set_cookie = store
        .store_tokens(&request_with_cookie("x=1"), &tokens())
        .await
        .expect("storing tokens must succeed")
        .expect("cookie store must emit a header");
    let parts = request_with_cookie(&cookie_pair(set_cookie.to_str().unwrap()));
    assert!(store.has_oidc_flag(&parts).await);
}

#[tokio::test]
#[serial]
async fn cookie_store_ignores_foreign_and_garbage_cookies() {
    install_cookie_store("oidc_tokens");
    let store = &*oidc::store::OIDC_STORE;

    assert!(
        store
            .load_tokens(&request_with_cookie("other=value"))
            .await
            .is_none()
    );
    // Base64 of valid JSON that is not an `AuthTokens` must not resurrect a
    // session: a decode failure has to look identical to "no cookie".
    let garbage = base64::engine::general_purpose::STANDARD.encode("{\"sub\":\"x\"}");
    assert!(
        store
            .load_tokens(&request_with_cookie(&format!("oidc_tokens={garbage}")))
            .await
            .is_none()
    );
    assert!(
        store
            .load_tokens(&request_with_cookie("oidc_tokens=not-base64!!"))
            .await
            .is_none()
    );
}

#[tokio::test]
#[serial]
async fn cookie_store_reset_emits_expiring_cookie() {
    install_cookie_store("oidc_tokens");
    let store = &*oidc::store::OIDC_STORE;

    let header = store
        .reset_oidc(&request_with_cookie("x=1"))
        .await
        .expect("reset must succeed")
        .expect("reset must emit a header");
    let header = header.to_str().expect("header must be ascii");

    assert!(header.starts_with("oidc_tokens="), "got {header}");
    // A non-positive Max-Age is what makes the browser drop it.
    let max_age = header
        .split(';')
        .map(str::trim)
        .find(|p| p.to_ascii_lowercase().starts_with("max-age="))
        .expect("Max-Age must be present");
    let secs: i64 = max_age
        .split('=')
        .nth(1)
        .expect("Max-Age needs a value")
        .parse()
        .expect("Max-Age must be numeric");
    assert!(secs <= 0, "Max-Age must expire the cookie, got {secs}");
}

#[tokio::test]
#[serial]
async fn state_cookie_round_trips_authorization_state() {
    oidc::config::set_config(common::build_config(ISSUER, "^(?<org>.*)$"));

    let state = AuthorizationState {
        pkce_verifier: "verifier".into(),
        csrf_state: "csrf".into(),
        nonce: "nonce".into(),
    };
    let cookie = oidc::cookies::build_state_cookie(&state).expect("state cookie must build");
    let encoded = cookie.encoded().to_string();

    let read = oidc::cookies::read_state_cookie(jar_with(&cookie_pair(&encoded)))
        .expect("state must decode back");

    assert_eq!(read.pkce_verifier, "verifier");
    assert_eq!(read.csrf_state, "csrf");
    assert_eq!(read.nonce, "nonce");
}

#[tokio::test]
#[serial]
async fn state_cookie_is_ignored_when_absent_or_corrupt() {
    oidc::config::set_config(common::build_config(ISSUER, "^(?<org>.*)$"));

    assert!(oidc::cookies::read_state_cookie(jar_with("other=1")).is_none());
    assert!(oidc::cookies::read_state_cookie(jar_with("auth_state=%%%bad%%%")).is_none());
}

#[tokio::test]
#[serial]
async fn state_cookie_expires_before_the_session_cookie() {
    oidc::config::set_config(common::build_config(ISSUER, "^(?<org>.*)$"));

    let cookie = oidc::cookies::build_state_cookie(&AuthorizationState {
        pkce_verifier: "v".into(),
        csrf_state: "c".into(),
        nonce: "n".into(),
    })
    .expect("state cookie must build");

    // The state cookie only has to survive the round-trip to the IdP; giving
    // it the full session lifetime leaves it readable after the callback.
    let max_age = cookie.max_age().expect("Max-Age must be set");
    assert!(
        max_age < oidc::config::CookieConfig::default().cookie_max_age,
        "state cookie must expire before the session cookie"
    );
}
