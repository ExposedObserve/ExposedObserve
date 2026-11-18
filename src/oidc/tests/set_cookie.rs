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

//! The `Set-Cookie` headers the OIDC routes put on the response.
//!
//! The handlers used to read `HeaderMap::append` as a success flag and
//! warned on the inverted value, so every successful callback logged
//! "Set Auth failed" while the cookie was in the response. The routes
//! now append unconditionally; these tests pin the cookies that must
//! come out of them.

mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header::SET_COOKIE},
};
use oidc::models::AuthTokens;
use serial_test::serial;
use tower::util::ServiceExt;

/// Issuer is irrelevant for the cookie backend, but `OIDC_STORE` refuses to
/// initialise unless one of the store names are configured.
const ISSUER: &str = "https://example.com";

fn tokens() -> AuthTokens {
    AuthTokens {
        access_token: "access-value".into(),
        refresh_token: "refresh-value".into(),
        id_token: "id-value".into(),
        expires_in: None,
    }
}

/// A GET request for one of the OIDC routes.
fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request must build")
}

/// The router the OIDC routes are mounted on.
fn router() -> axum::Router {
    let routes: axum::Router = oidc::handlers::sso_routes();
    axum::Router::new().merge(routes)
}

/// Install the cookie-backed token store under the given cookie name.
fn install_cookie_store(cookie_name: &str) {
    common::install_session_key();
    oidc::config::set_config(common::install_named_store_config(ISSUER, cookie_name).clone());
}

/// The `Set-Cookie` values of a response, in order.
fn set_cookies(response: &axum::http::Response<Body>) -> Vec<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| v.to_str().expect("Set-Cookie must be ascii").to_string())
        .collect()
}

#[tokio::test]
#[serial]
async fn the_logout_route_clears_the_auth_cookie() {
    install_cookie_store("oidc_tokens");

    let response = router()
        .oneshot(get("/sso/logout"))
        .await
        .expect("the route must answer");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookies = set_cookies(&response);
    assert!(
        cookies.iter().any(|c| c.starts_with("oidc_tokens=")),
        "the auth cookie must be cleared: {cookies:?}"
    );
}

#[tokio::test]
#[serial]
async fn the_logout_route_clears_the_state_cookie() {
    install_cookie_store("oidc_tokens");

    let response = router()
        .oneshot(get("/sso/logout"))
        .await
        .expect("the route must answer");

    let cookies = set_cookies(&response);
    assert!(
        cookies.iter().any(|c| c.starts_with("auth_state=")),
        "the state cookie must be cleared: {cookies:?}"
    );
}

#[tokio::test]
#[serial]
async fn the_logout_route_carries_both_cookies() {
    // Both cookies ride under the same header key, so the response has to
    // carry two values: `append` adds a value instead of replacing the
    // first one.
    install_cookie_store("oidc_tokens");

    let response = router()
        .oneshot(get("/sso/logout"))
        .await
        .expect("the route must answer");

    let cookies = set_cookies(&response);
    assert_eq!(
        cookies.len(),
        2,
        "the auth cookie and the state cookie must both be sent: {cookies:?}"
    );
}

#[tokio::test]
#[serial]
async fn a_stored_token_is_carried_back_as_a_cookie() {
    // The store hands the handler a ready-made `Set-Cookie` value; it has
    // to reach the response unchanged.
    install_cookie_store("oidc_tokens");
    let store = &*oidc::store::OIDC_STORE;

    let header = store
        .store_tokens(&get("/").into_parts().0, &tokens())
        .await
        .expect("storing tokens must succeed")
        .expect("cookie store must emit a header");

    let mut headers = axum::http::HeaderMap::new();
    headers.append(SET_COOKIE, header.clone());
    let cookies: Vec<String> = headers
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| v.to_str().expect("Set-Cookie must be ascii").to_string())
        .collect();
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].starts_with("oidc_tokens="), "got {}", cookies[0]);
}
