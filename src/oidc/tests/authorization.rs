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

//! Authorisation tests for `handlers::validate_user_info`.
//!
//! Kept as an integration binary rather than a `handlers` unit test because
//! the function strips the base URI off the path using the process-global
//! `config::get_config()`; a unit test would inherit whatever `.env` the
//! developer's shell happens to define.

use std::collections::{HashMap, HashSet};

use axum::http::{Method, Request, StatusCode, request::Parts};
use oidc::models::UserInfo;
use serial_test::serial;

// The router does `nest(&base_uri, app)`, so axum strips that prefix before any
// middleware runs: `validate_user_info` always sees `/api/<org>/...`, never
// `/<base_uri>/api/<org>/...`.
//
// It then strips `format!("{base_uri}/api/")` from the path and looks for an
// `api` segment in what is left. With the default empty base URI that strip
// succeeds and consumes the very segment the code later checks for, so
// `target_org` is `None` and the org/role gate never runs. It is reached only
// when a base URI is configured and the strip therefore fails to match.
const BASE_URI: &str = "e2e-base";

/// API path as the middleware sees it: no base URI prefix.
fn api(rest: &str) -> String {
    format!("/api/{}", rest.trim_start_matches('/'))
}

/// Install a `Config` carrying the given base URI.
fn set_base_uri(base_uri: &str) {
    // `Config` is not `Clone`, so rebuild through the crate's own loader and
    // patch one field. `config::config::init()` is the sync path; the bare
    // `config::init` name is shadowed by the async OIDC init in this test.
    let mut cfg = config::config::init();
    cfg.common.base_uri = base_uri.to_string();
    config::CONFIG.store(std::sync::Arc::new(cfg));
}

/// Pin a non-empty base URI so the org/role gate is reachable.
fn pin_base_uri() {
    set_base_uri(BASE_URI);
    assert_eq!(config::get_config().common.base_uri, BASE_URI);
}

/// User in `acme` as `admin`, which outranks the editor threshold.
fn admin_of_acme() -> UserInfo {
    UserInfo {
        sub: "user-1".into(),
        email: "user-1@example.com".into(),
        orgs: HashSet::from(["acme".to_string()]),
        org_roles: HashMap::from([("acme".to_string(), "admin".to_string())]),
        is_internal: false,
    }
}

fn user_of_acme() -> UserInfo {
    UserInfo {
        org_roles: HashMap::from([("acme".to_string(), "user".to_string())]),
        ..admin_of_acme()
    }
}

fn parts(method: Method, path: &str) -> Parts {
    Request::builder()
        .method(method)
        .uri(path)
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

#[test]
#[serial]
fn admin_may_write_to_its_own_org() {
    pin_base_uri();
    let user = admin_of_acme();
    assert!(
        oidc::handlers::validate_user_info(
            &user,
            &mut parts(Method::POST, &api("/acme/streams/default"))
        )
        .is_ok(),
        "admin outranks the editor threshold and must be allowed to write"
    );
}

#[test]
#[serial]
fn plain_user_may_read_but_not_write() {
    pin_base_uri();
    let user = user_of_acme();
    assert!(
        oidc::handlers::validate_user_info(
            &user,
            &mut parts(Method::GET, &api("/acme/streams/default"))
        )
        .is_ok()
    );
    let denied = oidc::handlers::validate_user_info(
        &user,
        &mut parts(Method::POST, &api("/acme/streams/default")),
    )
    .expect_err("a `user` role must not be allowed to write");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[test]
#[serial]
fn plain_user_may_post_to_search_endpoints() {
    pin_base_uri();
    // The `_search` carve-out exists because search bodies are POSTs but
    // semantically reads.
    let user = user_of_acme();
    assert!(
        oidc::handlers::validate_user_info(
            &user,
            &mut parts(Method::POST, &api("/acme/streams/default/_search"))
        )
        .is_ok()
    );
}

#[test]
#[serial]
fn unknown_org_is_allowed_through() {
    pin_base_uri();
    // A path that names no org (or an org the IdP never mentioned) must fall
    // through to the native auth middleware rather than 403 here.
    let user = admin_of_acme();
    assert!(
        oidc::handlers::validate_user_info(
            &user,
            &mut parts(Method::GET, &api("/other-org/streams/default"))
        )
        .is_ok()
    );
    assert!(oidc::handlers::validate_user_info(&user, &mut parts(Method::GET, "/healthz")).is_ok());
}

#[test]
#[serial]
fn role_for_org_the_user_does_not_belong_to_is_forbidden() {
    pin_base_uri();
    let mut user = admin_of_acme();
    user.org_roles
        .insert("other-org".to_string(), "admin".to_string());
    let denied = oidc::handlers::validate_user_info(
        &user,
        &mut parts(Method::GET, &api("/other-org/streams/default")),
    )
    .expect_err("holding a role for an org you are not a member of must be rejected");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[test]
#[serial]
fn invalid_role_string_is_forbidden() {
    pin_base_uri();
    let mut user = admin_of_acme();
    user.org_roles
        .insert("acme".to_string(), "wizard".to_string());
    let denied = oidc::handlers::validate_user_info(
        &user,
        &mut parts(Method::GET, &api("/acme/streams/default")),
    )
    .expect_err("an unparsable role must not be treated as a pass");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

/// The strip/lookup mismatch: with the default empty base URI the code eats
/// the `api` segment and then looks for it, so the org/role gate is skipped
/// and even an impossible role is let through. Recorded here so the day
/// `validate_user_info` is fixed this test fails and gets updated, rather than
/// the gap quietly staying invisible.
#[test]
#[serial]
fn empty_base_uri_skips_the_role_gate() {
    set_base_uri("");
    let mut user = user_of_acme();
    user.org_roles
        .insert("acme".to_string(), "wizard".to_string());

    let allowed = oidc::handlers::validate_user_info(
        &user,
        &mut parts(Method::GET, &api("/acme/streams/default")),
    );
    assert!(
        allowed.is_ok(),
        "empty base URI is expected to bypass the role gate — this test \
         documents the bug and must be updated when it is fixed"
    );
}

#[test]
#[serial]
fn stamps_user_id_header_and_default_content_type() {
    pin_base_uri();
    let user = admin_of_acme();
    let mut req = parts(Method::POST, &api("/acme/streams/default"));
    oidc::handlers::validate_user_info(&user, &mut req).expect("admin POST must be allowed");

    // The downstream native auth middleware reads the identity from this
    // header, so it has to be the IdP email.
    assert_eq!(
        req.headers
            .get("user_id")
            .expect("user_id must be stamped")
            .to_str()
            .unwrap(),
        "user-1@example.com"
    );
    // Without this the form parsers downstream reject the body.
    assert_eq!(
        req.headers
            .get("content-type")
            .expect("content-type must be defaulted"),
        "application/x-www-form-urlencoded"
    );
}

#[test]
#[serial]
fn preserves_explicit_content_type_and_ignores_get() {
    pin_base_uri();
    let user = admin_of_acme();
    let mut post = Request::builder()
        .method(Method::POST)
        .uri(api("/acme/streams/default"))
        .header("content-type", "application/json")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    oidc::handlers::validate_user_info(&user, &mut post).unwrap();
    assert_eq!(
        post.headers.get("content-type").unwrap().to_str().unwrap(),
        "application/json",
        "an explicit content-type must not be overwritten"
    );

    let mut get = parts(Method::GET, &api("/acme/streams/default"));
    oidc::handlers::validate_user_info(&user, &mut get).unwrap();
    assert!(
        get.headers.get("content-type").is_none(),
        "GET requests must not gain a form content-type"
    );
}

#[test]
#[serial]
fn v2_api_paths_resolve_the_target_org() {
    pin_base_uri();
    let user = admin_of_acme();
    let mut req = parts(Method::GET, &api("/v2/acme/streams/default"));
    oidc::handlers::validate_user_info(&user, &mut req)
        .expect("v2 path must resolve to the same org and pass");
    assert_eq!(
        req.headers.get("user_id").unwrap().to_str().unwrap(),
        "user-1@example.com"
    );
}

#[test]
#[serial]
fn user_without_roles_for_target_org_may_still_read() {
    pin_base_uri();
    // The role check only applies when the IdP told us about this org; an
    // unknown role set must not become an implicit denial.
    let mut user = user_of_acme();
    user.org_roles.clear();
    assert!(
        oidc::handlers::validate_user_info(
            &user,
            &mut parts(Method::GET, &api("/acme/streams/default"))
        )
        .is_ok()
    );
}
