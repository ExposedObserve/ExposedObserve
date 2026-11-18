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

//! Authorisation tests for `handlers::validate_user_info`.
//!
//! The paths used here are the ones the middleware really sees: axum strips
//! the `/api` nest prefix (and the configured base URI) before the auth
//! middleware runs, so a request to `/api/acme/streams` arrives as
//! `/acme/streams`.

use std::collections::{HashMap, HashSet};

use axum::http::{Method, Request, StatusCode, request::Parts};
use oidc::models::UserInfo;

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
fn admin_may_write_to_its_own_org() {
    let user = admin_of_acme();
    assert!(
        oidc::handlers::validate_user_info(
            &user,
            &mut parts(Method::POST, "/acme/streams/default")
        )
        .is_ok(),
        "admin outranks the editor threshold and must be allowed to write"
    );
}

#[test]
fn plain_user_may_read_but_not_write() {
    let user = user_of_acme();
    assert!(
        oidc::handlers::validate_user_info(&user, &mut parts(Method::GET, "/acme/streams/default"))
            .is_ok()
    );
    let denied = oidc::handlers::validate_user_info(
        &user,
        &mut parts(Method::POST, "/acme/streams/default"),
    )
    .expect_err("a `user` role must not be allowed to write");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[test]
fn plain_user_may_post_to_search_endpoints() {
    // The `_search` carve-out exists because search bodies are POSTs but
    // semantically reads.
    let user = user_of_acme();
    assert!(
        oidc::handlers::validate_user_info(
            &user,
            &mut parts(Method::POST, "/acme/streams/default/_search")
        )
        .is_ok()
    );
}

#[test]
fn two_segment_paths_resolve_the_org() {
    let user = user_of_acme();
    let denied =
        oidc::handlers::validate_user_info(&user, &mut parts(Method::POST, "/acme/streams"))
            .expect_err("a two-segment path must still resolve the org and gate the role");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[test]
fn two_segment_paths_allow_reads_for_a_member() {
    let user = user_of_acme();
    assert!(
        oidc::handlers::validate_user_info(&user, &mut parts(Method::GET, "/acme/streams")).is_ok(),
        "a member with a valid role must still be allowed to read"
    );
}

#[test]
fn three_segment_paths_resolve_the_org() {
    let user = user_of_acme();
    let denied = oidc::handlers::validate_user_info(
        &user,
        &mut parts(Method::POST, "/acme/streams/default"),
    )
    .expect_err("a three-segment path must resolve the org and gate the role");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[test]
fn org_scoped_config_path_resolves_the_org() {
    let user = user_of_acme();
    let denied =
        oidc::handlers::validate_user_info(&user, &mut parts(Method::POST, "/acme/config"))
            .expect_err("the org must be resolved from a two-segment config path");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[test]
fn v2_paths_resolve_the_target_org() {
    let user = user_of_acme();
    let denied =
        oidc::handlers::validate_user_info(&user, &mut parts(Method::POST, "/v2/acme/alerts"))
            .expect_err("the v2 path must resolve to the same org and gate the role");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[test]
fn the_proxy_path_is_not_gated_by_this_middleware() {
    // `/proxy` carries `proxy_auth_middleware`, which resolves the org and the
    // role on its own, so the OIDC gate never sees this path. Resolving an org
    // from it here would gate a request nobody routes through this code.
    let user = user_of_acme();
    assert!(
        oidc::handlers::validate_user_info(
            &user,
            &mut parts(Method::POST, "/proxy/acme/some/target")
        )
        .is_ok(),
        "the proxy path must not be gated twice"
    );
}

#[test]
fn admin_may_write_through_the_v2_api() {
    let user = admin_of_acme();
    assert!(
        oidc::handlers::validate_user_info(&user, &mut parts(Method::POST, "/v2/acme/alerts"))
            .is_ok(),
        "the admin role must be honoured on the v2 routes as well"
    );
}

#[test]
fn unknown_org_is_allowed_through() {
    // A path that names no org (or an org the IdP never mentioned) must fall
    // through to the native auth middleware rather than 403 here.
    let user = admin_of_acme();
    assert!(
        oidc::handlers::validate_user_info(
            &user,
            &mut parts(Method::GET, "/other-org/streams/default")
        )
        .is_ok()
    );
    assert!(oidc::handlers::validate_user_info(&user, &mut parts(Method::GET, "/healthz")).is_ok());
}

#[test]
fn role_for_org_the_user_does_not_belong_to_is_forbidden() {
    let mut user = admin_of_acme();
    user.org_roles
        .insert("other-org".to_string(), "admin".to_string());
    let denied = oidc::handlers::validate_user_info(
        &user,
        &mut parts(Method::GET, "/other-org/streams/default"),
    )
    .expect_err("holding a role for an org you are not a member of must be rejected");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[test]
fn invalid_role_string_is_forbidden() {
    let mut user = admin_of_acme();
    user.org_roles
        .insert("acme".to_string(), "wizard".to_string());
    let denied =
        oidc::handlers::validate_user_info(&user, &mut parts(Method::GET, "/acme/streams/default"))
            .expect_err("an unparsable role must not be treated as a pass");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[test]
fn the_role_gate_runs_on_a_real_path() {
    let mut user = user_of_acme();
    user.org_roles
        .insert("acme".to_string(), "wizard".to_string());
    let denied =
        oidc::handlers::validate_user_info(&user, &mut parts(Method::GET, "/acme/streams/default"))
            .expect_err("the role gate must reject an invalid role on a real request path");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[test]
fn stamps_user_id_header_and_default_content_type() {
    let user = admin_of_acme();
    let mut req = parts(Method::POST, "/acme/streams/default");
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
fn preserves_explicit_content_type_and_ignores_get() {
    let user = admin_of_acme();
    let mut post = Request::builder()
        .method(Method::POST)
        .uri("/acme/streams/default")
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

    let mut get = parts(Method::GET, "/acme/streams/default");
    oidc::handlers::validate_user_info(&user, &mut get).unwrap();
    assert!(
        get.headers.get("content-type").is_none(),
        "GET requests must not gain a form content-type"
    );
}

#[test]
fn user_without_roles_for_target_org_may_still_read() {
    // The role check only applies when the IdP told us about this org; an
    // unknown role set must not become an implicit denial.
    let mut user = user_of_acme();
    user.org_roles.clear();
    assert!(
        oidc::handlers::validate_user_info(&user, &mut parts(Method::GET, "/acme/streams/default"))
            .is_ok()
    );
}
