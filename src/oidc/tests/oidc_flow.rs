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

//! OIDC client tests against an in-process mock provider.
//!
//! These replace the former `e2e_mock_oauth2.rs`, which shelled out to
//! `docker run ghcr.io/navikt/mock-oauth2-server`. Everything under test
//! here — discovery, JWKS fetch, authorization-URL construction — is plain
//! HTTP, so a `wiremock` server covers it without a container, a fixed port,
//! or the readiness poll the old suite paid on every run.
//!
//! Scope: no token exchange. Minting a signed `id_token` needs an RSA key and
//! a JWT encoder, which buys coverage of the `openidconnect` crate rather
//! than of this crate; claims mapping is covered by unit tests in `models`.

mod common;

use common::{
    CLIENT_ID, REDIRECT_URL,
    discovery::{document, empty_jwks},
    install_config,
};
use oidc::client::{
    build_authorization_url, create_authorization_state, create_oidc_client,
    reset_metadata_cache_for_tests,
};
use serial_test::serial;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// Org/role pattern the suite installs: `groups` entries look like `org:admin`.
const ORG_PATTERN: &str = "^(?<org>org:(?<role>\\w+))$";

/// Mock provider serving discovery + JWKS, installed as the global config.
async fn provider() -> MockServer {
    let server = MockServer::start().await;
    let issuer = server.uri();
    server
        .register(
            Mock::given(method("GET"))
                .and(path("/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(document(&issuer)))
                .expect(1),
        )
        .await;
    server
        .register(
            Mock::given(method("GET"))
                .and(path("/jwks"))
                .respond_with(ResponseTemplate::new(200).set_body_json(empty_jwks()))
                .expect(1),
        )
        .await;
    install_config(&issuer, ORG_PATTERN);
    reset_metadata_cache_for_tests().await;
    server
}

#[tokio::test]
#[serial]
async fn discovery_resolves_provider_metadata() {
    let server = provider().await;

    let client = create_oidc_client()
        .await
        .expect("discovery against a live mock must succeed");

    // The verifier is what discovery feeds; building it proves the JWKS
    // fetch completed rather than short-circuiting on an empty key set.
    let _verifier = client.id_token_verifier();
    server.verify().await;
}

#[tokio::test]
#[serial]
async fn authorization_url_carries_pkce_state_and_nonce() {
    // Held for the whole test: dropping the server tears it down, and
    // discovery against a dead endpoint would fail for the wrong reason.
    let _provider = provider().await;

    let (state, challenge) = create_authorization_state();
    let url = build_authorization_url(&state, &challenge)
        .await
        .expect("authorization URL build must succeed");

    let params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let get = |k: &str| -> Option<String> {
        params
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };

    assert_eq!(get("response_type").as_deref(), Some("code"));
    assert_eq!(get("client_id").as_deref(), Some(CLIENT_ID));
    assert_eq!(get("redirect_uri").as_deref(), Some(REDIRECT_URL));
    // `openidconnect` prepends the `openid` scope itself and `client.rs`
    // adds it again, so the parameter carries it twice today.
    let scope_param = get("scope").expect("scope must be present");
    let scopes: Vec<&str> = scope_param.split_whitespace().collect();
    assert_eq!(scopes, ["openid", "openid"]);
    // PKCE must use S256 and echo the caller-supplied challenge, otherwise
    // the callback cannot verify either half of the flow.
    assert_eq!(get("code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(
        get("code_challenge").as_deref(),
        Some(challenge.as_str()),
        "challenge must come from the caller-supplied PKCE pair"
    );
    assert_eq!(get("state").as_deref(), Some(state.csrf_state.as_str()));
    assert_eq!(get("nonce").as_deref(), Some(state.nonce.as_str()));
}

#[tokio::test]
#[serial]
async fn authorization_state_is_unique_per_call() {
    let (first, _) = create_authorization_state();
    let (second, _) = create_authorization_state();

    // Reusing a CSRF token or nonce across logins would let a stale callback
    // be replayed, so freshness is a security property, not a detail.
    assert_ne!(first.csrf_state, second.csrf_state);
    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.pkce_verifier, second.pkce_verifier);
}

#[tokio::test]
#[serial]
async fn metadata_is_cached_after_first_discovery() {
    let server = provider().await;
    // The mock expects exactly one discovery hit, so a second build that
    // re-fetched would fail `server.verify()`.
    create_oidc_client()
        .await
        .expect("first discovery must succeed");
    create_oidc_client()
        .await
        .expect("second discovery must be served from cache");

    server.verify().await;
}

#[tokio::test]
#[serial]
async fn discovery_failure_is_reported_as_internal_error() {
    // Nothing is listening on this port; discovery must fail rather than
    // silently fall back to the default issuer.
    install_config("http://127.0.0.1:1/unreachable", ORG_PATTERN);
    reset_metadata_cache_for_tests().await;

    let err = create_oidc_client()
        .await
        .expect_err("discovery against a dead endpoint must fail");

    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
#[serial]
async fn discovery_rejects_mismatched_issuer() {
    let server = MockServer::start().await;
    // Document advertises a different issuer than the one discovery ran
    // against — `openidconnect` must refuse it.
    server
        .register(
            Mock::given(method("GET"))
                .and(path("/.well-known/openid-configuration"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(document("http://127.0.0.1:9/some-other-issuer")),
                )
                .expect(1),
        )
        .await;
    install_config(&server.uri(), ORG_PATTERN);
    reset_metadata_cache_for_tests().await;

    let err = create_oidc_client()
        .await
        .expect_err("a discovery document with a foreign issuer must be rejected");

    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
#[serial]
async fn discovery_requires_json_content_type() {
    let server = MockServer::start().await;
    server
        .register(
            Mock::given(method("GET"))
                .and(path("/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_string("issuer=nope"))
                .expect(1),
        )
        .await;
    install_config(&server.uri(), ORG_PATTERN);
    reset_metadata_cache_for_tests().await;

    create_oidc_client()
        .await
        .expect_err("a non-JSON discovery document must be rejected");
}
// MARKERS_NEXT
