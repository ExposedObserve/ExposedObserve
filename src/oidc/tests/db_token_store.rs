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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Tests for the database-backed session store.
//!
//! The meta store is the only session backend every node of a cluster can
//! resolve: the cookie carries a session id and the tokens live in the shared
//! `sessions` table. These tests pin that round-trip, because a break here
//! logs every clustered user out.

mod common;

use axum::http::{Request, request::Parts};
use oidc::{
    config::{OidcConfig, SessionConfig},
    models::AuthTokens,
    store::{DbTokenStore, TokenStore},
};
use serial_test::serial;

const ISSUER: &str = "https://example.com";
const SESSION_NAME: &str = "oidc_test_session";

fn tokens() -> AuthTokens {
    AuthTokens {
        access_token: "access-value".into(),
        refresh_token: "refresh-value".into(),
        id_token: "id-value".into(),
        expires_in: None,
    }
}

/// A config whose session name is set and whose cookie name is not, which is
/// what selects the database backend.
fn db_store_config() -> OidcConfig {
    OidcConfig {
        session_config: SessionConfig {
            session_name: SESSION_NAME.to_string(),
            ..SessionConfig::default()
        },
        ..common::build_config(ISSUER, "^(?<org>.*)$")
    }
}

fn request_with_cookie(header: &str) -> Parts {
    Request::builder()
        .uri("/")
        .header("cookie", header)
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

fn cookie_pair(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .expect("Set-Cookie must carry a pair")
        .to_string()
}

/// Prepare the session table and the shared caches the session lookups use.
async fn prepare_db() {
    let _ = infra::db::get_orm_client_rw().await;
    let _ = infra::db::create_table().await;
    let _ = infra::table::sessions::create_table().await;
}

#[tokio::test]
#[serial]
async fn tokens_survive_a_database_round_trip() {
    prepare_db().await;

    let cfg = db_store_config();
    oidc::config::set_config(cfg.clone());
    let store = DbTokenStore::new(std::sync::Arc::new(cfg));

    let parts = request_with_cookie("none=1");
    let header = store
        .store_tokens(&parts, &tokens())
        .await
        .expect("storing tokens must succeed")
        .expect("a cookie must be set");
    let set_cookie = header.to_str().expect("header must be text");

    let echoed = request_with_cookie(&cookie_pair(set_cookie));
    let loaded = store
        .load_tokens(&echoed)
        .await
        .expect("the session must be readable back");

    assert_eq!(loaded.id_token, "id-value");
    assert_eq!(loaded.access_token, "access-value");
    assert_eq!(loaded.refresh_token, "refresh-value");
}

#[tokio::test]
#[serial]
async fn the_cookie_carries_the_session_id_and_not_the_tokens() {
    prepare_db().await;

    let cfg = db_store_config();
    oidc::config::set_config(cfg.clone());
    let store = DbTokenStore::new(std::sync::Arc::new(cfg));

    let parts = request_with_cookie("none=1");
    let header = store
        .store_tokens(&parts, &tokens())
        .await
        .expect("storing tokens must succeed")
        .expect("a cookie must be set");
    let set_cookie = header.to_str().expect("header must be text");

    // The tokens must not travel in the cookie: that is the whole point of
    // keeping them server-side.
    assert!(
        !set_cookie.contains("id-value"),
        "the id_token must not be in the cookie: {set_cookie}"
    );
    assert!(
        set_cookie.contains(SESSION_NAME),
        "the cookie must be named after the session: {set_cookie}"
    );
}

#[tokio::test]
#[serial]
async fn the_session_is_readable_from_another_store_instance() {
    // Two nodes of a cluster are two store instances over the same table.
    prepare_db().await;

    let cfg = std::sync::Arc::new(db_store_config());
    oidc::config::set_config((*cfg).clone());
    let writer = DbTokenStore::new(cfg.clone());
    let reader = DbTokenStore::new(cfg);

    let parts = request_with_cookie("none=1");
    let header = writer
        .store_tokens(&parts, &tokens())
        .await
        .expect("storing tokens must succeed")
        .expect("a cookie must be set");
    let echoed = request_with_cookie(&cookie_pair(header.to_str().unwrap()));

    assert!(
        reader.load_tokens(&echoed).await.is_some(),
        "a peer node must resolve the session from the shared store"
    );
}

#[tokio::test]
#[serial]
async fn an_unknown_session_resolves_to_nothing() {
    prepare_db().await;

    let cfg = db_store_config();
    oidc::config::set_config(cfg.clone());
    let store = DbTokenStore::new(std::sync::Arc::new(cfg));

    let parts = request_with_cookie(&format!("{SESSION_NAME}=does-not-exist"));
    assert!(
        store.load_tokens(&parts).await.is_none(),
        "an unknown session must read as absent, not as an error"
    );
}

#[tokio::test]
#[serial]
async fn logging_out_removes_the_session() {
    prepare_db().await;

    let cfg = std::sync::Arc::new(db_store_config());
    oidc::config::set_config((*cfg).clone());
    let store = DbTokenStore::new(cfg.clone());

    let parts = request_with_cookie("none=1");
    let header = store
        .store_tokens(&parts, &tokens())
        .await
        .expect("storing tokens must succeed")
        .expect("a cookie must be set");
    let echoed = request_with_cookie(&cookie_pair(header.to_str().unwrap()));
    assert!(store.load_tokens(&echoed).await.is_some());

    store
        .reset_oidc(&echoed)
        .await
        .expect("resetting must succeed");

    assert!(
        store.load_tokens(&echoed).await.is_none(),
        "a logged-out session must not resolve"
    );
}

#[tokio::test]
#[serial]
async fn a_refresh_updates_the_session_in_place() {
    // The browser's cookie still points at the original row, so a refresh has
    // to update that row rather than mint a new session id — otherwise the
    // old row is orphaned and the rotated refresh token is lost.
    prepare_db().await;

    let cfg = db_store_config();
    oidc::config::set_config(cfg.clone());
    let store = DbTokenStore::new(std::sync::Arc::new(cfg));

    let parts = request_with_cookie("none=1");
    let header = store
        .store_tokens(&parts, &tokens())
        .await
        .expect("storing tokens must succeed")
        .expect("a cookie must be set");
    let original = cookie_pair(header.to_str().unwrap());

    let refreshed = AuthTokens {
        access_token: "new-access".into(),
        refresh_token: "new-refresh".into(),
        id_token: "new-id".into(),
        expires_in: None,
    };
    let echoed = request_with_cookie(&original);
    let header = store
        .store_tokens(&echoed, &refreshed)
        .await
        .expect("storing the refreshed tokens must succeed")
        .expect("a cookie must be set");

    assert_eq!(
        cookie_pair(header.to_str().unwrap()),
        original,
        "the refresh must keep the session id the browser already holds"
    );

    let loaded = store
        .load_tokens(&request_with_cookie(&original))
        .await
        .expect("the session must still be readable");
    assert_eq!(loaded.id_token, "new-id");
    assert_eq!(loaded.refresh_token, "new-refresh");
}

#[tokio::test]
#[serial]
async fn the_sso_routes_build_without_a_tower_sessions_layer() {
    // The database store needs no `tower-sessions` layer, so the layer is
    // never built. The routes must still build: asking for the unbuilt layer
    // used to panic at start-up, which took the whole node down.
    let cfg = db_store_config();
    oidc::config::set_config(cfg);

    let _routes = oidc::handlers::sso_routes();
}

#[tokio::test]
#[serial]
async fn the_database_store_needs_no_tower_sessions_layer() {
    let cfg = std::sync::Arc::new(db_store_config());
    let store = DbTokenStore::new(cfg);

    assert!(
        !store.need_session(),
        "the database store must not require the tower-sessions layer"
    );
    assert!(
        !store.is_process_local(),
        "the database store is shared, so it is not process-local"
    );
    assert_eq!(store.kind(), "db");
}
