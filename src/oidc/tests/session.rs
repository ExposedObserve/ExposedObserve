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

//! Session storage behaviour: cookie attributes, key round-trips, and the
//! Redis connection settings that select and configure the store.
//!
//! Redis itself is never dialled here. The Redis tests cover configuration and
//! layer construction, which is where mistakes actually happen; a real
//! round-trip needs a live server and belongs in an integration job.

mod common;

use axum::{Router, routing::get};
use common::{build_config, build_redis_config};
use oidc::{models::AuthTokens, session};
use serial_test::serial;
use tower::ServiceExt;
use tower_sessions::Session;

fn sample_tokens() -> AuthTokens {
    AuthTokens {
        access_token: "access".to_string(),
        refresh_token: "refresh".to_string(),
        id_token: "id".to_string(),
        expires_in: None,
    }
}

/// Router exposing the two session operations the tests need.
fn session_probe() -> Router {
    Router::new()
        .route(
            "/write",
            get(|s: Session| async move {
                session::store_tokens(&s, &sample_tokens()).await.unwrap();
                (axum::http::StatusCode::OK, ())
            }),
        )
        .route(
            "/read",
            get(|s: Session| async move {
                let tokens = session::load_tokens(&s).await;
                let access = tokens.map(|t| t.access_token).unwrap_or_default();
                (axum::http::StatusCode::OK, access)
            }),
        )
}

#[tokio::test]
async fn tokens_survive_a_session_round_trip() {
    let cfg = build_config("https://example.com", "^(?<org>org:(?<role>\\w+))$");
    let app = session_probe().layer(session::memory_layer(&cfg));

    let write = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/write")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = write
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .expect("a session cookie must be set")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let read = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/read")
                .header(axum::http::header::COOKIE, cookie)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(read.into_body(), 64).await.unwrap();
    assert_eq!(
        body.as_ref(),
        b"access",
        "the token must survive the cookie round-trip"
    );
}

#[tokio::test]
async fn reset_oidc_drops_tokens_but_keeps_the_session() {
    let store = std::sync::Arc::new(tower_sessions::MemoryStore::default());
    let s = Session::new(None, store, None);

    session::store_tokens(&s, &sample_tokens()).await.unwrap();
    assert!(session::load_tokens(&s).await.is_some());

    session::reset_oidc(&s).await.unwrap();
    assert!(session::load_tokens(&s).await.is_none());
}

#[test]
fn memory_store_is_selected_without_a_redis_url() {
    let cfg = build_config("https://example.com", "^(?<org>org:(?<role>\\w+))$");
    assert!(!cfg.session_config.redis.is_enabled());
}

#[test]
fn redis_store_is_selected_by_url_alone() {
    let cfg = build_redis_config("redis://127.0.0.1:6379");
    assert!(cfg.session_config.redis.is_enabled());
    assert_eq!(cfg.session_config.redis.pool_size, 4);
    assert_eq!(cfg.session_config.redis.key_prefix, "o2-oidc:session:");
}

#[cfg(feature = "redis-session")]
#[tokio::test]
async fn redis_layer_rejects_an_empty_url() {
    let cfg = build_redis_config("");
    let err = session::redis_layer(&cfg)
        .await
        .expect_err("empty url must fail");
    assert!(err.to_string().contains("OIDC_REDIS_URL"), "got: {err}");
}

#[cfg(feature = "redis-session")]
#[tokio::test]
async fn redis_layer_reports_a_malformed_url() {
    let cfg = build_redis_config("not-a-redis-url");
    let err = session::redis_layer(&cfg)
        .await
        .expect_err("a url without a scheme must fail");
    assert!(err.to_string().contains("OIDC_REDIS_URL"), "got: {err}");
}

#[cfg(feature = "redis-session")]
#[tokio::test]
async fn redis_layer_accepts_credentials_tls_and_database() {
    use oidc::config::{OidcConfig, RedisConfig, SessionConfig};

    let cfg = OidcConfig {
        session_config: SessionConfig {
            redis: RedisConfig {
                url: "redis://redis.internal:6379".to_string(),
                username: Some("o2".to_string()),
                password: Some("s3cret".to_string()),
                database: Some(3),
                tls: true,
                tls_server_name: Some("lb.internal".to_string()),
                pool_size: 8,
                ..Default::default()
            },
            ..SessionConfig::default()
        },
        ..build_config("https://example.com", "^(?<org>org:(?<role>\\w+))$")
    };

    // No server is dialled: building the layer must succeed regardless, and the
    // pool reconnects on its own in the background.
    let layer = session::redis_layer(&cfg)
        .await
        .expect("a well-formed url must build a layer");
    drop(layer);
}

#[test]
#[serial]
fn redis_env_vars_are_parsed_into_the_config() {
    let keys = [
        "OIDC_REDIS_URL",
        "OIDC_REDIS_USERNAME",
        "OIDC_REDIS_PASSWORD",
        "OIDC_REDIS_DB",
        "OIDC_REDIS_POOL_SIZE",
        "OIDC_REDIS_CONNECT_TIMEOUT",
        "OIDC_REDIS_KEY_PREFIX",
    ];
    for (key, value) in [
        (keys[0], "rediss://redis.internal:6380"),
        (keys[1], "o2"),
        (keys[2], "s3cret"),
        (keys[3], "3"),
        (keys[4], "8"),
        (keys[5], "9"),
        (keys[6], "custom:"),
    ] {
        unsafe { std::env::set_var(key, value) };
    }

    let redis = oidc::config::load_config_from_env()
        .expect("config must parse")
        .session_config
        .redis;
    assert_eq!(redis.url, "rediss://redis.internal:6380");
    assert_eq!(redis.username.as_deref(), Some("o2"));
    assert_eq!(redis.password.as_deref(), Some("s3cret"));
    assert_eq!(redis.database, Some(3));
    assert_eq!(redis.pool_size, 8);
    assert_eq!(redis.connect_timeout.as_secs(), 9);
    assert_eq!(redis.key_prefix, "custom:");
    assert!(redis.tls, "a rediss:// url must imply tls");

    for key in keys {
        unsafe { std::env::remove_var(key) };
    }
}
