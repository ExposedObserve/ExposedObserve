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
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Axum 0.8 HTTP handlers for the OIDC login / callback / logout routes.
//!
//! These are intentionally tiny wrappers around `oidc::client` and
//! `oidc::session`. All openidconnect crate types are converted to axum
//! types at the boundary (Redirect, Json, StatusCode) so the rest of
//! the request stack only sees standard axum extractors.

use std::str::FromStr;

use axum::{
    Router,
    extract::{Query, Request},
    http::{
        HeaderMap,
        header::{CONTENT_TYPE, HeaderName, HeaderValue, SET_COOKIE},
    },
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::CookieJar;
use base64::Engine as _;
use http::{Method, request::Parts};
use serde::Deserialize;

use crate::{
    client, config::get_oidc_config, cookies, errors::AuthError, ext_users, models::UserInfo,
    session, store,
};

/// Where the front-end should land after a successful OIDC login. Read
/// from the OIDC config so the same value is shared between the bootstrap
/// path and any future SPA-routed callback URL.
fn post_login_redirect() -> String {
    // `OIDC_CALLBACK_URL` is the SPA-side landing path the browser
    // should hit after the IdP round-trip — distinct from
    // `OIDC_REDIRECT_URL` (the IdP-registered callback). Picking the
    // SPA URL directly keeps the URL fragment (`#userInfo=...`)
    // attached through the 302; hitting the root would 308 to `/web/`
    // and drop it.
    let cfg = get_oidc_config();
    if !cfg.callback_url.is_empty() {
        return cfg.callback_url.clone();
    }
    let url = cfg.redirect_url.as_str();
    if url.contains("/auth/sso/callback") {
        let cut = url.find("/auth/sso/callback").unwrap_or(url.len());
        url[..cut].to_string()
    } else {
        url.to_string()
    }
}

/// Query string on `/auth/sso/callback`.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

/// Inspect the request for a valid OIDC session. Returns:
/// - `Ok(Some(user_info))` — the OIDC session is valid; caller skips the native auth middleware and
///   stamps `user_id` itself.
/// - `Ok(None)` — no OIDC session is present; caller should fall through to the native auth
///   middleware.
/// - `Err(AuthError)` — an OIDC session is present but invalid (expired refresh, signature failure,
///   etc.). The HTTP status code is `err.status_code()`.
///
/// This is a pure probe: it never calls `next.run()` or produces a
/// response, so the HTTP auth middleware can compose the OIDC path
/// with the native one however it likes. Authorisation checks
/// (org membership, role vs. method) live in `validate_user_info`.
pub async fn check_oidc(parts: &mut Parts) -> Result<Option<UserInfo>, AuthError> {
    let Some(tokens) = store::OIDC_STORE.load_tokens(parts).await else {
        return Ok(None);
    };

    let (user_info, rotated) = client::verify_with_refresh(&tokens).await?;
    if user_info.email.trim().is_empty() {
        return Err(AuthError::Unauthorized(format!(
            "User {} email required",
            user_info.sub
        )));
    }
    if rotated.id_token != tokens.id_token
        && let Some(header) = store::OIDC_STORE.store_tokens(parts, &tokens).await?
        && !parts.headers.append(SET_COOKIE, header)
    {
        return Err(AuthError::Unauthorized("Auth update failed".into()));
    }
    match ext_users::sync_user_info(&user_info).await {
        Ok(()) => Ok(Some(user_info)),
        Err(err) => Err(err),
    }
}

/// Authorisation check for an already-authenticated OIDC user: org
/// membership and method-vs-role rules. Returns the HTTP status to
/// short-circuit with, or `None` when the user is allowed through.
pub fn validate_user_info(user_info: &UserInfo, parts: &mut Parts) -> Result<(), Response> {
    use config::meta::user::UserRole;

    let path = parts.uri.path();
    let method = parts.method.as_str();
    let cfg_upstream = config::get_config();
    let stripped = path
        .strip_prefix(format!("{}/api/", cfg_upstream.common.base_uri).as_str())
        .unwrap_or(path.strip_prefix("/").unwrap_or(path));
    let path_columns: Vec<&str> = stripped.split('/').collect();
    let is_v2_or_proxy = path_columns[0] == "proxy"
        || (path_columns[0] == "api" && path_columns.get(1) == Some(&"v2"));
    let target_org: Option<&str> = if path_columns.len() >= 3 && is_v2_or_proxy {
        let idx = if path_columns[0] == "api" && path_columns[1] == "v2" {
            2
        } else {
            1
        };
        path_columns.get(idx).copied()
    } else if path_columns.len() >= 3 && path_columns[0] == "api" {
        Some(path_columns[1])
    } else {
        None
    };
    // Если target_org — это Option<String>
    if let Some(org) = target_org
        && let Some(role_str) = user_info.org_roles.get(org)
    {
        if !user_info.orgs.contains(org) {
            let reason = format!("OIDC user {} denied access to org {}", user_info.email, org);
            return Err(AuthError::Forbidden(reason).into_response());
        }
        if !UserRole::is_valid_role(role_str) {
            let reason = format!(
                "OIDC user {} org {} role {} is not valid",
                user_info.email, org, role_str
            );
            return Err(AuthError::Forbidden(reason).into_response());
        }
        let user_role = UserRole::from_str(role_str).map_err(|_| {
            let reason = format!(
                "OIDC user {} org {} role {} is not valid",
                user_info.email, org, role_str
            );
            AuthError::Forbidden(reason).into_response()
        })?;

        let allow_post = path.contains("_search");
        if !method.eq("GET") && !(2_i16 >= user_role.into()) && !(method.eq("POST") && allow_post) {
            let reason = format!("OIDC user {} denied method {}", user_info.email, method);
            return Err(AuthError::Forbidden(reason).into_response());
        }
    }

    parts.headers.insert(
        HeaderName::from_static("user_id"),
        HeaderValue::from_str(&user_info.email).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    if parts.method.eq(&Method::POST) && !parts.headers.contains_key(CONTENT_TYPE) {
        parts.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
    }
    Ok(())
}

/// Mount the OIDC routes on `/auth/sso/*` with the cached
/// `tower-sessions` layer already applied. The caller is expected to
/// `.merge()` (or `nest`) the result into the parent router that already
/// nests `/auth`. The session layer must have been initialised via
/// `oidc::session::init_layer` (called from `oidc::init`).
pub fn sso_routes() -> Router {
    let layer = session::get_layer();
    apply_session_layer(
        Router::new()
            .route("/sso/login", get(login))
            .route("/sso/callback", get(callback))
            .route("/sso/logout", get(logout)),
        &layer,
    )
}

fn apply_session_layer(
    router: Router,
    layer: &std::sync::Arc<session::SessionManagerLayerForStore>,
) -> Router {
    use session::SessionManagerLayerForStore;
    // Each store variant produces a different concrete `Layer` type, so
    // we dispatch the layer manually. The feature-gated Redis branch only
    // exists when the `redis-session` feature is enabled.
    match &**layer {
        SessionManagerLayerForStore::Memory(typed) => router.layer(typed.clone()),
        #[cfg(feature = "redis-session")]
        SessionManagerLayerForStore::Redis(typed) => router.layer(typed.clone()),
    }
}

/// `GET /auth/sso/login` — generate a fresh PKCE challenge + state, stash
/// them in the session and 302 the browser to the IdP's authorize endpoint.
async fn login(_request: Request) -> Result<impl IntoResponse, AuthError> {
    let (auth_state, pkce_challenge) = client::create_authorization_state();
    let cookie = cookies::build_state_cookie(&auth_state)?;
    let url = client::build_authorization_url(&auth_state, &pkce_challenge).await?;
    Ok((
        [(SET_COOKIE, cookie.to_string())],
        Redirect::to(url.as_str()),
    ))
}

/// `GET /auth/sso/callback?code=...&state=...` — exchange the code, fetch
/// the user info, persist OIDC tokens, set the session flag and 302 the
/// browser to `post_login_redirect`.
async fn callback(
    Query(q): Query<CallbackQuery>,
    request: Request,
) -> Result<impl IntoResponse, AuthError> {
    let (parts, _) = request.into_parts();
    let jar = CookieJar::from_headers(&parts.headers);

    let stored = cookies::read_state_cookie(jar)
        .ok_or_else(|| AuthError::BadRequest("OIDC state cookie missing".into()))?;

    if stored.csrf_state != q.state {
        return Err(AuthError::BadRequest("OIDC state mismatch".into()));
    }

    let (user_info, tokens) = client::exchange_authorization_code(&q.code, &stored).await?;
    if tokens.id_token.is_empty() {
        return Err(AuthError::upstream("OIDC provider returned no id_token"));
    }

    ext_users::sync_user_info(&user_info).await?;

    let mut headers = HeaderMap::new();
    if let Some(auth_cookie) = store::OIDC_STORE.store_tokens(&parts, &tokens).await?
        && !headers.append(SET_COOKIE, auth_cookie)
    {
        log::warn!("Set Auth failed")
    };
    let clear_cookie = cookies::clear_state_cookie()?;
    if !headers.append(SET_COOKIE, clear_cookie) {
        log::warn!("Clear State failed")
    };

    let redirect = user_post_login_redirect(&user_info);

    Ok((headers, Redirect::to(&redirect)))
}

/// `GET /auth/sso/logout` — wipe OIDC artefacts from the session and
/// 302 the browser back to the SPA root. The `tower-sessions` layer
/// expires its own cookie as part of `session::reset_oidc`; we don't
/// need a separate `Set-Cookie` for an OIDC-specific token cookie.
async fn logout(request: Request) -> Result<impl IntoResponse, AuthError> {
    let (parts, _) = request.into_parts();
    store::OIDC_STORE.reset_oidc(&parts).await?;

    let mut headers = HeaderMap::new();
    if let Some(auth_cookie) = store::OIDC_STORE.reset_oidc(&parts).await?
        && !headers.append(SET_COOKIE, auth_cookie)
    {
        log::warn!("Clear AUTH failed")
    };
    let clear_cookie = cookies::clear_state_cookie()?;
    if !headers.append(SET_COOKIE, clear_cookie) {
        log::warn!("Clear State failed")
    };

    Ok((headers, Redirect::to("/web/")))
}

fn user_post_login_redirect(user: &UserInfo) -> String {
    // The SPA bootstrap (see `web/src/views/Login.vue`) reads its
    // initial user info from the URL fragment: `...#userInfo=<base64
    // of the UserInfo JSON>`. Appending the claims here lets the SPA
    // skip a `/api/.../userinfo` round-trip on first render and avoids
    // a redirect-loop on the login screen when only the auth_tokens
    // cookie is set.
    let base = post_login_redirect();
    let json = serde_json::to_string(user).unwrap_or_else(|_| "{}".to_string());
    let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(json);
    format!("{base}#userInfo={encoded}")
}
