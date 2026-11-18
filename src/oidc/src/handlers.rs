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
    // The refreshed tokens have to be the ones stored: the provider rotates the
    // refresh token, so keeping the old set would leave the session with a
    // token the provider has already invalidated.
    if rotated.id_token != tokens.id_token
        && let Some(header) = store::OIDC_STORE.store_tokens(parts, &rotated).await?
    {
        parts.headers.append(SET_COOKIE, header);
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
    let target_org = resolve_target_org(path);
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

/// The organisation a request targets, as seen by the auth middleware.
///
/// Axum strips the nest prefixes before the middleware runs, so the path
/// never carries `/api` or the configured base URI: it starts at the org
/// segment. The v2 routes insert one extra segment in front.
///
/// `/proxy` is not handled here: it carries `proxy_auth_middleware`, which
/// resolves the org and the role on its own, and the OIDC gate never runs
/// there.
fn resolve_target_org(path: &str) -> Option<&str> {
    let segments: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    match segments.first().copied()? {
        "v2" => segments.get(1).copied(),
        _ => segments.first().copied(),
    }
}

/// Mount the OIDC routes on `/auth/sso/*`. The caller is expected to
/// `.merge()` (or `nest`) the result into the parent router that already
/// nests `/auth`.
///
/// The `tower-sessions` layer is applied only for the stores that use it: the
/// shared meta store keeps the session in the database and needs no layer.
pub fn sso_routes() -> Router {
    let router = Router::new()
        .route("/sso/login", get(login))
        .route("/sso/callback", get(callback))
        .route("/sso/logout", get(logout));

    match crate::config::SessionStoreKind::from_config(
        &crate::config::get_oidc_config().session_config,
    ) {
        Some(kind) if kind.uses_tower_sessions() => {
            let layer = session::get_layer();
            apply_session_layer(router, &layer)
        }
        _ => router,
    }
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
    let cookie = cookies::build_state_cookie(&auth_state).await?;
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
        .await
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
    if let Some(auth_cookie) = store::OIDC_STORE.store_tokens(&parts, &tokens).await? {
        headers.append(SET_COOKIE, auth_cookie);
    }
    let clear_cookie = cookies::clear_state_cookie()?;
    headers.append(SET_COOKIE, clear_cookie);

    let redirect = user_post_login_redirect(&user_info);

    Ok((headers, Redirect::to(&redirect)))
}

/// Drop the OIDC session of a request and return the cookie that clears it.
///
/// The native logout endpoint calls this so that an OIDC session ends with the
/// native one: without it the session row survives in the meta store and the
/// next request is still authenticated as the OIDC user.
pub async fn clear_session(headers: &HeaderMap) -> Option<HeaderValue> {
    let request = axum::http::Request::builder().body(()).ok()?;
    let (mut parts, _) = request.into_parts();
    parts.headers = headers.clone();
    log::info!(
        "clear_session: cookie header present = {}, len = {}",
        headers.contains_key(axum::http::header::COOKIE),
        headers
            .get(axum::http::header::COOKIE)
            .map(|v| v.len())
            .unwrap_or(0)
    );
    match store::OIDC_STORE.reset_oidc(&parts).await {
        Ok(header) => header,
        Err(err) => {
            log::error!(
                "Failed to clear the OIDC session: {}",
                err.internal_log_message()
            );
            None
        }
    }
}

/// `GET /auth/sso/logout` — wipe OIDC artefacts from the session and
/// 302 the browser back to the SPA root. The `tower-sessions` layer
/// expires its own cookie as part of `session::reset_oidc`; we don't
/// need a separate `Set-Cookie` for an OIDC-specific token cookie.
async fn logout(request: Request) -> Result<impl IntoResponse, AuthError> {
    let (parts, _) = request.into_parts();
    // The id token has to be read before the session is wiped: it is the
    // `id_token_hint` the provider needs to end its own session.
    let id_token = store::OIDC_STORE
        .load_tokens(&parts)
        .await
        .map(|t| t.id_token);

    let mut headers = HeaderMap::new();
    if let Some(auth_cookie) = store::OIDC_STORE.reset_oidc(&parts).await? {
        headers.append(SET_COOKIE, auth_cookie);
    }
    let clear_cookie = cookies::clear_state_cookie()?;
    headers.append(SET_COOKIE, clear_cookie);

    let redirect = match id_token {
        Some(id_token) => rp_logout_url(&id_token).await,
        None => post_logout_redirect(),
    };

    Ok((headers, Redirect::to(&redirect)))
}

/// The provider's RP-initiated logout URL, with the id token hint and the
/// post-logout redirect appended. Falls back to the SPA landing page when the
/// provider advertises no logout endpoint.
async fn rp_logout_url(id_token: &str) -> String {
    // Ending the session at the provider can sign the operator out of the
    // other applications of the realm too, so it stays opt-in.
    if !get_oidc_config().rp_logout_enabled {
        return post_logout_redirect();
    }
    let Some(endpoint) = client::end_session_endpoint().await else {
        return post_logout_redirect();
    };
    let mut url = match url::Url::parse(&endpoint) {
        Ok(url) => url,
        Err(err) => {
            log::warn!("OIDC logout endpoint is not a valid URL: {err}");
            return post_logout_redirect();
        }
    };
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("id_token_hint", id_token);
        query.append_pair("post_logout_redirect_uri", &post_logout_redirect());
    }
    url.to_string()
}

/// Where the provider sends the browser back after the logout.
///
/// The callback URL is the wrong target here: it demands a state cookie that
/// the logout round trip never carries, so the browser would land on a 400.
fn post_logout_redirect() -> String {
    get_oidc_config().post_logout_redirect_uri()
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
