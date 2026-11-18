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
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use axum::{extract::Request, middleware::Next, response::Response};

/// SSO-aware auth wrapper. Runs the OIDC auth probe and the
/// `validate_user_info` authorisation check, then delegates to the
/// upstream `auth_middleware`. The probes only log their outcome for
/// now; the actual OIDC fast path will replace the `auth_middleware`
/// fallback once the rest of the wiring is in place.
#[cfg(feature = "sso")]
pub async fn sso_auth_middleware(request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();
    let auth_result = oidc::handlers::check_oidc(&mut parts).await;
    match auth_result {
        Ok(Some(user_info)) => match oidc::handlers::validate_user_info(&user_info, &mut parts) {
            Ok(()) => next.run(Request::from_parts(parts, body)).await,
            Err(resp) => resp,
        },
        Ok(None) => super::super::auth_middleware(Request::from_parts(parts, body), next).await,
        Err(e) => {
            log::warn!("OIDC auth failed: {}", e.public_message());
            drop(e);
            super::super::auth_middleware(Request::from_parts(parts, body), next).await
        }
    }
}

/// Resolves to `sso_auth_middleware` when the `sso` feature is enabled,
/// and to the upstream `auth_middleware` otherwise. Route layers use this
/// so a single `middleware::from_fn(active_auth_middleware)` covers both
/// builds without scattering `#[cfg(feature = "sso")]` over every call site.
pub async fn active_auth_middleware(request: Request, next: Next) -> Response {
    #[cfg(feature = "sso")]
    return sso_auth_middleware(request, next).await;
    #[cfg(not(feature = "sso"))]
    return super::super::auth_middleware(request, next).await;
}
