// Copyright (C) 2025 Mike Sauh
//
// This file is part of ExposedObserve, a modified fork of OpenObserve.
//
// OpenObserve is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// Original project: https://github.com/openobserve/openobserve
//
// This file is NOT part of the original OpenObserve codebase.
// It was created independently to add OIDC authentication and claim-based authorization.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

/// External validator module for authentication.
///
/// This module handles authentication and authorization for external users
/// using OpenID Connect (OIDC). It provides validation logic that checks
/// user access to organization-specific endpoints, routes requests based
/// on user type (internal vs external), and handles authentication failures
/// with appropriate error responses including redirects for short URLs.
/// 
use actix_http::{Payload, header};
use actix_web::{Error, FromRequest, dev::ServiceRequest, error::{ErrorForbidden, ErrorUnauthorized}, http::Method};
use log::{error, info};
use oidc::models::UserInfo;
use once_cell::sync::OnceCell;
use regex::Regex;

use crate::{
    common::utils::{auth::AuthExtractor, redirect_response::RedirectResponseBuilder},
    handler::http::auth::validator::oo_validator,
    service::ext_users::check_user_in_org,
};

static ORG_ID_REGEX: OnceCell<Regex> = OnceCell::new();
static ORG_ID_TAG: &str = "org_id";
static SERVICE_TAG: &str = "service";

const ORG_ID_REGEX_PATTERN: &str = r"^\/api(\/v2){0,1}\/(?<org_id>\w+)\/(?<service>\w+)(\/)?";

/// Main entry point for external user authentication validation.
///
/// This function determines the appropriate validator based on user type:
/// - For internal users, delegates to `oo_validator`
/// - For external users, delegates to `oidc_validator`
///
/// Handles authentication failures with appropriate responses, including
/// redirects for short URL paths.
pub async fn root_validator(
    req: ServiceRequest,
    auth_result: Result<UserInfo, Error>,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    info!("Check access to: {}", &req.path().to_string());

    // short_url logic from oo_validator
    let is_short_url = {
        let path = extract_relative_path(req.request().path(), "/api/");
        let path_parts: Vec<&str> = path.split('/').collect();
        is_short_url_path(&path_parts)
    };

    let user_info = match auth_result {
        Err(e) => {
            error!("Validation failed\n{}", e);
            return unauthorized_response(req, is_short_url);
        }
        Ok(info) => info,
    };

    // Call oo_validator
    if user_info.is_internal {
        let _p = &mut Payload::from(bytes::Bytes::new());
        let auth = AuthExtractor::from_request(&req.request(), _p).await;
        return oo_validator(req, auth).await;
    }
    return oidc_validator(req, &user_info).await;
}

/// Validates requests for external OIDC users.
///
/// Checks if the request method is allowed: GET for all users, or any method for admin users.
/// Extracts the organization ID from the path and verifies if the user has access
/// to that organization. If access is granted, adds the user email to the request headers.
///
/// Returns the modified request on success, or an error response on failure.
pub async fn oidc_validator(
    req: ServiceRequest,
    user_info: &UserInfo,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let (org_id, _) = extract_path_params(req.path());

    // Check if user has admin role - allows all HTTP methods
    let is_admin = user_info.org_roles.values().any(|role| role == "admin");

    if req.request().method() != Method::GET && !is_admin {
        return forbidden_response(req);
    }

    let is_granted = match org_id {
        Some(id) => check_user_in_org(&user_info.email, &id).await.is_some(),
        None => true,
    };

    if is_granted {
        match header::HeaderValue::from_str(&user_info.email) {
            Ok(header_value) => {
                let mut req = req;
                req.headers_mut().insert(
                    header::HeaderName::from_static("user_id"),
                    header_value,
                );
                Ok(req)
            }
            Err(_) => {
                // If email contains invalid characters for HTTP header, return internal error
                Err((actix_web::error::ErrorInternalServerError("Invalid user email format"), req))
            }
        }
    } else {
        forbidden_response(req)
    }
}

fn unauthorized_response(
    req: ServiceRequest,
    is_short_url: bool,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let e = ErrorUnauthorized("Unauthorized Access");
    if is_short_url {
        Err(handle_auth_failure_for_redirect(req, &e))
    } else {
        Err((e, req))
    }
}

fn forbidden_response(
    req: ServiceRequest,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let e = ErrorForbidden("Forbidden Access");
    Err((e, req))
}

fn extract_path_params(path: &str) -> (Option<String>, Option<String>) {
    let re = ORG_ID_REGEX.get_or_init(|| {
        Regex::new(ORG_ID_REGEX_PATTERN).expect("Invalid regex")
    });
    let captures = match re.captures(path) {
        Some(c) => c,
        None => return (None, None),
    };
    (
        captures.name(ORG_ID_TAG).map(|m| m.as_str().to_owned()),
        captures.name(SERVICE_TAG).map(|m| m.as_str().to_owned()),
    )
}

// Copy from validators.rs
/// Helper function to extract the relative path after the base URI and path prefix
fn extract_relative_path(full_path: &str, path_prefix: &str) -> String {
    let base_uri = config::get_config().common.base_uri.clone();
    let full_prefix = format!("{base_uri}{path_prefix}");
    full_path
        .strip_prefix(&full_prefix)
        .unwrap_or(full_path)
        .to_string()
}

// Copy from validators.rs
/// Helper function to check if the path corresponds to a short URL
fn is_short_url_path(path_columns: &[&str]) -> bool {
    path_columns
        .get(1)
        .is_some_and(|&segment| segment.to_lowercase() == "short")
}

// Copy from validators.rs
/// Handles authentication failure by logging the error and returning a redirect response.
///
/// This function is responsible for logging the authentication failure and returning a redirect
/// response. It takes in the request and the error message, and returns a tuple containing the
/// redirect response and the service request.
fn handle_auth_failure_for_redirect(req: ServiceRequest, error: &Error) -> (Error, ServiceRequest) {
    let full_url = extract_full_url(&req);
    let redirect_http = RedirectResponseBuilder::default()
        .with_query_param("short_url", &full_url)
        .build();
    log::warn!(
        "Authentication failed for path: {}, err: {}, {}",
        req.path(),
        error,
        &redirect_http,
    );
    (redirect_http.into(), req)
}

// Copy from validators.rs
/// Extracts the full URL from the request.
fn extract_full_url(req: &ServiceRequest) -> String {
    let connection_info = req.connection_info();
    let scheme = connection_info.scheme();
    let host = connection_info.host();
    let path = req
        .request()
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("");

    format!("{scheme}://{host}{path}")
}
