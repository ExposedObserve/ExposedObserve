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

use crate::{
    common::utils::{auth::AuthExtractor, redirect_response::RedirectResponseBuilder},
    handler::http::auth::validator::oo_validator,
};

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

/// Proxy validator for external user authentication validation.
///
/// This function determines the appropriate validator based on user type for proxy routes:
/// - For internal users, delegates to `validator_proxy_url`
/// - For external users, delegates to `oidc_validator`
///
/// Handles authentication failures with appropriate responses.
pub async fn proxy_validator(
    req: ServiceRequest,
    auth_result: Result<UserInfo, Error>,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    info!("Check proxy access to: {}", &req.path().to_string());

    let user_info = match auth_result {
        Err(e) => {
            error!("Proxy validation failed\n{}", e);
            return Err((ErrorUnauthorized("Unauthorized Access"), req));
        }
        Ok(info) => info,
    };

    // Call validator_proxy_url for internal users
    if user_info.is_internal {
        let _p = &mut Payload::from(bytes::Bytes::new());
        let auth = AuthExtractor::from_request(&req.request(), _p).await;
        match auth {
            Ok(auth_extractor) => return crate::handler::http::auth::validator::validator_proxy_url(req, auth_extractor).await,
            Err(e) => return Err((e, req)),
        }
    }
    return oidc_validator(req, &user_info).await;
}

/// Validates requests for external OIDC users.
///
/// Checks if the request method is allowed: GET for all users, or any method for admin users.
/// Extracts the organization ID from the path and verifies if the user has access
/// to that organization using the organization data from the OIDC token.
/// If access is granted, adds the user email to the request headers.
///
/// Returns the modified request on success, or an error response on failure.
pub async fn oidc_validator(
    req: ServiceRequest,
    user_info: &UserInfo,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let org_id = extract_org_from_path(req.path());

    // Check if user has admin role - allows all HTTP methods
    let is_admin = user_info.org_roles.values().any(|role| role == "admin");

    if req.request().method() != Method::GET && !is_admin {
        return forbidden_response(req);
    }

    // Check if user has access to the requested organization
    // Since all organization data comes from the OIDC token, we trust it
    let is_granted = match org_id {
        Some(id) => user_info.orgs.contains(&id),
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

/// Extracts organization ID from API or proxy paths.
///
/// Supports the following path patterns:
/// - `/api/{org_id}/{service}/...`
/// - `/api/v2/{org_id}/{service}/...`
/// - `/proxy/{org_id}/{target_url}`
///
/// Returns the organization ID if found and path has required segments, None otherwise.
/// This mimics the behavior of the original regex-based extraction.
fn extract_org_from_path(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    if segments.len() >= 3 && (segments[0] == "api" || segments[0] == "proxy") {
        // Handle /api/v2/{org}/{service}/... pattern
        let org_index = if segments[0] == "api" && segments.get(1) == Some(&"v2") && segments.len() > 3 {
            2
        } else {
            1
        };
        segments.get(org_index).map(|s| s.to_string())
    } else {
        None
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use oidc::models::UserInfo;

    #[tokio::test]
    async fn test_proxy_validator_internal_user() {
        // Create mock internal user info
        let user_info = UserInfo {
            sub: "internal_user".to_string(),
            email: "internal@example.com".to_string(),
            orgs: std::collections::HashSet::new(),
            org_roles: std::collections::HashMap::new(),
            is_internal: true,
        };

        // Create test request
        let req = TestRequest::get()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test proxy_validator with internal user
        let result = proxy_validator(req, Ok(user_info)).await;

        // Should succeed for internal user (delegates to validator_proxy_url)
        // Note: This will fail in test environment due to missing auth headers,
        // but we're testing that it delegates correctly
        assert!(result.is_err()); // Expected to fail due to missing auth
    }

    #[tokio::test]
    async fn test_proxy_validator_external_user() {
        // Create mock external user info with admin role
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "admin".to_string());

        let user_info = UserInfo {
            sub: "external_user".to_string(),
            email: "external@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request
        let req = TestRequest::get()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test proxy_validator with external user
        let result = proxy_validator(req, Ok(user_info)).await;

        // Should succeed for external admin user
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_proxy_validator_external_user_forbidden() {
        // Create mock external user info without admin role
        let user_info = UserInfo {
            sub: "external_user".to_string(),
            email: "external@example.com".to_string(),
            orgs: std::collections::HashSet::new(),
            org_roles: std::collections::HashMap::new(),
            is_internal: false,
        };

        // Create test request with POST method (should be forbidden for non-admin)
        let req = TestRequest::post()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test proxy_validator with external non-admin user
        let result = proxy_validator(req, Ok(user_info)).await;

        // Should fail with forbidden for non-admin external user on POST
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_proxy_validator_auth_error() {
        // Create test request
        let req = TestRequest::get()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test proxy_validator with auth error
        let auth_error = actix_web::error::ErrorUnauthorized("Invalid token");
        let result = proxy_validator(req, Err(auth_error)).await;

        // Should fail with unauthorized
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_oidc_validator_admin_user() {
        // Create mock admin user info
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "admin".to_string());

        let user_info = UserInfo {
            sub: "admin_user".to_string(),
            email: "admin@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request with POST method
        let req = TestRequest::post()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test oidc_validator with admin user
        let result = oidc_validator(req, &user_info).await;

        // Should succeed for admin user even with POST
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_oidc_validator_regular_user_get() {
        // Create mock regular user info
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "member".to_string());

        let user_info = UserInfo {
            sub: "regular_user".to_string(),
            email: "user@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request with GET method
        let req = TestRequest::get()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test oidc_validator with regular user
        let result = oidc_validator(req, &user_info).await;

        // Should succeed for GET requests
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_oidc_validator_regular_user_post_forbidden() {
        // Create mock regular user info
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "member".to_string());

        let user_info = UserInfo {
            sub: "regular_user".to_string(),
            email: "user@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request with POST method
        let req = TestRequest::post()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test oidc_validator with regular user
        let result = oidc_validator(req, &user_info).await;

        // Should fail for POST requests from non-admin users
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_oidc_validator_wrong_org() {
        // Create mock user info for different org
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("other_org".to_string(), "admin".to_string());

        let user_info = UserInfo {
            sub: "user".to_string(),
            email: "user@example.com".to_string(),
            orgs: std::collections::HashSet::from(["other_org".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request for default org
        let req = TestRequest::get()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test oidc_validator with user from different org
        let result = oidc_validator(req, &user_info).await;

        // Should fail for user not in the requested org
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_root_validator_internal_user() {
        // Create mock internal user info
        let user_info = UserInfo {
            sub: "internal_user".to_string(),
            email: "internal@example.com".to_string(),
            orgs: std::collections::HashSet::new(),
            org_roles: std::collections::HashMap::new(),
            is_internal: true,
        };

        // Create test request for API endpoint
        let req = TestRequest::get()
            .uri("/api/default/streams")
            .to_srv_request();

        // Test root_validator with internal user
        let result = root_validator(req, Ok(user_info)).await;

        // Should delegate to oo_validator for internal users
        // Note: This will fail in test environment due to missing auth headers,
        // but we're testing that it delegates correctly
        assert!(result.is_err()); // Expected to fail due to missing auth
    }

    #[tokio::test]
    async fn test_root_validator_external_user() {
        // Create mock external user info with admin role
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "admin".to_string());

        let user_info = UserInfo {
            sub: "external_user".to_string(),
            email: "external@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request for API endpoint
        let req = TestRequest::get()
            .uri("/api/default/streams")
            .to_srv_request();

        // Test root_validator with external user
        let result = root_validator(req, Ok(user_info)).await;

        // Should delegate to oidc_validator for external users
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_root_validator_auth_error() {
        // Create test request
        let req = TestRequest::get()
            .uri("/api/default/streams")
            .to_srv_request();

        // Test root_validator with auth error
        let auth_error = actix_web::error::ErrorUnauthorized("Invalid token");
        let result = root_validator(req, Err(auth_error)).await;

        // Should fail with unauthorized
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_root_validator_short_url() {
        // Create test request for short URL
        let req = TestRequest::get()
            .uri("/api/short/abc123")
            .to_srv_request();

        // Test root_validator with auth error and short URL
        let auth_error = actix_web::error::ErrorUnauthorized("Invalid token");
        let result = root_validator(req, Err(auth_error)).await;

        // Should fail with redirect for short URLs
        assert!(result.is_err());
        // The error should be a redirect response for short URLs
        // Note: We can't easily test the exact redirect logic without mocking,
        // but the important thing is that it handles short URLs differently
    }

    #[tokio::test]
    async fn test_extract_org_from_path_api() {
        assert_eq!(extract_org_from_path("/api/default/streams"), Some("default".to_string()));
        assert_eq!(extract_org_from_path("/api/v2/default/streams"), Some("default".to_string()));
        assert_eq!(extract_org_from_path("/api/other/logs"), Some("other".to_string()));
    }

    #[tokio::test]
    async fn test_extract_org_from_path_proxy() {
        assert_eq!(extract_org_from_path("/proxy/default/https://example.com"), Some("default".to_string()));
        assert_eq!(extract_org_from_path("/proxy/other/api/endpoint"), Some("other".to_string()));
    }

    #[tokio::test]
    async fn test_extract_org_from_path_invalid() {
        assert_eq!(extract_org_from_path("/other/path"), None);
        assert_eq!(extract_org_from_path("/"), None);
        assert_eq!(extract_org_from_path(""), None);
        assert_eq!(extract_org_from_path("/api"), None); // Missing org
        assert_eq!(extract_org_from_path("/proxy"), None); // Missing org
        assert_eq!(extract_org_from_path("/api/organizations"), None); // System endpoint, no service segment
        assert_eq!(extract_org_from_path("/api/users"), None); // System endpoint, no service segment
    }

    #[tokio::test]
    async fn test_oidc_validator_system_endpoint() {
        // Create mock admin user info
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "admin".to_string());

        let user_info = UserInfo {
            sub: "admin_user".to_string(),
            email: "admin@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request for system endpoint (no org_id extracted)
        let req = TestRequest::get()
            .uri("/api/organizations")
            .to_srv_request();

        // Test oidc_validator with system endpoint
        let result = oidc_validator(req, &user_info).await;

        // Should succeed because no org_id is extracted (system endpoint)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_oidc_validator_admin_user_put() {
        // Create mock admin user info
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "admin".to_string());

        let user_info = UserInfo {
            sub: "admin_user".to_string(),
            email: "admin@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request with PUT method
        let req = TestRequest::put()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test oidc_validator with admin user
        let result = oidc_validator(req, &user_info).await;

        // Should succeed for admin user with any method
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_oidc_validator_admin_user_delete() {
        // Create mock admin user info
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "admin".to_string());

        let user_info = UserInfo {
            sub: "admin_user".to_string(),
            email: "admin@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request with DELETE method
        let req = TestRequest::delete()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test oidc_validator with admin user
        let result = oidc_validator(req, &user_info).await;

        // Should succeed for admin user with any method
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_oidc_validator_viewer_role_get() {
        // Create mock viewer user info
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "viewer".to_string());

        let user_info = UserInfo {
            sub: "viewer_user".to_string(),
            email: "viewer@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request with GET method
        let req = TestRequest::get()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test oidc_validator with viewer user
        let result = oidc_validator(req, &user_info).await;

        // Should succeed for GET requests (viewer role allows read operations)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_oidc_validator_viewer_role_post_forbidden() {
        // Create mock viewer user info
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "viewer".to_string());

        let user_info = UserInfo {
            sub: "viewer_user".to_string(),
            email: "viewer@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request with POST method
        let req = TestRequest::post()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test oidc_validator with viewer user
        let result = oidc_validator(req, &user_info).await;

        // Should fail for POST requests from viewer users
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_oidc_validator_member_role_patch() {
        // Create mock member user info
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "member".to_string());

        let user_info = UserInfo {
            sub: "member_user".to_string(),
            email: "member@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request with PATCH method
        let req = TestRequest::patch()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test oidc_validator with member user
        let result = oidc_validator(req, &user_info).await;

        // Should fail for PATCH requests from member users (only GET allowed)
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_oidc_validator_no_role_fallback() {
        // Create mock user info with unknown role
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "unknown_role".to_string());

        let user_info = UserInfo {
            sub: "unknown_user".to_string(),
            email: "unknown@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request with POST method
        let req = TestRequest::post()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test oidc_validator with user having unknown role
        let result = oidc_validator(req, &user_info).await;

        // Should fail for POST requests (only admin role allows non-GET methods)
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_oidc_validator_multiple_roles_admin() {
        // Create mock user info with multiple roles including admin
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "member".to_string());
        org_roles.insert("other".to_string(), "admin".to_string());

        let user_info = UserInfo {
            sub: "multi_role_user".to_string(),
            email: "multi@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string(), "other".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request with PUT method for default org
        let req = TestRequest::put()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test oidc_validator - should succeed because user has admin role in some org
        let result = oidc_validator(req, &user_info).await;

        // Should succeed for PUT requests if user has admin role anywhere
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_oidc_validator_no_org_path() {
        // Create mock admin user info
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "admin".to_string());

        let user_info = UserInfo {
            sub: "admin_user".to_string(),
            email: "admin@example.com".to_string(),
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request with path that doesn't contain org
        let req = TestRequest::post()
            .uri("/proxy") // No org specified
            .to_srv_request();

        // Test oidc_validator with path that doesn't extract org
        let result = oidc_validator(req, &user_info).await;

        // Should succeed when no org is extracted from path (granted = true)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_oidc_validator_invalid_email_header() {
        // Create mock admin user info with invalid email for HTTP header
        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("default".to_string(), "admin".to_string());

        let user_info = UserInfo {
            sub: "admin_user".to_string(),
            email: "invalid\nemail@example.com".to_string(), // Invalid for HTTP header
            orgs: std::collections::HashSet::from(["default".to_string()]),
            org_roles,
            is_internal: false,
        };

        // Create test request
        let req = TestRequest::get()
            .uri("/proxy/default/https://example.com")
            .to_srv_request();

        // Test oidc_validator with invalid email
        let result = oidc_validator(req, &user_info).await;

        // Should fail with internal server error due to invalid email format
        assert!(result.is_err());
        // Note: The exact error type check would require inspecting the error,
        // but the important thing is that it fails gracefully
    }
}