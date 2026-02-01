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

//! External authentication module handling OIDC-based login, logout, and callback flows.
//!
//! This module provides HTTP endpoints for external user authentication using OpenID Connect (OIDC).
//! It manages the authentication lifecycle including login initiation, callback processing,
//! user validation, and logout. User information is exchanged via OIDC client interactions
//! and validated against the external users service.

use actix_http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, get};
use base64::Engine;
use oidc::models::UserInfo;

use crate::service::{self};

/// Handles user logout by delegating to the OIDC client.
///
/// This endpoint initiates the logout process for the authenticated user.
/// It calls the OIDC client's logout method which handles the protocol-specific
/// logout flow, including any necessary redirects or token invalidation.
///
/// # Arguments
/// * `req` - The HTTP request containing session information
///
/// # Returns
/// A redirect response or error from the OIDC logout process
#[get("/logout")]
pub async fn logout(req: HttpRequest) -> Result<HttpResponse, actix_web::Error> {
    oidc::client::logout(req).await
}

/// Handles authentication initiation and user info processing.
///
/// This endpoint serves as the entry point for user authentication. It expects
/// user info to be provided (likely from middleware). If authentication succeeded
/// but the user has no email, or if authentication failed, it redirects to the
/// OIDC login page. If authentication succeeded with valid user info, it redirects
/// to the callback URL with the user information embedded.
///
/// # Arguments
/// * `req` - The HTTP request
/// * `auth_result` - Result containing user info if authentication was successful
///
/// # Returns
/// A redirect response to either login page or callback URL with user info
#[get("/login")]
pub async fn auth(
    req: HttpRequest,
    auth_result: Result<UserInfo, actix_web::Error>,
) -> Result<HttpResponse, actix_web::Error> {
    match auth_result {
        Ok(user_info) => {
            if user_info.email.is_empty() {
                log::warn!("Invalied user info received: {:?}", user_info);
                oidc::client::login(req).await
            } else {
                log::info!(
                    "Authentication succeeded for user: {}",
                    user_info.email
                );
                let cb = cb_url(Some(&user_info));
                Ok(HttpResponse::Found()
                    .append_header(("Location", cb))
                    .finish())
            }
        }
        Err(err) => {
            log::warn!("Authentication failed: {:?}", err);
            oidc::client::login(req).await
        }
    }
}

/// Processes the OIDC callback after successful authentication.
///
/// This endpoint is called by the OIDC provider after the user has authenticated.
/// It retrieves the user information from the OIDC client and validates it against
/// the external users service before redirecting to the final destination.
///
/// # Arguments
/// * `req` - The HTTP request containing authorization code/tokens from OIDC
///
/// # Returns
/// A redirect response with validated user info or an error response
#[get("/callback")]
pub async fn callback(req: HttpRequest) -> Result<HttpResponse, actix_web::Error> {
    match oidc::client::retrieve_user_info(req).await {
        Ok(user_info) => {
            log::info!("Successfully retrieved user info from OIDC provider: {}", user_info.email);
            build_validation_response(&user_info).await
        }
        Err(err) => {
            log::error!("Failed to retrieve user info from OIDC provider: {}", err);
            Err(err.into())
        }
    }
}

/// Builds HTTP response based on user validation result.
///
/// This function checks if the provided user info is authorized to access the system
/// by calling the external users service. If valid, it returns a redirect response to
/// the callback URL (user info is passed via URL fragment). If invalid, it returns
/// an authentication failure response with 403 Forbidden status.
///
/// # Arguments
/// * `user_info` - The user information to validate
///
/// # Returns
/// A redirect response if valid, or error response if invalid
async fn build_validation_response(user_info: &UserInfo) -> Result<HttpResponse, actix_web::Error> {
    log::debug!("Validating user info for: {} (sub: {})", user_info.email, user_info.sub);
    if service::ext_users::sync_user_info(&user_info).await {
        log::info!("User validation successful for: {}", user_info.email);
        let cb = cb_url(Some(user_info));
        log::debug!("Redirecting to frontend with user info: {}", cb);
        log::debug!("About to create and return HTTP redirect response");
        let response = HttpResponse::Found()
            .append_header(("Location", cb))
            .finish();
        log::debug!("HTTP response object created successfully");
        Ok(response)
    } else {
        log::error!("User validation failed for: {} (sub: {})", user_info.email, user_info.sub);
        Ok(oidc::errors::auth_failure_response(
            None,
            StatusCode::FORBIDDEN,
        ))
    }
}

/// Constructs the callback URL with optional user information.
///
/// This function builds the callback URL used for redirects after authentication.
/// If user info is provided, it serializes it to JSON, base64 encodes it, and appends
/// it as a URL fragment. This allows the client-side to access the user information
/// after the redirect.
///
/// Note: If JSON serialization fails, an empty JSON object is used as fallback.
/// Consider adding proper error handling if this becomes an issue.
///
/// # Arguments
/// * `user_info` - Optional reference to user information to include in the URL
///
/// # Returns
/// The callback URL, optionally with base64-encoded user info as a fragment
fn cb_url(user_info: Option<&UserInfo>) -> String {
    let url = &oidc::config::get_oidc_config().callback_url;
    match user_info {
        Some(info) => {
            let json_str = serde_json::to_string(info)
                .inspect_err(|err|{
                    log::error!("Failed to serialize user info {:?}", err);
                })
                .unwrap_or("{}".to_string());
            format!(
                "{}#userInfo={}",
                url,
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(json_str)
            )
        }
        None => url.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oidc::models::UserInfo;

    #[tokio::test]
    async fn test_cb_url_with_user_info() {
        // Test the JSON serialization and base64 encoding logic

        let user_info = UserInfo {
            sub: "user123".to_string(),
            email: "test@example.com".to_string(),
            orgs: std::collections::HashSet::new(),
            org_roles: std::collections::HashMap::new(),
            is_internal: false,
        };

        // Test JSON serialization works
        let json_result = serde_json::to_string(&user_info);
        assert!(json_result.is_ok(), "UserInfo should serialize to JSON");

        let json_str = json_result.unwrap();
        assert!(json_str.contains("test@example.com"), "JSON should contain email");
        assert!(json_str.contains("user123"), "JSON should contain sub");

        // Test base64 encoding
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&json_str);
        assert!(!encoded.is_empty(), "Base64 encoding should produce non-empty string");

        // Test that we can decode it back
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&encoded)
            .unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert_eq!(decoded_str, json_str, "Base64 roundtrip should work");
    }

    #[tokio::test]
    async fn test_user_info_serialization() {
        // Test that UserInfo can be serialized to JSON with all fields
        let mut orgs = std::collections::HashSet::new();
        orgs.insert("org1".to_string());

        let mut org_roles = std::collections::HashMap::new();
        org_roles.insert("org1".to_string(), "admin".to_string());

        let user_info = UserInfo {
            sub: "user123".to_string(),
            email: "test@example.com".to_string(),
            orgs,
            org_roles,
            is_internal: false,
        };

        let json = serde_json::to_string(&user_info);
        assert!(json.is_ok(), "UserInfo should be serializable");

        let json_str = json.unwrap();
        assert!(json_str.contains("test@example.com"));
        assert!(json_str.contains("user123"));
        assert!(json_str.contains("org1"));
        assert!(json_str.contains("admin"));
    }

    // Note: auth() function tests are skipped as they require external OIDC client mocking
    // and the function is decorated with #[get("/login")] which complicates direct testing
}
