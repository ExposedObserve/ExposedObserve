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

use std::{fmt::{self, Write}, process::exit};

use actix_session::{SessionGetError, SessionInsertError};
use actix_web::{HttpResponse, HttpResponseBuilder, http::StatusCode};
use openidconnect::{
    ClaimsVerificationError, ConfigurationError, SignatureVerificationError, SigningError,
};

use crate::{config, cookies::clear_all_auth_cookies};

#[derive(Debug)]
pub struct AuthError {
    pub message: Option<String>,
    pub status_code: StatusCode,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}

impl AuthError {
    pub fn new<S: Into<String>>(msg: S, status_code: StatusCode) -> Self {
        AuthError {
            message: Some(msg.into()),
            status_code,
            source: None,
        }
    }

    pub fn to_internal_error<E>(fail: E, message: Option<String>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        AuthError {
            message,
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            source: Some(Box::new(fail)),
        }
    }

    pub fn from_error<E>(fail: E, message: Option<String>, status_code: StatusCode) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        AuthError {
            message: match message {
                Some(msg) => Some(msg),
                None => Some(format!("{}", fail)),
            },
            status_code,
            source: Some(Box::new(fail)),
        }
    }
}

pub fn error_message_formatter<T: std::error::Error>(fail: &T, msg: &str) -> String {
    let mut result = String::new();
    if msg.is_empty() {
        write!(result, "{}", fail).unwrap();
    } else {
        write!(result, "{}", msg).unwrap();
    }
    let mut cur = fail.source();
    while let Some(e) = cur {
        write!(result, "\n    caused by: {}", e).unwrap();
        cur = e.source();
    }
    result
}

pub(crate) fn handle_error<T: std::error::Error>(fail: &T, msg: &str) {
    println!("{}", error_message_formatter(fail, msg));
    exit(1);
}

pub(crate) fn handle_env_error<T: std::error::Error>(fail: &T, env_variable: &str) {
    let error_message = &format!("Variable '{env_variable}' parsing error");
    handle_error(fail, error_message);
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", error_message_formatter(&self, self.message.as_ref().unwrap()))
    }
}

impl actix_web::error::ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        auth_failure_response(self.message.clone(), self.status_code.clone())
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        self.status_code
    }
}

pub fn auth_failure_response(msg: Option<String>, status_code: StatusCode) -> HttpResponse {
    let resp_builder = &mut HttpResponseBuilder::new(status_code);
    clear_all_auth_cookies(resp_builder);
    let config = config::get_oidc_config();
    let login_url = config.callback_url.as_str();
    resp_builder.append_header(("Location", login_url));
    match msg {
        Some(msg) => resp_builder.json(serde_json::json!({
            "error": format!("{msg}"),
            "redirect": login_url
        })),
        None => resp_builder.json(serde_json::json!({
            "redirect": login_url
        })),
    }
}

impl From<SignatureVerificationError> for AuthError {
    fn from(error: SignatureVerificationError) -> Self {
        AuthError::from_error(error, None, StatusCode::UNAUTHORIZED)
    }
}

impl From<ClaimsVerificationError> for AuthError {
    fn from(error: ClaimsVerificationError) -> Self {
        AuthError::from_error(error, None, StatusCode::UNAUTHORIZED)
    }
}

impl From<SigningError> for AuthError {
    fn from(error: SigningError) -> Self {
        AuthError::from_error(error, None, StatusCode::UNAUTHORIZED)
    }
}

impl From<SessionInsertError> for AuthError {
    fn from(error: SessionInsertError) -> Self {
        AuthError::from_error(error, None, StatusCode::INTERNAL_SERVER_ERROR)
    }
}
impl From<SessionGetError> for AuthError {
    fn from(error: SessionGetError) -> Self {
        AuthError::from_error(error, None, StatusCode::UNAUTHORIZED)
    }
}

impl From<ConfigurationError> for AuthError {
    fn from(error: ConfigurationError) -> Self {
        AuthError::from_error(error, None, StatusCode::INTERNAL_SERVER_ERROR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, ResponseError};
    use std::io::{Error as IoError, ErrorKind};

    // Test AuthError constructors
    #[test]
    fn test_auth_error_new() {
        let error = AuthError::new("Test message", StatusCode::BAD_REQUEST);
        assert_eq!(error.message, Some("Test message".to_string()));
        assert_eq!(error.status_code, StatusCode::BAD_REQUEST);
        assert!(error.source.is_none());
    }

    #[test]
    fn test_auth_error_to_internal_error() {
        let io_error = IoError::new(ErrorKind::NotFound, "File not found");
        let error = AuthError::to_internal_error(io_error, Some("Database error".to_string()));
        assert_eq!(error.message, Some("Database error".to_string()));
        assert_eq!(error.status_code, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(error.source.is_some());
    }

    #[test]
    fn test_auth_error_from_error_with_message() {
        let io_error = IoError::new(ErrorKind::InvalidInput, "Bad input");
        let error = AuthError::from_error(io_error, Some("Parsed error".to_string()), StatusCode::UNAUTHORIZED);
        assert_eq!(error.message, Some("Parsed error".to_string()));
        assert_eq!(error.status_code, StatusCode::UNAUTHORIZED);
        assert!(error.source.is_some());
    }

    #[test]
    fn test_auth_error_from_error_without_message() {
        let io_error = IoError::new(ErrorKind::InvalidInput, "Bad input");
        let error = AuthError::from_error(io_error, None, StatusCode::UNAUTHORIZED);
        assert_eq!(error.message, Some("Bad input".to_string()));
        assert_eq!(error.status_code, StatusCode::UNAUTHORIZED);
        assert!(error.source.is_some());
    }

    // Test error_message_formatter
    #[test]
    fn test_error_message_formatter_with_empty_msg() {
        let root = IoError::new(ErrorKind::NotFound, "Root error");
        let result = error_message_formatter(&root, "");
        assert!(result.contains("Root error"));
    }

    #[test]
    fn test_error_message_formatter_with_msg() {
        let root = IoError::new(ErrorKind::NotFound, "Root error");
        let result = error_message_formatter(&root, "Custom message");
        assert!(result.starts_with("Custom message"));
    }

    #[test]
    fn test_error_message_formatter_with_chain() {
        let root = TestError::new("Root error", Some(Box::new(IoError::new(ErrorKind::InvalidData, "Nested error"))));
        let result = error_message_formatter(&root, "");
        assert!(result.contains("Root error"));
        assert!(result.contains("Nested error"));
    }

    // Test AuthError Display
    #[test]
    fn test_auth_error_display() {
        let error = AuthError::new("Display test", StatusCode::BAD_REQUEST);
        let display = format!("{}", error);
        assert_eq!(display, "Display test");
    }

    #[test]
    fn test_auth_error_display_with_chain() {
        let io_error = IoError::new(ErrorKind::NotFound, "IO failure");
        let error = AuthError::from_error(io_error, Some("Auth chain error".to_string()), StatusCode::UNAUTHORIZED);
        let display = format!("{}", error);
        print!("{}", display);
        assert!(display.contains("Auth chain error"));
        assert!(display.contains("IO failure"));
    }


    // Test ResponseError
    #[test]
    fn test_auth_error_status_code() {
        let error = AuthError::new("Test", StatusCode::NOT_FOUND);
        assert_eq!(error.status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_auth_error_response_regular_msg() {
        let error = AuthError::new("Regular error", StatusCode::BAD_REQUEST);
        let response = error.error_response();
        let status = response.status();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_auth_error_response_with_chain() {
        let io_error = IoError::new(ErrorKind::PermissionDenied, "Permission denied");
        let error = AuthError::from_error(io_error, None, StatusCode::FORBIDDEN);
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    // Helper struct for chain tests
    #[derive(Debug)]
    struct TestError {
        msg: String,
        source: Option<Box<dyn std::error::Error>>,
    }

    impl TestError {
        fn new(msg: &str, source: Option<Box<dyn std::error::Error>>) -> Self {
            TestError {
                msg: msg.to_string(),
                source,
            }
        }
    }

    impl std::error::Error for TestError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.source.as_ref().map(|e| e.as_ref())
        }
    }

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.msg)
        }
    }
}
