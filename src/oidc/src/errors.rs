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

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use openidconnect::{
    ClaimsVerificationError, ConfigurationError, SignatureVerificationError, SigningError,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("internal error: {context}")]
    Internal {
        context: String,
        #[source]
        source: Option<anyhow::Error>,
    },

    #[error("unsupported")]
    Unsupported(),

    #[error("invalid request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("upstream OIDC error: {context}")]
    Upstream {
        context: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl AuthError {
    pub fn internal<E>(context: impl Into<String>, source: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        AuthError::Internal {
            context: context.into(),
            source: Some(source.into()),
        }
    }

    pub fn internal_msg(context: impl Into<String>) -> Self {
        AuthError::Internal {
            context: context.into(),
            source: None,
        }
    }

    pub fn upstream(context: impl Into<String>) -> Self {
        AuthError::Upstream {
            context: context.into(),
            source: None,
        }
    }

    pub fn upstream_with<E>(context: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        AuthError::Upstream {
            context: context.into(),
            source: Some(Box::new(source)),
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            AuthError::Internal { .. } | AuthError::Upstream { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AuthError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AuthError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AuthError::Forbidden(_) => StatusCode::FORBIDDEN,
            AuthError::Unsupported() => StatusCode::NOT_FOUND,
        }
    }

    pub fn public_message(&self) -> String {
        match self {
            AuthError::Internal { .. } | AuthError::Upstream { .. } => {
                "An internal server error occurred".into()
            }
            AuthError::BadRequest(m) | AuthError::Unauthorized(m) | AuthError::Forbidden(m) => {
                m.clone()
            }
            AuthError::Unsupported() => "".into(),
        }
    }

    pub fn internal_log_message(&self) -> String {
        match self {
            AuthError::Internal { context, source } => match source {
                Some(s) => format!("internal error: {context}: {s:#}"),
                None => format!("internal error: {context}"),
            },
            AuthError::Upstream { context, source } => match source {
                Some(s) => format!("upstream error: {context}: {s:#}"),
                None => format!("upstream error: {context}"),
            },
            AuthError::BadRequest(m) => format!("bad request: {m}"),
            AuthError::Forbidden(m) => format!("forbidden: {m}"),
            AuthError::Unauthorized(m) => format!("unauthorized: {m}"),
            AuthError::Unsupported() => "".into(),
        }
    }
}

impl From<SignatureVerificationError> for AuthError {
    fn from(err: SignatureVerificationError) -> Self {
        AuthError::Unauthorized(format!("signature verification failed: {err}"))
    }
}

impl From<ClaimsVerificationError> for AuthError {
    fn from(err: ClaimsVerificationError) -> Self {
        AuthError::Unauthorized(format!("claims verification failed: {err}"))
    }
}

impl From<SigningError> for AuthError {
    fn from(err: SigningError) -> Self {
        AuthError::Internal {
            context: "OIDC signing error".to_string(),
            source: Some(err.into()),
        }
    }
}

impl From<ConfigurationError> for AuthError {
    fn from(err: ConfigurationError) -> Self {
        AuthError::Internal {
            context: "OIDC configuration error".to_string(),
            source: Some(err.into()),
        }
    }
}

impl From<reqwest::Error> for AuthError {
    fn from(err: reqwest::Error) -> Self {
        AuthError::Upstream {
            context: "HTTP request to OIDC provider failed".to_string(),
            source: Some(Box::new(err)),
        }
    }
}

pub fn auth_failure_body(message: &str, status_code: StatusCode) -> Response {
    let body = json!({
        "code": status_code.as_u16(),
        "error": message,
    });
    (status_code, Json(body)).into_response()
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        log::error!("Auth failure: {}", self.internal_log_message());
        let status = self.status_code();
        let body = self.public_message();
        auth_failure_body(&body, status)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error as IoError, ErrorKind};

    use axum::body::to_bytes;

    use super::*;

    #[test]
    fn status_code_for_variants() {
        let bad = AuthError::BadRequest("x".into());
        let un = AuthError::Unauthorized("x".into());
        let internal = AuthError::internal("ctx".to_string(), IoError::other("boom"));
        assert_eq!(bad.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(un.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(internal.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn internal_preserves_source() {
        use std::error::Error as _;
        let err = AuthError::internal(
            "ctx".to_string(),
            IoError::new(ErrorKind::PermissionDenied, "denied"),
        );
        let src = err.source().expect("source must be preserved");
        assert!(src.to_string().contains("denied"));
    }

    #[tokio::test]
    async fn into_response_emits_json_envelope() {
        let err = AuthError::Unauthorized("nope".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains("nope"));
        assert!(s.contains("\"code\":401"));
    }
}
