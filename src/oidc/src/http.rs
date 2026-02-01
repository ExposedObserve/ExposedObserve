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

use log::warn;
use openidconnect::reqwest;
use tokio::sync::OnceCell;

use crate::{
    config,
    errors::{AuthError, handle_error},
};

static HTTP_CLIENT: OnceCell<openidconnect::reqwest::Client> = OnceCell::const_new();

pub(crate) async fn get_http_client() -> &'static openidconnect::reqwest::Client {
    HTTP_CLIENT.get_or_init(init_async_client).await
}

async fn init_async_client() -> openidconnect::reqwest::Client {
    let config = config::get_oidc_config();
    match create_async_http_client(&config.http_client_config) {
        Ok(client) => client,
        Err(err) => {
            handle_error(&err, "Initioalization failed");
            unreachable!()
        }
    }
}

/// Creates a new HTTP client configured for OIDC requests.
/// This function configures the client with OIDC-specific settings like disabled redirects,
/// custom timeouts, and optional insecure certificate acceptance.
/// Returns None if client creation fails (logged as error).
fn create_async_http_client(
    http_config: &config::HttpClientConfig,
) -> Result<openidconnect::reqwest::Client, AuthError> {
    let mut builder = openidconnect::reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(http_config.timeout)
        .connect_timeout(http_config.connect_timeout)
        .pool_idle_timeout(http_config.pool_idle_timeout)
        .pool_max_idle_per_host(http_config.pool_max_idle_per_host);
    if http_config.insecure {
        warn!(
            "Creating HTTP client with insecure TLS settings (invalid certificates will be accepted)"
        );
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().map_err(|e| {
        AuthError::to_internal_error(e, Some("Failed to build OIDC HTTP client".to_owned()))
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[test]
    fn test_create_async_http_client_success() {
        // Create a test HTTP config
        let http_config = crate::config::HttpClientConfig::default();
        let result = super::create_async_http_client(&http_config);
        assert!(
            result.is_ok(),
            "HTTP client creation should succeed with valid config"
        );
    }

    #[test]
    fn test_create_async_http_client_with_insecure() {
        let http_config = crate::config::HttpClientConfig {
            insecure: true,
            timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(3),
            pool_idle_timeout: Duration::from_secs(30),
            pool_max_idle_per_host: 5,
        };

        let result = super::create_async_http_client(&http_config);
        assert!(
            result.is_ok(),
            "HTTP client creation should succeed with insecure=true"
        );
    }
}
