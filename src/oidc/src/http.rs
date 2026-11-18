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

use log::warn;
use tokio::sync::OnceCell;

use crate::{
    config::{self, HttpClientConfig},
    errors::AuthError,
};

static HTTP_CLIENT: OnceCell<reqwest::Client> = OnceCell::const_new();

/// Returns the shared HTTP client used for OIDC requests. Initialised lazily.
pub async fn get_http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(init_http_client).await
}

async fn init_http_client() -> reqwest::Client {
    let cfg = config::get_oidc_config();
    build_http_client(&cfg.http_client_config)
        .unwrap_or_else(|err| panic!("failed to build OIDC HTTP client: {err}"))
}

/// Construct a `reqwest::Client` configured for OIDC traffic.
pub fn build_http_client(cfg: &HttpClientConfig) -> Result<reqwest::Client, AuthError> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(cfg.timeout)
        .connect_timeout(cfg.connect_timeout)
        .pool_idle_timeout(cfg.pool_idle_timeout)
        .pool_max_idle_per_host(cfg.pool_max_idle_per_host);
    if cfg.insecure {
        warn!("OIDC HTTP client is configured to accept invalid certificates");
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder
        .build()
        .map_err(|err| AuthError::internal("building OIDC HTTP client", err))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn build_http_client_succeeds_with_default_config() {
        let client = build_http_client(&HttpClientConfig::default()).expect("default must build");
        drop(client);
    }

    #[test]
    fn build_http_client_succeeds_with_insecure() {
        let cfg = HttpClientConfig {
            insecure: true,
            ..HttpClientConfig::default()
        };
        let client = build_http_client(&cfg).expect("insecure must build");
        drop(client);
        // silence unused warning on Duration in the test build
        let _ = Duration::from_secs(1);
    }
}
