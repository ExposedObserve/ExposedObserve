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
//
// Reads OIDC banners/errors that the HTTP interceptor stashed in
// `localStorage` and exposes them as plain messages. Toast display
// is left to the caller so that the helper can run outside a
// Quasar/Vue setup where `toast()` may not have its context yet.

const LOGOUT_KEY = "oidc_logout_msg";
const ERROR_KEY = "oidc_error_msg";

export interface OidcNotice {
  reason?: string;
  raw?: string;
}

export const useOidcNotice = () => {
  const read = (key: string): string | null => {
    let value: string | null = null;
    try {
      value = localStorage.getItem(key);
      if (value) localStorage.removeItem(key);
    } catch {
      return null;
    }
    return value;
  };

  const consume = (key: string): string | null => read(key);

  return {
    flush: (): { logout?: string; error?: string } => ({
      logout: consume(LOGOUT_KEY) ?? undefined,
      error: consume(ERROR_KEY) ?? undefined,
    }),
    consumeLogoutBanner: () => consume(LOGOUT_KEY),
    consumeErrorBanner: () => consume(ERROR_KEY),
  };
};
