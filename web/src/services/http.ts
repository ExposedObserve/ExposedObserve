// Copyright 2026 OpenObserve Inc.
// Modifications Copyright (C) 2026 Mike Sauh
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import store from "../stores";
import type { AxiosInstance } from "axios";
import axios from "axios";
import config from "../aws-exports";
import { useLocalUserInfo, useLocalCurrentUser } from "@/utils/zincutils";
import { addUnauthorizedError } from "@/composables/useUnauthorizedErrorGrouper";
import { usePasswordReset } from "@/composables/usePasswordReset";
import { isPasswordResetError } from "@/utils/passwordResetErrors";

// Shared refresh state — ensures only one dex_refresh request is in-flight
// at a time across all axios instances and streaming fetch requests. All
// concurrent 401s wait on the same Promise and retry once it resolves.
let refreshPromise: Promise<void> | null = null;

// Exported so streaming (fetch-based) requests that bypass the axios interceptor
// can participate in the same token-refresh flow.
export const attemptTokenRefresh = (requestUrl: string = ""): Promise<void> => {
  // Avoid infinite loops for auth endpoints
  if (
    requestUrl.includes("/config/dex_login") ||
    requestUrl.includes("/config/dex_refresh") ||
    requestUrl.includes("/auth/sso/login") ||
    requestUrl.includes("/auth/sso/callback") ||
    requestUrl.includes("/auth/login")
  ) {
    return Promise.reject(new Error("Cannot refresh: auth endpoint"));
  }

  if (config.isCloud == "true") {
    store.dispatch("logout");
    useLocalCurrentUser("", true);
    useLocalUserInfo("", true);
    sessionStorage.clear();
    window.location.reload();
    return Promise.reject(new Error("Cloud environment: direct logout"));
  }

  if ((store.state as any).zoConfig.sso_enabled) {
    if (!refreshPromise) {
      const refreshInstance = axios.create({
        withCredentials: true,
        baseURL: store.state.API_ENDPOINT,
      });
      // Enterprise uses Dex and exposes refresh at /config/dex_refresh
      // (GET). CE+oss relies on the backend to refresh the
      // `auth_tokens` cookie transparently on the next request (see
      // `api/common::auth::token::token_validator` under the `oss`
      // feature), so the SPA has nothing to call — the response just
      // carries a fresh Set-Cookie the browser picks up.
      const refreshRequest =
        config.isEnterprise == "true"
          ? refreshInstance.get("/config/dex_refresh")
          : Promise.resolve({ status: 200 });
      refreshPromise = refreshRequest
        .then((res) => {
          if (res.status !== 200) {
            return Promise.reject(new Error("Refresh returned non-200"));
          }
          return undefined;
        })
        .catch(() => {
          return refreshInstance
            .get("/config/logout")
            .finally(() => {
              store.dispatch("logout");
              useLocalCurrentUser("", true);
              useLocalUserInfo("", true);
              sessionStorage.clear();
              window.location.reload();
            })
            .then(() => Promise.reject(new Error("Refresh failed")));
        })
        .finally(() => {
          refreshPromise = null;
        });
    }
    return refreshPromise;
  }

  // Not enterprise SSO — standard logout
  store.dispatch("logout");
  useLocalCurrentUser("", true);
  useLocalUserInfo("", true);
  sessionStorage.clear();
  window.location.reload();
  return Promise.reject(new Error("Not SSO: cannot refresh"));
};

const http = ({ headers } = {} as any) => {
  let instance: AxiosInstance;

  headers = {
    ...headers,
  };

  instance = axios.create({
    // timeout: 10000,
    withCredentials: true,
    baseURL: store.state.API_ENDPOINT,
    headers,
  });

  instance.interceptors.response.use(
    function (response) {
      return response;
    },
    function (error) {
      // Ahead of the status switch: a reset-required 403 is a policy state, not an authorization failure.
      if (isPasswordResetError(error)) {
        usePasswordReset().open(error.response.data.reason);
        // A blocked page fires many requests behind an undismissable dialog; one toast per rejection would stack.
        return new Promise(() => {});
      }
      if (error && error.response && error.response.status) {
        const reason =
          (error.response.data as { message?: string } | undefined)?.message ?? "Unknown error";
        console.warn("error?.response?.data", error?.response?.data);
        console.warn("error?.response", error?.response);
        console.warn("error", error);
        switch (error.response.status) {
          case 400:
            try {
              localStorage.setItem("oidc_error_msg", reason);
            } catch {
              /* localStorage may be unavailable in private mode */
            }
            break;
          case 401:
            if (config.isCloud == "true" && !error.request.responseURL.includes("/auth/login")) {
              console.warn("Auth error; redirecting to /web/login", reason);
              store.dispatch("logout");
              useLocalCurrentUser("", true);
              useLocalUserInfo("", true);
              sessionStorage.clear();
              // Navigate to the login screen so the SPA stops issuing
              // 401-bound requests on the same broken session. A reload
              // would re-fire the in-flight fetches before navigation
              // completes and trip the 401 path again.
              window.location.assign("/web/login");
            }
            // OIDC sessions don't have a client-side refresh. The
            // backend either rotated the `auth_tokens` cookie
            // transparently (success) or cleared it (hard failure); in
            // both cases the next request would either succeed or land
            // here again. Drop the local session and hand control back
            // to the login screen with a single navigate so the SPA
            // stops re-issuing 401-bound requests on the same broken
            // session.
            else if ((store.state as any).zoConfig.sso_enabled) {
              // The login screen reads this key on mount to render an
              // inline banner / toast explaining why the user landed
              // back here. The `assign` below destroys the current
              // page, so any toast raised from the interceptor itself
              // is dropped before it can paint.
              try {
                localStorage.setItem("oidc_logout_msg", reason);
              } catch {
                /* localStorage may be unavailable in private mode */
              }
              store.dispatch("logout");
              useLocalCurrentUser("", true);
              useLocalUserInfo("", true);
              sessionStorage.clear();
              window.location.assign("/web/login");
              return Promise.reject(error);
            } else {
              if (!error.request.responseURL.includes("/login")) {
                store.dispatch("logout");
                useLocalCurrentUser("", true);
                useLocalUserInfo("", true);
                sessionStorage.clear();
                window.location.assign("/web/login");
              }
            }
            break;
          case 403:
            if (
              (store.state as any).zoConfig.sso_enabled ||
              config.isEnterprise == "true" ||
              config.isCloud == "true"
            ) {
              const responseUrl = error.request?.responseURL || error.config?.url || "";
              addUnauthorizedError(responseUrl);
            }
            break;
          case 404:
            break;
          case 500:
            break;
          default:
          // noop
        }
      }
      return Promise.reject(error);
    },
  );

  return instance;
};

export default http;
