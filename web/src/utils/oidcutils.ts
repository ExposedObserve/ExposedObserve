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

import { b64DecodeUnicode, b64EncodeStandard } from "@/utils/formatters";
import { useLocalUserInfo } from "@/utils/storage";

/// Parse the `userInfo=<base64>` URL fragment the OIDC callback
/// returns after a successful IdP round-trip. The login screen calls
/// this from `onBeforeMount` so a returning OIDC user lands straight
/// on the org picker with their email and orgs pre-filled, without
/// waiting for an extra `/api/.../userinfo` request.
///
/// `hash` is whatever `route.hash` exposes (the leading `#` is
/// preserved or stripped — both work). Returns `null` if the fragment
/// is missing or not shaped like the OIDC payload.
export const getUserInfoFromClaims = (hash: string | undefined) => {
  if (!hash) return null;
  // Normalise: drop leading '#' or '##' (vue-router sometimes
  // double-encodes), then split on the first '='.
  const trimmed = hash.replace(/^#+/, "");
  const eq = trimmed.indexOf("=");
  if (eq <= 0) return null;
  const key = trimmed.slice(0, eq);
  const value = trimmed.slice(eq + 1);
  if (key !== "userInfo" || !value) return null;
  try {
    const decoded = b64DecodeUnicode(value) || "";
    const result = JSON.parse(decoded);
    // The login store keys on the presence of `pgdata = "exists"` to
    // know the session is hydrated. The bootstrap handler in
    // `oidc::handlers::user_post_login_redirect` doesn't set it, so
    // we add it here.
    (result as Record<string, unknown>).pgdata = "exists";
    const encoded = b64EncodeStandard(JSON.stringify(result));
    useLocalUserInfo(encoded);
    return result;
  } catch (e) {
    console.log(`Error in getUserInfoFromClaims with hash: ${hash}: ${e}`);
    return null;
  }
};
