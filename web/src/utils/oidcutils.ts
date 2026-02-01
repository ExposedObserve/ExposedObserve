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

import { DateTime as _DateTime } from "luxon";
import { b64DecodeUnicode, b64EncodeStandard, useLocalUserInfo } from "@/utils/zincutils"

export const getUserInfoFromClaims = (userInfoStr: string) => {
  let result = null
  const propArr = userInfoStr.split("=")
  let key = propArr[0]
  while (key.charAt(0) === '#') {
    key = key.substring(1);
    break
  }
  if (key == "userInfo") {
    try {
      result = JSON.parse(b64DecodeUnicode(propArr[1]) || "")
      result['pgdata'] = "exists"
      const encodedSessionData: any = b64EncodeStandard(
        JSON.stringify(result),
      )
      useLocalUserInfo(encodedSessionData)
      return result
    } catch (e) {
      console.log(`Error in getUserInfo util with loginString: ${userInfoStr}`)
    }
  }
  return result
};
