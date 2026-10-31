// Copyright (C) 2026 Mike Sauh
//
// This file is part of ExposedObserve, a modified fork of OpenObserve.
// OpenObserve is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// Original project: https://github.com/openobserve/openobserve
//
// This file was created independently to make the product brand configurable.
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

export const DEFAULT_APP_NAME = "ExposedObserve";

// VITE_APP_NAME lets a white-label deployment rename the product at build time;
// an unset or blank value must still yield the default, never an empty title.
export const resolveAppName = (env: Record<string, unknown>): string => {
  const configured = env?.VITE_APP_NAME;
  return typeof configured === "string" && configured.trim() !== ""
    ? configured.trim()
    : DEFAULT_APP_NAME;
};

// Logo paths are relative to `src/assets/`, matching what `getImageURL` expects.
// The defaults are the fork's own mark; a white-label build points them at its
// own artwork without touching component code.
export const DEFAULT_LOGO_LIGHT = "images/common/eo_logo_light.svg";
export const DEFAULT_LOGO_DARK = "images/common/eo_logo_dark.svg";

const readLogoPath = (env: Record<string, unknown>, key: string, fallback: string): string => {
  const configured = env?.[key];
  return typeof configured === "string" && configured.trim() !== "" ? configured.trim() : fallback;
};

export const resolveLogoLight = (env: Record<string, unknown>): string =>
  readLogoPath(env, "VITE_LOGO_LIGHT", DEFAULT_LOGO_LIGHT);

export const resolveLogoDark = (env: Record<string, unknown>): string =>
  readLogoPath(env, "VITE_LOGO_DARK", DEFAULT_LOGO_DARK);

// The fork's own project page. A white-label deployment points it at its own
// site with VITE_WEBSITE_URL.
export const DEFAULT_WEBSITE_URL = "https://github.com/ExposedObserve/ExposedObserve";

export const resolveWebsiteUrl = (env: Record<string, unknown>): string => {
  const configured = env?.["VITE_WEBSITE_URL"];
  return typeof configured === "string" && configured.trim() !== ""
    ? configured.trim()
    : DEFAULT_WEBSITE_URL;
};
