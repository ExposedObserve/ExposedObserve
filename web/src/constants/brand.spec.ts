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

import { describe, it, expect } from "vitest";
import {
  DEFAULT_APP_NAME,
  DEFAULT_LOGO_DARK,
  DEFAULT_LOGO_LIGHT,
  resolveAppName,
  resolveLogoDark,
  resolveLogoLight,
} from "@/constants/brand";

describe("brand resolution", () => {
  it("falls back to the default app name", () => {
    expect(resolveAppName({})).toBe(DEFAULT_APP_NAME);
    expect(resolveAppName({ VITE_APP_NAME: "  " })).toBe(DEFAULT_APP_NAME);
    expect(resolveAppName({ VITE_APP_NAME: "Acme" })).toBe("Acme");
  });

  it("falls back to the default logo paths", () => {
    expect(resolveLogoLight({})).toBe(DEFAULT_LOGO_LIGHT);
    expect(resolveLogoDark({})).toBe(DEFAULT_LOGO_DARK);
  });

  it("keeps light and dark distinguishable", () => {
    expect(DEFAULT_LOGO_LIGHT).toContain("light");
    expect(DEFAULT_LOGO_DARK).toContain("dark");
  });

  it("honours a configured logo path", () => {
    expect(resolveLogoLight({ VITE_LOGO_LIGHT: "images/brand/mark.svg" })).toBe(
      "images/brand/mark.svg",
    );
    expect(resolveLogoDark({ VITE_LOGO_DARK: "images/brand/mark-dark.svg" })).toBe(
      "images/brand/mark-dark.svg",
    );
  });
});
