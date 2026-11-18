# Known-Failing Tests (Registry)

Tests that are **red on the upstream baseline** this fork sits on, and are therefore
not caused by fork changes. This file exists so a red test in one of these files is
recognised as pre-existing instead of being re-investigated on every run.

**Upstream baseline:** `v1.1.0-rc2`
**Measured on:** Node v26.11.1, vitest 4.1.12
**Scope:** web unit tests (`web/src/**/*.spec.ts`)

## How to reproduce the baseline

```bash
git worktree add /tmp/oo-baseline v1.1.0-rc2
cd /tmp/oo-baseline/web && npm ci
npx vitest run --environment jsdom --root src/
```

A test belongs in this registry when it fails on that baseline **and** passes or
behaves identically on the fork branch. Any test that fails only on the fork is a
regression and must NOT be listed here.

## Environment prerequisite: Node 26 `localStorage`

Node 26 exposes `localStorage` as an experimental global that is `undefined` unless
the process is started with `--localstorage-file`. Without the flag, **887 tests
across 283 files** fail on `localStorage.getItem` / `.clear` / `.setItem`, and the
result says nothing about the code under test.

```bash
cd web && NODE_OPTIONS="--localstorage-file=/tmp/ls.json" npx vitest run --environment jsdom --root src/
```

All numbers below were measured **with** the flag. Without it the failure count is
an artifact of the Node version, not of the code.

## Registry

46 tests across 25 files fail on the `v1.1.0-rc2` baseline.

### Group A — `Error: async function passed to sync validator` (22 tests, 17 files)

`@tanstack/form-core` rejects an async validator when the form submits through
`validateSync`. Every `OForm*` component spec that submits a schema-backed form
hits this.

| File | Failing tests |
| --- | --- |
| `src/lib/forms/Form/OForm.spec.ts` | 4 |
| `src/lib/forms/TemplateInput/OTemplateSuggestList.spec.ts` | 6 |
| `src/lib/forms/TemplateInput/OTemplateTextarea.spec.ts` | 5 |
| `src/lib/core/ToggleGroup/OFormToggleGroup.spec.ts` | 3 |
| `src/lib/forms/Combobox/OFormCombobox.spec.ts` | 3 |
| `src/lib/forms/Input/OFormInput.spec.ts` | 3 |
| `src/lib/forms/Checkbox/OFormCheckbox.spec.ts` | 1 |
| `src/lib/forms/Color/OFormColor.spec.ts` | 1 |
| `src/lib/forms/Date/OFormDate.spec.ts` | 1 |
| `src/lib/forms/File/OFormFile.spec.ts` | 1 |
| `src/lib/forms/OptionGroup/OFormOptionGroup.spec.ts` | 1 |
| `src/lib/forms/Range/OFormRange.spec.ts` | 1 |
| `src/lib/forms/Select/OFormSelect.spec.ts` | 1 |
| `src/lib/forms/Slider/OFormSlider.spec.ts` | 1 |
| `src/lib/forms/Switch/OFormSwitch.spec.ts` | 1 |
| `src/lib/forms/TemplateInput/OTemplateInput.spec.ts` | 1 |
| `src/lib/forms/Time/OFormTime.spec.ts` | 1 |

### Group B — storage and mock-isolation assertions (13 tests, 7 files)

These assert on `localStorage` / `sessionStorage` calls or on module mocks that no
longer intercept the write. They depend on the Node 26 storage behaviour described
above and on mock-hoisting order, so they are sensitive to the runner, not to the
component logic.

| File | Failing tests |
| --- | --- |
| `src/plugins/traces/ServiceGraph.spec.ts` | 3 |
| `src/plugins/logs/DetailTable.spec.ts` | 2 |
| `src/components/onboardingPopupCoordination.spec.ts` | 1 |
| `src/components/rum/productAnalytics/SavedFunnelsPage.spec.ts` | 1 |
| `src/composables/dashboard/useExemplarOverride.spec.ts` | 1 |
| `src/composables/useAutoNavigationPreferences.spec.ts` | 1 |
| `src/composables/usePromptHistory.spec.ts` | 1 |
| `src/services/httpsearch.spec.ts` | 1 |

## Flaky, not deterministic

Two files fail intermittently with `Error: database is locked`, raised by msw's
`CookieStore` when several vitest workers open the same `--localstorage-file`:

- `src/plugins/traces/TraceDetails.spec.ts`
- `src/plugins/traces/Index.spec.ts`

The error reproduces on the untouched upstream baseline as well (it passed on 2 of 3
consecutive runs there). Give each worker its own storage file, or run these
separately, before treating them as real failures.

## Maintenance

- Re-measure the baseline after every upstream sync (`fork-sync`): the numbers above
  describe `v1.1.0-rc2`, not the current upstream tip.
- When a listed test starts passing, remove it from this file in the same commit
  that fixes it — a stale entry hides a real regression later.
- A test that fails only on the fork branch is never listed here. Fix it instead.
