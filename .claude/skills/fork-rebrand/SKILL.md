---
name: fork-rebrand
description: Playbook for turning an OpenObserve fork into a self-branded product across an upstream sync — renaming the binary, CLI and log output, making the visible brand configurable, normalizing license headers on fork-owned files, and stripping upstream vendor/enterprise promo from the UI. Use when rebranding, white-labelling, or preparing a fork release (replacing OpenObserve/o2/O2 branding, `ExposedObserve` naming, "Get Enterprise Free" promo, license-header years), or when re-applying those changes after an upstream merge. Not for changing identifiers: crate/package names, env-var prefixes and external SDK names stay put by design.
---

# Fork rebranding — OpenObserve fork → own-brand product

The fork tracks upstream (`openobserve/openobserve`) and adds features on top (currently OIDC/SSO in `src/oidc/`).
Goal: the product reads as **our** brand to end users, while the source stays a lawful, auditable AGPL derivative of upstream.

Two forces pull in opposite directions, and every rule below resolves one of them:

- **Brand** — users must not see the upstream vendor's name, trademark, or sales pitch.
- **Provenance** — AGPL-3.0 obliges us to keep upstream's copyright notices, license text, and "this is a modified fork" statement. Removing those would *violate* the license, not merely be undesirable.

So: **replace brand in human-facing output; never in identifiers or attribution.**

## -1. CRITICAL SAFETY GUARD: Protecting Uncommitted Work

Before executing any script, find-and-replace, or edit across the repository, the AI agent **must** adhere to these absolute safety rules:

1. **NEVER use destructive git commands (`git checkout --`, `git reset --hard`, `git clean`) on uncommitted files.** The working tree may contain uncommitted feature work (e.g., `src/oidc/`) that is not yet in Git. Running `git checkout --` will permanently destroy that work. If an edit or header script goes wrong, fix the file surgically in place or ask the user.
2. **Never run blind bulk scripts over `src/oidc/` or other fork-owned feature modules** without reading the existing file header first. If a file already has a license header, replace only the comment block lines rather than prepending a duplicate header.
3. **Always inspect before replacing.** Limit regex/find-and-replace scope strictly to targeted files—never run blind global replacements across the entire `src/` tree.

---

## 0. Golden rules

1. **Never touch identifiers.** Cargo package/crate names, npm/Swift package names, env-var prefixes (`ZO_*`, `ZINC_*`), and cfg-shim paths (`o2_enterprise`) are contracts. Renaming them breaks the build, the deploy pipeline, or the enterprise pairing — for zero visible branding gain.
2. **Never strip upstream copyright.** Headers, the `LICENSE` file, and fork/provenance lines stay. This is the license, not legacy cruft.
3. **Never do a blind global find-and-replace.** `openobserve` appears as brand, as identifier, and as URL. Each occurrence needs a decision.
4. **Prefer a configurable brand over a hardcoded one.** One source of truth read at runtime beats literals scattered across components.
5. **Prove it.** Every run ends with the gates below; a rebrand that doesn't build is worth nothing.

## 1. Decision table — what to change per occurrence

Classify *before* editing. When in doubt, ask which one the occurrence is:

| Category | Examples | Action |
|---|---|---|
| Human-facing text | `Starting OpenObserve …`, CLI `.about(...)`, `description`, `document.title`, i18n strings, comments naming the product to a reader | ✅ Replace |
| Artifact / output filename | `target/release/openobserve`, `CMD ["/openobserve"]`, Docker `COPY` | ✅ Rename (see §3) |
| Upstream provenance | `Copyright … OpenObserve Inc.`, `This file is part of …, a modified fork of OpenObserve`, `Original project: https://github.com/openobserve/openobserve`, README badges | ❌ Keep |
| Rust crate/package names | `openobserve-core`, `openobserve-api-http`, the root `name = "openobserve"` | ❌ Keep |
| Enterprise shim + cfg paths | `o2_enterprise`, `o2_openfga`, `o2_dex`, `#[cfg(feature = "enterprise")]`, `src/enterprise/` | ❌ Keep |
| External SDK / package names | `@openobserve/browser-rum`, `@openobserve/browser-logs`, `openobserve-sdk-ios` | ❌ Keep |
| Upstream forks of third-party deps | `tantivy = { git = "https://github.com/openobserve/tantivy" }` | ❌ Keep |
| Env-var prefixes | `ZO_ROOT_USER_EMAIL`, `ZINC_QUOTA_THRESHOLD` | ❌ Keep |
| Product-feature names | `O2 Assistant` (an AI feature, not the vendor) | ❌ Keep unless renaming the feature is the goal |

`rg` output is not a to-do list — it is a list of decisions. Count first, classify, then edit.

## 2. Make the brand configurable

One module owns the product name; everything reads from it. Follow the repo's existing env-flag convention (see `web/src/aws-exports.ts` and the `fontLicensePlugin` in `web/vite.config.ts`).

```text
web/src/constants/brand.ts   →  DEFAULT_APP_NAME + resolveAppName(env) reading VITE_APP_NAME
web/src/aws-exports.ts       →  appName: resolveAppName(import.meta.env)   // alongside other env flags
web/src/router/index.ts      →  document.title = `${config.appName} - ${title}`
web/index.html               →  <title>%APP_NAME%</title>
web/vite.config.ts           →  tiny transformIndexHtml plugin substituting the default
```

Why a Vite plugin for `index.html`: the static `<title>` is evaluated before any JS runs, so a runtime-only value would leave a literal `%APP_NAME%` on first paint. The plugin mirrors `fontLicensePlugin`'s existing pattern instead of introducing a new mechanism.

Default is the fork's own name (`ExposedObserve`); operators override with `VITE_APP_NAME` at build time. Keep the fallback in code so an unset variable never yields an empty title.

## 3. The binary name (and why not the packages)

Cargo derives the artifact name from `package.name`. Since we keep the package name (§1), rename the **target** instead:

```toml
[package]
name = "openobserve"          # unchanged — keeps all crate deps and cfg paths valid

[[bin]]
name = "exposedobserve"       # ← the artifact becomes target/release/exposedobserve
path = "src/main.rs"
```

**Then update every consumer of the filename**, or image builds break with a missing-file error:

- `deploy/build/Dockerfile*` — `COPY … /openobserve`, `CMD ["/openobserve"]`, `RUN ["/openobserve", "init-dir"]`
- release/download scripts that fetch or name the artifact
- CI paths, `docker-compose` `command:`/`entrypoint:`, systemd units, Helm values

Check whether the Dockerfile variant is ours or upstream CI's before editing — prefer the tagged release variants for our own images.

Renaming the *packages* (`openobserve-*` → `exposed-*`) is legal under AGPL but is a large, low-value refactor: it touches every crate manifest, every `use openobserve_…` import, and `Cargo.toml.openobserve` in the o2-enterprise repo, and it manufactures merge conflicts at every upstream sync. Recommend **against** unless the user explicitly asks for it.

## 4. CLI and log output

Startup and `--help` are high-visibility brand surfaces; sweep them explicitly rather than waiting for a grep to find them.

- **CLI**: `Command::new("openobserve")` (the program name in usage/errors) → our name; `.about(clap::crate_description!())` inherits `description` from `Cargo.toml`, so that must be reworded too; audit every subcommand `.about("… openobserve data …")`.
- **Startup logs**: the "Starting …" line and any component banners naming the product.
- **Package metadata**: `description`, `homepage`, `repository`, and `keywords` in `Cargo.toml` — these surface in `--version`, on crates.io-style listings, and in generated docs.

Rule of thumb: if the string is printed to a terminal or rendered in a browser, it is brand and it changes.

### 4.1 The string-embedding surfaces a grep for the product name misses

A plain search for `OpenObserve` finds literals, but brand also hides inside **composed** strings and in subsystems whose output leaves the process. Sweep these by category, not by one search:

- **Telemetry / analytics event names** — `send_track_event("OpenObserve - …")`, `send_keyevent_track_event(...)`. These are the ones most often missed because the vendor name is glued to a suffix with a hyphen (`"OpenObserve - Starting server"`). Search `send_track_event`, `send_keyevent`, `event_name`.
- **Alert subjects and notification bodies** — Slack/email/webhook titles built with `format!("[OpenObserve Synthetics] …")`. These reach end users directly, so they are the most brand-sensitive strings in the codebase, and they are usually far from any "startup" or "CLI" concept.
- **Module doc-comments and inline comments** naming the product — lower priority (not user-visible), but change them when you are already editing the file so the diff stays coherent.
- **Test fixtures that assert on those literals** — a test like `assert!(event_name.contains("OpenObserve"))` breaks the moment the string is renamed. Fix them in the same pass, or the suite goes red for a reason unrelated to your change.

Procedure: search the *sink* function (`send_track_event`, `format!` inside subject builders, `log::info!`) and read every call site, rather than searching the brand string and trusting the result. Files behind `#[cfg(feature = "cloud")]` or `enterprise` do not compile in a default build, so clippy will not catch a miss there — grep them explicitly.

`"Hello, OpenObserve!"` in a test fixture and doc-comments describing upstream's own OTEL extensions are harmless; leave them.

## 5. License headers on fork-owned files

AGPL-3.0 §5a requires modified files to carry prominent notices that they were changed, and the license text to be preserved. New fork-authored files get a header that does both: names the fork, credits upstream, states the origin file, and carries the AGPL grant.

Canonical form for this fork — note the **double space** in `PURPOSE.  See the`, which matches the upstream header; copy an adjacent upstream file's exact spacing rather than normalizing it:

```text
// Copyright (C) 2026 <fork author>
//
// This file is part of <ForkName>, a modified fork of OpenObserve.
// OpenObserve is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// Original project: https://github.com/openobserve/openobserve
//
// This file was created independently to <what it adds>.
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
```

Applying it consistently:

1. **Inventory the fork's own files first** (`git status` plus the diff against the upstream tag) — don't sweep the whole tree; upstream files keep their headers untouched.
2. **One canonical wording, every file.** Variant headers (a short two-line form, a version missing the license paragraph) are drift: normalize them to the canonical text.
3. **Comment syntax follows the file type**: `//` for `.rs`/`.ts`/`.js`, `<!-- … -->` for `.vue`, `#` for shell/TOML if used.
4. **Keep the year honest** — the year of authorship, matching the current calendar year for new work; don't restate the upstream copyright line.
5. **New fork files must not ship an upstream-only header** claiming `Copyright <year> OpenObserve Inc.` for code we wrote.

Never "fix" the year inside upstream files — that header describes upstream's authorship of upstream's code.

### 5.1 Modified upstream files — the `Modifications Copyright` line

The canonical header above covers **new** fork-authored files. It is **not** enough for an upstream file you edited: AGPL-3.0 §5(a) requires that the work "carry prominent notices stating that you modified it, and giving a relevant date", and §5(b) requires keeping the upstream notices intact. A modified upstream file therefore needs an *addition*, never a replacement — leave `Copyright <year> OpenObserve Inc.` exactly as it is and add your own line directly beneath it:

```text
// Copyright 2026 OpenObserve Inc.
// Modifications Copyright (C) 2026 <fork author>
//
// This program is free software: ...
```

Rules:

- **Add, never replace.** Deleting or rewriting the upstream copyright line is the one thing that turns a lawful fork into a licensing violation.
- **Add immediately after the upstream copyright line**, before the license paragraphs, so the notice stays attached to the copyright block.
- **Only for files whose content you changed.** A file you merely opened, or a repo-wide mechanical rename that did not alter it, keeps the upstream header untouched. Blanket-inserting the line across a whole directory manufactures noise and false claims of authorship.
- **Give a real date** — the year the modification was made, not the year the upstream file was written and not a future year.
- **Comment syntax follows the file type**: `//` for `.rs`/`.ts`/`.js`, `<!-- … -->` for `.vue`, `#` for shell/TOML/YAML.
- A one-line diff (a log string, a translated literal) needs the notice just as much as a 500-line refactor — §5(a) is per-file, not per-diff-size.

Sourcing the list of modified files, when the work is uncommitted or stacked on an upstream tag:

```bash
git diff <upstream-tag> --name-only -- src/ web/src/ Cargo.toml
git status --porcelain
```

Exclude generated/lock files (`Cargo.lock`, `package-lock.json`, `web/dist/`) — those carry no per-file header.

## 6. Stripping upstream vendor/enterprise promo

The OSS build still ships sales surfaces for the vendor's paid tier. In this codebase they are:

- a header CTA button (upgrade-to-enterprise) plus the dialog it opens;
- onboarding/trial pages (trial CTA, vendor terms/privacy links, marketing banner, `© Vendor` footer);
- vendor docs/website links in feature dialogs;
- i18n strings carrying the pitch (`get_enterprise_free`, `enterprise_offer.*`, `startTrialButton`, `copyrightNotice`).

Remove the whole path, not just the button:

1. Delete the CTA **and** the dialog component, its import, its registration, its state/refs/computed, and any now-dead scoped CSS keyed to its `data-test`.
2. Delete an orphaned component only if nothing else references it; otherwise neutralize its content.
3. Replace promo copy with neutral equivalents ("Get Started" instead of "Start your 14-day Trial"); keep layouts intact so the UI still reads as finished.
4. Point the footer at the configurable brand (§2) and the live year.
5. Sweep the English locale for the pitch strings. Other locales fall back to `en-US` — translating the marketing copy in every language is optional follow-up, not a blocker.
6. **Before deleting a component, check for tests that assert on it.** A `data-test` selector in a spec means the spec breaks; either update the spec in the same pass or delete it alongside the component.

## 7. Working against an upstream-tracked fork

The repo carries fork work on top of an upstream tag, and that work may be uncommitted. Operational habits that keep the diff rebaseable:

- **Establish the baseline before editing**: `git describe --tags --abbrev=0 --match "v*[0-9]*"`, `git status --porcelain`, and `git diff <tag> --stat`. Know which files are ours vs. inherited — a rebrand that assumes "all files are mine" will touch upstream code that needed no change.
- **Minimise edits to upstream files.** Every hunk in `Header.vue`, `GetStarted.vue`, or `en-US.json` is a future merge conflict. Push behaviour into new files (`brand.ts`, a Vite plugin) wherever the architecture allows — that is the single biggest lever on rebase cost.
- When a change *must* touch an upstream file, keep it surgical (one expression, one block) and easy to re-derive after a sync.
- After an upstream sync, expect the promo dialog, the header CTA, and the hardcoded title to **return from upstream** and be swept again. Re-apply by pattern, not from memory.
- Don't judge the result from a stale `web/dist/` — it's gitignored build output; rebuild or read the source.

## 8. Graphical assets and trademarks

Text renames are the easy half; the **logo** is the strongest trademark signal and the one users recognise fastest.

- Inventory every vendor-branded image and where it's used: light/dark/favicon/banner variants often live as separate files.
- Prefer a single **colour-adaptive** mark (`currentColor`, no hardcoded fill) plus a `<title>` for screen readers, so one file serves light and dark backgrounds. If a mark is hardcoded to a dark colour it vanishes on a dark banner, and a second hand-drawn variant becomes a permanent maintenance tax.
- If an asset is missing (no banner or wordmark of ours exists yet), removing the vendor's background image and using the mark alone is preferable to shipping someone else's artwork.
- Replace in every slot that references it — including the HTML favicon — and delete the old files once unreferenced.
- Asset filenames are internal, but a leading `o2_`/`openobserve_` prefix is a needless tell; renaming a file plus its import sites is cheap and safe.

### 8.1 Logos: separate the product mark from the vendor's other artwork

A grep for the vendor name in asset paths returns several unrelated things. Classify before replacing — only the **product mark** is yours to change:

| Asset | What it is | Replace? |
|---|---|---|
| Header/login wordmark | the product logo | ✅ yes |
| Pipeline destination icon + `value: "openobserve"` | a **wire format** — the value is persisted in users' pipeline configs | ❌ no |
| Provider icon in a model-pricing list | marks the *source* of a price row | ❌ no |
| An AI-feature icon (`o2_ai_logo`) | a feature's own icon, like a feature's own name | ❌ no |

Renaming a wire value or a persisted identifier breaks existing user data; that is a migration, not a rebrand.

### 8.2 Make the logo path configurable, and mind the aspect ratio

Expose the logo through env (`VITE_LOGO_LIGHT` / `VITE_LOGO_DARK`) resolved in the brand module, so a white-label build swaps artwork without touching components.

Two constraints decide the default filenames:

- **Keep `light`/`dark` in the default filenames.** Existing specs assert `expect(src).toContain("light")` / `toContain("dark")`; a shared neutral name breaks them. The substring, not the whole path, is what the tests bind to.
- **Expect a wordmark slot to hold a square mark.** Vendor wordmarks are wide (893×239); a square glyph in a `h-8 max-w-37.5` slot renders as a small icon. That is a real visual change — decide deliberately rather than discovering it in review.

Two more traps when the logo becomes a runtime value:

- **Options API components need it returned from `setup()`.** A template cannot see a module import; `config` must appear in the returned object or it is `undefined` at render time.
- **Component tests mock the config module.** Every `vi.mock("@/aws-exports", …)` needs the new logo fields, or the component reads `undefined` and the whole suite fails. A mock without them is the usual cause of a sudden "41 tests failed" after adding one config field.

## 9. Gates

Run after every change set; never hand off a rebrand that hasn't been built.

```bash
# Rust
cargo fmt --all
cargo clippy --workspace --all-targets -- -W clippy::too_many_lines -W clippy::cognitive_complexity -W clippy::excessive_nesting -D warnings
cargo build            # confirm the artifact name actually changed: target/debug/<name>

# Web
cd web && npm run format:check   # fix a flagged file with `npx prettier --write <file>`
npm run type-check
```

- Touching `#[cfg(feature = "enterprise")]` code? Default features don't compile it, so a green local check proves nothing — verify with the o2-enterprise `Cargo.toml.openobserve` swap, or state in the PR that it wasn't checked.
- Run the unit tests covering changed components (`npx vitest run src/components/Header.spec.ts`, …). A rebrand that leaves a red spec behind is unfinished.
- If only web changed, skip the Rust gates and vice versa.

## 10. Checklist

- [ ] Baseline captured: tag, `git status`, diff vs. upstream; fork-owned files inventoried
- [ ] Every brand occurrence classified (brand / identifier / provenance) — no unclassified leftovers
- [ ] Brand name centralised and overridable (`VITE_APP_NAME`), consumed by title, footer, header
- [ ] `[[bin]]` renamed **and** every Dockerfile/script consumer updated; artifact name confirmed on disk
- [ ] CLI program name, `--help` about, subcommand help, startup logs, package metadata swept
- [ ] String-embedding surfaces swept by sink, not by brand grep (§4.1): telemetry event names, alert subjects, test fixtures asserting on them
- [ ] License headers: canonical, correct year, correct comment syntax, upstream files untouched
- [ ] Every **modified** upstream file carries a `Modifications Copyright` line beneath the untouched upstream copyright (§5.1)
- [ ] Vendor promo removed end-to-end (CTA → dialog → copy → locale strings), no dead CSS/imports left
- [ ] Logo/favicon swapped everywhere; mark works on light and dark; old assets unreferenced
- [ ] Logo paths configurable via env; default filenames keep `light`/`dark` so path assertions still hold (§8.2)
- [ ] Gates green: `cargo fmt`, CI clippy, `cargo build`, `npm run format:check`, type-check, touched specs
- [ ] Upstream-provenance lines (copyright, license text, original-project URL) still intact
