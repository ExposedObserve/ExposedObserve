---
name: fork-commit-prep
description: Playbook for turning uncommitted work and/or partial WIP commits on top of an upstream OpenObserve tag into a clean, single 4-commit stack (`feat(fork)`, `feat(integration)`, `chore(rebrand)`, `chore(lock)`) and updating `CHANGELOG.fork.md`. Safe to run multiple times on the same upstream tag after iterative improvements. Pairs with `fork-rebrand` and `fork-sync`.
---

# Preparing & layering fork commits (`fork-commit-prep`)

This skill structures all fork changes sitting on top of an upstream release tag (e.g., `v1.1.0-rc2`) into a **strict, 4-layer commit stack** on your working branch (`eo-dev`, `eo-dev-*`, or `master`).

It works both for a **first-time commit** (dirty working tree directly on the tag) and for **re-runs after iterative changes** (when partial commits or an earlier 4-commit stack already exist on top of the tag).

## -1. CRITICAL SAFETY GUARD: Never Lose Work

1. **NEVER run destructive git commands (`git checkout --`, `git reset --hard`, `git clean`)** that discard working-tree changes.
2. When collapsing existing partial commits back to `$BASE_TAG` on a re-run, **ONLY use `git reset $BASE_TAG` (mixed/soft reset)**, which keeps 100% of file modifications intact on disk.
3. Before resetting or restaging, create a lightweight backup ref (`git branch -f backup/pre-commit-prep HEAD`) so the previous state can be restored instantly if needed.

---

## 0. Golden rules of commit preparation

1. **Always compare against `$BASE_TAG`, never just `HEAD`.** `git status` only compares against the last commit. To see the true delta of the fork, always compare against the upstream tag (`v*`).
2. **Always maintain a single 4-commit stack per upstream tag.** If you add more changes later (before upgrading upstream), do not pile commit #5, #6, #7 on top—unstage the existing stack back to `$BASE_TAG` (`git reset $BASE_TAG`) and re-build the 4 clean commits.
3. **Never mix "our feature wiring" and "cosmetic rebranding" in the same commit.** Untangle mixed files at the hunk level (`git add -p`).
4. **Never touch upstream's `CHANGELOG.md`.** All fork release notes go into `CHANGELOG.fork.md`.

---

## 1. Establish the baseline & flatten partial commits (if re-running)

```bash
# 1. Find the exact upstream tag (matching "v*", ignoring our own "eo-v*" tags)
BASE_TAG=$(git describe --tags --abbrev=0 --match "v*[0-9]*")
echo "Upstream base tag: $BASE_TAG"

# 2. Ensure we are on a valid fork branch (e.g., eo-dev, eo-dev-*, master), NOT detached HEAD
git branch --show-current

# 3. Check if there are already partial or previous fork commits between $BASE_TAG and HEAD
COMMIT_COUNT=$(git rev-list --count "$BASE_TAG..HEAD")
echo "Existing commits on top of $BASE_TAG:$COMMIT_COUNT"
```

**If `COMMIT_COUNT > 0` (Second+ run or partial commits exist):**
Do not stack duplicate layers on top of old commits. Flatten the commits back into the working tree without touching any files on disk:

```bash
# Save a safety pointer to the current HEAD just in case
git branch -f backup/pre-commit-prep HEAD

# Uncommit everything back to $BASE_TAG while keeping all file changes on disk intact
git reset "$BASE_TAG"
```

Now `HEAD` is at `$BASE_TAG`, and **100% of your fork's work** (both previously committed and newly edited) is sitting safely in the working tree ready to be classified against `$BASE_TAG`.

---

## 2. True Comparison against `$BASE_TAG` (The 3 Change Categories)

Because `HEAD` now points directly to `$BASE_TAG`, inspect the full delta between the upstream tag and your disk using two commands:

```bash
# Tracked files that were Added (A), Modified (M), or Deleted (D) vs. $BASE_TAG:
git diff --name-status "$BASE_TAG"

# Untracked new files not yet known to Git:
git ls-files --others --exclude-standard
```

Every file falls into one of three Git states relative to `$BASE_TAG`, which map into our **4 Commit Buckets**:

### Category A: New Functionality (Not in `$BASE_TAG` — Untracked / Added)

Files that did not exist in the upstream tag at all:

- **Bucket 1 (Isolated Fork Modules):** `src/oidc/**`, `web/src/constants/brand.ts`, new SVG logos, `CHANGELOG.fork.md`, `.github/workflows/*` (if fork-specific).

### Category B: Modified Functionality (Existed in `$BASE_TAG` and changed — `M`)

Files that existed in `$BASE_TAG` and were modified by us. You **must** split these into three sub-types:

- **Bucket 2 (Upstream Feature Hooks):** Surgical edits in upstream files that wire up our new functionality (e.g., `mod oidc;` in `src/main.rs` or `lib.rs`, HTTP router registration, auth middleware, new OIDC crate dependencies in `Cargo.toml`).
- **Bucket 3 (Rebrand & Config Edits):** Edits in upstream files that change branding, binary names, or remove references to deleted promo components (`Cargo.toml` `[[bin]]`, `Dockerfile*`, `Header.vue`, `en-US.json`, `vite.config.ts`, `index.html`).
- **Bucket 4 (Lockfiles):** `Cargo.lock`, `web/package-lock.json`, `web/yarn.lock`.

### Category C: Deleted Files (Existed in `$BASE_TAG` and removed — `D`)

Files that existed in the upstream tag and were deleted by us:

- **Bucket 3 (Promo & Old Asset Removal):** Deleted upstream enterprise promo dialogs (`.vue`), their unit tests (`.spec.ts`), and replaced upstream logo files. *(Must be committed together with Bucket 3 so removing the file and removing its `import` happen in the same commit).*

### Handling "Mixed" Category B Files

Inspect modified files (`git diff "$BASE_TAG" -- <file>`) that contain **both** Bucket 2 (feature wiring) and Bucket 3 (rebranding) changes—typically `Cargo.toml`, `src/main.rs`, or `web/src/aws-exports.ts`.

- Stage their **Bucket 2** hunks during Pass 2 (`git add -p <file>`).
- Leave their **Bucket 3** hunks for Pass 3.

---

## 3. Pre-commit Hygiene & Gates

Before creating the commits:

1. **License headers (`fork-rebrand` §5):** Ensure every Category A (new fork-owned) code file has the canonical AGPL-3.0 fork header.
2. **Noise check:** Inspect `git diff "$BASE_TAG"` on Category B files and revert accidental formatting/whitespace noise (`git checkout -p <file>` — only on unintentional whitespace hunks, never whole files!).
3. **Gates (`fork-rebrand` §9):** Run `cargo fmt --all -- --check`, `cargo clippy`, `cargo build`, and `cd web && npm run format:check && npm run type-check`.

---

## 4. Update `CHANGELOG.fork.md`

Create or update `CHANGELOG.fork.md` at the repo root (leave upstream's `CHANGELOG.md` untouched). Document changes relative to `$BASE_TAG` under three clear sections matching our categories:

```markdown
# Fork Changelog

## [eo-<BASE_TAG>] - YYYY-MM-DD
**Upstream Baseline:** `<BASE_TAG>`

### Added (New Fork Functionality — not in upstream tag)
- **OIDC / SSO (`src/oidc/`):** <capabilities, endpoints, config vars>.
- **Brand Config (`web/src/constants/brand.ts`):** Configurable brand name via `VITE_APP_NAME`.

### Changed (Modified from upstream tag)
- **Feature Integration:** Wired OIDC routes and auth middleware into upstream HTTP router.
- **Rebrand & Build:** Renamed `[[bin]]` target to `exposedobserve`, updated `Dockerfile*` paths, CLI help, and HTML title.

### Removed (Deleted from upstream tag)
- Stripped upstream enterprise upgrade CTAs, trial dialogs, and vendor promo components/locales.
```

---

## 5. Build the 4-Commit Stack

Execute the 4 passes in strict order:

### Pass 1: Bucket 1 — New Isolated Fork Files (`feat(fork)`)

```bash
git add src/oidc/ web/src/constants/brand.ts CHANGELOG.fork.md <other-new-fork-files>
# Verify only new files ('A') are staged against $BASE_TAG:
git diff --cached --name-status
git commit -m "feat(fork): add isolated fork modules, brand config, and changelog"
```

### Pass 2: Bucket 2 — Modified Upstream Files for Feature Hooks (`feat(integration)`)

```bash
# Add pure feature-hook files, and use `git add -p` for mixed files (like Cargo.toml / main.rs):
git add <feature-hook-files>
git diff --cached   # Verify: only functional hooks/deps, zero branding or promo edits!
git commit -m "feat(integration): wire fork features into upstream server and UI"
```

### Pass 3: Bucket 3 — Modified & Deleted Files for Rebranding (`chore(rebrand)`)

```bash
# Stage all remaining modified ('M') and deleted ('D') tracked files, plus any new logo assets:
git add -u
git add <new-logo-assets-if-any>
# Exclude lockfiles for Pass 4:
git reset HEAD Cargo.lock web/package-lock.json web/yarn.lock 2>/dev/null || true
git diff --cached --name-status   # Verify: only 'M' and 'D' rebrand/promo files
git commit -m "chore(rebrand): apply ExposedObserve branding and strip vendor promo"
```

### Pass 4: Bucket 4 — Lockfiles (`chore(lock)`)

```bash
git add Cargo.lock web/package-lock.json web/yarn.lock 2>/dev/null || true
git diff --cached --quiet || git commit -m "chore(lock): update dependency lockfiles"
```

---

## 6. Final Verification

1. `git status --porcelain` must be **empty** (nothing untracked or left unstaged).
2. `git log --oneline "$BASE_TAG..HEAD"` must show **at most 4 commits** sitting cleanly on `$BASE_TAG`.
3. `git diff backup/pre-commit-prep..HEAD` (if re-run) must be **empty** (confirming zero code was lost or altered during restacking), after which you can delete the temporary pointer (`git branch -d backup/pre-commit-prep`).
