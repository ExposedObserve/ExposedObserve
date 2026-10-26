---
name: fork-sync
description: Playbook for upgrading the OpenObserve fork (`ExposedObserve`) from an older upstream tag (e.g., v1.1.0-rc2) to a newer upstream release tag (e.g., v1.2.1) using `git rebase --onto`. Relies on the 4-layer commit stack created by `fork-commit-prep` and triggers a post-rebase audit via `fork-rebrand`. Compatible with `master`, `eo-dev`, `eo-dev-*` branches and `eo-v*` release tags. Use when pulling new upstream tags, rebasing fork branches, or resolving upstream sync conflicts.
---

# Upgrading the fork to a new upstream tag (`fork-sync`)

This skill moves our 4-layer fork commit stack (created via **`fork-commit-prep`**) from `<old-tag>` (e.g., `v1.1.0-rc2`) onto `<new-tag>` (e.g., `v1.2.1`) using `git rebase --onto`, and then sweeps new upstream code using **`fork-rebrand`**.

## 1. Pre-flight & Overlap Check

1. Ensure the working tree on your active fork branch (e.g., `eo-dev`) is clean (`git status --porcelain` is empty) and `git config rerere.enabled true` is set.
2. Verify our current upstream base tag (`<old-tag>`) and verify we have a clean 4-commit stack on top of it (if there are messy WIP commits, run **`fork-commit-prep`** first!):

   ```bash
   OLD_TAG=$(git describe --tags --abbrev=0 --match "v*[0-9]*")
   echo "Current upstream base: $OLD_TAG"
   git log --oneline "$OLD_TAG..HEAD"
   ```

3. Fetch tags from `upstream` (`https://github.com/openobserve/openobserve.git`):

   ```bash
   git fetch upstream --tags --prune
   ```

4. Preview which of our modified files were also touched by upstream between `$OLD_TAG` and `<new-tag>`:

   ```bash
   git diff --name-only "$OLD_TAG..HEAD" > /tmp/fork_files.txt
   git diff --stat "$OLD_TAG..<new-tag>" -- $(cat /tmp/fork_files.txt)
   ```

## 2. Branch and `rebase --onto`

Create a dedicated sync/feature branch (matching CI pattern `eo-dev-*`, e.g., `eo-dev-v1.2.1`) and save a backup tag/branch of the current state before rebasing:

```bash
# Save backup reference of the old state
git branch -f "backup/pre-sync-$OLD_TAG" HEAD

# Create a working sync branch and rebase our stack onto <new-tag>
git checkout -b "eo-dev-<new-tag>"
git rebase --onto "<new-tag>" "$OLD_TAG" "eo-dev-<new-tag>"
```

*(Note: because CI uses `git describe --tags --abbrev=0 --match "v*"` to bake `GIT_VERSION` into the binary, rebasing directly onto `<new-tag>` ensures CI automatically picks up `<new-tag>` as `GIT_VERSION`.)*

## 3. Layer-by-Layer Conflict Resolution

Because **`fork-commit-prep`** structured our work into 4 layers, Git replays them in order:

1. **Commit 1 (`feat(fork): isolated modules`):** Touches only fork-owned files (`src/oidc/`, `brand.ts`, `CHANGELOG.fork.md`). Applies with **zero conflicts**.
2. **Commit 2 (`feat(integration): upstream hooks`):** Small surgical hooks in upstream files. If a conflict occurs because upstream refactored a router or struct signature, adapt the hook in place, `git add <file>`, and `git rebase --continue`.
3. **Commit 3 (`chore(rebrand): branding & promo strip`):** Most conflicts happen here (`Header.vue`, `en-US.json`, `Cargo.toml`, `Dockerfile`).
   - **Shortcut for messy UI conflicts:** If upstream heavily rewrote a component we stripped promo from, do **not** waste time merging Vue templates line-by-line. Run `git checkout --theirs <file>` to accept upstream's new file, finish the rebase, and re-strip the promo cleanly during Step 4 using **`fork-rebrand`**.
4. **Commit 4 (`chore(lock): lockfiles`):** If `Cargo.lock` or `package-lock.json` conflicts, never edit by hand:

   ```bash
   git checkout --theirs Cargo.lock web/package-lock.json 2>/dev/null || true
   git add Cargo.lock web/package-lock.json 2>/dev/null || true
   git rebase --continue
   ```

   They will be regenerated cleanly when running the build gates in Step 4.

## 4. Mandatory Post-Rebase `fork-rebrand` Sweep & Finalization

Even if `git rebase --onto` finishes with zero conflicts, `<new-tag>` may have introduced **new** upstream branding, new CLI subcommands, or new enterprise promo surfaces.

1. Run the **`fork-rebrand`** playbook against the rebased branch:
   - Check new/modified UI components for vendor links or enterprise CTAs (**`fork-rebrand` §6**).
   - Check CLI and startup logs for new `"OpenObserve"` literals (**`fork-rebrand` §4**).
   - Check `deploy/build/Dockerfile*` for any new `/openobserve` binary references (**`fork-rebrand` §3**).
2. Run all **`fork-rebrand` §9** gates (`cargo fmt`, `cargo clippy`, `cargo build`, `npm run format:check`, `npm run type-check`, and unit specs).
3. Update `CHANGELOG.fork.md` with a new `## [eo-<new-tag>]` section documenting the upstream bump.
4. Run **`fork-commit-prep`** if needed to fold any new rebrand fixes and regenerated lockfiles back into the clean 4-commit stack.
5. Fast-forward/update `eo-dev` (or `master`) and tag `eo-<new-tag>` when ready to release.
