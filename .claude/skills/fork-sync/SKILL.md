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

   `git describe` picks the tag by **tag date**, not by distance to HEAD. If the fork's
   newer upstream tags were never pushed to the fork repo, it silently returns an old
   `v0.x` tag and the rebase below lands on the wrong base. Sanity-check it:

   ```bash
   git merge-base --is-ancestor "$OLD_TAG" HEAD \
     || echo "WARN: $OLD_TAG is not an ancestor of HEAD — the base tag is wrong"
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

*(Note: CI bakes `GIT_VERSION` from `git describe --tags --abbrev=0 --match "v*"`, run after a checkout of the **fork** repo only. Rebasing onto `<new-tag>` does not move the tag — `<new-tag>` must exist as a tag in the fork repo, which is what Step 4.5 does. Without it CI resolves an old `v0.x` tag and bakes the wrong version into the binary.)*

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
   - Check the root `Dockerfile` for any new `/openobserve` binary references (**`fork-rebrand` §3**).
2. Run all **`fork-rebrand` §9** gates (`cargo fmt`, `cargo clippy`, `cargo build`, `npm run format:check`, `npm run type-check`, and unit specs).
3. Update `CHANGELOG.fork.md` with a new `## [eo-<new-tag>]` section documenting the upstream bump.
4. Run **`fork-commit-prep`** if needed to fold any new rebrand fixes and regenerated lockfiles back into the clean 4-commit stack.
5. **Mirror the upstream tags into the fork repo.** CI checks out the fork, so the fork must carry `<new-tag>` itself — otherwise `git describe` falls back to an old `v0.x` tag and bakes that wrong version into the binary:

   ```bash
   git fetch upstream --tags --prune
   # Push only the tags the fork is missing; existing tags are left untouched.
   git push origin $(comm -23 \
     <(git ls-remote --tags upstream | grep -v '\^{}' | sed 's|.*refs/tags/||' | sort) \
     <(git ls-remote --tags origin   | grep -v '\^{}' | sed 's|.*refs/tags/||' | sort))
   ```

   Verify from a clean clone of the fork (this is exactly what CI sees):

   ```bash
   git clone --bare --quiet https://github.com/ExposedObserve/ExposedObserve.git /tmp/forkcheck.git
   git -C /tmp/forkcheck.git describe --tags --abbrev=0 --match "v*" origin/eo-dev
   # must print <new-tag>
   ```
6. **Update `eo-dev` / `master` and push.** After a rebase onto `<new-tag>` the
   remote branches still point at the old pre-rebase history, so a **fast-forward is
   impossible** — `<new-tag>` is not an ancestor of `origin/master`. Check which case
   you are in instead of assuming:

   ```bash
   git merge-base --is-ancestor origin/master HEAD \
     && echo "FF possible" || echo "FF impossible — force-update required"
   ```

   For the FF-impossible case, move the branch and push with a lease:

   ```bash
   git branch -f backup/pre-<new-tag>-master master
   git branch -f backup/pre-<new-tag>-eo-dev eo-dev
   git branch -f master HEAD
   git branch -f eo-dev HEAD
   git push --force-with-lease origin master eo-dev
   ```

   `--force-with-lease` refuses the push if the remote moved since your last fetch —
   never use a bare `--force` here.

7. **Tag the release** as an annotated tag on the final commit, then push it:

   ```bash
   SHORT=$(git rev-parse --short=10 HEAD)
   TAG="eo-<new-tag>-${SHORT}"
   git tag -a "$TAG" -m "ExposedObserve fork release based on upstream <new-tag>" HEAD
   git push origin "$TAG"
   ```

8. **Verify the remote actually moved.** Never report the sync as done on the strength
   of local refs:

   ```bash
   git ls-remote --heads origin master eo-dev
   git ls-remote --tags origin "eo-<new-tag>*"
   ```

   The hashes must match `git rev-parse master` and `git rev-parse "$TAG"`. A local
   commit is not a pushed commit — the task is only complete once this check passes.

