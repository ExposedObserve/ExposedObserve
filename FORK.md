# About This Fork

This repository is a community-driven fork of OpenObserve, created to extend its capabilities with additional features and improved flexibility.

Why this fork exists:

- To experiment with new authentication methods
- To explore modular architecture
- To maintain a fully open alternative without vendor lock-in

It is not affiliated with the official OpenObserve team.

All modifications are released under the same license: **AGPL-3.0**.

---

## Maintenance & Sync Tools

To keep this fork up to date with the original OpenObserve, follow the `fork-sync`
playbook in `.claude/skills/fork-sync/SKILL.md`.

### 1. Upstream tags must exist in this repo

CI builds the image from a checkout of **this** repo and bakes the version into the
binary with `git describe --tags --abbrev=0 --match "v*"`. Upstream tags therefore
have to be present here — `git fetch upstream --tags` alone is not enough, they must
be pushed to this repo:

```bash
git fetch upstream --tags --prune
git push origin $(comm -23 \
  <(git ls-remote --tags upstream | grep -v '\^{}' | sed 's|.*refs/tags/||' | sort) \
  <(git ls-remote --tags origin   | grep -v '\^{}' | sed 's|.*refs/tags/||' | sort))
```

Skipping this makes CI resolve an old `v0.x` tag and bake the wrong version.

### 2. Updating Your Code (Rebase Strategy)

When you want to move your branch to a newer version of OpenObserve:

1. **Analyze changes:** compare your stack against the upstream tag to see which of
   your modified files upstream also touched.
2. **Start Rebase:** `git rebase --onto <new-tag> <old-tag> <branch>`, replaying the
   4-layer stack created by `fork-commit-prep`.
3. **Finish & Push:** resolve conflicts layer by layer, run the `fork-rebrand` sweep
   and its build gates, then mirror the upstream tags as described above.

### 3. Publishing without breaking the released images

`master` publishes `:latest` and `eo-dev` publishes `:dev` and `:nightly`, so a push
to either replaces an image users pull. A build that has not been seen green yet
should not land there.

Push the work to a candidate branch first. It publishes only `:sha-<short>`, so it
cannot overwrite a released image:

```bash
git push origin HEAD:refs/heads/eo-dev-<tag>
gh run list --branch eo-dev-<tag> --limit 1   # wait for it to go green
```

Only then move the released branches, and tag the result:

```bash
git push --force-with-lease origin master eo-dev
git tag -a "eo-<tag>-$(git rev-parse --short=10 HEAD)" -m "..." HEAD
git push origin "eo-<tag>-$(git rev-parse --short=10 HEAD)"
```

The `eo-dev-*` branches also serve as the place for intermediate builds while a
feature is still being worked on: they build the image without touching the released
tags, so a candidate can be tried out before it is promoted.
