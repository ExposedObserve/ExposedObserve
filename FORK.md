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

To keep this fork up to date with the original OpenObserve, use the scripts located in `scripts/dev/`.

### 1. Automatic Sync (GitHub Actions)

The branch `main` and all upstream tags are automatically synced via GitHub Actions (`.github/workflows/sync.yml`). You don't need to pull them manually.

### 2. Updating Your Code (Rebase Strategy)

When you want to move your `master` branch to a newer version of OpenObserve:

1. **Analyze changes:** Run `./scripts/dev/rebase-prep.sh <tag_name>` to generate a report.
2. **Start Rebase:** Run `./scripts/dev/rebase-to-tag.sh <tag_name>`. This will create a temporary branch and start the rebase process.
3. **Finish & Push:** After resolving any conflicts, run `./scripts/dev/push-to-master.sh <tag_name>` to update your `origin/master`.
