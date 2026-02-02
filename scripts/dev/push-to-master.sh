#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Navigate to the root of the repository
cd "$SCRIPT_DIR/../../"

MASTER_BRANCH="master"

if [ -z "$1" ]; then
    echo "Usage: ./scripts/dev/push-to-master.sh <tag_name>"
    exit 1
fi

TARGET_TAG=$1
TEMP_SYNC_BRANCH="eo-sync-$TARGET_TAG"

echo "--- Starting safety checks ---"

# 1. Check if sync branch exists
if ! git rev-parse --verify "$TEMP_SYNC_BRANCH" >/dev/null 2>&1; then
    echo "Error: Branch $TEMP_SYNC_BRANCH not found locally."
    exit 1
fi

# 2. Ensure rebase is not stuck in conflict state
if [ -d ".git/rebase-merge" ] || [ -d ".git/rebase-apply" ]; then
    echo "Error: Rebase is in progress. Please finish it before pushing."
    exit 1
fi

# 3. Verify target tag is actually the base of the sync branch
if ! git merge-base --is-ancestor "$TARGET_TAG" "$TEMP_SYNC_BRANCH"; then
    echo "Error: Integrity check failed! $TARGET_TAG is not in the history of $TEMP_SYNC_BRANCH."
    exit 1
fi

echo "Checks passed. Updating $MASTER_BRANCH pointer..."

# 4. Backup and update master
git checkout $MASTER_BRANCH
git branch -f "${MASTER_BRANCH}-backup-$(date +%s)"
git reset --hard "$TEMP_SYNC_BRANCH"

# 5. Final Force Push
echo "Force-pushing to origin/$MASTER_BRANCH..."
if git push origin $MASTER_BRANCH --force-with-lease; then
    echo "-------------------------------------------------------"
    echo "DONE: Your fork is now updated to $TARGET_TAG"
    echo "-------------------------------------------------------"
    
    read -p "Cleanup: Delete temporary branch $TEMP_SYNC_BRANCH? (y/n): " cleanup
    if [[ $cleanup == [yY] ]]; then
        git branch -D "$TEMP_SYNC_BRANCH"
    fi
else
    echo "Push failed! Check for remote changes."
    exit 1
fi