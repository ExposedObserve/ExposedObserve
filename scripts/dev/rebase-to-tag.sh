#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Navigate to the root of the repository
cd "$SCRIPT_DIR/../../"

# Configuration
UPSTREAM_URL="https://github.com/openobserve/openobserve.git"
UPSTREAM_NAME="upstream"
MASTER_BRANCH="master"

# 0. Check for ANY uncommitted changes (staged, unstaged, and untracked)
# Using porcelain for a reliable machine-readable check
# if [ -n "$(git status --porcelain)" ]; then
#     echo "-------------------------------------------------------"
#     echo "ERROR: Working directory is not clean!"
#     echo "Please commit, stash, or discard changes before rebasing."
#     echo "-------------------------------------------------------"
#     git status -s
#     exit 1
# fi

# 1. Ensure upstream is configured
if ! git remote | grep -q "$UPSTREAM_NAME"; then
    echo "Remote '$UPSTREAM_NAME' not found."
    read -p "Do you want to add $UPSTREAM_URL as '$UPSTREAM_NAME'? (y/n): " confirm
    if [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]]; then
        git remote add $UPSTREAM_NAME $UPSTREAM_URL
    else
        echo "Aborting: Upstream remote is required."
        exit 1
    fi
fi

# 2. Fetch updates
echo "Fetching updates from $UPSTREAM_NAME..."
git fetch $UPSTREAM_NAME --tags --quiet

# 3. Handle Tag Selection
TARGET_TAG=$1
if [ -z "$TARGET_TAG" ]; then
    echo "-------------------------------------------------------"
    echo "No tag specified. Latest 5 tags from upstream:"
    git tag -l --sort=-v:refname | head -n 5
    echo "-------------------------------------------------------"
    read -p "Enter the tag you want to rebase onto: " TARGET_TAG
    if [ -z "$TARGET_TAG" ]; then
        echo "Aborting: No tag provided."
        exit 1
    fi
fi

# 4. Verify tag existence
if ! git rev-parse "$TARGET_TAG" >/dev/null 2>&1; then
    echo "Error: Tag '$TARGET_TAG' not found!"
    exit 1
fi

# 5. Pre-rebase Analysis (Diff overview)
echo "-------------------------------------------------------"
echo "ANALYSIS: Your changes in '$MASTER_BRANCH' relative to '$TARGET_TAG':"
git diff --stat "$TARGET_TAG"..."$MASTER_BRANCH"
echo "-------------------------------------------------------"

# PROMPT: Allow user to exit after seeing the diff
read -p "Do you want to proceed with the rebase onto $TARGET_TAG? (y/n): " proceed
if [[ $proceed != [yY] ]]; then
    echo "Aborting. No changes were made."
    exit 0
fi

# 6. Safety check for older versions
CURRENT_BASE=$(git merge-base $MASTER_BRANCH $UPSTREAM_NAME/main)
if git merge-base --is-ancestor "$TARGET_TAG" "$CURRENT_BASE" && [ "$TARGET_TAG" != "$(git describe --tags $CURRENT_BASE 2>/dev/null)" ]; then
    echo "Warning: $TARGET_TAG appears to be older than your current base."
    read -p "Are you sure you want to proceed anyway? (y/n): " confirm_old
    [[ $confirm_old != [yY] ]] && exit 1
fi

TEMP_SYNC_BRANCH="eo-sync-$TARGET_TAG"

# 7. Prepare temporary sync branch
echo "Creating temporary branch $TEMP_SYNC_BRANCH from $MASTER_BRANCH..."
git checkout $MASTER_BRANCH
git pull origin $MASTER_BRANCH --quiet
git checkout -b "$TEMP_SYNC_BRANCH"

# 8. Execute Rebase
echo "Rebasing custom changes onto $TARGET_TAG..."
if git rebase "$TARGET_TAG"; then
    echo "-------------------------------------------------------"
    echo "SUCCESS: Rebase completed. No conflicts."
    echo "Next step: ./scripts/dev/push-to-master.sh $TARGET_TAG"
    echo "-------------------------------------------------------"
else
    echo "-------------------------------------------------------"
    echo "CONFLICTS DETECTED!"
    echo "1. Fix them in your IDE."
    echo "2. Run 'git add .'"
    echo "3. Run 'git rebase --continue'"
    echo "4. After finishing, run: ./scripts/dev/push-to-master.sh $TARGET_TAG"
    echo "-------------------------------------------------------"
    exit 1
fi