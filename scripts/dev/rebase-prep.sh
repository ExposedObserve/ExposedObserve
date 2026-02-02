#!/bin/bash

# Get script location and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../../"

# Configuration
UPSTREAM_NAME="upstream"
MASTER_BRANCH="master"
TARGET_TAG=$1

# 1. Quietly fetch data
git fetch $UPSTREAM_NAME --tags --quiet

if [ -z "$TARGET_TAG" ]; then
    echo "ERROR: Please provide a target tag (e.g., ./scripts/dev/rebase-prep.sh v1.2.0)"
    exit 1
fi

# Disable pager for the entire script output
export GIT_PAGER=cat

echo "=== SYNC REPORT ==="
echo "Target Tag:  $TARGET_TAG"
echo "Your Branch: $MASTER_BRANCH"
echo "Date:        $(date)"
echo "========================="
echo ""

echo "--- 1. COMMIT LOG (YOUR CUSTOM CHANGES) ---"
# Showing what exactly you did since diverging from the tag
git --no-pager log --oneline --reverse "$TARGET_TAG"..."$MASTER_BRANCH"

echo ""
echo "--- 2. FILE DIFF STAT (OVERVIEW) ---"
# General overview: what is added, modified, or deleted
git --no-pager diff --stat "$TARGET_TAG"..."$MASTER_BRANCH"

echo ""
echo "--- 3. DETAILED CHANGES (MODIFIED FILES ONLY) ---"
# We show ONLY Modified (M) files. 
# Added (A) and Deleted (D) are skipped here because they don't cause code-level merge conflicts.
# This drastically reduces the size of the report.
git --no-pager diff -U1 --diff-filter=M "$TARGET_TAG"..."$MASTER_BRANCH"

echo ""
echo "--- 4. ADDED & DELETED FILES SUMMARY ---"
# Just a quick list of what you added or removed, without the full code.
git --no-pager diff --name-status --diff-filter=AD "$TARGET_TAG"..."$MASTER_BRANCH" | sed 's/^/      /'

# Check for files modified by BOTH sides
git diff --name-only "$COMMON_BASE" "$MASTER_BRANCH" | sort > /tmp/my_changes
git diff --name-only "$COMMON_BASE" "$TARGET_TAG" | sort > /tmp/upstream_changes

COMM_FILES=$(comm -12 /tmp/my_changes /tmp/upstream_changes)

if [ -z "$COMM_FILES" ]; then
    echo "  [OK] No direct file overlaps detected."
else
    echo "  [!] WARNING: These files were modified in BOTH your branch and Upstream:"
    echo "$COMM_FILES" | sed 's/^/      - /'
fi

echo ""
echo "--- 5. DELETED FILES & UPSTREAM UPDATES ---"
# Critical check: did you delete a file that Upstream just updated?
DELETED_BY_US=$(git diff --name-only --diff-filter=D "$TARGET_TAG"..."$MASTER_BRANCH")

if [ -z "$DELETED_BY_US" ]; then
    echo "  [OK] No files were deleted in your branch."
else
    for FILE in $DELETED_BY_US; do
        if grep -q "^$FILE$" /tmp/upstream_changes; then
            echo "  [!!!] DANGER: You deleted '$FILE', but Upstream has NEW UPDATES for it!"
        else
            echo "  [i] Notice: '$FILE' deleted (clean delete, no upstream changes)."
        fi
    done
fi

# Cleanup temporary files
rm -f /tmp/my_changes /tmp/upstream_changes

echo ""
echo "=== END OF REPORT ==="