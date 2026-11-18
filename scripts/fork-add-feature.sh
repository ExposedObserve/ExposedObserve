#!/bin/sh
# Incrementally add a feature branch into the 4-layer fork commit stack.
# Usage:
#   scripts/fork-add-feature.sh prepare <feature-branch>
#   scripts/fork-add-feature.sh finalize
#
# prepare: checks preconditions, safety-ref, squash-merges the feature into the
#          working tree, then pauses for manual bucket classification
#          (git add / git commit --fixup per layer).
# finalize: autosquashes the fixup commits back into the 4-layer stack and
#           verifies nothing was lost.
set -eu

usage() {
    echo "Usage: $0 prepare <feature-branch> | finalize" >&2
    exit 2
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

BASE_TAG=""
CURRENT_BRANCH=""
FEATURE_BRANCH=""

find_base_tag() {
    BASE_TAG=$(git describe --tags --abbrev=0 --match "v*[0-9]*" 2>/dev/null) \
        || die "no upstream v* tag found"
}

find_layer_shas() {
    # Order of layers in the stack (oldest first) is defined by the skill:
    # feat(fork) -> feat(integration) -> chore(rebrand) -> chore(lock)
    LAYER_FORK=$(git log --format="%H" "$BASE_TAG..HEAD" --grep="^feat(fork)" -1) \
        || true
    LAYER_INTEGRATION=$(git log --format="%H" "$BASE_TAG..HEAD" --grep="^feat(integration)" -1) \
        || true
    LAYER_REBRAND=$(git log --format="%H" "$BASE_TAG..HEAD" --grep="^chore(rebrand)" -1) \
        || true
    LAYER_LOCK=$(git log --format="%H" "$BASE_TAG..HEAD" --grep="^chore(lock)" -1) \
        || true
    [ -n "$LAYER_FORK" ] || die "feat(fork) layer not found"
    [ -n "$LAYER_INTEGRATION" ] || die "feat(integration) layer not found"
    [ -n "$LAYER_REBRAND" ] || die "chore(rebrand) layer not found"
    [ -n "$LAYER_LOCK" ] || die "chore(lock) layer not found"
}

check_preconditions() {
    CURRENT_BRANCH=$(git branch --show-current) || die "cannot determine branch"
    [ -n "$CURRENT_BRANCH" ] || die "detached HEAD"
    case "$CURRENT_BRANCH" in
        eo-dev|eo-dev-*|master) ;;
        *) die "must run on eo-dev / eo-dev-* / master, not '$CURRENT_BRANCH'" ;;
    esac
    git merge-base --is-ancestor "$BASE_TAG" HEAD \
        || die "$BASE_TAG is not an ancestor of HEAD"
    count=$(git rev-list --count "$BASE_TAG..HEAD")
    [ "$count" -eq 4 ] \
        || die "expected 4 commits on $BASE_TAG..HEAD, found $count — run fork-commit-prep instead"
    git diff --quiet || die "working tree has unstaged changes"
    git diff --cached --quiet || die "index has staged changes"
    if git ls-files --others --exclude-standard | grep -q .; then
        die "untracked files present: $(git ls-files --others --exclude-standard | head -5)"
    fi
}

cmd_prepare() {
    FEATURE_BRANCH=${1:-}
    [ -n "$FEATURE_BRANCH" ] || usage
    find_base_tag
    check_preconditions
    find_layer_shas

    backup="backup/pre-feature-$(echo "$FEATURE_BRANCH" | tr '/ ' '__')"
    git branch -f "$backup" HEAD
    echo "Safety ref: $backup"

    git fetch origin "$FEATURE_BRANCH" 2>/dev/null \
        || die "cannot fetch $FEATURE_BRANCH"
    git merge --no-commit --squash "origin/$FEATURE_BRANCH" \
        || die "merge of $FEATURE_BRANCH failed — resolve and retry"

    git diff --cached --name-only --diff-filter=A > /tmp/fork-owned-files.txt \
        || die "cannot record fork-owned files"

    cat <<EOF

Feature merged into working tree (not committed).
Classify the changes into buckets, then create fixup commits:

  Bucket 1 (feat(fork)):        git add <new-files> CHANGELOG.fork.md
                                git commit --fixup $LAYER_FORK
  Bucket 2 (feat(integration)): git add <hook-files>   # use git add -p for mixed files
                                git commit --fixup $LAYER_INTEGRATION
  Bucket 3 (chore(rebrand)):    git add -u             # usually empty for a feature
                                git commit --fixup $LAYER_REBRAND
  Bucket 4 (chore(lock)):       git add Cargo.lock web/package-lock.json web/yarn.lock 2>/dev/null
                                git commit --fixup $LAYER_LOCK

Then run: $0 finalize
EOF
}

verify_fork_files() {
    while read -r f; do
        git cat-file -e "HEAD:$f" 2>/dev/null || echo "LOST: $f"
    done
}

cmd_finalize() {
    find_base_tag
    find_layer_shas

    count=$(git rev-list --count "$BASE_TAG..HEAD")
    if [ "$count" -eq 4 ]; then
        echo "No fixup commits staged — nothing to finalize." >&2
        exit 1
    fi
    [ "$count" -gt 4 ] || die "unexpected: fewer than 4 commits on $BASE_TAG..HEAD"

    GIT_SEQUENCE_EDITOR=: git rebase -i --autosquash "$BASE_TAG" \
        || die "autosquash rebase failed — git rebase --abort and investigate"

    new_count=$(git rev-list --count "$BASE_TAG..HEAD")
    [ "$new_count" -eq 4 ] \
        || die "expected 4 commits after autosquash, found $new_count"

    git status --porcelain | grep -q . \
        && die "working tree not clean after rebase"

    if [ -f /tmp/fork-owned-files.txt ]; then
        verify_fork_files < /tmp/fork-owned-files.txt
    fi

    echo "OK: 4-layer stack rebuilt with feature included."
    echo ""
    echo "Run gates, then push:"
    echo "  cargo fmt --all -- --check"
    echo "  cargo clippy --workspace --all-targets -- -D warnings"
    echo "  cd web && npm run format:check"
    echo "  git push --force-with-lease origin $CURRENT_BRANCH"
}

case "${1:-}" in
    prepare) shift; cmd_prepare "$@" ;;
    finalize) shift; cmd_finalize "$@" ;;
    *) usage ;;
esac
