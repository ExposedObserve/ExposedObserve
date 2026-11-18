#!/bin/bash
set -euo pipefail

# 1. Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 2. Always run docker build from the repository root
# Since script is in scripts/build/, the root is two levels up
ROOT_DIR="$(cd "$SCRIPT_DIR/../../" && pwd)"

DEFAULT_CARGO_JOBS=2
CARGO_JOBS="${CARGO_JOBS:-$DEFAULT_CARGO_JOBS}"

# `.git` is excluded from the Docker context, so src/config/build.rs cannot
# resolve the version itself. Resolve it here, where the git history is
# available, and hand it in as a build arg.
GIT_VERSION="${GIT_VERSION:-$(git -C "$ROOT_DIR" describe --tags --abbrev=0 --match "v*" 2>/dev/null || echo "v0.0.0")}"
GIT_COMMIT_HASH="${GIT_COMMIT_HASH:-$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo "dev")}"

echo "Building with CARGO_JOBS=$CARGO_JOBS GIT_VERSION=$GIT_VERSION from root: $ROOT_DIR"

# 3. Change working directory to root so Docker finds the context correctly
cd "$ROOT_DIR"

DOCKER_BUILDKIT=1 docker build \
  --build-arg CARGO_JOBS="$CARGO_JOBS" \
  --build-arg GIT_VERSION="$GIT_VERSION" \
  --build-arg GIT_COMMIT_HASH="$GIT_COMMIT_HASH" \
  --tag exposedobserve:local \
  . --progress=plain