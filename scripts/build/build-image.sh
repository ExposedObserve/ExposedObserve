#!/bin/bash
set -euo pipefail

# 1. Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 2. Always run docker build from the repository root
# Since script is in scripts/build/, the root is two levels up
ROOT_DIR="$(cd "$SCRIPT_DIR/../../" && pwd)"

DEFAULT_CARGO_JOBS=2
CARGO_JOBS="${CARGO_JOBS:-$DEFAULT_CARGO_JOBS}"

echo "Building with CARGO_JOBS=$CARGO_JOBS from root: $ROOT_DIR"

# 3. Change working directory to root so Docker finds the context correctly
cd "$ROOT_DIR"

DOCKER_BUILDKIT=1 docker build \
  --build-arg CARGO_JOBS="$CARGO_JOBS" \
  --tag exposedobserve:local \
  . --progress=plain