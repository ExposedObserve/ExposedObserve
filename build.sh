#!/bin/bash
set -euo pipefail

DEFAULT_CARGO_JOBS=2

CARGO_JOBS="${CARGO_JOBS:-$DEFAULT_CARGO_JOBS}"

echo "Building with CARGO_JOBS=$CARGO_JOBS"

OCKER_BUILDKIT=1 docker build \
  --build-arg CARGO_JOBS="$CARGO_JOBS" \
  --tag exposedobserve:local \
  . --progress=plain