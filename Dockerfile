# syntax=docker/dockerfile:1

# Fork-only image build. Single platform (linux/amd64) on purpose: the CI
# runner is already x64, so `--target` would only relocate the output path, and
# one platform keeps the BuildKit cache small enough for free runners.

FROM public.ecr.aws/docker/library/node:24-bookworm-slim AS webbuilder

WORKDIR /web

COPY ./web/package*.json ./

RUN --mount=type=cache,id=npm,target=/root/.npm \
    npm ci

COPY ./web/ .

RUN --mount=type=cache,id=vite,target=/web/node_modules/.vite \
    --mount=type=cache,id=node,target=/web/node_modules/.cache \
    NODE_OPTIONS="--max-old-space-size=8192" npm run build

FROM public.ecr.aws/docker/library/rust:slim-bookworm AS rustbuilder

# protoc is required by src/proto/build.rs; lld/clang keep the link step fast.
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    lld \
    clang \
    protobuf-compiler \
    curl

WORKDIR /exposedobserve

COPY . ./

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git/db \
    --mount=type=cache,id=rustup,target=/usr/local/rustup \
    cargo fetch

# `.git` is excluded by .dockerignore, so src/config/build.rs cannot resolve the
# version on its own: it reads these two vars first and only then falls back to
# `git describe` / `git rev-parse`. CI passes the real values; a local
# `scripts/build/build-image.sh` run falls back to these defaults.
ARG GIT_VERSION=v0.0.0
ARG GIT_COMMIT_HASH=dev
ARG CARGO_JOBS=2

ENV GIT_VERSION=$GIT_VERSION
ENV GIT_COMMIT_HASH=$GIT_COMMIT_HASH

COPY --from=webbuilder /web/dist web/dist

# The artifact name comes from the [[bin]] override in the root Cargo.toml;
# keep this path in sync with it. `release` (not `release-prod`) is deliberate:
# release-prod trades build time for runtime speed, which is the wrong trade on
# a free CI runner. `sso-redis` (not the default `sso`) is what makes the
# docker-compose Redis service actually usable — without it a runtime
# OIDC_REDIS_URL is rejected because the session layer is compiled in-memory-only.
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git/db \
    --mount=type=cache,id=rustup,target=/usr/local/rustup \
    --mount=type=cache,id=target,target=/exposedobserve/target \
    cargo build --release --features mimalloc,sso-redis --jobs "$CARGO_JOBS" && \
    mkdir -p /out && \
    cp target/release/exposedobserve /out/exposedobserve

FROM public.ecr.aws/debian/debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    htop \
    iftop \
    sysstat \
    procps \
    lsof \
    net-tools \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

COPY --from=rustbuilder /out/exposedobserve /exposedobserve

RUN ["/exposedobserve", "init-dir", "-p", "/data/"]
CMD ["/exposedobserve"]
