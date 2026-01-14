# syntax=docker/dockerfile:1

FROM public.ecr.aws/docker/library/node:24-bookworm-slim AS webbuilder
COPY ./web/package*.json /tmp/web/
RUN cd /tmp/web && npm install
RUN mkdir /web && cp -a /tmp/web/node_modules /web/

WORKDIR /web
COPY ./web/ /web/

RUN NODE_OPTIONS="--max-old-space-size=8192" npm run build

FROM public.ecr.aws/docker/library/rust:slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    lld \
    clang \
    protobuf-compiler \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /exposedobserve

COPY . ./

COPY --from=webbuilder /web/dist web/dist

ARG GIT_VERSION=v0.0.0
ARG GIT_COMMIT_HASH=dev
ARG CARGO_JOBS=2

ENV GIT_VERSION=$GIT_VERSION
ENV GIT_COMMIT_HASH=$GIT_COMMIT_HASH

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/rustup \
    --mount=type=cache,target=/exposedobserve/target \
    cargo build --release --features mimalloc --jobs "$CARGO_JOBS" && \
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

COPY --from=builder /out/exposedobserve /exposedobserve

RUN ["/exposedobserve", "init-dir", "-p", "/data/"]
CMD ["/exposedobserve"]
