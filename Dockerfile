# syntax=docker/dockerfile:1

FROM public.ecr.aws/docker/library/node:24-bookworm-slim AS webbuilder
WORKDIR /web
COPY ./web /web/

RUN npm install
RUN NODE_OPTIONS="--max-old-space-size=8192" npm run build

FROM public.ecr.aws/docker/library/rust:slim-bookworm AS builder

ARG GIT_VERSION=v0.0.0
ARG GIT_COMMIT_HASH=dev

WORKDIR /exposedobserve

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    lld \
    clang \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY . /exposedobserve
COPY --from=webbuilder /web/dist web/dist

ENV GIT_VERSION=$GIT_VERSION
ENV GIT_COMMIT_HASH=$GIT_COMMIT_HASH
ENV RUSTFLAGS="-C link-arg=-fuse-ld=lld -C target-feature=+aes,+sse2"

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/exposedobserve/target \
    cargo build --release --features mimalloc --jobs 2

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

COPY --from=builder /exposedobserve/target/release/exposedobserve /

RUN ["/exposedobserve", "init-dir", "-p", "/data/"]
CMD ["/exposedobserve"]
