# Build the hub binary (and optionally the web client).
#
# Normal CI/release build — Voxply-web checked out to web-client-src/:
#
#   docker build -f hub/Dockerfile -t ghcr.io/voxply/hub:latest .
#
# Local build WITHOUT the web client source (produces an API-only image):
#
#   docker build -f hub/Dockerfile -t voxply-hub:dev .
#
# docker-compose from the workspace root:
#
#   docker compose up

# ── web client build stage ────────────────────────────────────────────────────
# Technique: a dedicated node:22-slim stage copies the entire build context
# (which includes web-client-src/ when checked out by CI, or just the Rust
# workspace otherwise).  The RUN command checks whether the web source landed
# and only runs npm when it is present.  /web-client always exists in the
# resulting layer so COPY --from=web-builder in the runtime stage never fails.
#
# CI/release: actions/checkout puts Voxply-web at web-client-src/ in the context
#   → npm ci && npm run build → /web-client contains the built SPA.
#   → ENV VOXPLY_WEB_CLIENT_DIR=/web-client activates serving.
#
# Local `docker build` without web-client-src/:
#   → /web-client is created but empty; index.html is absent.
#   → VOXPLY_WEB_CLIENT_DIR=/web-client is still set, but the hub's startup
#     validation will detect the missing index.html and exit with a clear error.
#   → Override at runtime with -e VOXPLY_WEB_CLIENT_DIR= to run API-only.
FROM node:22-slim AS web-builder

WORKDIR /build-web

# Copy the entire build context so we get web-client-src/ when it exists.
# COPY with a wildcard tolerates absence: `web-client-src*` copies the directory
# when present and silently skips when absent (Docker copies matching entries only).
COPY web-client-src* /build-web/web-client-src/

RUN mkdir -p /web-client && \
    if [ -f /build-web/web-client-src/web/package.json ]; then \
        cd /build-web/web-client-src/web && \
        npm ci --prefer-offline && \
        npm run build && \
        cp -r dist/. /web-client/; \
    fi

# ── Rust build stage ──────────────────────────────────────────────────────────
# Builder and runtime MUST be pinned to the same Debian release: a floating
# rust:1-slim tracks the newest Debian, and a binary built against its glibc
# will not start on an older runtime base (bit us on v0.2.1: GLIBC_2.38).
FROM rust:1-slim-trixie AS builder

# No system deps needed — all TLS is handled by rustls (pure Rust)

WORKDIR /build
COPY . .
RUN cargo build --release -p voxply-hub

# ── runtime ───────────────────────────────────────────────────────────────────
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The hub writes hub.db and hub_identity.json into the working directory.
# Mount a named volume here so data survives container restarts.
WORKDIR /data
VOLUME ["/data"]

COPY --from=builder /build/target/release/voxply-hub /usr/local/bin/voxply-hub

# Copy the pre-built web client assets produced by the web-builder stage.
# The directory always exists (populated in CI builds; empty in local builds
# without web-client-src/).  VOXPLY_WEB_CLIENT_DIR is set to /web-client below;
# if /web-client is empty (no index.html), the hub will exit with a clear error
# at startup — override with -e VOXPLY_WEB_CLIENT_DIR= to run API-only.
COPY --from=web-builder /web-client /web-client

# HTTP API
EXPOSE 3000
# Voice UDP relay
EXPOSE 3001/udp

# All env vars the hub reads. Override in docker-compose.yml or with -e flags.
ENV VOXPLY_HTTP_PORT=3000
ENV VOXPLY_VOICE_UDP_PORT=3001
# ENV VOXPLY_TLS_CERT=/certs/fullchain.pem
# ENV VOXPLY_TLS_KEY=/certs/privkey.pem
# ENV VOXPLY_FARM_URL=http://farm:4000
# ENV VOXPLY_LOG_FORMAT=json
# ENV VOXPLY_OTLP_ENDPOINT=http://otel-collector:4318

# When the web client was baked in (index.html present), serve it automatically.
# Overridable at runtime: -e VOXPLY_WEB_CLIENT_DIR= (empty) disables serving.
ENV VOXPLY_WEB_CLIENT_DIR=/web-client

ENTRYPOINT ["/usr/local/bin/voxply-hub"]
