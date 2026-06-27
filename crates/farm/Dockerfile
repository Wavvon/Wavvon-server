# Build the farm binary.
# Run from the workspace root:
#
#   docker build -f farm/Dockerfile -t ghcr.io/wavvon/farm:latest .
#
# Or use docker-compose.farm.yml from the workspace root.

# Builder and runtime MUST be pinned to the same Debian release: a floating
# rust:1-slim tracks the newest Debian, and a binary built against its glibc
# will not start on an older runtime base (bit us on v0.2.1: GLIBC_2.38).
FROM rust:1-slim-trixie AS builder

# No system deps needed — all TLS is handled by rustls (pure Rust)

WORKDIR /build
COPY . .
RUN cargo build --release -p wavvon-farm

# ---------- runtime ----------
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The farm writes farm.db and farm_identity.json into the working directory.
WORKDIR /data
VOLUME ["/data"]

COPY --from=builder /build/target/release/wavvon-farm /usr/local/bin/wavvon-farm

# Farm HTTP API
EXPOSE 4000

# All env vars the farm reads. Override in docker-compose.yml or with -e flags.
ENV WAVVON_FARM_HTTP_PORT=4000
# The externally reachable URL of this farm — used in session tokens.
# Must be set correctly in production.
# ENV WAVVON_FARM_URL=https://farm.example.com
# Path to the hub binary for auto-spawning hubs (Phase 3).
# ENV WAVVON_HUB_BIN=/usr/local/bin/wavvon-hub
# ENV WAVVON_LOG_FORMAT=json
# ENV WAVVON_OTLP_ENDPOINT=http://otel-collector:4318

ENTRYPOINT ["/usr/local/bin/wavvon-farm"]
