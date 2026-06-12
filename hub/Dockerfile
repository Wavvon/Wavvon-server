# Build the hub binary.
# Run from the workspace root so the identity crate is in the build context:
#
#   docker build -f hub/Dockerfile -t ghcr.io/voxply/hub:latest .
#
# Or use docker-compose from the workspace root:
#
#   docker compose up

# Builder and runtime MUST be pinned to the same Debian release: a floating
# rust:1-slim tracks the newest Debian, and a binary built against its glibc
# will not start on an older runtime base (bit us on v0.2.1: GLIBC_2.38).
FROM rust:1-slim-trixie AS builder

# No system deps needed — all TLS is handled by rustls (pure Rust)

WORKDIR /build
COPY . .
RUN cargo build --release -p voxply-hub

# ---------- runtime ----------
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The hub writes hub.db and hub_identity.json into the working directory.
# Mount a named volume here so data survives container restarts.
WORKDIR /data
VOLUME ["/data"]

COPY --from=builder /build/target/release/voxply-hub /usr/local/bin/voxply-hub

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

ENTRYPOINT ["/usr/local/bin/voxply-hub"]
