# Build from the workspace root so voxply-hub's dependency on voxply-identity
# is available to the compiler.
#
# Usage: docker build -f server/voxply-hub/Dockerfile -t voxply-hub .

FROM rust:1-slim AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p voxply-hub

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /build/target/release/voxply-hub /usr/local/bin/voxply-hub
EXPOSE 3000
EXPOSE 3001/udp
ENV DATABASE_URL=sqlite://hub.db
ENV BIND_ADDR=0.0.0.0:3000
ENV HUB_IDENTITY_PATH=/data/hub_identity.json
ENV VOICE_UDP_PORT=3001
ENTRYPOINT ["/usr/local/bin/voxply-hub"]
