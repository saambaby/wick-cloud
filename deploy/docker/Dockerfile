# Multi-stage build for wick-server.
#
# Stage 1 — builder: compile the wick-server binary using the workspace's
#   pinned toolchain. The full workspace is included so workspace
#   dependency resolution works correctly.
#
# Stage 2 — runner: minimal Debian image with only the binary and the
#   gRPC health probe. No Rust toolchain in the final image.

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM rust:1.88-bookworm AS builder

WORKDIR /build

# Copy workspace manifests first to cache dependency compilation.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ ./crates/

# Build only the wick-server binary in release mode.
RUN cargo build --release -p wick-server

# ── Stage 2: runner ───────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runner

# Runtime dependencies: libssl (reqwest TLS), CA certs (HTTPS to mutinynet.com).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# grpc_health_probe for compose healthcheck.
ARG GRPC_HEALTH_PROBE_VERSION=v0.4.34
RUN arch=$(dpkg --print-architecture) && \
    case "$arch" in \
        amd64) bin=grpc_health_probe-linux-amd64 ;; \
        arm64) bin=grpc_health_probe-linux-arm64 ;; \
        *) echo "unsupported arch: $arch" && exit 1 ;; \
    esac && \
    wget -qO /usr/local/bin/grpc_health_probe \
        "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/${bin}" && \
    chmod +x /usr/local/bin/grpc_health_probe

COPY --from=builder /build/target/release/wick-server /usr/local/bin/wick-server

# Non-root user.
RUN useradd -r -s /bin/false wick
USER wick

WORKDIR /app

EXPOSE 50051 19836 9464

ENTRYPOINT ["wick-server"]
