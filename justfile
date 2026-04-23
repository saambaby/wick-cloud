# Wick Cloud dev commands
# Run `just` or `just --list` to see available commands.

set shell := ["bash", "-uc"]

default:
    @just --list

# --- dev stack ---

# Start local dev stack (bitcoind regtest, postgres, esplora).
regtest-up:
    docker compose -f deploy/docker/docker-compose.yml up -d
    @echo "Waiting for services..."
    sleep 5
    just migrate

# Stop and remove the dev stack.
regtest-down:
    docker compose -f deploy/docker/docker-compose.yml down -v

# Apply global schema migrations via the containerised `psql`.
# No host-side sqlx CLI required. Integration tests also apply these
# automatically on `Harness::bootstrap`, so invoking this recipe is only
# necessary for ad-hoc `psql` use or running the server binary directly.
migrate:
    #!/usr/bin/env bash
    set -euo pipefail
    for f in migrations/global/*.sql; do
        echo "applying $f"
        docker exec -i wick-postgres psql -v ON_ERROR_STOP=1 -q \
            -U wick -d wick < "$f"
    done

# Provision a new tenant schema (requires TENANT_ID env var).
# Example: TENANT_ID=1 just migrate-tenant
migrate-tenant:
    bash scripts/tenant-provision.sh "${TENANT_ID}"

# --- build / test ---

# Format, lint, audit, deny, unit + integration tests — same gates as CI.
ci-local:
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --all-features
    cargo deny check
    cargo audit

# Build the whole workspace.
build:
    cargo build --workspace

# Run unit + integration tests.
test:
    cargo test --workspace --all-features

# --- phase demos ---

# Boot server against local regtest docker-compose stack (requires just regtest-up).
demo:
    cargo run --bin wick-server -- --config deploy/docker/config.regtest.toml

# Boot server against mutinynet (default dev target — no local daemon needed, just postgres-up).
mutinynet-dev:
    cargo run --bin wick-server -- --config deploy/docker/config.dev.toml

# Loom model: verify park/wake CAS + memory invariants under all interleavings.
# Runs without the dev stack — pure in-process model checker.
# `wick-loom-models` has no tokio dep so --cfg loom doesn't break concurrent-queue.
loom:
    RUSTFLAGS="--cfg loom" cargo test -p wick-loom-models --release

# --- signet / mutinynet ---

# Start only Postgres (for signet/mutinynet where local bitcoind is not needed).
postgres-up:
    docker compose -f deploy/docker/docker-compose.yml up -d postgres
    @echo "Waiting for Postgres..."
    sleep 3
    just migrate

# Run wick-server against the default signet network (mempool.space Esplora, no local node needed).
# Set a real 32-byte hex seed in deploy/docker/config.signet.toml before running.
# Generate one with: openssl rand -hex 32
signet-run:
    cargo run --bin wick-server -- --config deploy/docker/config.signet.toml

# Run wick-server against mutinynet (custom signet, 30-second blocks, mutinynet.com Esplora).
# Set a real 32-byte hex seed in deploy/docker/config.mutinynet.toml before running.
mutinynet-run:
    cargo run --bin wick-server -- --config deploy/docker/config.mutinynet.toml

# --- housekeeping ---

# Tidy up generated artefacts.
clean:
    cargo clean
    docker compose -f deploy/docker/docker-compose.yml down -v
