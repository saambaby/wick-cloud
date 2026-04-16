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

# Apply global schema migrations.
migrate:
    DATABASE_URL=postgres://wick:wick@localhost:5432/wick \
        sqlx migrate run --source migrations/global

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

# Run only the multi-tenant isolation tests.
test-multi-tenant:
    cargo test --package wick-server --test multi_tenant -- --nocapture

# --- phase demos ---

# Phase 0: boot server (single-tenant stub).
demo:
    cargo run --bin wick-server -- --config deploy/docker/config.dev.toml

# Phase 1: run multi-tenant isolation tests with verbose output.
multi-tenant-demo:
    @echo "=== Phase 1: Multi-tenant actor model demo ==="
    @echo "Running isolation tests across 5 tenants..."
    cargo test --package wick-server --test multi_tenant -- --nocapture
    @echo ""
    @echo "=== Demo complete. All tenants isolated. ==="

# --- housekeeping ---

# Tidy up generated artefacts.
clean:
    cargo clean
    docker compose -f deploy/docker/docker-compose.yml down -v
