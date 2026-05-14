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
    RUSTFLAGS="--cfg loom" cargo test -p wick-loom-models --release
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

# Phase 2 acceptance demo: park/wake concurrency + latency snapshot against
# an in-process stub (no Postgres / LDK / Esplora). Prints p50/p95/p99 wake
# latency for a concurrent wake storm and the final state breakdown.
park-wake-demo:
    cargo run --release --example park_wake_demo -p wick-server

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

# --- phase 3 LSPS2 JIT (self-custodial operator + tenant-side) ---

# Phase 3 hermetic regtest JIT flow (slice 3.3a). Three-role test:
# Operator (`wick_sdk::OperatorClient`, signs LSP funding txs from a
# local BDK wallet), Alice (JIT receiver), Bob (payer). The operator
# installs the LSP Lightning seed at runtime via the admin
# `RegisterLspIdentity` RPC; the server holds no on-chain seed.
# Requires `just regtest-up` to be running.
jit-demo:
    cargo test -p wick-sdk --test jit_flow --features regtest \
        -- --ignored --nocapture

# Live JIT receive flow against Mutiny's hub on mutinynet. The LSP
# Lightning seed is derived from the operator's BIP39 mnemonic (same
# mnemonic as the operator's BDK wallet, domain-separated derivation
# path `m/13037'/coin'/0'`). The operator's SDK process must:
#   1. Compute the LSP pubkey offline via
#      `wick_sdk::compute_operator_lsp_pubkey(...)` and place it in
#      `[lsp].pubkey_hex` of `deploy/docker/config.mutinynet.toml`.
#   2. After the server is up, call `OperatorClient::register_lsp()` to
#      install the seed in-memory (never persisted server-side).
#   3. Drive `wick_sdk::run_funding_loop()` to sign each parked
#      `FundingGenerationReady` from the operator's BDK wallet (top up
#      via https://faucet.mutinynet.com).
jit-mutinynet-demo:
    cargo test -p wick-sdk --test integration_mutinynet jit_receive \
        --features regtest -- --ignored --nocapture

# Live JIT receive flow against ACINQ on signet (or whatever is
# configured under [lsp].upstream_peer). Same operator workflow as
# `jit-mutinynet-demo` — see that recipe's comment for details.
jit-signet-demo:
    cargo test -p wick-sdk --test integration_signet jit_receive \
        --features regtest -- --ignored --nocapture

# --- phase 4 acceptance demo ---

# Phase 4 acceptance demo: device-held seed signs payment, `kill -9`
# server then payment-after-restart, revoke macaroon and assert
# cluster-wide rejection in <1s. Requires `just regtest-up`.
vls-demo:
    @echo "Phase 4 acceptance demo — requires 'just regtest-up' first."
    cargo test -p wick-sdk --test vls_demo --features regtest \
        -- --ignored --nocapture --test-threads=1
    @echo ""
    @echo "============================================================"
    @echo "PHASE 4 ACCEPTANCE DEMO: PASS"
    @echo "============================================================"

# --- housekeeping ---

# Tidy up generated artefacts.
clean:
    cargo clean
    docker compose -f deploy/docker/docker-compose.yml down -v
