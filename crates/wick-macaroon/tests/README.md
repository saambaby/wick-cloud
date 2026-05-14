# wick-macaroon integration tests

Two Phase 4 acceptance tests live here. Both are explicitly gated so
the default `cargo test -p wick-macaroon` stays green on a laptop
without Postgres or `--cfg loom`.

## `multi_node_revocation.rs` — p99 < 1s propagation

Spins up three `PgPool`s + three `RevocationSet::start` listeners
against the same database, fires 100 revocations from rotating source
nodes, and asserts that the p99 wall-clock time for *all three* nodes
to observe each revocation (via `LISTEN/NOTIFY`) is under 1s.

```bash
just regtest-up   # provides postgres at 127.0.0.1:5432
WICK_TEST_PG_URL=postgres://wick:wick@127.0.0.1:5432/wick \
  cargo test -p wick-macaroon --features postgres \
  --test multi_node_revocation -- --ignored --nocapture
```

Marked `#[ignore]` — never runs under a default `cargo test`. The
2ms poll loop quantises each measurement; well inside the 1s budget.

## `loom_revocation.rs` — concurrent state model

Loom permutes every meaningful interleaving of writers/readers against
the `Arc<RwLock<HashSet<[u8;16]>>>` pattern that backs
`RevocationSet`. Production uses `parking_lot::RwLock`; loom has no
shim for it, so the model substitutes `loom::sync::RwLock` — same
shape, same happens-before guarantees.

```bash
RUSTFLAGS="--cfg loom" cargo test -p wick-macaroon \
  --test loom_revocation --release
```

The whole file is `#![cfg(loom)]`, so without that `RUSTFLAGS` it
isn't even compiled by `cargo test`.

### Known limitation

`RUSTFLAGS="--cfg loom"` propagates to every transitive dep, which
breaks `tokio` and `concurrent-queue` (they switch their own internal
imports to `loom::sync` under that cfg, expecting loom to be an in-tree
dep — which it isn't for those crates' dependency view). The clean
production fix is to move the loom model into its own minimal crate
that depends only on wick-macaroon (no tokio / no sqlx). That's
follow-up work; the test scaffolding lives here as a reference for
the invariants the production `RevocationSet` must uphold.
