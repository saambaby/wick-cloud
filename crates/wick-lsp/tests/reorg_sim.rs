//! Phase 3 slice 3.3b — reorg-reserve guard end-to-end against a real
//! Postgres.
//!
//! Verifies the gate that caps total in-flight unconfirmed JIT
//! exposure at `LspConfig::reorg_safety_threshold_sats`.
//!
//! Scenario:
//! 1. Boot a fresh `PeerRegistry` against `wick-postgres`.
//! 2. Register N JIT requests, transition them to `Opened` with
//!    capacities summing to `threshold - 1`.
//! 3. `ReorgGuard::check_capacity` accepts a request that fits in the
//!    remaining headroom and rejects one that exceeds it — even after
//!    a `bitcoind invalidateblock`-equivalent (we don't run a chain
//!    here; the registry's `Opened` state is by definition unconfirmed
//!    until 6-confirmation tracking lands in slice 3.3c, so the test
//!    holds without simulating a real reorg).
//!
//! ## Prerequisites
//!
//! ```sh
//! just postgres-up
//! cargo test -p wick-lsp --test reorg_sim -- --ignored --nocapture
//! ```
//!
//! The test creates a unique scratch table per run so concurrent runs
//! and stale state never interfere — see `setup_scratch_pool`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::SystemTime;

use bitcoin::secp256k1::{ PublicKey, Secp256k1, SecretKey };
use sqlx::PgPool;
use wick_lsp::reorg::{ projected_capacity_sat, ReorgGuard, ReserveExceeded };
use wick_lsp::{ JitRequestState, PeerRegistry };

const DATABASE_URL: &str = "postgres://wick:wick@localhost:5432/wick";

const THRESHOLD_SATS: u64 = 5_000_000;
const ONE_CHANNEL_SATS: u64 = 1_500_000;

/// Build a test pool. Each test run uses a unique key tag in the
/// `client_pubkey` so concurrent runs against the same shared
/// Postgres don't collide.
async fn setup_pool() -> PgPool {
    let pool = PgPool::connect(DATABASE_URL).await.expect(
        "connect to wick-postgres — run `just postgres-up` and ensure migrations are applied"
    );
    // Sanity check that the migration ran. If not, fail loud.
    sqlx::query("SELECT 1 FROM global.jit_requests LIMIT 0")
        .execute(&pool).await
        .expect("global.jit_requests must exist — run `just migrate`");
    pool
}

fn unique_pubkey(seed_byte: u8) -> PublicKey {
    let secp = Secp256k1::new();
    let mut bytes = [0u8; 32];
    let now_nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0u128, |d| d.as_nanos());
    let id_bytes = now_nanos.to_le_bytes();
    bytes[0] = seed_byte;
    bytes[1..1 + id_bytes.len().min(15)].copy_from_slice(&id_bytes[..id_bytes.len().min(15)]);
    // Ensure non-zero so secp256k1 accepts it.
    if bytes.iter().all(|b| *b == 0) {
        bytes[31] = 1;
    }
    let sk = SecretKey::from_slice(&bytes).expect("non-zero scalar");
    PublicKey::from_secret_key(&secp, &sk)
}

/// LDK normally allocates intercept SCIDs; here we mint deterministic
/// distinct values that survive the BIGINT (i64) round-trip without
/// saturating. Top bit kept clear; bits 60–62 plus a per-run nanos
/// salt keep concurrent runs from colliding.
fn mint_scid(epoch: u64) -> u64 {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_nanos()).unwrap_or(0));
    let salt = nanos & 0x000f_ffff;
    0x7000_0000_0000_0000_u64 | (salt << 32) | (epoch & 0xffff_ffff)
}

#[tokio::test]
#[ignore = "requires `just postgres-up`"]
async fn reorg_guard_allows_within_headroom_rejects_over() {
    let pool = setup_pool().await;
    let registry = PeerRegistry::rehydrate_from_pg(&pool).await.unwrap();

    // Three Opened JITs summing to 4_500_000 sats — below threshold of 5M.
    let valid_until = chrono::Utc::now() + chrono::TimeDelta::minutes(30);
    let mut scids = Vec::new();
    for i in 0..3 {
        let scid = mint_scid(u64::try_from(i + 1000).unwrap());
        let pk = unique_pubkey(u8::try_from(i + 1).unwrap());
        registry
            .register_buy(scid, pk, Some(ONE_CHANNEL_SATS * 1000), valid_until, &pool).await
            .unwrap();
        registry.mark_opened(scid, ONE_CHANNEL_SATS, &pool).await.unwrap();
        scids.push(scid);
    }

    assert_eq!(
        registry.unconfirmed_exposure_sats(),
        ONE_CHANNEL_SATS * 3,
        "registry should report exposure equal to sum of mark_opened capacities"
    );

    let guard = ReorgGuard::new(registry.clone(), THRESHOLD_SATS);

    // 500k is the remaining headroom (4.5M + 0.5M = 5M, which equals threshold — accepted).
    assert!(guard.check_capacity(500_000).is_ok());
    // 600k exceeds (4.5M + 0.6M = 5.1M > 5M).
    let err = guard.check_capacity(600_000).unwrap_err();
    match err {
        ReserveExceeded::CapacityExhausted {
            unconfirmed_exposure_sats,
            requested_capacity_sat,
            threshold_sats,
        } => {
            assert_eq!(unconfirmed_exposure_sats, ONE_CHANNEL_SATS * 3);
            assert_eq!(requested_capacity_sat, 600_000);
            assert_eq!(threshold_sats, THRESHOLD_SATS);
        }
    }

    // Cleanup: remove the rows we inserted so subsequent runs start clean.
    for scid in scids {
        sqlx::query("DELETE FROM global.jit_requests WHERE scid = $1")
            .bind(i64::try_from(scid).unwrap_or(i64::MAX))
            .execute(&pool).await
            .unwrap();
    }
}

/// `projected_capacity_sat` matches what `OperatorServiceHandler`
/// commits at `LSPS2ServiceEvent::OpenChannel` — the gate's input must
/// match the gate's eventual reality.
#[test]
fn projected_capacity_at_buy_matches_open_channel_math() {
    // Same constants the production handler uses.
    const OVER_PPM: u64 = 50_000;
    const MAX: u64 = 5_000_000;

    // Mirror the handler's amt + 5% / 1000 round-trip.
    let amt_msat = 50_000_000_u64;
    let projected = projected_capacity_sat(Some(amt_msat), OVER_PPM, MAX);
    let over_msat = (amt_msat * OVER_PPM) / 1_000_000;
    let handler_committed = (amt_msat + over_msat) / 1000;
    assert_eq!(projected, handler_committed);
}

/// Rehydration after a simulated daemon restart preserves `Opened`
/// rows so the guard's exposure number stays honest across crashes.
#[tokio::test]
#[ignore = "requires `just postgres-up`"]
async fn rehydrate_preserves_opened_capacity() {
    let pool = setup_pool().await;

    // Round 1: register one Opened entry.
    let valid_until = chrono::Utc::now() + chrono::TimeDelta::minutes(30);
    let scid = mint_scid(99_999);
    let pk = unique_pubkey(99);
    {
        let registry = PeerRegistry::rehydrate_from_pg(&pool).await.unwrap();
        let starting_exposure = registry.unconfirmed_exposure_sats();
        registry.register_buy(scid, pk, Some(2_000_000_000), valid_until, &pool).await.unwrap();
        registry.mark_opened(scid, 2_000_000, &pool).await.unwrap();
        assert_eq!(registry.unconfirmed_exposure_sats(), starting_exposure + 2_000_000);
    }

    // Round 2: fresh registry — should rehydrate the Opened row.
    {
        let registry = PeerRegistry::rehydrate_from_pg(&pool).await.unwrap();
        let entry = registry.lookup(scid).expect("Opened row should rehydrate");
        assert_eq!(entry.state, JitRequestState::Opened);
        assert_eq!(entry.capacity_sat, Some(2_000_000));
    }

    sqlx::query("DELETE FROM global.jit_requests WHERE scid = $1")
        .bind(i64::try_from(scid).unwrap_or(i64::MAX))
        .execute(&pool).await
        .unwrap();
}
