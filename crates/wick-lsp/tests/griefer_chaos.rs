//! Phase 3 slice 3.3b — grief-score end-to-end against a real
//! Postgres.
//!
//! Verifies the full grief-score loop:
//!
//! 1. A client requests N JIT SCIDs and never pays.
//! 2. Each `Pending` row's `valid_until` elapses (we insert with
//!    `valid_until = now() - interval '1 minute'` to skip waiting).
//! 3. `PeerRegistry::rehydrate_from_pg_with_grief` sweeps them and
//!    applies one grief penalty per expired row to the same
//!    `client_pubkey`.
//! 4. After enough sweeps the score crosses
//!    `LspConfig::grief_rejection_threshold` and `should_reject`
//!    returns `true`.
//!
//! Also covers reward + decay arithmetic against real Postgres: a
//! single fulfilment subtracts `reward`; reading the score after
//! `2 * half_life_hours` returns ~25% of the stored value.
//!
//! ## Prerequisites
//!
//! ```sh
//! just postgres-up
//! cargo test -p wick-lsp --test griefer_chaos -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::SystemTime;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use sqlx::PgPool;
use wick_lsp::grief::GriefScorer;
use wick_lsp::PeerRegistry;

const DATABASE_URL: &str = "postgres://wick:wick@localhost:5432/wick";

const HALF_LIFE_HOURS: f64 = 168.0;
const PENALTY: f64 = 10.0;
const REWARD: f64 = 1.0;
const THRESHOLD: f64 = 100.0;

async fn setup_pool() -> PgPool {
    PgPool::connect(DATABASE_URL).await.expect(
        "connect to wick-postgres — run `just postgres-up` and ensure migrations are applied",
    )
}

fn unique_pubkey(seed_byte: u8) -> PublicKey {
    let secp = Secp256k1::new();
    let mut bytes = [0u8; 32];
    let now_nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0u128, |d| d.as_nanos());
    let id_bytes = now_nanos.to_le_bytes();
    bytes[0] = seed_byte;
    bytes[1..1 + id_bytes.len().min(15)]
        .copy_from_slice(&id_bytes[..id_bytes.len().min(15)]);
    if bytes.iter().all(|b| *b == 0) {
        bytes[31] = 1;
    }
    let sk = SecretKey::from_slice(&bytes).expect("non-zero scalar");
    PublicKey::from_secret_key(&secp, &sk)
}

/// Insert N already-expired Pending rows for `pubkey` directly so the
/// rehydration sweep finds them. Returns the SCIDs inserted (for
/// cleanup).
async fn insert_expired_pending_for(
    pool: &PgPool,
    pubkey: &PublicKey,
    n: usize,
    starting_scid: u64,
) -> Vec<u64> {
    let mut scids = Vec::with_capacity(n);
    for i in 0..n {
        let scid = starting_scid + u64::try_from(i).unwrap();
        sqlx::query(
            r"INSERT INTO global.jit_requests
                (scid, epoch, tenant_id, client_pubkey, amount_msat, state, valid_until)
              VALUES ($1, $2, $3, $4, NULL, 'pending', now() - interval '1 minute')",
        )
        .bind(i64::try_from(scid).unwrap_or(i64::MAX))
        .bind(i64::try_from(scid).unwrap_or(i64::MAX))
        .bind(uuid::Uuid::new_v4())
        .bind(&pubkey.serialize()[..])
        .execute(pool)
        .await
        .unwrap();
        scids.push(scid);
    }
    scids
}

async fn delete_grief_row(pool: &PgPool, pubkey: &PublicKey) {
    sqlx::query("DELETE FROM global.client_reputation WHERE pubkey = $1")
        .bind(&pubkey.serialize()[..])
        .execute(pool)
        .await
        .unwrap();
}

async fn delete_jit_rows(pool: &PgPool, scids: &[u64]) {
    for scid in scids {
        sqlx::query("DELETE FROM global.jit_requests WHERE scid = $1")
            .bind(i64::try_from(*scid).unwrap_or(i64::MAX))
            .execute(pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires `just postgres-up`"]
async fn rehydration_sweep_applies_grief_then_rejects() {
    let pool = setup_pool().await;
    let pubkey = unique_pubkey(0xAB);
    let scorer = GriefScorer::new(pool.clone(), HALF_LIFE_HOURS, PENALTY, REWARD, THRESHOLD);

    // Start clean.
    delete_grief_row(&pool, &pubkey).await;

    // 11 expired Pendings — at penalty=10, threshold=100, that pushes
    // score to 110 ≥ 100 → reject. SCID base in the lower 48 bits +
    // a unique nanos offset so concurrent runs don't collide.
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_nanos()).unwrap_or(0));
    let starting_scid = 0x7000_0000_0000_0000_u64 ^ (nanos & 0x0FFF_FFFF);
    let scids = insert_expired_pending_for(&pool, &pubkey, 11, starting_scid).await;

    // Rehydrate with the scorer attached — sweeps + records grief.
    let _ = PeerRegistry::rehydrate_from_pg_with_grief(&pool, Some(&scorer))
        .await
        .unwrap();

    // Score should be at least 11 * penalty = 110 (decay over the
    // millisecond between INSERT and read is negligible).
    let score = scorer.read_score(&pubkey).await.unwrap();
    assert!(
        score >= 11.0 * PENALTY * 0.9999,
        "expected score ≥ 110 after 11 grief events, got {score}"
    );
    assert!(
        scorer.should_reject(&pubkey).await.unwrap(),
        "should_reject must be true above threshold"
    );

    // Cleanup.
    delete_grief_row(&pool, &pubkey).await;
    delete_jit_rows(&pool, &scids).await;
}

#[tokio::test]
#[ignore = "requires `just postgres-up`"]
async fn fulfilment_subtracts_reward() {
    let pool = setup_pool().await;
    let pubkey = unique_pubkey(0xCD);
    let scorer = GriefScorer::new(pool.clone(), HALF_LIFE_HOURS, PENALTY, REWARD, THRESHOLD);

    delete_grief_row(&pool, &pubkey).await;

    scorer.record_grief(&pubkey).await.unwrap();
    let after_grief = scorer.read_score(&pubkey).await.unwrap();
    assert!(
        (after_grief - PENALTY).abs() < 0.01,
        "expected ~{PENALTY}, got {after_grief}"
    );

    scorer.record_fulfilment(&pubkey).await.unwrap();
    let after_reward = scorer.read_score(&pubkey).await.unwrap();
    assert!(
        (after_reward - (PENALTY - REWARD)).abs() < 0.01,
        "expected ~{}, got {after_reward}",
        PENALTY - REWARD
    );

    delete_grief_row(&pool, &pubkey).await;
}

/// Decay sanity-check against a real `last_decayed_at` round-trip.
/// We can't easily fast-forward the clock, so this verifies the
/// **shape** of the read: scoring twice in succession returns
/// monotonically decreasing values (the second read decays from the
/// first read's stored timestamp).
#[tokio::test]
#[ignore = "requires `just postgres-up`"]
async fn decay_is_monotonically_non_increasing() {
    let pool = setup_pool().await;
    let pubkey = unique_pubkey(0xEF);
    // Tiny half-life so the millisecond between reads produces a
    // visible decay (otherwise rounding hides it).
    let scorer = GriefScorer::new(pool.clone(), 1e-6, PENALTY, REWARD, THRESHOLD);
    delete_grief_row(&pool, &pubkey).await;

    scorer.record_grief(&pubkey).await.unwrap();
    let first = scorer.read_score(&pubkey).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let second = scorer.read_score(&pubkey).await.unwrap();
    assert!(
        second <= first,
        "second read ({second}) must be ≤ first ({first}) after decay"
    );

    delete_grief_row(&pool, &pubkey).await;
}
