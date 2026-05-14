//! Phase 4 acceptance test — revocation propagates across a simulated
//! 3-node wick-server cluster (three independent `PgPool`s + their own
//! `RevocationSet` listeners, all pointed at the same Postgres) with
//! p99 < 1s.
//!
//! Runs ignored by default (`#[ignore]`) because it requires a live
//! Postgres reachable via `WICK_TEST_PG_URL` (default
//! `postgres://wick:wick@127.0.0.1:5432/wick` — what `just regtest-up`
//! exposes). To execute:
//!
//! ```bash
//! just regtest-up
//! WICK_TEST_PG_URL=postgres://wick:wick@127.0.0.1:5432/wick \
//!   cargo test -p wick-macaroon --features postgres \
//!   --test multi_node_revocation -- --ignored --nocapture
//! ```
//!
//! The 2ms polling loop in the assertion introduces a ±2ms quantization
//! on measured per-revocation latency; that is well inside the 1s p99
//! budget and explicitly accepted.

#![cfg(feature = "postgres")]

use std::time::{Duration, Instant};

use sqlx::PgPool;
use wick_macaroon::store::RevocationSet;

/// Round-robin: which pool owns the SQL insert for revocation `i`. The
/// source `RevocationSet` always inserts via *its* pool, mirroring how
/// a real wick-server pod would only ever write through its own
/// connection.
fn pool_for_idx<'a>(i: usize, p1: &'a PgPool, p2: &'a PgPool, p3: &'a PgPool) -> &'a PgPool {
    match i % 3 {
        0 => p1,
        1 => p2,
        _ => p3,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires `just regtest-up` (live Postgres)"]
async fn revocation_propagates_under_1s_p99_across_3_nodes() {
    let pool_url = match std::env::var("WICK_TEST_PG_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "WICK_TEST_PG_URL not set — defaulting to \
                 postgres://wick:wick@127.0.0.1:5432/wick; run `just regtest-up` first"
            );
            "postgres://wick:wick@127.0.0.1:5432/wick".to_string()
        }
    };

    // Three independent pools/connections, mimicking 3 wick-server pods
    // that happen to share one Postgres.
    let p1 = PgPool::connect(&pool_url)
        .await
        .expect("connect node 1");
    let p2 = PgPool::connect(&pool_url)
        .await
        .expect("connect node 2");
    let p3 = PgPool::connect(&pool_url)
        .await
        .expect("connect node 3");

    let (rev1, _h1) = RevocationSet::start(p1.clone()).await.expect("start node 1");
    let (rev2, _h2) = RevocationSet::start(p2.clone()).await.expect("start node 2");
    let (rev3, _h3) = RevocationSet::start(p3.clone()).await.expect("start node 3");

    // pg_listener subscription takes ~50ms to engage — settle before
    // measuring so the first revocation's latency isn't a cold-start
    // outlier.
    tokio::time::sleep(Duration::from_millis(200)).await;

    const N: usize = 100;
    let mut latencies = Vec::with_capacity(N);
    let mut nonces: Vec<[u8; 16]> = Vec::with_capacity(N);

    for i in 0..N {
        let nonce: [u8; 16] = rand::random();
        nonces.push(nonce);
        let source = match i % 3 {
            0 => &rev1,
            1 => &rev2,
            _ => &rev3,
        };
        let pool = pool_for_idx(i, &p1, &p2, &p3);

        // t = 0 is "source node has locally observed the revocation"
        // (its `revoke` returns after the INSERT + local-cache insert).
        // We measure how long the OTHER two nodes take to catch up via
        // NOTIFY.
        let t0 = Instant::now();
        source
            .revoke(pool, nonce, Some("multi-node-test"))
            .await
            .expect("revoke insert");

        // Block until ALL three nodes (source already has it, but
        // checking is cheap) have it. 2ms poll introduces a ±2ms
        // quantization on each measurement — fine for a 1s budget.
        loop {
            if rev1.contains(&nonce) && rev2.contains(&nonce) && rev3.contains(&nonce) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        latencies.push(t0.elapsed());
    }

    latencies.sort();
    let median = latencies[latencies.len() / 2];
    let p99 = latencies[(latencies.len() * 99) / 100];
    let max = *latencies.last().expect("non-empty");
    println!("N={N} median={median:?} p99={p99:?} max={max:?}");

    // Cleanup the rows we created so reruns stay clean.
    for nonce in &nonces {
        let _ = sqlx::query("DELETE FROM global.revoked_macaroons WHERE nonce = $1")
            .bind(&nonce[..])
            .execute(&p1)
            .await;
    }

    assert!(
        p99 < Duration::from_secs(1),
        "revocation p99={p99:?} exceeds 1s budget (median={median:?}, max={max:?})"
    );
}
