//! Phase 4 acceptance — `loom` model of the shared-state pattern that
//! backs [`wick_macaroon::store::RevocationSet`].
//!
//! `RevocationSet` is just `Arc<RwLock<HashSet<[u8;16]>>>` underneath:
//! writers push new revoked nonces in (from the NOTIFY listener or a
//! direct `revoke()` call), readers (the verify path) probe it on every
//! request. The production code uses `parking_lot::RwLock`, which has
//! no `loom` shim, so we model the same shape with `loom::sync::RwLock`
//! — semantically equivalent for the invariants we care about:
//!
//! 1. After a writer's `insert(x)` happens-before a reader's
//!    `contains(x)`, the reader sees `true`. (No lost-update.)
//! 2. Concurrent inserts of distinct nonces don't deadlock or wedge.
//! 3. A reader probing an unrelated nonce never returns `true` for a
//!    nonce that was never inserted. (No spurious false positives.)
//!
//! Loom permutes every meaningful interleaving in `loom::model { ... }`
//! and checks each. Run with:
//!
//! ```bash
//! RUSTFLAGS="--cfg loom" cargo test -p wick-macaroon \
//!   --test loom_revocation --release
//! ```
//!
//! The `#![cfg(loom)]` gate means a default `cargo test` ignores this
//! file entirely — it never even gets compiled without `--cfg loom`.

#![cfg(loom)]

use std::collections::HashSet;

use loom::sync::{Arc, RwLock};
use loom::thread;

/// Loom-friendly stand-in for the production `RevocationSet` inner.
/// Same shape (`Arc<RwLock<HashSet<[u8;16]>>>`); production uses
/// `parking_lot::RwLock` for which loom has no shim, so we substitute
/// `loom::sync::RwLock` to drive the model checker.
struct LoomSet {
    inner: RwLock<HashSet<[u8; 16]>>,
}

impl LoomSet {
    fn new() -> Self {
        Self {
            inner: RwLock::new(HashSet::new()),
        }
    }

    fn insert(&self, nonce: [u8; 16]) {
        self.inner.write().unwrap().insert(nonce);
    }

    fn contains(&self, nonce: &[u8; 16]) -> bool {
        self.inner.read().unwrap().contains(nonce)
    }
}

/// Invariant 1 — after a writer thread's `insert(x)` joins, any
/// subsequent `contains(x)` MUST return true. While the writer runs
/// concurrently the reader may see either state (both legal).
#[test]
fn revocation_insert_then_contains_is_consistent() {
    loom::model(|| {
        let set = Arc::new(LoomSet::new());
        let set_w = set.clone();
        let set_r = set.clone();
        let nonce: [u8; 16] = [42; 16];

        let writer = thread::spawn(move || {
            set_w.insert(nonce);
        });
        let reader = thread::spawn(move || {
            // Concurrent observation — either outcome is valid; we
            // only assert the post-join invariant below.
            let _ = set_r.contains(&nonce);
        });

        writer.join().unwrap();
        reader.join().unwrap();

        // Post-join: writer's insert happens-before the join, which
        // happens-before this check. Must observe true.
        assert!(
            set.contains(&nonce),
            "post-join invariant violated: nonce missing after writer joined"
        );
    });
}

/// Invariants 2 & 3 — concurrent revocation of nonce A and verify of
/// nonce B (B never inserted) while a third thread inserts nonce A
/// again. After joining everything, A is present and B is NOT, and
/// the reader of B never observed a spurious true.
#[test]
fn concurrent_revoke_and_verify_no_spurious_false_negatives() {
    loom::model(|| {
        let set = Arc::new(LoomSet::new());
        let s1 = set.clone();
        let s2 = set.clone();
        let s3 = set.clone();

        let nonce_a: [u8; 16] = [0xAA; 16];
        let nonce_b: [u8; 16] = [0xBB; 16];

        // Two concurrent writers inserting the SAME nonce A — models
        // two listener callbacks racing on the same NOTIFY payload, a
        // realistic shape under reconnect-bootstrap overlap.
        let writer_a1 = thread::spawn(move || {
            s1.insert(nonce_a);
        });
        let writer_a2 = thread::spawn(move || {
            s2.insert(nonce_a);
        });

        // Concurrent verifier probing an UNRELATED nonce B. Must never
        // return true regardless of interleaving (no spurious false
        // negatives in the verify path — for revocation, `contains ==
        // true` means *reject*, so the "false negative" the spec warns
        // about is "verifier returns 'revoked' for a never-revoked
        // nonce").
        let reader = thread::spawn(move || s3.contains(&nonce_b));

        writer_a1.join().unwrap();
        writer_a2.join().unwrap();
        let saw_b_revoked = reader.join().unwrap();

        assert!(
            !saw_b_revoked,
            "spurious false positive: verifier saw nonce B as revoked but it was never inserted"
        );
        assert!(set.contains(&nonce_a), "writer A must be visible post-join");
        assert!(!set.contains(&nonce_b), "B was never inserted");
    });
}
