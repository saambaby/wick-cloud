//! Phase 4 W2-D — spend-window double-spend negative test.
//!
//! Drives the in-memory `WindowState` + `check_spend` seam from `wick-macaroon`
//! to assert that:
//!   1. A first spend under the cap is admitted.
//!   2. A second spend that would push the rolling total past the cap is
//!      rejected with `CaveatFailed` (the caller — the gRPC layer in M2 —
//!      uses this to deny the payment authz, preventing the double-spend).
//!   3. After the window resets (caller-driven — `spent_msat` is truncated
//!      back to 0 on a new window) spending is re-enabled at full cap.
//!
//! This is the unit-level proof; postgres-backed accumulation lives in
//! `wick-macaroon::store` and is exercised by the multi-node revocation /
//! ignored-by-default postgres tests.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use wick_macaroon::{
    check_spend, Caveat, MacaroonError, Macaroon, RootKey, Scope, VerifyContext, WindowState,
};

const CAP_MSAT: u64 = 1_000;
const WINDOW_SECS: u32 = 60;

fn issue_with_spend_cap() -> (RootKey, Macaroon) {
    let rk = RootKey::random();
    let mut m = Macaroon::issue(
        "wick.cloud",
        [7u8; 16],
        &rk,
        Scope::User {
            tenant_id: [1u8; 16],
        },
        Duration::from_secs(3600),
    );
    m.add_caveat(Caveat::max_payment(CAP_MSAT, WINDOW_SECS));
    (rk, m)
}

fn verify_and_extract_cap(rk: &RootKey, m: &Macaroon) -> (u64, u32) {
    let revoked: HashSet<[u8; 16]> = HashSet::new();
    let ctx = VerifyContext {
        now: SystemTime::now(),
        revoked_nonces: &revoked,
        expected_scope: None,
        noise_static_pk_observed: None,
    };
    let v = m.verify(rk, &ctx).expect("macaroon verifies");
    v.spend_caveat.expect("spend caveat present")
}

#[test]
fn first_spend_under_limit_succeeds() {
    let (rk, m) = issue_with_spend_cap();
    let (cap, win) = verify_and_extract_cap(&rk, &m);
    assert_eq!((cap, win), (CAP_MSAT, WINDOW_SECS));

    // Empty window — first 600 msat spend must be admitted (600 <= 1000).
    let state = WindowState {
        spent_msat: 0,
        window_started: SystemTime::now(),
    };
    check_spend(&state, cap, win, 600).expect("first spend under cap admitted");
}

#[test]
fn second_spend_exceeding_limit_rejected() {
    let (rk, m) = issue_with_spend_cap();
    let (cap, win) = verify_and_extract_cap(&rk, &m);

    // Caller persisted the 600 msat from the first spend. A second 600 msat
    // would push the running total to 1200, past the 1000 cap — must be
    // rejected. This is the double-spend the caveat exists to prevent.
    let state_after_first = WindowState {
        spent_msat: 600,
        window_started: SystemTime::now(),
    };
    let err = check_spend(&state_after_first, cap, win, 600)
        .expect_err("second spend over cap must be rejected");
    assert!(
        matches!(err, MacaroonError::CaveatFailed(_)),
        "expected CaveatFailed, got {err:?}"
    );

    // Boundary: a spend that exactly hits the cap is still admitted —
    // confirms the rejection is strictly `> cap`, not `>=`.
    check_spend(&state_after_first, cap, win, 400)
        .expect("spend that exactly hits cap is admitted");

    // And one msat over the boundary is rejected.
    let err = check_spend(&state_after_first, cap, win, 401)
        .expect_err("one msat over cap must be rejected");
    assert!(matches!(err, MacaroonError::CaveatFailed(_)));
}

#[test]
fn window_reset_re_enables_spending() {
    let (rk, m) = issue_with_spend_cap();
    let (cap, win) = verify_and_extract_cap(&rk, &m);

    // Old window: 900 msat already spent. A 200 msat top-up would breach.
    let exhausted = WindowState {
        spent_msat: 900,
        window_started: SystemTime::now() - Duration::from_secs(WINDOW_SECS as u64 + 1),
    };
    assert!(check_spend(&exhausted, cap, win, 200).is_err());

    // New window — the caller (gRPC layer) is responsible for truncating
    // `spent_msat` to entries within the rolling window. After truncation
    // the per-window total resets to 0 and the full cap is available again.
    let fresh = WindowState {
        spent_msat: 0,
        window_started: SystemTime::now(),
    };
    check_spend(&fresh, cap, win, CAP_MSAT)
        .expect("after window reset, full cap is spendable again");
}
