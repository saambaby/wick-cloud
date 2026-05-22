//! Phase-4 D3 W2-B red-team: realistic replay + per-macaroon revocation
//! attack flows against the in-memory revocation set.
//!
//! These tests are sibling to `multi_node_revocation.rs` (which exercises
//! the postgres-backed cluster propagation path). The cases here are
//! hermetic: in-memory `HashSet<[u8; 16]>` only, no #[ignore], no network.
//!
//! Coverage:
//!   1. `replay_succeeds_until_revoked` — verify-twice is a legal replay
//!      (Lightning-style bearer auth); inserting the nonce into the
//!      revocation set must flip the third verify to `Revoked`.
//!   2. `stolen_nonce_post_revoke_blocked` — an attacker who steals a
//!      revoked nonce and rebinds it onto a freshly-minted macaroon
//!      (different root key, fresh signature, attacker-controlled scope)
//!      still gets rejected on the nonce alone.

#![allow(clippy::unwrap_used)]

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use wick_macaroon::{
    Caveat, ExpectedScope, Macaroon, MacaroonError, RootKey, Scope, VerifyContext,
};

fn ctx<'a>(now: SystemTime, revoked: &'a HashSet<[u8; 16]>) -> VerifyContext<'a> {
    VerifyContext {
        now,
        revoked_nonces: revoked,
        expected_scope: None,
        noise_static_pk_observed: None,
    }
}

fn nonce_of(m: &Macaroon) -> [u8; 16] {
    // Last nonce caveat wins under verify(); we mirror that here.
    let cav = m
        .caveats()
        .iter()
        .rev()
        .find(|c| c.tag() == 0x03)
        .expect("issued macaroon always carries a nonce caveat");
    let mut n = [0u8; 16];
    n.copy_from_slice(cav.payload());
    n
}

#[test]
fn replay_succeeds_until_revoked() {
    let rk = RootKey::random();
    let m = Macaroon::issue(
        "wick.cloud",
        [1u8; 16],
        &rk,
        Scope::User { tenant_id: [2u8; 16] },
        Duration::from_secs(3600),
    );

    // Round-trip through serialize/deserialize to mirror what the gRPC
    // interceptor would actually do.
    let bytes = m.serialize();
    let m_wire = Macaroon::deserialize(&bytes).unwrap();

    let mut revoked: HashSet<[u8; 16]> = HashSet::new();

    // First verify: clean, accepted.
    let v1 = m_wire.verify(&rk, &ctx(SystemTime::now(), &revoked)).unwrap();
    assert!(matches!(v1.scope, Scope::User { .. }));

    // Second verify (replay): still accepted. Macaroons are bearer
    // creds; replay is normal and is policed by `spend_caveat` +
    // upstream idempotency, NOT by rejecting reuse.
    let v2 = m_wire.verify(&rk, &ctx(SystemTime::now(), &revoked)).unwrap();
    assert_eq!(v1.nonce, v2.nonce);

    // Now revoke the nonce.
    let n = nonce_of(&m_wire);
    revoked.insert(n);

    // Third verify: blocked.
    let err = m_wire
        .verify(&rk, &ctx(SystemTime::now(), &revoked))
        .unwrap_err();
    assert_eq!(err, MacaroonError::Revoked);

    // And re-issuing scope-expectation doesn't bypass it.
    let strict = VerifyContext {
        now: SystemTime::now(),
        revoked_nonces: &revoked,
        expected_scope: Some(ExpectedScope::AnyUser),
        noise_static_pk_observed: None,
    };
    let err = m_wire.verify(&rk, &strict).unwrap_err();
    assert_eq!(err, MacaroonError::Revoked);
}

#[test]
fn stolen_nonce_post_revoke_blocked() {
    // Step 1: issue M_A under root key RK_A, capture and revoke its nonce.
    let rk_a = RootKey::random();
    let m_a = Macaroon::issue(
        "wick.cloud",
        [0xAAu8; 16],
        &rk_a,
        Scope::User { tenant_id: [0x11u8; 16] },
        Duration::from_secs(3600),
    );
    let stolen_nonce = nonce_of(&m_a);

    let mut revoked: HashSet<[u8; 16]> = HashSet::new();
    revoked.insert(stolen_nonce);

    // Confirm M_A is now blocked.
    let err = m_a.verify(&rk_a, &ctx(SystemTime::now(), &revoked)).unwrap_err();
    assert_eq!(err, MacaroonError::Revoked);

    // Step 2: attacker mints M_B under a different (their own) root key
    // RK_B, with a different scope, but reuses the leaked nonce by
    // appending it as a second nonce caveat. The HMAC chain is fully
    // valid under RK_B and the macaroon would otherwise pass — except
    // the revocation set rejects on the nonce alone.
    //
    // `add_caveat` re-chains the signature so the on-wire macaroon is
    // a well-formed, attacker-signed credential carrying the stolen
    // nonce. This mirrors the real attack: a captured nonce reused
    // by a hostile party who controls their own keys.
    let rk_b = RootKey::random();
    let mut m_b = Macaroon::issue(
        "wick.cloud",
        [0xBBu8; 16],
        &rk_b,
        Scope::Admin,
        Duration::from_secs(3600),
    );
    m_b.add_caveat(Caveat::nonce(stolen_nonce));

    // Sanity: without revocation set, M_B verifies fine under its own
    // root key — the attacker built a structurally valid macaroon.
    let clean: HashSet<[u8; 16]> = HashSet::new();
    let ok = m_b.verify(&rk_b, &ctx(SystemTime::now(), &clean)).unwrap();
    assert_eq!(ok.nonce, stolen_nonce);

    // With the stolen nonce in the revocation set, M_B is blocked
    // regardless of its independent root key + signature.
    let err = m_b
        .verify(&rk_b, &ctx(SystemTime::now(), &revoked))
        .unwrap_err();
    assert_eq!(err, MacaroonError::Revoked);

    // Round-trip M_B through the wire too — same outcome after
    // serialize/deserialize.
    let bytes = m_b.serialize();
    let m_b_wire = Macaroon::deserialize(&bytes).unwrap();
    let err = m_b_wire
        .verify(&rk_b, &ctx(SystemTime::now(), &revoked))
        .unwrap_err();
    assert_eq!(err, MacaroonError::Revoked);
}
