//! Test-scope seed helpers.
//!
//! Seed-to-[`LocalKeysManager`] construction now lives in
//! [`wick_lightning::from_seed`] — that's seed-agnostic plumbing and has no
//! business being a test-only helper. This module is what's left: tenant-id
//! → deterministic seed derivation so tests have reproducible node
//! identities across runs.
//!
//! [`LocalKeysManager`]: wick_lightning::LocalKeysManager

use std::sync::Arc;

use rand::RngCore;
use wick_core::TenantId;
use wick_lightning::{from_seed, LocalKeysManager};

/// Deterministic per-tenant seed.
///
/// `seed[0..8] = tenant_id.to_le_bytes(); seed[8..8+n] = b"wick-testkit-regtest"`.
/// Same inputs → same seed → same Lightning node id across restarts, which
/// is what `NodeBuilder`'s persistence-load path needs to re-attach to
/// previously-persisted channel state.
#[must_use]
pub fn deterministic_seed(tenant_id: TenantId) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&tenant_id.as_u64().to_le_bytes());
    let tag = b"wick-testkit-regtest";
    let n = tag.len().min(24);
    seed[8..8 + n].copy_from_slice(&tag[..n]);
    seed
}

/// Random 32-byte seed for fresh ephemeral nodes.
#[must_use]
pub fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

/// Convenience: `Arc<LocalKeysManager>` built from the deterministic seed.
///
/// Pass into `NodeBuilder::with_signer` to wire a tenant's Lightning node
/// in the regtest harness.
#[must_use]
pub fn signer_for_tenant(tenant_id: TenantId) -> Arc<LocalKeysManager> {
    Arc::new(from_seed(deterministic_seed(tenant_id)))
}

/// Lightning node id that [`signer_for_tenant`] would produce, without
/// materialising a long-lived signer. Useful when tests need a peer's
/// pubkey to configure something *before* the counterparty has started.
#[must_use]
pub fn node_id_from_seed(seed: [u8; 32]) -> bitcoin::secp256k1::PublicKey {
    use lightning::sign::{NodeSigner, Recipient};
    let km = from_seed(seed);
    km.get_node_id(Recipient::Node)
        .expect("KeysManager node_id never fails for Recipient::Node")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_seeds_are_deterministic() {
        let a = deterministic_seed(TenantId::new(42));
        let b = deterministic_seed(TenantId::new(42));
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_tenants_get_distinct_seeds() {
        let a = deterministic_seed(TenantId::new(1));
        let b = deterministic_seed(TenantId::new(2));
        assert_ne!(a, b);
    }

    #[test]
    fn node_id_from_seed_matches_signer() {
        use lightning::sign::{NodeSigner, Recipient};
        let seed = deterministic_seed(TenantId::new(7));
        let id_a = node_id_from_seed(seed);
        let km = from_seed(seed);
        let id_b = km.get_node_id(Recipient::Node).unwrap();
        assert_eq!(id_a, id_b);
    }
}
