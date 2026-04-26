//! Reorg-reserve guard for LSPS2 `BuyRequest`.
//!
//! Each 0-conf JIT channel the LSP opens is exposed to a Bitcoin reorg
//! that drops the funding tx. The LSP underwrites that risk on the
//! tenant's behalf — but only up to a per-deployment ceiling
//! ([`LspConfig::reorg_safety_threshold_sats`]). New `BuyRequest`s
//! whose requested capacity would push the running unconfirmed total
//! past that ceiling are rejected outright with
//! [`ReserveExceeded::CapacityExhausted`].
//!
//! "Unconfirmed exposure" is the sum of [`RegisteredJit::capacity_sat`]
//! over registry entries in state [`JitRequestState::Opened`] — channels
//! whose `create_jit_channel` succeeded but where chain confirmation
//! hasn't yet observed enough blocks to drop them out of the at-risk
//! window. (Wick treats unconfirmed Opened entries as "exposed";
//! confirmation tracking that drops Opened past N confirmations lives
//! in slice 3.3c's chain-monitor mirror.)

use std::sync::Arc;

use crate::peer_registry::PeerRegistry;

/// Failure modes from [`ReorgGuard::check_capacity`]. Each carries the
/// numbers needed to render an actionable LSPS2 error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveExceeded {
    /// `unconfirmed_exposure + requested_capacity > threshold`. The
    /// LSP cannot underwrite another channel of this size right now;
    /// the tenant must retry once existing JIT channels confirm.
    CapacityExhausted {
        /// Current unconfirmed exposure across all `Opened` entries.
        unconfirmed_exposure_sats: u64,
        /// Capacity the new request would add.
        requested_capacity_sat: u64,
        /// Configured ceiling.
        threshold_sats: u64,
    },
}

impl std::fmt::Display for ReserveExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapacityExhausted {
                unconfirmed_exposure_sats,
                requested_capacity_sat,
                threshold_sats,
            } => write!(
                f,
                "LSP_CAPACITY_EXHAUSTED: \
                 unconfirmed exposure {unconfirmed_exposure_sats} sat + \
                 requested {requested_capacity_sat} sat > threshold {threshold_sats} sat"
            ),
        }
    }
}

/// Stateless guard wrapping a [`PeerRegistry`] handle and the configured
/// threshold. Cheap to construct per `BuyRequest`.
#[derive(Debug, Clone)]
pub struct ReorgGuard {
    registry: Arc<PeerRegistry>,
    threshold_sats: u64,
}

impl ReorgGuard {
    /// Build a guard. `threshold_sats = 0` disables the gate (every
    /// request passes) — useful for development.
    #[must_use]
    pub fn new(registry: Arc<PeerRegistry>, threshold_sats: u64) -> Self {
        Self {
            registry,
            threshold_sats,
        }
    }

    /// Reject `requested_capacity_sat` if accepting it would push
    /// unconfirmed JIT exposure past the threshold. Pure in-memory
    /// check; no I/O.
    pub fn check_capacity(&self, requested_capacity_sat: u64) -> Result<(), ReserveExceeded> {
        if self.threshold_sats == 0 {
            return Ok(());
        }
        let exposure = self.registry.unconfirmed_exposure_sats();
        let projected = exposure.saturating_add(requested_capacity_sat);
        if projected > self.threshold_sats {
            return Err(ReserveExceeded::CapacityExhausted {
                unconfirmed_exposure_sats: exposure,
                requested_capacity_sat,
                threshold_sats: self.threshold_sats,
            });
        }
        Ok(())
    }
}

/// Compute the channel capacity that an LSPS2 `BuyRequest` will produce
/// once it reaches the `OpenChannel` event. Mirrors
/// `OperatorServiceHandler`'s over-provisioning math so the BuyRequest
/// gate uses the same number the OpenChannel handler will commit to.
///
/// ```text
/// over_msat       = amt_msat * over_provisioning_ppm / 1_000_000
/// capacity_sat    = (amt_msat + over_msat) / 1000   (rounded down)
/// ```
///
/// Returns the projected sat capacity. `payment_size_msat = None`
/// (any-amount JIT) returns the configured `max_jit_channel_sats` —
/// the worst-case capacity such a request could materialise into.
#[must_use]
pub fn projected_capacity_sat(
    payment_size_msat: Option<u64>,
    over_provisioning_ppm: u64,
    max_jit_channel_sats: u64,
) -> u64 {
    match payment_size_msat {
        Some(amt_msat) => {
            let over = amt_msat
                .saturating_mul(over_provisioning_ppm)
                .saturating_div(1_000_000);
            amt_msat
                .saturating_add(over)
                .saturating_div(1000)
                .min(max_jit_channel_sats)
        }
        None => max_jit_channel_sats,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::peer_registry::{JitRequestState, PeerRegistry, RegisteredJit};
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    use wick_core::TenantId;

    fn dummy_pubkey(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn registry_with_opened(scids_capacities: &[(u64, u64)]) -> Arc<PeerRegistry> {
        let reg = PeerRegistry::empty();
        let pk = dummy_pubkey(7);
        let tenant_id = TenantId::from_pubkey(&pk.serialize());
        for (scid, cap) in scids_capacities {
            // Bypass register_buy (needs a pool) — test the guard math
            // against a hand-built registry state.
            reg.inner_mut_for_test().insert(
                *scid,
                RegisteredJit {
                    tenant_id,
                    tenant_pubkey: pk,
                    epoch: *scid,
                    amount_msat: Some(cap.saturating_mul(1000)),
                    state: JitRequestState::Opened,
                    capacity_sat: Some(*cap),
                    channel_id: None,
                },
            );
        }
        reg
    }

    #[test]
    fn check_capacity_passes_below_threshold() {
        let reg = registry_with_opened(&[(1, 1_000_000), (2, 2_000_000)]);
        let guard = ReorgGuard::new(reg, 5_000_000);
        assert!(guard.check_capacity(1_500_000).is_ok());
    }

    #[test]
    fn check_capacity_rejects_at_threshold() {
        let reg = registry_with_opened(&[(1, 4_000_000)]);
        let guard = ReorgGuard::new(reg, 5_000_000);
        let err = guard.check_capacity(2_000_000).unwrap_err();
        match err {
            ReserveExceeded::CapacityExhausted {
                unconfirmed_exposure_sats,
                requested_capacity_sat,
                threshold_sats,
            } => {
                assert_eq!(unconfirmed_exposure_sats, 4_000_000);
                assert_eq!(requested_capacity_sat, 2_000_000);
                assert_eq!(threshold_sats, 5_000_000);
            }
        }
    }

    #[test]
    fn check_capacity_zero_threshold_disables_gate() {
        let reg = registry_with_opened(&[(1, u64::MAX / 2)]);
        let guard = ReorgGuard::new(reg, 0);
        assert!(guard.check_capacity(u64::MAX / 2).is_ok());
    }

    #[test]
    fn projected_capacity_sat_matches_handler_math() {
        // Same constants the handler uses (5% over-provisioning).
        const OVER_PPM: u64 = 50_000;
        const MAX_CAP: u64 = 5_000_000;
        // 100k sats payment → 105k msat over → 100_005 sat ≈ 100 005.
        let cap = projected_capacity_sat(Some(100_000_000), OVER_PPM, MAX_CAP);
        assert_eq!(cap, 105_000);

        // Any-amount → max ceiling.
        assert_eq!(projected_capacity_sat(None, OVER_PPM, MAX_CAP), MAX_CAP);

        // Above ceiling clamps.
        let cap = projected_capacity_sat(Some(10_000_000_000), OVER_PPM, MAX_CAP);
        assert_eq!(cap, MAX_CAP);
    }
}
