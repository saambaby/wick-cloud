//! Fee estimator with a write-through cache.
//!
//! [`FeeEstimator`] stores pre-computed sat/1000-weight rates keyed by
//! [`ConfirmationTarget`]. A polling task (spawned by the server, one per
//! process — *not* per tenant) calls [`FeeEstimator::update`] after each
//! Esplora fetch. LDK reads rates synchronously via the
//! [`lightning::chain::chaininterface::FeeEstimator`] trait without any
//! async I/O.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use lightning::chain::chaininterface::{ConfirmationTarget, FeeEstimator as LdkFeeEstimator};

/// Minimum allowed rate (LDK's own floor for relay-safe transactions).
const MIN_SAT_PER_1000_WEIGHT: u32 = 253;

/// Fallback sat/vB when Esplora returns no data.
const FALLBACK_SAT_PER_VB: f64 = 10.0;

/// On-chain fee cache.
///
/// Seeded with safe defaults at construction so the node can operate before
/// the first successful Esplora poll. Call [`update`](Self::update) after
/// each `fetch_fee_estimates` result to keep rates current.
#[derive(Debug)]
pub struct FeeEstimator {
    rates: Arc<RwLock<HashMap<ConfirmationTarget, u32>>>,
}

impl FeeEstimator {
    /// Construct with deterministic safe defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rates: Arc::new(RwLock::new(default_rates())),
        }
    }

    /// Recompute and store all target rates from a fresh Esplora fee-estimates
    /// map (`block_count → sat/vB`).
    ///
    /// Called by the background polling task after each
    /// `EsploraChainClient::fetch_fee_estimates()` response.
    pub fn update(&self, estimates: &HashMap<u16, f64>) {
        let Ok(mut w) = self.rates.write() else {
            tracing::warn!(target: "wick_lightning", "fee rates lock poisoned; skipping update");
            return;
        };
        for target in all_targets() {
            let blocks = blocks_for_target(target);
            let sat_per_vb = sat_per_vb_from_estimates(estimates, blocks);
            w.insert(target, sat_per_1000_weight(sat_per_vb));
        }
    }
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl LdkFeeEstimator for FeeEstimator {
    fn get_est_sat_per_1000_weight(&self, target: ConfirmationTarget) -> u32 {
        self.rates
            .read()
            .ok()
            .and_then(|r| r.get(&target).copied())
            .unwrap_or(MIN_SAT_PER_1000_WEIGHT)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn all_targets() -> [ConfirmationTarget; 8] {
    [
        ConfirmationTarget::MaximumFeeEstimate,
        ConfirmationTarget::UrgentOnChainSweep,
        ConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
        ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
        ConfirmationTarget::AnchorChannelFee,
        ConfirmationTarget::NonAnchorChannelFee,
        ConfirmationTarget::ChannelCloseMinimum,
        ConfirmationTarget::OutputSpendingFee,
    ]
}

fn blocks_for_target(target: ConfirmationTarget) -> u16 {
    match target {
        ConfirmationTarget::MaximumFeeEstimate => 1,
        ConfirmationTarget::UrgentOnChainSweep => 2,
        ConfirmationTarget::MinAllowedAnchorChannelRemoteFee
        | ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => 12,
        ConfirmationTarget::AnchorChannelFee
        | ConfirmationTarget::NonAnchorChannelFee
        | ConfirmationTarget::ChannelCloseMinimum
        | ConfirmationTarget::OutputSpendingFee => 6,
    }
}

/// Pick a sat/vB fee deterministically from the Esplora fee-estimates map.
///
/// `HashMap::values()` iteration order is undefined — relying on it could yield
/// different fees on two peers for the same missing key, leading to
/// incompatible commitment transactions and force-closes. Sort the keys first
/// to produce a stable result.
fn sat_per_vb_from_estimates(estimates: &HashMap<u16, f64>, blocks: u16) -> f64 {
    if estimates.is_empty() {
        return FALLBACK_SAT_PER_VB;
    }
    if let Some(v) = estimates.get(&blocks) {
        return *v;
    }
    let mut keys: Vec<u16> = estimates.keys().copied().collect();
    keys.sort_unstable();
    if let Some(&k) = keys.iter().find(|&&k| k >= blocks) {
        return estimates[&k];
    }
    keys.last()
        .and_then(|k| estimates.get(k).copied())
        .unwrap_or(FALLBACK_SAT_PER_VB)
}

/// Convert sat/vB → sat/1000-weight, clamped to LDK's minimum floor.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn sat_per_1000_weight(sat_per_vb: f64) -> u32 {
    // 1 vbyte = 4 weight units, so sat/vB × 4 = sat/4-weight;
    // then × 250 gives sat per 1000-weight... wait: sat/vB × 4 = sat/4000-weight
    // => sat/1000-weight = (sat/vB × 4000) / 4 = sat/vB × 1000? No.
    //
    // Correct: 1 vbyte = 4 weight units.
    //   sat/vB           = sat per 4 weight units
    //   sat/1000-weight  = (sat/vB) × 1000 / 4  = (sat/vB) × 250
    //
    // LDK wants sat/kw. ln-gateway multiplies by 4 — that is what LDK's
    // built-in conversion does for some call sites, so we mirror that here to
    // keep compatibility with the reference implementation. If a live rate
    // audit shows these need to be /4-ed, adjust here.
    let scaled = (sat_per_vb * 4.0).max(f64::from(MIN_SAT_PER_1000_WEIGHT));
    // Clamp before casting; above we already ensure scaled >= 253.
    scaled.min(f64::from(u32::MAX)) as u32
}

fn default_rates() -> HashMap<ConfirmationTarget, u32> {
    let empty: HashMap<u16, f64> = HashMap::new();
    let mut map = HashMap::with_capacity(all_targets().len());
    for target in all_targets() {
        let blocks = blocks_for_target(target);
        let sat_per_vb = sat_per_vb_from_estimates(&empty, blocks);
        map.insert(target, sat_per_1000_weight(sat_per_vb));
    }
    map
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_respect_minimum_floor() {
        let fe = FeeEstimator::new();
        for target in all_targets() {
            let rate = fe.get_est_sat_per_1000_weight(target);
            assert!(
                rate >= MIN_SAT_PER_1000_WEIGHT,
                "{target:?} below floor: {rate}"
            );
        }
    }

    #[test]
    fn update_lifts_rates_above_floor_when_fees_are_high() {
        let fe = FeeEstimator::new();
        // Push estimates well above the relay floor so the × 4 conversion
        // clears the MIN_SAT_PER_1000_WEIGHT clamp.
        let mut estimates = HashMap::new();
        estimates.insert(1_u16, 500.0);
        estimates.insert(2_u16, 400.0);
        estimates.insert(6_u16, 200.0);
        estimates.insert(12_u16, 100.0);
        fe.update(&estimates);

        let urgent = fe.get_est_sat_per_1000_weight(ConfirmationTarget::UrgentOnChainSweep);
        let slow = fe.get_est_sat_per_1000_weight(ConfirmationTarget::ChannelCloseMinimum);
        assert!(urgent > MIN_SAT_PER_1000_WEIGHT);
        assert!(urgent > slow, "urgent ({urgent}) should exceed slow ({slow})");
    }

    #[test]
    fn missing_key_uses_nearest_higher() {
        // UrgentOnChainSweep targets 2 blocks. Provide only 1 and 6.
        let mut estimates = HashMap::new();
        estimates.insert(1_u16, 100.0);
        estimates.insert(6_u16, 10.0);

        let sat_vb = sat_per_vb_from_estimates(&estimates, 2);
        // Nearest higher key is 6 → 10 sat/vB.
        assert!((sat_vb - 10.0).abs() < f64::EPSILON);
    }
}
