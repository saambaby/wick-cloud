//! Static LSPS2 fee parameters fed into LDK's
//! [`lightning_liquidity::lsps2::service::LSPS2ServiceHandler`].
//!
//! LDK's service handler owns the HMAC `promise` rotation logic
//! internally — we just supply the per-network fee menu derived from
//! `[lsp]` config. Slice 3.3 hardening adds `param_id` revocation +
//! per-client binding on top of LDK's defaults.

use lightning_liquidity::lsps0::ser::LSPSDateTime;
use lightning_liquidity::lsps2::msgs::LSPS2RawOpeningFeeParams;
use sqlx::types::chrono;

const VALID_UNTIL_WINDOW_SECS: u64 = 30 * 60;
const MIN_LIFETIME_BLOCKS: u32 = 4_032;
const MAX_CLIENT_TO_SELF_DELAY: u32 = 1_440;

/// Resolved view of the operator's opening fee params, suitable for
/// caching at the gRPC layer (no LDK types leak).
#[derive(Debug, Clone, Copy)]
pub struct OpeningParamsView {
    /// Floor fee (msat).
    pub min_fee_msat: u64,
    /// Proportional fee (ppm).
    pub proportional_ppm: u32,
    /// Min payment size (msat).
    pub min_payment_size_msat: u64,
    /// Max payment size (msat).
    pub max_payment_size_msat: u64,
}

/// Single-tier fee param menu builder.
///
/// LDK's service handler accepts a `Vec<LSPS2RawOpeningFeeParams>` for
/// every `lsps2.get_info` response — operators may serve multiple tiers
/// (e.g. cheap-but-slow / expensive-but-fast). Phase 3 ships one tier;
/// slice 3.3 may add tiers behind config.
#[derive(Debug, Clone, Copy)]
pub struct FeeParamCache {
    view: OpeningParamsView,
}

impl FeeParamCache {
    /// Construct from operator-provided params. The `promise_secret` for
    /// HMAC binding is owned by LDK's service handler — passed at
    /// `LSPS2ServiceConfig` construction time, not here.
    #[must_use]
    pub fn new(view: OpeningParamsView) -> Self {
        Self { view }
    }

    /// Return the static config view (UI / metrics surface).
    #[must_use]
    pub fn current_params(&self) -> OpeningParamsView {
        self.view
    }

    /// Build the menu LDK will pass to `lsps2.get_info` requesters.
    /// Single-tier for now.
    #[must_use]
    pub fn menu(&self) -> Vec<LSPS2RawOpeningFeeParams> {
        let valid_until =
            std::time::SystemTime::now() + std::time::Duration::from_secs(VALID_UNTIL_WINDOW_SECS);
        let valid_until_dt = chrono::DateTime::<chrono::Utc>::from(valid_until);
        vec![LSPS2RawOpeningFeeParams {
            min_fee_msat: self.view.min_fee_msat,
            proportional: self.view.proportional_ppm,
            valid_until: LSPSDateTime(valid_until_dt),
            min_lifetime: MIN_LIFETIME_BLOCKS,
            max_client_to_self_delay: MAX_CLIENT_TO_SELF_DELAY,
            min_payment_size_msat: self.view.min_payment_size_msat,
            max_payment_size_msat: self.view.max_payment_size_msat,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_params() -> OpeningParamsView {
        OpeningParamsView {
            min_fee_msat: 2_000,
            proportional_ppm: 7_000,
            min_payment_size_msat: 100_000,
            max_payment_size_msat: 100_000_000_000,
        }
    }

    #[test]
    fn current_params_reflects_input() {
        let cache = FeeParamCache::new(default_params());
        let p = cache.current_params();
        assert_eq!(p.min_fee_msat, 2_000);
        assert_eq!(p.proportional_ppm, 7_000);
    }

    #[test]
    fn menu_emits_single_tier() {
        let cache = FeeParamCache::new(default_params());
        let menu = cache.menu();
        assert_eq!(menu.len(), 1);
        assert_eq!(menu[0].min_fee_msat, 2_000);
        assert_eq!(menu[0].max_payment_size_msat, 100_000_000_000);
    }
}
