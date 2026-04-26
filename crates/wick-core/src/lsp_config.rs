//! Configuration for the in-process LSP daemon (Phase 3 operator role).
//!
//! `LspConfig` is loaded from the `[lsp]` block of `config.{network}.toml`
//! and shared between `wick-server` (which boots the LSP node alongside
//! tenant nodes) and `wick-lsp` (which owns the LSPS2 service handlers,
//! UTXO pool, and webhook dispatcher).

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::network::WickNetwork;

/// Operator-mode LSP daemon configuration.
///
/// When `enabled = false` (the default) `wick-server` skips the LSP
/// bootstrap entirely and behaves identically to a Phase 2 deployment.
/// Tenants can still receive non-JIT BOLT11 payments over their existing
/// channels.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LspConfig {
    /// Master switch. Default: `false`.
    #[serde(default)]
    pub enabled: bool,

    /// LSP-side P2P listen address. Set to `0.0.0.0:0` to let the OS
    /// pick a free port (useful when running multiple wick-server
    /// instances on one host for testing). Default: `0.0.0.0:19836`.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,

    /// Upstream peer (`pubkey_hex`, `"host:port"`). Empty string means use
    /// `WickNetwork::default_lsp_upstream` for the configured network.
    /// Set to a non-empty string to override (e.g. self-hosted upstream
    /// or a private testnet hub).
    #[serde(default)]
    pub upstream_peer: String,

    /// Floor opening fee in millisatoshis charged on every JIT channel.
    /// Default: 2 000 (2 sats — calibrated for testnet).
    #[serde(default = "default_min_fee_msat")]
    pub min_fee_msat: u64,

    /// Proportional fee in parts-per-million of the JIT payment size.
    /// Default: 7 000 (0.7%).
    #[serde(default = "default_proportional_ppm")]
    pub proportional_ppm: u32,

    /// Reserved BTC pool (sats) covering unconfirmed 0-conf exposure
    /// across all open JIT channels. JIT requests above this remaining
    /// budget fall back to LSPS1 (or fail if LSPS1 is not configured).
    /// Default: 1 000 000 (~$0 worth on testnet).
    #[serde(default = "default_reorg_reserve_sats")]
    pub reorg_reserve_sats: u64,

    /// Hard ceiling on total in-flight unconfirmed JIT exposure
    /// (sum of `capacity_sat` across `Opened` JIT channels). New
    /// `BuyRequest`s whose requested capacity would push the total
    /// past this threshold are rejected with `LSP_CAPACITY_EXHAUSTED`.
    /// Default: 5 000 000 (5M sats — matches `max_jit_channel_sats`
    /// so a single max-size channel can land but a second can't until
    /// the first confirms).
    #[serde(default = "default_reorg_safety_threshold_sats")]
    pub reorg_safety_threshold_sats: u64,

    /// Maximum capacity (sats) of any single JIT channel. Hard ceiling
    /// regardless of payment size. Default: 5 000 000 (~5M sats).
    #[serde(default = "default_max_jit_channel_sats")]
    pub max_jit_channel_sats: u64,

    /// Minimum payment size (msat) we'll quote for. Smaller payments are
    /// rejected at `lsps2.get_info`. Default: 100 000 (100 sats).
    #[serde(default = "default_min_payment_size_msat")]
    pub min_payment_size_msat: u64,

    /// Maximum payment size (msat) we'll quote for. Default: 100M sats.
    #[serde(default = "default_max_payment_size_msat")]
    pub max_payment_size_msat: u64,

    /// CLTV expiry delta we add to the route hint we publish in the
    /// client's BOLT11. Default: 144 (1 day in 10-min-block terms;
    /// safe across all supported networks).
    #[serde(default = "default_cltv_expiry_delta")]
    pub cltv_expiry_delta: u32,

    /// Timeout (blocks) for the client to fulfil the JIT channel by
    /// sending the payment after the channel is opened. Channels left
    /// unfulfilled past this are force-closed. Default: 40.
    #[serde(default = "default_jit_fulfil_timeout_blocks")]
    pub jit_fulfil_timeout_blocks: u32,

    /// Half-life (hours) of the grief score's exponential decay.
    /// `score *= exp(-elapsed_h / half_life_h)` on every read. Default:
    /// 168 (1 week — a griefer's score returns to ~50% after a week of
    /// good behaviour).
    #[serde(default = "default_grief_half_life_hours")]
    pub grief_half_life_hours: f64,

    /// Score added per detected grief event (e.g. a `BuyRequest` whose
    /// SCID expired without becoming `Opened`). Default: 10.
    #[serde(default = "default_grief_penalty")]
    pub grief_penalty: f64,

    /// Score subtracted per fulfilment (`PaymentForwarded` on a JIT
    /// channel). Default: 1 — slow recovery, mirrors LSP economics
    /// where every honest payment is worth less than each abuse event.
    #[serde(default = "default_grief_reward")]
    pub grief_reward: f64,

    /// Threshold above which subsequent `BuyRequest`s from the same
    /// client pubkey are rejected. Default: 100. With the default
    /// penalty of 10, that's 10 consecutive grief events before the
    /// LSP refuses service to a client.
    #[serde(default = "default_grief_rejection_threshold")]
    pub grief_rejection_threshold: f64,

    /// LSP node pubkey, hex-encoded (33-byte compressed secp256k1).
    ///
    /// **Public material only — never a secret.** Operators publish this
    /// at deployment so tenant nodes know which counterparty to expect
    /// LSPS2 messages from. The matching *signing seed* is supplied at
    /// runtime by the operator's SDK via the admin
    /// `RegisterLspIdentity` RPC and is never stored on the server. On
    /// registration, the server validates that the seed-derived pubkey
    /// equals this value; mismatches abort the registration.
    #[serde(default)]
    pub pubkey_hex: Option<String>,
}

impl Default for LspConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_listen_addr(),
            upstream_peer: String::new(),
            min_fee_msat: default_min_fee_msat(),
            proportional_ppm: default_proportional_ppm(),
            reorg_reserve_sats: default_reorg_reserve_sats(),
            reorg_safety_threshold_sats: default_reorg_safety_threshold_sats(),
            max_jit_channel_sats: default_max_jit_channel_sats(),
            min_payment_size_msat: default_min_payment_size_msat(),
            max_payment_size_msat: default_max_payment_size_msat(),
            cltv_expiry_delta: default_cltv_expiry_delta(),
            jit_fulfil_timeout_blocks: default_jit_fulfil_timeout_blocks(),
            grief_half_life_hours: default_grief_half_life_hours(),
            grief_penalty: default_grief_penalty(),
            grief_reward: default_grief_reward(),
            grief_rejection_threshold: default_grief_rejection_threshold(),
            pubkey_hex: None,
        }
    }
}

impl LspConfig {
    /// Resolve the upstream peer to use, applying the per-network
    /// default when `upstream_peer` is empty.
    ///
    /// Returns `(pubkey_hex, host_port)` or `None` if neither config
    /// nor network default supplies one.
    #[must_use]
    pub fn resolved_upstream(&self, network: WickNetwork) -> Option<(String, String)> {
        if self.upstream_peer.is_empty() {
            network
                .default_lsp_upstream()
                .map(|(pk, addr)| (pk.to_owned(), addr.to_owned()))
        } else {
            let parts: Vec<&str> = self.upstream_peer.splitn(2, '@').collect();
            match parts.as_slice() {
                [pk, addr] => Some(((*pk).to_owned(), (*addr).to_owned())),
                _ => None,
            }
        }
    }
}

fn default_listen_addr() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 19836))
}

fn default_min_fee_msat() -> u64 {
    2_000
}

fn default_proportional_ppm() -> u32 {
    7_000
}

fn default_reorg_reserve_sats() -> u64 {
    1_000_000
}

fn default_reorg_safety_threshold_sats() -> u64 {
    5_000_000
}

fn default_max_jit_channel_sats() -> u64 {
    5_000_000
}

fn default_min_payment_size_msat() -> u64 {
    100_000
}

fn default_max_payment_size_msat() -> u64 {
    100_000_000_000
}

fn default_cltv_expiry_delta() -> u32 {
    144
}

fn default_jit_fulfil_timeout_blocks() -> u32 {
    40
}

fn default_grief_half_life_hours() -> f64 {
    168.0
}

fn default_grief_penalty() -> f64 {
    10.0
}

fn default_grief_reward() -> f64 {
    1.0
}

fn default_grief_rejection_threshold() -> f64 {
    100.0
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_doc() {
        let c = LspConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.min_fee_msat, 2_000);
        assert_eq!(c.proportional_ppm, 7_000);
        assert_eq!(c.cltv_expiry_delta, 144);
        assert_eq!(c.jit_fulfil_timeout_blocks, 40);
    }

    #[test]
    fn resolved_upstream_uses_network_default_when_empty() {
        let c = LspConfig::default();
        assert!(c.resolved_upstream(WickNetwork::Regtest).is_none());
        assert!(c.resolved_upstream(WickNetwork::Signet).is_some());
        assert!(c.resolved_upstream(WickNetwork::Mutinynet).is_some());
    }

    #[test]
    fn resolved_upstream_respects_explicit_override() {
        let c = LspConfig {
            upstream_peer:
                "0364913d18a19c664bb4802c61fd7bbd915498e5c8a4a2fcb9e9ddd80a5e5a1d96@127.0.0.1:9735"
                    .to_owned(),
            ..LspConfig::default()
        };
        let Some((pk, addr)) = c.resolved_upstream(WickNetwork::Regtest) else {
            panic!("explicit override should resolve");
        };
        assert!(pk.starts_with("0364"));
        assert_eq!(addr, "127.0.0.1:9735");
    }
}
