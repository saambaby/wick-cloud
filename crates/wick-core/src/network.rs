//! Bitcoin network abstraction for Wick Cloud.
//!
//! [`WickNetwork`] is the single source of truth for which network the server
//! is running against. It carries per-network defaults (Esplora URL, RGS URL,
//! faucet, seed peers) so every crate derives them from one place rather than
//! scattering magic strings.

use serde::{ Deserialize, Serialize };

/// Networks supported by Wick Cloud.
///
/// Mutinynet is a custom signet (30-second blocks) run by Mutiny Wallet.
/// It uses the same address formats as signet (tb1 bech32) and the same
/// genesis hash as default signet (BIP-325 rule: all signets share genesis).
/// LDK treats it as `bitcoin::Network::Signet` at the protocol layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WickNetwork {
    /// Local regtest — requires a local `bitcoind` + Esplora/electrs.
    Regtest,
    /// Default signet (mempool.space Esplora, ACINQ node as seed peer).
    Signet,
    /// Mutinynet — custom signet with 30-second blocks.
    /// No local daemon required; uses public mutinynet.com Esplora.
    #[default]
    Mutinynet,
}
impl From<WickNetwork> for bitcoin::Network {
    fn from(network: WickNetwork) -> Self {
        match network {
            WickNetwork::Regtest => bitcoin::Network::Regtest,
            WickNetwork::Signet | WickNetwork::Mutinynet => bitcoin::Network::Signet,
        }
    }
}
impl WickNetwork {
    /// BIP-84 `coin_type` for HD key derivation.
    ///
    /// `1` for all test networks (regtest, signet, mutinynet) per SLIP-44.
    #[must_use]
    pub const fn bip84_coin_type(self) -> u32 {
        match self {
            Self::Regtest | Self::Signet | Self::Mutinynet => 1,
        }
    }

    /// Default Esplora HTTP endpoint for this network.
    ///
    /// Can be overridden by setting `esplora_url` in the TOML config.
    #[must_use]
    pub const fn default_esplora(self) -> &'static str {
        match self {
            Self::Regtest => "http://localhost:3002",
            Self::Signet => "https://mempool.space/signet/api",
            Self::Mutinynet => "https://mutinynet.com/api",
        }
    }

    /// Default Rapid Gossip Sync snapshot URL for this network, if available.
    ///
    /// `None` for regtest — there is no public RGS for a local regtest chain.
    /// Append `/{unix_timestamp}` to fetch a delta snapshot.
    #[must_use]
    pub const fn default_rgs(self) -> Option<&'static str> {
        match self {
            Self::Regtest => None,
            Self::Signet => Some("https://rapidsync.lightningdevkit.org/testnet/snapshot"),
            Self::Mutinynet => Some("https://rgs.mutinynet.com/snapshot"),
        }
    }

    /// HTTP faucet base URL for this network, if available.
    ///
    /// Mutinynet exposes `POST /api/onchain` and `POST /api/channel`.
    #[must_use]
    pub const fn default_faucet(self) -> Option<&'static str> {
        match self {
            Self::Regtest => None,
            Self::Signet => None,
            Self::Mutinynet => Some("https://faucet.mutinynet.com"),
        }
    }

    /// Well-known seed peers for this network as `(pubkey_hex, host:port)` pairs.
    ///
    /// On first boot, if the `PeerStore` is empty the node connects to these
    /// peers so it can start gossiping and routing. At least one of these
    /// should be a highly-connected hub (e.g. Mutiny's hub on mutinynet).
    #[must_use]
    pub const fn seed_peers(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Regtest => &[],
            Self::Signet =>
                &[
                    // ACINQ signet node
                    (
                        "0364913d18a19c664bb4802c61fd7bbd915498e5c8a4a2fcb9e9ddd80a5e5a1d96",
                        "13.248.222.197:9735",
                    ),
                ],
            Self::Mutinynet =>
                &[
                    // Mutiny hub node — primary routing peer for mutinynet
                    (
                        "02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b",
                        "45.79.52.207:9735",
                    ),
                ],
        }
    }
}

impl std::fmt::Display for WickNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Regtest => write!(f, "regtest"),
            Self::Signet => write!(f, "signet"),
            Self::Mutinynet => write!(f, "mutinynet"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_test_networks_use_coin_type_1() {
        assert_eq!(WickNetwork::Regtest.bip84_coin_type(), 1);
        assert_eq!(WickNetwork::Signet.bip84_coin_type(), 1);
        assert_eq!(WickNetwork::Mutinynet.bip84_coin_type(), 1);
    }

    #[test]
    fn serde_roundtrip() {
        for (s, net) in [
            ("\"regtest\"", WickNetwork::Regtest),
            ("\"signet\"", WickNetwork::Signet),
            ("\"mutinynet\"", WickNetwork::Mutinynet),
        ] {
            let de: WickNetwork = serde_json::from_str(s).unwrap();
            assert_eq!(de, net);
            let ser = serde_json::to_string(&net).unwrap();
            assert_eq!(ser, s);
        }
    }
}
