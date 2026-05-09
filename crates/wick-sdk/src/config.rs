//! SDK configuration.
//!
//! [`WickConfig`] is explicit and immutable — constructed once at
//! [`crate::WickClient::new`] time and never mutated. A network-specific
//! constructor ([`WickConfig::for_network`]) picks sensible defaults for the
//! public Esplora endpoint the device should talk to.

use wick_core::WickNetwork;

use crate::error::{Error, Result};

/// The BDK on-chain stop-gap: the number of consecutive empty addresses the
/// first `full_scan` walks before declaring a keychain fully discovered.
pub(crate) const DEFAULT_GAP_LIMIT: usize = 20;

/// Number of concurrent Esplora HTTP requests during sync.
pub(crate) const DEFAULT_PARALLEL_ESPLORA_REQUESTS: usize = 5;

/// SDK configuration.
#[derive(Debug, Clone)]
pub struct WickConfig {
    /// Network the device is operating on. Drives Esplora/faucet defaults
    /// and BIP32 `coin_type`. Mutinynet and Signet are distinct here even
    /// though they both map to `bitcoin::Network::Signet` at the protocol
    /// layer — the distinction is what lets the SDK auto-select the right
    /// Esplora endpoint for mutinynet's 30-second-block chain.
    pub network: WickNetwork,

    /// gRPC endpoint of the `wick-server` instance, e.g.
    /// `http://127.0.0.1:50051` or `https://wick.example.com`. Accepts
    /// `http://` and `https://` schemes; tonic configures TLS accordingly.
    pub server_endpoint: String,

    /// Public Esplora HTTP endpoint the SDK queries for on-chain data
    /// (UTXOs, broadcasts, fee estimates). Must **never** be the server's
    /// internal Esplora pool — portfolio queries are deliberately routed to
    /// a public endpoint.
    pub esplora_url: String,

    /// BDK stop-gap: consecutive empty addresses the first `full_scan`
    /// walks before declaring a keychain fully discovered. Defaults to 20.
    pub gap_limit: usize,

    /// Parallel Esplora HTTP requests during sync.
    pub parallel_esplora_requests: usize,

    /// Operator-supplied override for the expected server pubkey.
    ///
    /// Phase-4 server-pubkey pinning: when `Some`, this 33-byte
    /// compressed secp256k1 pubkey takes precedence over the SDK's
    /// release-pinned const for the configured network. Set this when
    /// dialing a self-hosted `wick-server` whose pubkey isn't in the
    /// upstream SDK release pin. `None` means "use the release pin
    /// for `network`" (or, on `Regtest`, no pin at all).
    pub expected_server_pubkey: Option<[u8; 33]>,
}

impl WickConfig {
    /// Build a config with public Esplora defaults for `network`.
    ///
    /// Callers almost always want to override `server_endpoint` afterwards.
    #[must_use]
    pub fn for_network(network: WickNetwork) -> Self {
        Self {
            network,
            server_endpoint: "http://127.0.0.1:50051".to_owned(),
            esplora_url: network.default_esplora().to_owned(),
            gap_limit: DEFAULT_GAP_LIMIT,
            parallel_esplora_requests: DEFAULT_PARALLEL_ESPLORA_REQUESTS,
            expected_server_pubkey: None,
        }
    }

    /// HTTP faucet base URL for this network, if the network publishes one.
    ///
    /// Only Mutinynet currently returns `Some` (see
    /// [`WickNetwork::default_faucet`]). Integration tests that need to
    /// top up a BDK wallet can use this without reaching into `wick_core`.
    #[must_use]
    pub fn faucet_url(&self) -> Option<&'static str> {
        self.network.default_faucet()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.server_endpoint.is_empty() {
            return Err(Error::Config("server_endpoint is empty".to_owned()));
        }
        if self.esplora_url.is_empty() {
            return Err(Error::Config("esplora_url is empty".to_owned()));
        }
        if self.gap_limit == 0 {
            return Err(Error::Config("gap_limit must be > 0".to_owned()));
        }
        if self.parallel_esplora_requests == 0 {
            return Err(Error::Config(
                "parallel_esplora_requests must be > 0".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the BIP32 `coin_type` suitable for BIP84 / BIP86 derivation
    /// paths (1 for all current networks per SLIP-44; 0 reserved for mainnet
    /// if/when added to `WickNetwork`).
    #[must_use]
    pub(crate) fn coin_type(&self) -> u32 {
        self.network.bip84_coin_type()
    }

    /// The underlying `bitcoin::Network` BDK / rust-bitcoin expect.
    /// Mutinynet maps to `bitcoin::Network::Signet`.
    #[must_use]
    pub(crate) fn bitcoin_network(&self) -> bitcoin::Network {
        self.network.into()
    }
}
