//! SDK configuration.
//!
//! [`WickConfig`] is explicit and immutable — constructed once at
//! [`crate::WickClient::new`] time and never mutated. A network-specific
//! constructor ([`WickConfig::for_network`]) picks sensible defaults for the
//! public Esplora endpoint the device should talk to.

use crate::error::{Error, Result};

/// The BDK on-chain stop-gap: the number of consecutive empty addresses the
/// first `full_scan` walks before declaring a keychain fully discovered.
pub(crate) const DEFAULT_GAP_LIMIT: usize = 20;

/// Number of concurrent Esplora HTTP requests during sync.
pub(crate) const DEFAULT_PARALLEL_ESPLORA_REQUESTS: usize = 5;

/// SDK configuration.
#[derive(Debug, Clone)]
pub struct WickConfig {
    /// Bitcoin network the device is operating on. Controls address formats
    /// and BIP32 `coin_type`.
    pub network: bitcoin::Network,

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
}

impl WickConfig {
    /// Build a config with public Esplora defaults for `network`.
    ///
    /// Callers almost always want to override `server_endpoint` afterwards.
    #[must_use]
    pub fn for_network(network: bitcoin::Network) -> Self {
        // Mutinynet is a custom signet; the public Bitcoin signet is served
        // by mempool.space/signet, but mutinynet has its own faster-block
        // chain. Default to the generic signet endpoint; mutinynet users
        // override `esplora_url` directly.
        let esplora_url = match network {
            bitcoin::Network::Testnet => "https://mempool.space/testnet/api",
            bitcoin::Network::Testnet4 => "https://mempool.space/testnet4/api",
            bitcoin::Network::Signet => "https://mempool.space/signet/api",
            bitcoin::Network::Regtest => "http://127.0.0.1:3002",
            bitcoin::Network::Bitcoin => "https://mempool.space/api",
        };
        Self {
            network,
            server_endpoint: "http://127.0.0.1:50051".to_owned(),
            esplora_url: esplora_url.to_owned(),
            gap_limit: DEFAULT_GAP_LIMIT,
            parallel_esplora_requests: DEFAULT_PARALLEL_ESPLORA_REQUESTS,
        }
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

    /// Returns the BIP32 `coin_type` (0 for mainnet, 1 for test-style networks)
    /// suitable for BIP84 / BIP86 derivation paths.
    #[must_use]
    pub(crate) fn coin_type(&self) -> u32 {
        match self.network {
            bitcoin::Network::Bitcoin => 0,
            _ => 1,
        }
    }
}
