//! Chain-backend primitives for the LDK node.
//!
//! Each type carries a single LDK trait responsibility:
//!
//! | Type | LDK trait |
//! |---|---|
//! | [`EsploraChainClient`] | `lightning_block_sync::BlockSource` |
//! | [`EsploraBroadcaster`] | `lightning::chain::chaininterface::BroadcasterInterface` |
//! | [`FeeEstimator`] | `lightning::chain::chaininterface::FeeEstimator` |
//!
//! All three are network-agnostic — they work identically against mainnet,
//! testnet, signet, or regtest.

mod broadcaster;
mod esplora;
mod fee_estimator;

pub use broadcaster::EsploraBroadcaster;
pub use esplora::EsploraChainClient;
pub use fee_estimator::FeeEstimator;
