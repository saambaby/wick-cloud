//! Lightning node implementation for Wick Cloud.
//!
//! Wick Cloud is self-custodial: the user's device holds the seed and runs the
//! wallet. The server runs a Lightning *node* on the user's behalf and cannot
//! sign without the device (VLS). This crate owns the node-side runtime —
//! channel management, payments, persistence — but never custody.
//!
//! Phase 1: in-memory stub — balances and payments are not persisted.
//! Phase 3: stub fields replaced by a real LDK assembly (`ChannelManager`,
//! `ChainMonitor`, `PeerManager`, `BackgroundProcessor`, event loop).
//!
//! `wick-server` depends on this crate for all Lightning operations. This
//! crate knows nothing about gRPC, actors, or mpsc dispatch.

pub mod api;
pub mod builder;
pub mod chain;
pub mod deps;
pub mod error;
pub mod event;
pub mod funding;
pub mod logger;
pub mod node;
pub mod payment_store;
pub mod peer_store;
pub mod persistence;
pub mod signer;

pub use api::NodeApi;
pub use builder::NodeBuilder;
pub use chain::{EsploraBroadcaster, EsploraChainClient, FeeEstimator};
pub use deps::{NodeDeps, DEFAULT_LISTEN_PORT_BASE};
pub use error::{Result, WickLightningError};
pub use event::{ChannelManagerOps, ChannelManagerRuntimeOps, EventHandler, EventRuntimeOps};
pub use funding::FundingSource;
pub use logger::TracingLogger;
pub use node::{Balance, ChannelSummary, Node, PaymentRecord, PaymentResult};
pub use payment_store::{Direction, PaymentStatus, PaymentStore, PaymentWrite};
pub use peer_store::{PeerInfo, PeerStore};
pub use persistence::PgKvStore;
pub use signer::{from_seed, LocalKeysManager, WickSigner};
