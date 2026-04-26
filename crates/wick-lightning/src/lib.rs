//! Lightning node implementation for Wick Cloud.
//!
//! Wick Cloud is self-custodial: the user's device holds the seed and runs the
//! wallet. The server runs a Lightning *node* on the user's behalf and cannot
//! sign without the device (VLS). This crate owns the node-side runtime —
//! channel management, payments, persistence — but never custody.
//!
//! Real LDK 0.2 assembly — `ChannelManager`, `ChainMonitor`, `PeerManager`,
//! `BackgroundProcessor`, SPV loop, peer-reconnect loop. Payments and
//! channels are persisted via [`PaymentStore`] and [`ChannelStore`] into
//! the per-tenant Postgres schema.
//!
//! `wick-server` depends on this crate for all Lightning operations. This
//! crate knows nothing about gRPC, actors, or mpsc dispatch.

pub mod api;
pub mod builder;
pub mod chain;
pub mod channel_store;
pub mod deps;
pub mod error;
pub mod event;
pub mod funding;
pub mod funding_registry;
pub mod funding_store;
pub mod gossip;
pub mod jit_registry;
pub mod liquidity_hook;
pub mod logger;
pub mod node;
pub mod payment_store;
pub mod peer_store;
pub mod peers;
pub mod persistence;
pub mod signer;

pub use api::NodeApi;
pub use builder::NodeBuilder;
pub use chain::{EsploraBroadcaster, EsploraChainClient, FeeEstimator};
pub use channel_store::{ChannelState, ChannelStore, ChannelUpsert};
pub use deps::{NodeDeps, DEFAULT_LISTEN_PORT_BASE};
pub use error::{Result, WickLightningError};
pub use event::{ChannelManagerOps, ChannelManagerRuntimeOps, EventHandler, EventRuntimeOps};
pub use funding::FundingSource;
pub use funding_registry::{PendingFunding, PendingFundingRegistry};
pub use funding_store::{FundingStore, StoredFunding, FUNDING_TTL};
pub use jit_registry::{JitResponse, PendingJitRegistry};
pub use liquidity_hook::LspServiceEventHandler;
pub use logger::TracingLogger;
pub use node::{
    Balance, ChannelSummary, JitInvoice, JitQuote, LiquidityFilter, LnLiquidityManager, Node,
    PaymentRecord, PaymentResult,
};
pub use payment_store::{Direction, PaymentStatus, PaymentStore, PaymentWrite};
pub use peer_store::{PeerInfo, PeerStore};
pub use persistence::PgKvStore;
pub use signer::{from_seed, LocalKeysManager, WickSigner};
pub use wick_core::WickNetwork;
