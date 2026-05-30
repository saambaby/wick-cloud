//! Multi-tenant Lightning-node actor model.
//!
//! Each tenant owns a single [`actor::NodeActor`] running as a dedicated tokio
//! task. All external interaction goes through an mpsc channel, serialising
//! access to the node and eliminating the need for any internal mutexes.
//!
//! ## Terminology
//!
//! Wick Cloud is self-custodial: the *user's device* holds the seed and runs
//! the wallet. The server runs a Lightning **node** on the user's behalf and
//! cannot sign without the device (VLS). Hence "node", not "wallet", on the
//! server side.
//!
//! ## State machine
//!
//! ```text
//! Parked(0) ─wake─▶ Loading(1) ─done─▶ Active(2)
//!    ▲                                      │
//!    └────────────── park ──────────────────┘
//!
//! Any state ─error─▶ Error(3) ─recovery─▶ Parked(0)
//! ```
//!
//! See [`manager::NodeManager`] for the park/wake, eviction, and recovery
//! implementations that drive these transitions.

pub mod actor;
pub mod admission;
pub mod event_buffer;
pub mod manager;

use std::sync::{
    atomic::{AtomicU64, AtomicU8},
    Arc, RwLock,
};
use std::time::Instant;

use arc_swap::ArcSwap;
use tokio::sync::{mpsc, oneshot, Notify};
use wick_lightning::NodeApi;

/// Memory reserved per active node (bytes).
///
/// All active nodes are charged this flat amount against the global
/// `ManagerConfig::memory_budget_bytes`. Replace with real LDK per-node
/// measurement in a later phase once `BackgroundProcessor` exposes it.
pub const PER_NODE_BYTES: usize = 64 * 1024;

/// Channel capacity for each node's command queue.
pub const NODE_CMD_CAPACITY: usize = 64;

// ── Node state constants ───────────────────────────────────────────────────

/// Raw u8 values stored in [`NodeHandle::state`] (`AtomicU8`).
pub mod state {
    /// Node state serialised to Postgres; no in-memory state.
    pub const PARKED: u8 = 0;
    /// Node state loading from Postgres; actor starting.
    pub const LOADING: u8 = 1;
    /// Node fully active; actor processing commands.
    pub const ACTIVE: u8 = 2;
    /// Actor encountered a fatal error; awaiting recovery.
    pub const ERROR: u8 = 3;
}

// ── Error state ──────────────────────────────────────────────────────────────

/// Reason a tenant is in [`state::ERROR`].
#[derive(Debug, Clone)]
pub enum ErrorReason {
    /// Factory call (node build) or wake activation failed.
    FactoryFailed(String),
    /// Node shutdown exceeded its 10 s task-join timeout.
    ShutdownTimeout,
}

/// Per-tenant error bookkeeping. Stored on [`NodeHandle::error`]; `None`
/// when the tenant is healthy.
#[derive(Debug, Clone)]
pub struct ErrorState {
    /// What transitioned the tenant into [`state::ERROR`].
    pub reason: ErrorReason,
    /// When the tenant entered the current error state.
    pub since: Instant,
    /// Consecutive failed wake/recovery attempts. Starts at 1 on the
    /// transition into ERROR, increments each failed recovery probe.
    pub attempts: u8,
}

// ── Response types (owned by `wick-lightning`) ───────────────────────────────

/// Re-exported from [`wick_lightning`] so callers need only import from here.
pub use wick_lightning::{Balance, ChannelSummary, PaymentRecord, PaymentResult};

// ── NodeCmd ──────────────────────────────────────────────────────────────────

/// Outcome of a [`NodeCmd::Park`] request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkOutcome {
    /// Actor drained its mpsc queue, all safety checks passed, `shutdown`
    /// completed. Caller should run `NodeManager::complete_park` to flip
    /// state and release the memory budget.
    Parked,
    /// Post-drain recheck found pending HTLCs, an inflight outbound
    /// payment, or unacknowledged monitor updates. Actor stayed running;
    /// caller should re-enqueue `Park` after a backoff.
    RequeuedDueToActivity,
}

/// Commands sent to a [`actor::NodeActor`] over its mpsc channel.
///
/// Each variant carries a `oneshot::Sender` for the response so callers can
/// await the result without polling.
#[derive(Debug)]
pub enum NodeCmd {
    /// Return the current balance.
    GetBalance {
        /// Response channel.
        resp: oneshot::Sender<anyhow::Result<Balance>>,
    },
    /// Initiate an outbound payment.
    SendPayment {
        /// BOLT11 invoice to pay.
        bolt11: String,
        /// Response channel.
        resp: oneshot::Sender<anyhow::Result<PaymentResult>>,
    },
    /// Create a BOLT11 invoice for this node.
    ReceivePayment {
        /// Optional fixed amount in millisatoshis.
        amount_msat: Option<u64>,
        /// Invoice memo / description.
        memo: String,
        /// Response channel — yields `(bolt11_string, payment_hash_bytes)`.
        resp: oneshot::Sender<anyhow::Result<(String, Vec<u8>)>>,
    },
    /// Return paginated payment history.
    GetTransactions {
        /// Maximum records to return.
        limit: u32,
        /// Response channel.
        resp: oneshot::Sender<anyhow::Result<Vec<PaymentRecord>>>,
    },
    /// Return the node's pubkey + local listen address.
    GetNodeInfo {
        /// Response channel — `(pubkey, Some(host:port)) | (pubkey, None)` if
        /// the node has no listener.
        resp: oneshot::Sender<
            anyhow::Result<(bitcoin::secp256k1::PublicKey, Option<std::net::SocketAddr>)>,
        >,
    },
    /// Connect to a Lightning peer and persist it for reconnection.
    ConnectPeer {
        /// Peer's compressed secp256k1 pubkey.
        peer: bitcoin::secp256k1::PublicKey,
        /// Peer host.
        host: String,
        /// Peer port.
        port: u16,
        /// Response channel.
        resp: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Start an outbound channel open and wait for LDK's
    /// `FundingGenerationReady`. Returns the temp_channel_id + pending
    /// funding request the caller must satisfy with a signed tx.
    OpenChannelInit {
        /// Counterparty pubkey.
        peer: bitcoin::secp256k1::PublicKey,
        /// Channel value in satoshis (funder side).
        value_sat: u64,
        /// Amount pushed to the counterparty in millisatoshis.
        push_msat: u64,
        /// Max wait for `Event::FundingGenerationReady`.
        timeout: std::time::Duration,
        /// Response channel — yields the temp_channel_id LDK assigned and
        /// the parked `PendingFunding` (output_script + value).
        resp: oneshot::Sender<
            anyhow::Result<(
                lightning::ln::types::ChannelId,
                wick_lightning::PendingFunding,
            )>,
        >,
    },
    /// Complete an outbound channel open with a caller-supplied, pre-signed
    /// funding transaction.
    OpenChannelFinalize {
        /// Temp channel id returned from [`Self::OpenChannelInit`].
        temp_channel_id: lightning::ln::types::ChannelId,
        /// Counterparty pubkey.
        counterparty: bitcoin::secp256k1::PublicKey,
        /// Serialised funding tx paying `channel_value_sat` to the
        /// `output_script` returned from `OpenChannelInit`.
        funding_tx: bitcoin::Transaction,
        /// Response channel.
        resp: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Snapshot of the node's current channels.
    ListChannels {
        /// Response channel.
        resp: oneshot::Sender<anyhow::Result<Vec<ChannelSummary>>>,
    },
    /// Close a channel. Phase-4: the closing transaction is signed via the
    /// on-device VLS signer over `SignerService::Attach`. When `force` is
    /// true, broadcast the latest local commitment unilaterally — required
    /// when in-flight HTLCs prevent a cooperative close.
    CloseChannel {
        /// 32-byte channel id of the channel to close.
        channel_id: lightning::ln::types::ChannelId,
        /// Counterparty pubkey carried on the channel.
        counterparty: bitcoin::secp256k1::PublicKey,
        /// If true, force-close (unilateral broadcast).
        force: bool,
        /// Response channel.
        resp: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Negotiate LSPS2 `lsps2.get_info` and return a fee quote.
    Lsps2GetInfo {
        /// Optional payment size to filter the LSP's fee menu against.
        amount_msat: Option<u64>,
        /// Response channel.
        resp: oneshot::Sender<anyhow::Result<wick_lightning::JitQuote>>,
    },
    /// Issue a JIT-enabled BOLT11 invoice (LSPS2 end-to-end).
    GetJitInvoice {
        /// Required payment size in millisatoshis.
        amount_msat: u64,
        /// Invoice memo / description.
        memo: String,
        /// Response channel.
        resp: oneshot::Sender<anyhow::Result<wick_lightning::JitInvoice>>,
    },
    /// Install (or re-install) a [`NodeApi`] into a parked actor.
    ///
    /// Sent by [`crate::node::manager::NodeManager::wake_loading`] after the
    /// factory has built a fresh node. The actor stores the node, publishes it
    /// to the shared [`NodeInner`] via `ArcSwap`, and acks via `resp`. The
    /// manager then CAS-es state `LOADING → ACTIVE`.
    ///
    /// Note: the original `Activate { node, tasks }` spec dropped the `tasks`
    /// parameter — the node owns its `BackgroundProcessor` / SPV loop /
    /// peer-reconnect loop internally via `NodeBuilder`. The actor never holds
    /// task handles.
    Activate {
        /// The freshly-built node to install.
        node: Arc<dyn NodeApi>,
        /// Response channel — `Ok(())` on success.
        resp: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Request the actor park itself.
    ///
    /// The handler drains any already-enqueued commands, then — unless
    /// `force` is `true` — re-checks the three park-safety conditions
    /// ([`wick_lightning::NodeApi::has_pending_htlcs`],
    /// [`wick_lightning::NodeApi::has_inflight_outbound`],
    /// [`wick_lightning::NodeApi::has_unresolved_monitor_events`]). If any
    /// returns `true`, responds [`ParkOutcome::RequeuedDueToActivity`] and
    /// stays running. Otherwise calls `node.shutdown()`, responds
    /// [`ParkOutcome::Parked`], clears the internal node reference, and
    /// continues the run loop (the actor stays alive — only `Shutdown`
    /// exits the loop).
    ///
    /// `force = true` skips the safety checks and unconditionally shuts
    /// the node down. Used by emergency eviction; accepts that in-flight
    /// HTLCs may time out.
    Park {
        /// When `true`, bypass the three park-safety checks.
        force: bool,
        /// Response channel.
        resp: oneshot::Sender<ParkOutcome>,
    },
    /// Gracefully shut down the actor (exits the run loop).
    Shutdown,
}

// ── NodeHandle ───────────────────────────────────────────────────────────────

/// The mutable pair swapped atomically on park/wake transitions.
///
/// When a node is `ACTIVE`, both fields are `Some`. When it is `PARKED` or
/// `LOADING`, both are `None` — no actor is running, no memory is held.
///
/// Swapping `(tx, node)` together (rather than separately) is load-bearing:
/// publishing a fresh `tx` without publishing the matching `node` (or vice
/// versa) would produce a window where `dispatch` could see a live tx
/// pointing at a not-yet-usable node.
#[derive(Debug, Default)]
pub struct NodeInner {
    /// Sender into the actor's mpsc command channel.
    pub tx: Option<mpsc::Sender<NodeCmd>>,
    /// The same `Arc<dyn NodeApi>` the actor owns. Integration tests
    /// borrow this to run setup operations not yet exposed via
    /// [`NodeCmd`] (`connect_peer`, `open_channel`, `list_channels`).
    pub node: Option<Arc<dyn NodeApi>>,
}

/// A non-owning reference to a running [`actor::NodeActor`], stored in the
/// [`manager::NodeManager`]'s `DashMap`.
///
/// All fields are cheap to clone (`Arc`). The mutable `(tx, node)` pair lives
/// inside [`NodeInner`] behind an [`ArcSwap`] so that park/wake can publish
/// it atomically without stranding callers mid-dispatch.
#[derive(Debug, Clone)]
pub struct NodeHandle {
    /// Current lifecycle state (see `state::*` constants).
    pub state: Arc<AtomicU8>,
    /// Unix timestamp of last activity, `SeqCst` ordering.
    pub last_active: Arc<AtomicU64>,
    /// Notified when a `Loading → Active` transition completes.
    pub wake_notify: Arc<Notify>,
    /// `(tx, node)` — swapped atomically on park/wake. Lock-free read on
    /// the dispatch hot path via [`ArcSwap::load`].
    pub inner: Arc<ArcSwap<NodeInner>>,
    /// Populated when `state == ERROR`; drives the error recovery loop.
    /// `None` for healthy tenants.
    pub error: Arc<RwLock<Option<ErrorState>>>,
}

impl NodeHandle {
    /// Current sender, if the node is `ACTIVE`. Returns `None` when
    /// `PARKED` / `LOADING` / `ERROR`.
    #[must_use]
    pub fn tx(&self) -> Option<mpsc::Sender<NodeCmd>> {
        self.inner.load().tx.clone()
    }

    /// Current `Arc<dyn NodeApi>` if `ACTIVE`. Returns `None` otherwise.
    /// Integration tests use this to drive setup operations not yet exposed
    /// via [`NodeCmd`]; production code should prefer [`Self::tx`].
    #[must_use]
    pub fn node(&self) -> Option<Arc<dyn NodeApi>> {
        self.inner.load().node.clone()
    }

    /// Construct a `NodeHandle` with no backing actor — the mpsc sender is
    /// paired with an immediately-dropped receiver, so any send fails.
    /// Intended purely for bookkeeping-only tests that do **not** exercise
    /// the wake path (no `mgr.wake()` calls).
    ///
    /// Not gated by `#[cfg(test)]` because `#[tokio::test]` integration
    /// tests in sibling crates need it too.
    #[doc(hidden)]
    #[must_use]
    pub fn for_test() -> Self {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        Self {
            state: Arc::new(AtomicU8::new(state::ACTIVE)),
            last_active: Arc::new(AtomicU64::new(0)),
            wake_notify: Arc::new(Notify::new()),
            inner: Arc::new(ArcSwap::from_pointee(NodeInner {
                tx: Some(tx),
                node: None,
            })),
            error: Arc::new(RwLock::new(None)),
        }
    }
}
