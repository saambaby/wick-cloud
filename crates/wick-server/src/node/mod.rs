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
//! Phase 1 ships `Active` only; park/wake arrives in Phase 2.

pub mod actor;
pub mod manager;

use std::sync::{
    atomic::{AtomicU64, AtomicU8, AtomicUsize},
    Arc,
};

use tokio::sync::{mpsc, oneshot, Notify};

/// Memory placeholder per active node (64 KiB).
/// Phase 2 will replace this with actual LDK memory measurement.
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

// ── Response types (owned by `wick-lightning`) ───────────────────────────────

/// Re-exported from [`wick_lightning`] so callers need only import from here.
pub use wick_lightning::{Balance, PaymentRecord, PaymentResult};

// ── NodeCmd ──────────────────────────────────────────────────────────────────

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
        /// Response channel — yields the BOLT11 string.
        resp: oneshot::Sender<anyhow::Result<String>>,
    },
    /// Return paginated payment history.
    GetTransactions {
        /// Maximum records to return.
        limit: u32,
        /// Response channel.
        resp: oneshot::Sender<anyhow::Result<Vec<PaymentRecord>>>,
    },
    /// Gracefully shut down the actor.
    Shutdown,
}

// ── NodeHandle ───────────────────────────────────────────────────────────────

/// A non-owning reference to a running [`actor::NodeActor`], stored in the
/// [`manager::NodeManager`]'s `DashMap`.
///
/// All fields are cheap to clone (`Arc` or `Sender`).
#[derive(Debug, Clone)]
pub struct NodeHandle {
    /// Send commands to the actor's mpsc channel.
    pub tx: mpsc::Sender<NodeCmd>,
    /// Current lifecycle state (see `state::*` constants).
    pub state: Arc<AtomicU8>,
    /// Unix timestamp of last activity, `SeqCst` ordering.
    pub last_active: Arc<AtomicU64>,
    /// Bytes reserved in the global memory budget for this node.
    pub mem_bytes: Arc<AtomicUsize>,
    /// Notified when a `Loading → Active` transition completes.
    pub wake_notify: Arc<Notify>,
}

impl NodeHandle {
    /// Construct a `NodeHandle` with no backing actor — the mpsc sender is
    /// paired with an immediately-dropped receiver, so any `tx.send(...)`
    /// fails. Intended purely for bookkeeping-only tests (DashMap counts,
    /// memory-budget arithmetic) that don't dispatch commands.
    ///
    /// Not gated by `#[cfg(test)]` because `#[tokio::test]` integration
    /// tests in sibling crates need it too.
    #[doc(hidden)]
    #[must_use]
    pub fn for_test() -> Self {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        Self {
            tx,
            state: Arc::new(AtomicU8::new(state::ACTIVE)),
            last_active: Arc::new(AtomicU64::new(0)),
            mem_bytes: Arc::new(AtomicUsize::new(PER_NODE_BYTES)),
            wake_notify: Arc::new(Notify::new()),
        }
    }
}
