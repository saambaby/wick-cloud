//! Per-tenant Lightning-node actor.
//!
//! Each tenant runs exactly one `NodeActor` task. The actor owns its node
//! state exclusively — no shared references, no internal mutexes. All
//! interaction goes through the mpsc `NodeCmd` channel.
//!
//! The actor holds the node as an `Arc<dyn NodeApi>` so its lifecycle code
//! stays **non-generic** while the concrete `Node<S>` in `wick-lightning` is
//! generic over the signer (required because LDK's [`SignerProvider`] has an
//! associated type — dynamic dispatch cannot name it). Phase-1 uses
//! `Node<LocalKeysManager>`; Phase-4 flips to a VLS-backed `Node<RemoteVls>`.
//!
//! There is intentionally no mock / stub variant: actor behaviour is
//! verified end-to-end against a real `Node<LocalKeysManager>` in
//! `crates/wick-testkit/tests/ldk_assembly.rs`, not through a separate
//! in-memory double that would duplicate coverage at a lower level.
//!
//! [`SignerProvider`]: lightning::sign::SignerProvider

use std::fmt;
use std::sync::{
    atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, Notify};
use tracing::{debug, info, warn};
use wick_core::TenantId;
use wick_lightning::NodeApi;

use crate::node::{state, NodeCmd, NodeHandle, NODE_CMD_CAPACITY, PER_NODE_BYTES};

// ── Actor ─────────────────────────────────────────────────────────────────────

/// Per-tenant actor. Owns all mutable Lightning-node state.
///
/// Spawned by [`crate::node::manager::NodeManager::provision`]; communicated
/// with via [`NodeHandle::tx`].
pub struct NodeActor {
    tenant_id: TenantId,
    rx: mpsc::Receiver<NodeCmd>,
    state: Arc<AtomicU8>,
    last_active: Arc<AtomicU64>,
    node: Arc<dyn NodeApi>,
}

impl fmt::Debug for NodeActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeActor")
            .field("tenant_id", &self.tenant_id)
            .finish_non_exhaustive()
    }
}

impl NodeActor {
    /// Spawn an actor for `tenant_id` around an already-built [`NodeApi`].
    ///
    /// Production path: `wick_lightning::NodeBuilder::new(tenant_id, deps)
    /// .with_signer(s).build().await?` returns an `Arc<Node<S>>` which
    /// coerces to `Arc<dyn NodeApi>` because `Node<S>: NodeApi`.
    #[must_use]
    pub fn spawn_with_node(tenant_id: TenantId, node: Arc<dyn NodeApi>) -> NodeHandle {
        let (tx, rx) = mpsc::channel(NODE_CMD_CAPACITY);
        let state = Arc::new(AtomicU8::new(state::ACTIVE));
        let last_active = Arc::new(AtomicU64::new(now_secs()));
        let mem_bytes = Arc::new(AtomicUsize::new(PER_NODE_BYTES));
        let wake_notify = Arc::new(Notify::new());

        let actor = NodeActor {
            tenant_id,
            rx,
            state: state.clone(),
            last_active: last_active.clone(),
            node,
        };

        tokio::spawn(async move { actor.run().await });

        NodeHandle {
            tx,
            state,
            last_active,
            mem_bytes,
            wake_notify,
        }
    }

    /// Main actor loop. Processes commands until the channel is closed or
    /// `Shutdown` is received.
    async fn run(mut self) {
        info!(tenant = %self.tenant_id, "node actor started");

        loop {
            match self.rx.recv().await {
                None => {
                    debug!(tenant = %self.tenant_id, "node cmd channel closed — stopping");
                    break;
                }
                Some(NodeCmd::Shutdown) => {
                    info!(tenant = %self.tenant_id, "node actor received Shutdown");
                    self.node.shutdown().await;
                    break;
                }
                Some(cmd) => {
                    self.touch_last_active();
                    self.handle(cmd).await;
                }
            }
        }

        self.state.store(state::PARKED, Ordering::SeqCst);
        info!(tenant = %self.tenant_id, "node actor stopped");
    }

    fn touch_last_active(&self) {
        self.last_active.store(now_secs(), Ordering::SeqCst);
    }

    async fn handle(&mut self, cmd: NodeCmd) {
        match cmd {
            NodeCmd::GetBalance { resp } => {
                if resp.send(self.node.get_balance().await).is_err() {
                    warn!(tenant = %self.tenant_id, "GetBalance: caller dropped response receiver");
                }
            }

            NodeCmd::SendPayment { bolt11, resp } => {
                if resp.send(self.node.send_payment(&bolt11).await).is_err() {
                    warn!(tenant = %self.tenant_id, "SendPayment: caller dropped response receiver");
                }
            }

            NodeCmd::ReceivePayment { amount_msat, memo, resp } => {
                if resp.send(self.node.receive_payment(amount_msat, &memo).await).is_err() {
                    warn!(tenant = %self.tenant_id, "ReceivePayment: caller dropped response receiver");
                }
            }

            NodeCmd::GetTransactions { limit, resp } => {
                if resp.send(self.node.get_transactions(limit).await).is_err() {
                    warn!(tenant = %self.tenant_id, "GetTransactions: caller dropped response receiver");
                }
            }

            NodeCmd::Shutdown => {
                unreachable!("Shutdown handled in actor run loop");
            }
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
