//! Per-tenant Lightning-node actor.
//!
//! Each tenant runs exactly **one** `NodeActor` task for the process lifetime.
//! The actor owns its node state exclusively — no shared references, no
//! internal mutexes. All interaction goes through the mpsc `NodeCmd` channel.
//!
//! ## Lifecycle
//!
//! ```text
//! spawn(tid) → PARKED (node = None)
//!   ↓  Activate { node }
//! ACTIVE (node = Some)
//!   ↓  Park (safety checks pass)
//! PARKED (node = None, actor still running)
//!   ↓  Activate { node }   ← re-activation on each wake
//! ACTIVE
//!   ↓  Shutdown
//! exits run loop
//! ```
//!
//! State transitions (`AtomicU8`) are owned by the manager, not the actor. The
//! actor clears/installs the `NodeApi` reference and publishes it to the shared
//! `NodeInner` via `ArcSwap`, but never writes the state atom directly.

use std::fmt;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, info, warn};
use wick_core::TenantId;
use wick_lightning::NodeApi;

use crate::node::{state, NodeCmd, NodeHandle, NodeInner, ParkOutcome, NODE_CMD_CAPACITY};

// ── Actor ─────────────────────────────────────────────────────────────────────

/// Per-tenant actor. Owns all mutable Lightning-node state.
///
/// Spawned once per tenant by [`crate::node::manager::NodeManager::provision`]
/// and lives for the process lifetime. Park/wake cycles install and remove
/// the `Arc<dyn NodeApi>` reference; the actor task and its mpsc channel
/// persist across them.
pub struct NodeActor {
    tenant_id: TenantId,
    rx: mpsc::Receiver<NodeCmd>,
    last_active: Arc<AtomicU64>,
    /// Shared `(tx, node)` pair, also held by [`NodeHandle`].
    /// Actor writes `node` on Activate and clears it on park; `tx` is set
    /// at spawn and never changed.
    inner: Arc<ArcSwap<NodeInner>>,
    /// `Some` when ACTIVE; `None` when PARKED.
    node: Option<Arc<dyn NodeApi>>,
}

impl fmt::Debug for NodeActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeActor")
            .field("tenant_id", &self.tenant_id)
            .field("active", &self.node.is_some())
            .finish_non_exhaustive()
    }
}

impl NodeActor {
    /// Spawn a long-lived actor for `tenant_id`.
    ///
    /// The actor starts in `PARKED` state (`node = None`). The first
    /// [`NodeCmd::Activate`] from [`crate::node::manager::NodeManager::wake_loading`]
    /// installs the node and the manager then CAS-es state to `ACTIVE`.
    #[must_use]
    pub fn spawn(tenant_id: TenantId) -> NodeHandle {
        let (tx, rx) = mpsc::channel(NODE_CMD_CAPACITY);
        let state_atom = Arc::new(std::sync::atomic::AtomicU8::new(state::PARKED));
        let last_active = Arc::new(AtomicU64::new(0));
        let wake_notify = Arc::new(Notify::new());
        let inner = Arc::new(ArcSwap::from_pointee(NodeInner {
            tx: Some(tx),
            node: None,
        }));

        let actor = NodeActor {
            tenant_id,
            rx,
            last_active: last_active.clone(),
            inner: inner.clone(),
            node: None,
        };

        tokio::spawn(async move { actor.run().await });

        NodeHandle {
            state: state_atom,
            last_active,
            wake_notify,
            inner,
            error: Arc::new(RwLock::new(None)),
        }
    }

    /// Main run loop. Processes commands until `Shutdown` is received or
    /// the mpsc channel is closed.
    ///
    /// The actor **never** writes the lifecycle state atom — the manager
    /// owns all `state::*` transitions. The actor only manages the node
    /// reference in `self.node` and publishes it to `self.inner`.
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
                    if let Some(node) = self.node.take() {
                        node.shutdown().await;
                    }
                    break;
                }
                Some(NodeCmd::Activate { node, resp }) => {
                    self.handle_activate(node, resp);
                }
                Some(NodeCmd::Park { force, resp }) => {
                    if self.node.is_none() {
                        // Already parked — nothing to do; signal requeue so
                        // the manager knows the request was a no-op.
                        let _ = resp.send(ParkOutcome::RequeuedDueToActivity);
                        continue;
                    }
                    if self.try_park(force, resp).await {
                        // Shutdown arrived during drain — exit the loop.
                        break;
                    }
                }
                Some(cmd) => {
                    if self.node.is_none() {
                        // Parked: no node to service this command.
                        self.reject_parked(cmd);
                    } else {
                        self.touch_last_active();
                        self.handle(cmd).await;
                    }
                }
            }
        }

        info!(tenant = %self.tenant_id, "node actor stopped");
    }

    /// Install a fresh node and publish it to the shared `NodeInner`.
    fn handle_activate(
        &mut self,
        node: Arc<dyn NodeApi>,
        resp: tokio::sync::oneshot::Sender<anyhow::Result<()>>,
    ) {
        self.node = Some(node.clone());
        // Publish node — preserve the existing tx (set at spawn, never changes).
        let current = self.inner.load();
        self.inner.store(Arc::new(NodeInner {
            tx: current.tx.clone(),
            node: Some(node),
        }));
        self.touch_last_active();
        let _ = resp.send(Ok(()));
        info!(tenant = %self.tenant_id, "node activated");
    }

    /// Drain already-enqueued commands, run the three park-safety checks
    /// (skipped when `force` is `true`), and if all clear: shut down the
    /// node, clear the inner reference, and respond [`ParkOutcome::Parked`].
    ///
    /// Returns `true` only if a `Shutdown` was received during the drain
    /// (caller should exit the run loop). Returns `false` for both
    /// [`ParkOutcome::Parked`] and [`ParkOutcome::RequeuedDueToActivity`]
    /// — the actor keeps running in both cases.
    async fn try_park(
        &mut self,
        force: bool,
        resp: tokio::sync::oneshot::Sender<ParkOutcome>,
    ) -> bool {
        // Drain any commands that arrived between the poller enqueueing Park
        // and Park being dequeued. Non-park commands must be processed so user
        // requests are not silently dropped.
        while let Ok(cmd) = self.rx.try_recv() {
            match cmd {
                NodeCmd::Shutdown => {
                    if let Some(node) = self.node.take() {
                        node.shutdown().await;
                    }
                    // Drop `resp` without sending — caller's resp_rx.await
                    // will surface RecvError, which manager.park maps to
                    // an actor-dropped error. Previously responded
                    // `RequeuedDueToActivity`, which left the manager
                    // thinking the tenant could still receive traffic
                    // while the actor was exiting.
                    drop(resp);
                    return true;
                }
                NodeCmd::Park { resp: other, .. } => {
                    // Duplicate Park — collapse.
                    let _ = other.send(ParkOutcome::RequeuedDueToActivity);
                }
                NodeCmd::Activate { resp: act_resp, .. } => {
                    // Activate arrived during drain (manager racing with poller).
                    // Reject: the poller wins; wake will re-activate on next demand.
                    let _ = act_resp.send(Err(anyhow::anyhow!(
                        "Activate rejected: Park already in progress for tenant {}",
                        self.tenant_id
                    )));
                }
                other => {
                    self.touch_last_active();
                    self.handle(other).await;
                }
            }
        }

        // Post-drain recheck — all three must be false for park to be safe.
        // Force-park (used by emergency eviction) skips the checks entirely
        // and accepts that in-flight HTLCs may time out.
        if force {
            warn!(tenant = %self.tenant_id, "force-park: skipping safety checks");
        } else {
            let node = self.node.as_ref().expect("checked is_some before try_park");

            let has_htlcs = node.has_pending_htlcs().await.unwrap_or_else(|e| {
                warn!(tenant = %self.tenant_id, error = %e,
                    "has_pending_htlcs failed; assuming activity and requeueing Park");
                true
            });
            let has_inflight = node.has_inflight_outbound().await.unwrap_or_else(|e| {
                warn!(tenant = %self.tenant_id, error = %e,
                    "has_inflight_outbound failed; assuming activity and requeueing Park");
                true
            });
            let has_monitor = node
                .has_unresolved_monitor_events()
                .await
                .unwrap_or_else(|e| {
                    warn!(tenant = %self.tenant_id, error = %e,
                    "has_unresolved_monitor_events failed; assuming activity and requeueing Park");
                    true
                });

            if has_htlcs || has_inflight || has_monitor {
                debug!(tenant = %self.tenant_id, has_htlcs, has_inflight, has_monitor,
                    "park requeued due to activity");
                let _ = resp.send(ParkOutcome::RequeuedDueToActivity);
                return false;
            }
        }

        info!(tenant = %self.tenant_id, force, "park safe — shutting down node");
        // Take the node *before* shutdown so the borrow on `self.node` above ends.
        let node = self.node.take().expect("checked above");
        node.shutdown().await;

        // Clear the node reference from the shared inner (preserve tx).
        let current = self.inner.load();
        self.inner.store(Arc::new(NodeInner {
            tx: current.tx.clone(),
            node: None,
        }));

        let _ = resp.send(ParkOutcome::Parked);
        // Actor stays in the run loop — only Shutdown exits.
        false
    }

    /// Send an error response for a command that arrived while the actor is
    /// parked (no node installed). Callers observing the error can retry;
    /// the manager's dispatch path will transparent-wake on next attempt.
    fn reject_parked(&self, cmd: NodeCmd) {
        let tid = self.tenant_id;
        match cmd {
            NodeCmd::GetBalance { resp } => {
                let _ = resp.send(Err(anyhow::anyhow!("node {tid} is parked")));
            }
            NodeCmd::SendPayment { resp, .. } => {
                let _ = resp.send(Err(anyhow::anyhow!("node {tid} is parked")));
            }
            NodeCmd::ReceivePayment { resp, .. } => {
                let _ = resp.send(Err(anyhow::anyhow!("node {tid} is parked")));
            }
            NodeCmd::GetTransactions { resp, .. } => {
                let _ = resp.send(Err(anyhow::anyhow!("node {tid} is parked")));
            }
            NodeCmd::GetNodeInfo { resp } => {
                let _ = resp.send(Err(anyhow::anyhow!("node {tid} is parked")));
            }
            NodeCmd::ConnectPeer { resp, .. } => {
                let _ = resp.send(Err(anyhow::anyhow!("node {tid} is parked")));
            }
            NodeCmd::OpenChannelInit { resp, .. } => {
                let _ = resp.send(Err(anyhow::anyhow!("node {tid} is parked")));
            }
            NodeCmd::OpenChannelFinalize { resp, .. } => {
                let _ = resp.send(Err(anyhow::anyhow!("node {tid} is parked")));
            }
            NodeCmd::ListChannels { resp } => {
                let _ = resp.send(Err(anyhow::anyhow!("node {tid} is parked")));
            }
            NodeCmd::CloseChannel { resp, .. } => {
                let _ = resp.send(Err(anyhow::anyhow!("node {tid} is parked")));
            }
            NodeCmd::Lsps2GetInfo { resp, .. } => {
                let _ = resp.send(Err(anyhow::anyhow!("node {tid} is parked")));
            }
            NodeCmd::GetJitInvoice { resp, .. } => {
                let _ = resp.send(Err(anyhow::anyhow!("node {tid} is parked")));
            }
            NodeCmd::Activate { .. } | NodeCmd::Park { .. } | NodeCmd::Shutdown => {
                unreachable!("Activate / Park / Shutdown handled before reject_parked")
            }
        }
    }

    fn touch_last_active(&self) {
        self.last_active.store(Self::now_secs(), Ordering::SeqCst);
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    async fn handle(&mut self, cmd: NodeCmd) {
        let node = self
            .node
            .as_ref()
            .expect("handle only called when node is Some");
        match cmd {
            NodeCmd::GetBalance { resp } => {
                if resp.send(node.get_balance().await).is_err() {
                    warn!(tenant = %self.tenant_id, "GetBalance: caller dropped response receiver");
                }
            }

            NodeCmd::SendPayment { bolt11, resp } => {
                if resp.send(node.send_payment(&bolt11).await).is_err() {
                    warn!(tenant = %self.tenant_id, "SendPayment: caller dropped response receiver");
                }
            }

            NodeCmd::ReceivePayment {
                amount_msat,
                memo,
                resp,
            } => {
                if resp
                    .send(node.receive_payment(amount_msat, &memo).await)
                    .is_err()
                {
                    warn!(tenant = %self.tenant_id, "ReceivePayment: caller dropped response receiver");
                }
            }

            NodeCmd::GetTransactions { limit, resp } => {
                if resp.send(node.get_transactions(limit).await).is_err() {
                    warn!(tenant = %self.tenant_id, "GetTransactions: caller dropped response receiver");
                }
            }

            NodeCmd::GetNodeInfo { resp } => {
                let info = Ok((node.node_id(), node.local_listen_addr()));
                if resp.send(info).is_err() {
                    warn!(tenant = %self.tenant_id, "GetNodeInfo: caller dropped response receiver");
                }
            }

            NodeCmd::ConnectPeer {
                peer,
                host,
                port,
                resp,
            } => {
                if resp
                    .send(node.connect_peer(peer, &host, port).await)
                    .is_err()
                {
                    warn!(tenant = %self.tenant_id, "ConnectPeer: caller dropped response receiver");
                }
            }

            NodeCmd::OpenChannelInit {
                peer,
                value_sat,
                push_msat,
                timeout,
                resp,
            } => {
                let t0 = std::time::Instant::now();
                tracing::info!(
                    target: "wick_server::open_channel",
                    tenant = %self.tenant_id,
                    value_sat,
                    push_msat,
                    "actor → node.open_channel_init"
                );
                let outcome = node
                    .open_channel_init(peer, value_sat, push_msat, timeout)
                    .await;
                tracing::info!(
                    target: "wick_server::open_channel",
                    tenant = %self.tenant_id,
                    elapsed_ms = t0.elapsed().as_millis() as u64,
                    ok = outcome.is_ok(),
                    "actor ← node.open_channel_init"
                );
                if resp.send(outcome).is_err() {
                    warn!(tenant = %self.tenant_id, "OpenChannelInit: caller dropped response receiver");
                }
            }

            NodeCmd::OpenChannelFinalize {
                temp_channel_id,
                counterparty,
                funding_tx,
                resp,
            } => {
                let result = node
                    .open_channel_finalize(&temp_channel_id, &counterparty, funding_tx)
                    .await;
                if resp.send(result).is_err() {
                    warn!(tenant = %self.tenant_id, "OpenChannelFinalize: caller dropped response receiver");
                }
            }

            NodeCmd::ListChannels { resp } => {
                if resp.send(node.list_channels().await).is_err() {
                    warn!(tenant = %self.tenant_id, "ListChannels: caller dropped response receiver");
                }
            }

            NodeCmd::CloseChannel {
                channel_id,
                counterparty,
                resp,
            } => {
                let result = node.close_channel(&channel_id, &counterparty).await;
                if resp.send(result).is_err() {
                    warn!(tenant = %self.tenant_id, "CloseChannel: caller dropped response receiver");
                }
            }

            NodeCmd::Lsps2GetInfo { amount_msat, resp } => {
                if resp.send(node.lsps2_get_info(amount_msat).await).is_err() {
                    warn!(tenant = %self.tenant_id, "Lsps2GetInfo: caller dropped response receiver");
                }
            }

            NodeCmd::GetJitInvoice {
                amount_msat,
                memo,
                resp,
            } => {
                if resp
                    .send(node.receive_payment_jit(amount_msat, &memo).await)
                    .is_err()
                {
                    warn!(tenant = %self.tenant_id, "GetJitInvoice: caller dropped response receiver");
                }
            }

            NodeCmd::Activate { .. } | NodeCmd::Shutdown | NodeCmd::Park { .. } => {
                unreachable!("Activate / Shutdown / Park handled in actor run loop");
            }
        }
    }
}
