//! Bounded retry queue for HTLCs whose intercept SCID isn't yet
//! registered in [`crate::peer_registry::PeerRegistry`].
//!
//! BOLT11 invoices ship with the LSPS2 intercept SCID in the route
//! hint. A payer can route an HTLC the moment the buy response lands
//! at the client — which means [`Event::HTLCIntercepted`] can fire on
//! the LSP node before the local `register_buy` has finished
//! committing its `global.jit_requests` row. The window is small (a
//! single Postgres round-trip) but real.
//!
//! This queue parks unknown-SCID HTLCs in a bounded `mpsc` and a
//! background poll loop:
//!
//! - Every 1 s, the worker walks the queue and drains entries whose
//!   SCID has since registered, calling
//!   `lsps2_service_handler.htlc_intercepted` for each.
//! - Entries older than the configured retry window (default 30 s) are
//!   failed back via `fail_intercepted_htlc` — past 30 s the payer's
//!   CLTV budget is cooked anyway.
//! - The mpsc has capacity 256; saturation immediately fails the new
//!   HTLC via [`Node::channel_manager_fail_intercepted_htlc`] (LDK 0.2
//!   returns unknown-next-peer semantics regardless of caller intent).
//!   This is back-pressure, not a stub: a saturated queue means the LSP is
//!   pathologically behind on registry writes and forwarding the HTLC
//!   would only deepen the backlog.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lightning::ln::channelmanager::InterceptId;
use lightning::types::payment::PaymentHash;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use wick_lightning::{LnLiquidityManager, LocalKeysManager, Node};

use crate::peer_registry::PeerRegistry;

/// One parked HTLC waiting on a SCID registration.
pub struct HtlcParkRequest {
    /// LDK's intercept handle — required to fail-back or forward.
    pub intercept_id: InterceptId,
    /// The SCID the payer routed against.
    pub intercept_scid: u64,
    /// Outbound amount (after the LSP's skimmed fee).
    pub expected_outbound_amount_msat: u64,
    /// Payment hash (echoed into `htlc_intercepted`).
    pub payment_hash: PaymentHash,
    /// LiquidityManager handle held during park so the worker can drive
    /// `lsps2_service_handler().htlc_intercepted(...)` from inside the
    /// poll loop without re-borrowing the daemon.
    pub liquidity_manager: Arc<LnLiquidityManager<LocalKeysManager>>,
}

impl std::fmt::Debug for HtlcParkRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HtlcParkRequest")
            .field("intercept_scid", &self.intercept_scid)
            .field(
                "expected_outbound_amount_msat",
                &self.expected_outbound_amount_msat,
            )
            .field("payment_hash", &self.payment_hash)
            .finish_non_exhaustive()
    }
}

struct ParkedEntry {
    parked_at: Instant,
    request: HtlcParkRequest,
}

/// Public handle for the queue. Cheap to clone — internally Arc-shared.
pub struct UnknownScidQueue {
    sender: mpsc::Sender<HtlcParkRequest>,
    node: Arc<Node<LocalKeysManager>>,
    /// Worker task handle; aborted on drop so the runtime doesn't keep
    /// a dangling poll loop after the daemon shuts down.
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for UnknownScidQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnknownScidQueue")
            .field("capacity", &CHANNEL_CAPACITY)
            .field("sender_capacity", &self.sender.capacity())
            .finish_non_exhaustive()
    }
}

impl Drop for UnknownScidQueue {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.worker.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}

/// Bounded mpsc capacity. Tuned to the BOLT11 batch size a single
/// payer is likely to fan out before the registry write commits;
/// larger numbers risk hiding genuine backlog.
const CHANNEL_CAPACITY: usize = 256;

/// Worker poll cadence. Cheap (no I/O) — each tick is a DashMap probe
/// per parked entry.
const POLL_INTERVAL: Duration = Duration::from_millis(1_000);

impl UnknownScidQueue {
    /// Default retry window. Past this, the payer's CLTV budget is
    /// effectively cooked even if the SCID does eventually register.
    pub const DEFAULT_RETRY_WINDOW: Duration = Duration::from_secs(30);

    /// Start the worker and return a handle.
    ///
    /// `node` is held for the `fail_intercepted_htlc` callback used
    /// when the retry window expires.
    pub fn spawn(
        registry: Arc<PeerRegistry>,
        node: Arc<Node<LocalKeysManager>>,
        retry_window: Duration,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let worker_node = node.clone();
        let worker = tokio::spawn(run_worker(rx, registry, worker_node, retry_window));
        Arc::new(Self {
            sender: tx,
            node,
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Park an HTLC. On queue saturation the HTLC is failed back
    /// immediately with `TemporaryNodeFailure` and a warning is logged
    /// — saturation = pathological backlog, not a normal case.
    pub fn park(&self, request: HtlcParkRequest) {
        let scid = request.intercept_scid;
        let intercept_id = request.intercept_id;
        if let Err(e) = self.sender.try_send(request) {
            tracing::error!(
                target: "wick_lsp",
                intercept_scid = scid,
                queue_full = matches!(e, mpsc::error::TrySendError::Full(_)),
                "unknown_scid_queue saturated; failing HTLC TemporaryNodeFailure"
            );
            if let Err(fail_err) = self
                .node
                .channel_manager_fail_intercepted_htlc(intercept_id)
            {
                tracing::warn!(
                    target: "wick_lsp",
                    error = %fail_err,
                    "fail_intercepted_htlc on queue saturation failed"
                );
            }
        } else {
            tracing::debug!(
                target: "wick_lsp",
                intercept_scid = scid,
                "parked HTLC awaiting SCID registration"
            );
        }
    }
}

async fn run_worker(
    mut rx: mpsc::Receiver<HtlcParkRequest>,
    registry: Arc<PeerRegistry>,
    node: Arc<Node<LocalKeysManager>>,
    retry_window: Duration,
) {
    let mut parked: Vec<ParkedEntry> = Vec::new();
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            maybe_req = rx.recv() => {
                match maybe_req {
                    Some(request) => parked.push(ParkedEntry {
                        parked_at: Instant::now(),
                        request,
                    }),
                    None => {
                        tracing::debug!(
                            target: "wick_lsp",
                            "unknown_scid_queue sender dropped; worker exiting"
                        );
                        return;
                    }
                }
            }
            _ = ticker.tick() => {
                drain_pass(&mut parked, &registry, &node, retry_window).await;
            }
        }
    }
}

async fn drain_pass(
    parked: &mut Vec<ParkedEntry>,
    registry: &PeerRegistry,
    node: &Node<LocalKeysManager>,
    retry_window: Duration,
) {
    if parked.is_empty() {
        return;
    }
    let now = Instant::now();
    // Walk in reverse so swap_remove is index-stable.
    let mut i = parked.len();
    while i > 0 {
        i -= 1;
        let registered = registry.lookup(parked[i].request.intercept_scid).is_some();
        let expired = now.duration_since(parked[i].parked_at) >= retry_window;

        if registered {
            let entry = parked.swap_remove(i);
            forward_now(entry, node).await;
        } else if expired {
            let entry = parked.swap_remove(i);
            tracing::warn!(
                target: "wick_lsp",
                intercept_scid = entry.request.intercept_scid,
                age_ms = u128::try_from(now.duration_since(entry.parked_at).as_millis()).unwrap_or(u128::MAX),
                "unknown SCID retry window elapsed; failing HTLC UnknownNextPeer"
            );
            if let Err(e) =
                node.channel_manager_fail_intercepted_htlc(entry.request.intercept_id)
            {
                tracing::warn!(
                    target: "wick_lsp",
                    error = %e,
                    "fail_intercepted_htlc on retry-window expiry failed"
                );
            }
        }
    }
}

async fn forward_now(entry: ParkedEntry, _node: &Node<LocalKeysManager>) {
    let req = entry.request;
    let Some(handler) = req.liquidity_manager.lsps2_service_handler() else {
        tracing::warn!(
            target: "wick_lsp",
            intercept_scid = req.intercept_scid,
            "lsps2 service handler vanished while HTLC was parked"
        );
        return;
    };
    if let Err(e) = handler
        .htlc_intercepted(
            req.intercept_scid,
            req.intercept_id,
            req.expected_outbound_amount_msat,
            req.payment_hash,
        )
        .await
    {
        tracing::error!(
            target: "wick_lsp",
            error = ?e,
            intercept_scid = req.intercept_scid,
            "lsps2 htlc_intercepted forward failed after queue release"
        );
    } else {
        tracing::debug!(
            target: "wick_lsp",
            intercept_scid = req.intercept_scid,
            "released parked HTLC into lsps2 handler"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// `ParkedEntry::parked_at` advances over the configured window —
    /// sanity-check the time math without a real LDK node.
    #[test]
    fn retry_window_default_is_thirty_seconds() {
        assert_eq!(
            UnknownScidQueue::DEFAULT_RETRY_WINDOW,
            Duration::from_secs(30)
        );
    }

    #[test]
    fn channel_capacity_is_256() {
        assert_eq!(CHANNEL_CAPACITY, 256);
    }
}
