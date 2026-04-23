//! [`PendingFundingRegistry`] — parks `FundingGenerationReady` events
//! awaiting a caller-supplied funding transaction.
//!
//! This is the backbone of the two-phase channel-open flow used when the
//! Lightning node doesn't own the funding UTXOs (self-custodial path):
//!
//! 1. Caller invokes `ChannelManager::create_channel(peer, value, ...)`.
//!    Eventually LDK fires `Event::FundingGenerationReady` with the
//!    2-of-2 multisig `output_script` and `channel_value_satoshis`.
//! 2. The event handler parks the request in this registry (instead of
//!    calling a server-side `FundingSource`).
//! 3. Caller (the gRPC handler) awaits [`Self::take`] to pick up the
//!    request, sends `{ output_script, value }` to the client over the
//!    wire.
//! 4. Client builds + signs a BDK transaction paying `value` to the
//!    script, returns the signed tx to the server.
//! 5. Caller invokes `ChannelManager::funding_transaction_generated` with
//!    the supplied tx — LDK broadcasts, channel proceeds.
//!
//! The registry decouples LDK's event loop (which is synchronous from
//! LDK's perspective) from the async RPC round-trip the client owes us.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::ScriptBuf;
use dashmap::DashMap;
use lightning::ln::types::ChannelId;
use tokio::sync::oneshot;

use crate::funding_store::FundingStore;

/// A parked channel-funding request.
#[derive(Debug, Clone)]
pub struct PendingFunding {
    /// Peer's compressed secp256k1 pubkey.
    pub counterparty: PublicKey,
    /// Channel value in satoshis — the exact amount the funding tx must
    /// pay to `output_script`.
    pub value_sat: u64,
    /// 2-of-2 multisig `scriptPubKey` LDK wants to fund.
    pub output_script: ScriptBuf,
}

/// Map of in-flight `FundingGenerationReady` events keyed by
/// `temporary_channel_id`.
///
/// Uses a oneshot-per-key pattern so there's no race between `park` and
/// `take`:
///
/// - If `take` runs first, it installs a `oneshot::Sender` in `waiters`.
///   When `park` fires it finds the sender and delivers the request
///   directly.
/// - If `park` runs first, it stashes the request in `ready`. When
///   `take` runs it finds the request on its first probe and returns.
///
/// Either ordering delivers exactly once; there's no notification that
/// can be dropped.
#[derive(Default)]
pub struct PendingFundingRegistry {
    /// Pending requests that have been parked but not yet taken.
    ready: DashMap<ChannelId, PendingFunding>,
    /// Senders installed by active `take` waiters. `park` prefers
    /// delivering via these rather than stashing in `ready`.
    waiters: DashMap<ChannelId, oneshot::Sender<PendingFunding>>,
    /// Optional durable backing. When `Some`, `park`/`take` mirror
    /// their in-memory work to Postgres so a crash between the two
    /// leaves a rehydratable row. When `None` (unit tests without a
    /// Postgres pool), the registry is pure in-memory — the crash
    /// recovery guarantee is forfeit.
    store: Option<Arc<FundingStore>>,
}

impl fmt::Debug for PendingFundingRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingFundingRegistry")
            .field("ready_count", &self.ready.len())
            .field("waiter_count", &self.waiters.len())
            .field("durable", &self.store.is_some())
            .finish()
    }
}

impl PendingFundingRegistry {
    /// Construct an in-memory-only registry. Used by unit tests and by
    /// any builder path that doesn't have a Postgres pool on hand.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Construct a registry with a durable backing. Call
    /// [`Self::rehydrate_from_store`] once after construction to
    /// re-populate `ready` from any rows left over from a previous
    /// boot.
    #[must_use]
    pub fn with_store(store: Arc<FundingStore>) -> Arc<Self> {
        Arc::new(Self {
            ready: DashMap::new(),
            waiters: DashMap::new(),
            store: Some(store),
        })
    }

    /// Pull every surviving row from Postgres into the in-memory
    /// `ready` map. Call exactly once, right after `with_store`, before
    /// the node is allowed to accept dispatches.
    ///
    /// A failed rehydrate is logged and treated as "no rows" — the
    /// node still boots; the cost is that any genuinely parked request
    /// stays stuck until its TTL expires. The alternative — blocking
    /// boot on Postgres transients — is worse.
    pub async fn rehydrate_from_store(&self) {
        let Some(ref store) = self.store else {
            return;
        };
        match store.rehydrate().await {
            Ok(rows) => {
                let n = rows.len();
                for row in rows {
                    self.ready.insert(row.temp_channel_id, row.request);
                }
                if n > 0 {
                    tracing::info!(
                        target: "wick_lightning",
                        count = n,
                        "funding_registry: rehydrated parked funding requests from Postgres"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "wick_lightning",
                    error = %e,
                    "funding_registry: rehydrate failed; booting without durable rows"
                );
            }
        }
    }

    /// Park `req` against `temp_id`. Delivers directly to an active
    /// `take` waiter if one is installed; otherwise stashes for later.
    /// Called from the event handler on `FundingGenerationReady`.
    ///
    /// The durable insert is best-effort: an insert failure is logged
    /// but does not stop the in-memory delivery. Losing durability on
    /// one request is preferable to failing an LDK event handler.
    pub fn park(&self, temp_id: ChannelId, req: PendingFunding) {
        if let Some(ref store) = self.store {
            // LDK's event handler runs in a Tokio context, so we can
            // spawn the insert as a fire-and-forget task. Keeping park
            // synchronous preserves the current call shape in
            // `EventHandler::handle_funding_generation_ready`.
            let store = store.clone();
            let temp_id_copy = temp_id;
            let req_copy = req.clone();
            tokio::spawn(async move {
                if let Err(e) = store.insert(temp_id_copy, &req_copy).await {
                    tracing::warn!(
                        target: "wick_lightning",
                        error = %e,
                        "funding_registry: durable insert failed"
                    );
                }
            });
        }

        if let Some((_, tx)) = self.waiters.remove(&temp_id) {
            // There's already a waiter — hand the request over directly.
            // The oneshot receiver unblocks `take` immediately.
            let _ = tx.send(req);
        } else {
            // No waiter yet. Stash for the inevitable `take` call.
            self.ready.insert(temp_id, req);
        }
    }

    /// Remove and return the parked request for `temp_id`. Waits up to
    /// `timeout` for `park` to fire — the event fires asynchronously
    /// after `create_channel`, usually within tens of milliseconds once
    /// the peer accepts the open message.
    ///
    /// Returns `None` on timeout.
    pub async fn take(&self, temp_id: ChannelId, timeout: Duration) -> Option<PendingFunding> {
        // Fast path: `park` already ran, the request is stashed.
        if let Some((_, req)) = self.ready.remove(&temp_id) {
            self.delete_from_store(temp_id).await;
            return Some(req);
        }

        // Install a waiter and re-check. The re-check covers the window
        // where `park` could have fired after the first probe and before
        // the sender was installed — in which case the request is now in
        // `ready` and we pull it from there.
        let (tx, rx) = oneshot::channel();
        self.waiters.insert(temp_id, tx);
        if let Some((_, req)) = self.ready.remove(&temp_id) {
            self.waiters.remove(&temp_id);
            self.delete_from_store(temp_id).await;
            return Some(req);
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(req)) => {
                self.delete_from_store(temp_id).await;
                Some(req)
            }
            Ok(Err(_)) => None,
            Err(_) => {
                self.waiters.remove(&temp_id);
                None
            }
        }
    }

    /// Remove the durable row for `temp_id`, if a store is configured.
    /// Logs but does not surface errors — the in-memory state is
    /// authoritative.
    async fn delete_from_store(&self, temp_id: ChannelId) {
        if let Some(ref store) = self.store {
            if let Err(e) = store.remove(temp_id).await {
                tracing::warn!(
                    target: "wick_lightning",
                    error = %e,
                    "funding_registry: durable remove failed"
                );
            }
        }
    }
}
