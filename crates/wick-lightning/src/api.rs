//! [`NodeApi`] — the capability surface of a Lightning node.
//!
//! `wick-server`'s [`NodeActor`] owns a `Box<dyn NodeApi + Send>` rather than a
//! concrete [`Node`]. That keeps the actor non-generic while the concrete node
//! is generic over its signer (`Node<S: WickSigner>`), which is required
//! because `lightning::sign::SignerProvider` has an associated type
//! (`EcdsaSigner`) that dynamic dispatch cannot name.
//!
//! Both production and tests bind [`crate::Node<S>`]; tests use
//! `S = LocalKeysManager` constructed via the `wick-testkit` harness.
//! Phase 4's VLS flip changes only which `S` is bound at construction — the
//! actor side never sees it.
//!
//! [`Node`]: crate::Node
//! [`NodeActor`]: https://docs.rs/wick-server/latest/wick_server/node/actor/struct.NodeActor.html

use std::fmt::Debug;
use std::net::SocketAddr;

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::types::ChannelId;

use crate::node::{Balance, ChannelSummary, PaymentRecord, PaymentResult};

/// Capability surface for a per-tenant Lightning node.
///
/// Each method corresponds 1:1 to a `NodeCmd` variant in `wick-server`. All
/// methods take `&self` — the concrete [`crate::Node`] uses interior
/// synchronisation (LDK primitives are already `Sync`), so the actor doesn't
/// need `&mut self` anywhere.
#[async_trait]
pub trait NodeApi: Send + Sync + Debug + 'static {
    /// Current Lightning + on-chain balance snapshot.
    async fn get_balance(&self) -> anyhow::Result<Balance>;

    /// Initiate an outbound BOLT11 payment. Returns once the payment has been
    /// enqueued; final status is reported by the event handler.
    async fn send_payment(&self, bolt11: &str) -> anyhow::Result<PaymentResult>;

    /// Create a BOLT11 invoice.
    ///
    /// Returns `(bolt11_string, payment_hash_bytes)` — the 32-byte payment
    /// hash is taken straight from the LDK-generated invoice so callers can
    /// surface it without re-parsing the BOLT11.
    async fn receive_payment(
        &self,
        amount_msat: Option<u64>,
        memo: &str,
    ) -> anyhow::Result<(String, Vec<u8>)>;

    /// Return the most recent `limit` payment rows from Postgres.
    async fn get_transactions(&self, limit: u32) -> anyhow::Result<Vec<PaymentRecord>>;

    /// Lightning node pubkey (derived from the signer).
    fn node_id(&self) -> PublicKey;

    /// Local socket address the P2P listener bound to — populated once
    /// [`crate::NodeBuilder::build`] returns. `None` only on impls that
    /// don't open a listener (none ship today; reserved for future use).
    ///
    /// Callers use this to hand the `host:port` to the counterparty's
    /// [`Self::connect_peer`] when two nodes run in the same process
    /// (integration tests, dev harness).
    fn local_listen_addr(&self) -> Option<SocketAddr>;

    /// Connect to a Lightning peer and persist it for reconnection on restart.
    async fn connect_peer(&self, node_id: PublicKey, host: &str, port: u16) -> anyhow::Result<()>;

    /// Open an outbound channel to an already-connected peer.
    async fn open_channel(
        &self,
        peer_id: PublicKey,
        channel_value_sat: u64,
        push_msat: u64,
    ) -> anyhow::Result<()>;

    /// Cooperatively close a channel.
    async fn close_channel(
        &self,
        channel_id: &ChannelId,
        counterparty: &PublicKey,
    ) -> anyhow::Result<()>;

    /// Snapshot of all channels known to the channel manager.
    async fn list_channels(&self) -> anyhow::Result<Vec<ChannelSummary>>;

    /// Park-safety probe: `true` if any channel has inbound or outbound HTLCs
    /// in flight. Used by the post-drain recheck in the actor's `Park` handler
    /// — parking a node mid-HTLC would lose funds.
    async fn has_pending_htlcs(&self) -> anyhow::Result<bool>;

    /// Park-safety probe: `true` if Postgres has any outbound payment row in
    /// `pending` status. Delegates to
    /// [`crate::payment_store::PaymentStore::has_inflight_outbound`] — which is
    /// also usable standalone (no live `Node` required) from the activity
    /// poller's pre-flight check.
    async fn has_inflight_outbound(&self) -> anyhow::Result<bool>;

    /// Park-safety probe: `true` if `ChainMonitor` has persisted updates that
    /// haven't been fully processed yet (e.g. a pending force-close watch that
    /// hasn't been acknowledged). Used by the post-drain recheck; a monitor
    /// update in flight means the `BackgroundProcessor` has work to finish
    /// before the node can be safely dropped.
    async fn has_unresolved_monitor_events(&self) -> anyhow::Result<bool>;

    /// Signal all background tasks to exit. Idempotent.
    async fn shutdown(&self);
}
