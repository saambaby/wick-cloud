//! [`NodeApi`] — the capability surface of a Lightning node.
//!
//! `wick-server`'s [`NodeActor`] owns a `Box<dyn NodeApi + Send>` rather than a
//! concrete [`Node`]. That keeps the actor non-generic while the concrete node
//! is generic over its signer (`Node<S: WickSigner>`), which is required
//! because `lightning::sign::SignerProvider` has an associated type
//! (`EcdsaSigner`) that dynamic dispatch cannot name.
//!
//! Both production and tests bind [`crate::Node<S>`] with `S = LocalKeysManager`.
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

use crate::node::{Balance, ChannelSummary, JitInvoice, JitQuote, PaymentRecord, PaymentResult};

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

    /// Negotiate LSPS2 `lsps2.get_info` with the configured LSP peer
    /// and return a fee quote. Use the result to display a fee preview
    /// before issuing a JIT invoice via [`Self::receive_payment_jit`].
    ///
    /// Errors if no LSP is configured (`builder.with_liquidity_client`
    /// was not called) or if the LSP fails / times out.
    async fn lsps2_get_info(&self, amount_msat: Option<u64>) -> anyhow::Result<JitQuote>;

    /// Issue a JIT-enabled BOLT11 invoice. End-to-end: negotiates
    /// `get_info` + `buy` with the LSP, embeds the LSP's intercept SCID
    /// as a private route hint, and returns the signed invoice. Pays
    /// reach the LSP first and trigger a 0-conf channel open to this
    /// tenant before forwarding.
    ///
    /// `amount_msat` is required; LSPS2 buy quotes against a payment
    /// size, so any-amount JIT invoices are rejected at this layer.
    async fn receive_payment_jit(&self, amount_msat: u64, memo: &str)
        -> anyhow::Result<JitInvoice>;

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
    ///
    /// Legacy one-shot path: works only if the node was built with a
    /// [`crate::FundingSource`] bound. LDK's `Event::FundingGenerationReady`
    /// is consumed by the bound source, which produces + signs the funding
    /// transaction synchronously. Used by testkit's in-process tests where
    /// the same process holds both the LDK node and the funding wallet.
    ///
    /// Self-custodial callers should use the two-phase
    /// [`Self::open_channel_init`] + [`Self::open_channel_finalize`] pair
    /// instead, so the funding tx is built + signed by the **client's**
    /// BDK wallet and the server-side node is never custodial of the
    /// funding UTXOs.
    async fn open_channel(
        &self,
        peer_id: PublicKey,
        channel_value_sat: u64,
        push_msat: u64,
    ) -> anyhow::Result<()>;

    /// Start an outbound channel open and wait for LDK to ask for its
    /// funding transaction.
    ///
    /// Calls `ChannelManager::create_channel` (which returns the
    /// `temporary_channel_id` LDK will use), then blocks on the node's
    /// pending-funding registry for up to `timeout`, waiting for the
    /// matching `Event::FundingGenerationReady` to fire. Returns the
    /// `(temporary_channel_id, PendingFunding)` pair — `PendingFunding`
    /// carries the `output_script` and exact `value_sat` the funding tx
    /// must pay.
    ///
    /// Complete the open by calling [`Self::open_channel_finalize`] with
    /// the signed tx.
    async fn open_channel_init(
        &self,
        peer_id: PublicKey,
        channel_value_sat: u64,
        push_msat: u64,
        timeout: std::time::Duration,
    ) -> anyhow::Result<(ChannelId, crate::PendingFunding)>;

    /// Complete an outbound channel open by handing LDK a pre-signed
    /// funding transaction.
    ///
    /// `temp_channel_id` must match the value LDK returned from the
    /// matching [`Self::open_channel_init`] call. `funding_tx` must pay
    /// the exact `channel_value_sat` to the `output_script` from that same
    /// pending request.
    async fn open_channel_finalize(
        &self,
        temp_channel_id: &ChannelId,
        counterparty: &PublicKey,
        funding_tx: bitcoin::Transaction,
    ) -> anyhow::Result<()>;

    /// Close a channel. When `force` is true, broadcast the latest local
    /// commitment unilaterally (required when in-flight HTLCs prevent a
    /// cooperative close).
    async fn close_channel(
        &self,
        channel_id: &ChannelId,
        counterparty: &PublicKey,
        force: bool,
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
