//! [`NodeApi`] — the capability surface of a Lightning node.
//!
//! `wick-server`'s [`NodeActor`] owns a `Box<dyn NodeApi + Send>` rather than a
//! concrete [`Node`]. That keeps the actor non-generic while the concrete node
//! is generic over its signer (`Node<S: WickSigner>`), which is required
//! because `lightning::sign::SignerProvider` has an associated type
//! (`EcdsaSigner`) that dynamic dispatch cannot name.
//!
//! Tests implement a stub against this trait; production uses [`crate::Node`].
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
    async fn receive_payment(
        &self,
        amount_msat: Option<u64>,
        memo: &str,
    ) -> anyhow::Result<String>;

    /// Return the most recent `limit` payment rows from Postgres.
    async fn get_transactions(&self, limit: u32) -> anyhow::Result<Vec<PaymentRecord>>;

    /// Lightning node pubkey (derived from the signer).
    fn node_id(&self) -> PublicKey;

    /// Local socket address the P2P listener bound to — populated once
    /// [`crate::NodeBuilder::build`] returns. `None` for stub / dry-run
    /// impls that don't open a listener.
    ///
    /// Callers use this to hand the `host:port` to the counterparty's
    /// [`Self::connect_peer`] when two nodes run in the same process
    /// (integration tests, dev harness).
    fn local_listen_addr(&self) -> Option<SocketAddr>;

    /// Connect to a Lightning peer and persist it for reconnection on restart.
    async fn connect_peer(&self, node_id: PublicKey, host: &str, port: u16)
        -> anyhow::Result<()>;

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

    /// Signal all background tasks to exit. Idempotent.
    async fn shutdown(&self);
}
