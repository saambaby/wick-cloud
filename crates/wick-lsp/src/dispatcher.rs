//! [`LspDispatcher`] — bridges LSPS2 service events to tenant nodes.
//!
//! When LDK fires `LSPS2ServiceEvent::OpenChannel`, the LSP looks up
//! the corresponding tenant via [`crate::PeerRegistry`] and uses the
//! dispatcher trait to forward the open into that tenant's mpsc
//! channel inside `wick-server`'s `NodeManager`.
//!
//! This trait lives in `wick-lsp` (not `wick-server`) so the daemon
//! has a stable interface to call without depending on
//! `wick-server`'s concrete `NodeManager` type.

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;

/// A request to open a JIT channel for the tenant identified by
/// `tenant_pubkey`. Emitted by the LSP in response to
/// `LSPS2ServiceEvent::OpenChannel` and consumed by `wick-server`,
/// which resolves the pubkey to a [`wick_core::TenantId`], wakes the
/// tenant if parked, then lets the LSP-owned `Node<S>` drive the
/// 0-conf channel open over BOLT8.
///
/// `tenant_id` resolution lives on the host side, not on the LSP — the
/// LSP only knows pubkeys (from LSPS2's `counterparty_node_id`).
#[derive(Debug, Clone)]
pub struct OpenChannelRequest {
    /// Tenant's Lightning node id (counterparty for the open).
    pub tenant_pubkey: PublicKey,
    /// Forwardable amount after the LSP deducts its opening fee.
    pub amt_to_forward_msat: u64,
    /// Opening fee owed to the LSP, deducted from the inbound HTLC.
    pub opening_fee_msat: u64,
    /// User-provided channel id from the buy request — echo back to
    /// LDK on `funding_transaction_generated`.
    pub user_channel_id: u128,
    /// Intercept SCID this open is satisfying.
    pub intercept_scid: u64,
}

/// Capability the LSP needs from the host (`wick-server`).
#[async_trait]
pub trait LspDispatcher: Send + Sync + 'static {
    /// Drive a JIT channel open for `req.tenant_id`. The implementation
    /// is responsible for waking the tenant if parked and propagating
    /// the open into LDK via the LSP node's `ChannelManager`.
    async fn dispatch_open_channel(&self, req: OpenChannelRequest) -> anyhow::Result<()>;
}
