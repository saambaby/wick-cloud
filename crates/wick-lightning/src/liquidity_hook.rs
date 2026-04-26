//! Trait hook for the operator-mode LSP daemon.
//!
//! `LiquidityManager` exposes a single `next_event_async()` consumer.
//! When a node runs in service mode, the LSP daemon needs to handle
//! `LSPS2ServiceEvent`s (GetInfo / BuyRequest / OpenChannel) by
//! calling back into the same `LiquidityManager`'s service handler
//! with the operator-supplied fee menu + channel-open policy.
//!
//! [`LspServiceEventHandler`] gives the daemon a stable trait it can
//! implement; [`crate::NodeBuilder::with_lsp_service_handler`] wires
//! it into the per-node event pump.

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::events::HTLCHandlingFailureType;
use lightning::ln::types::ChannelId;
use lightning::types::payment::PaymentHash;
use lightning_liquidity::lsps2::event::LSPS2ServiceEvent;

/// Operator hook for LSPS2 service-side events + LDK lifecycle
/// forwarding.
///
/// All methods are best-effort — failures are logged but never bubble
/// out of LDK's event pipeline (which would replay the event forever).
#[async_trait]
pub trait LspServiceEventHandler: Send + Sync + 'static {
    /// Handle a service-side LSPS2 event. The implementation must
    /// drive the corresponding response on the
    /// [`LiquidityManager`]'s service handler — otherwise the client
    /// times out waiting for a response.
    async fn handle_service_event(&self, event: LSPS2ServiceEvent);

    /// Forward [`Event::HTLCIntercepted`] into the LSPS2 service
    /// handler. Required for JIT channel opens to fire.
    async fn forward_htlc_intercepted(
        &self,
        intercept_id: lightning::ln::channelmanager::InterceptId,
        intercept_scid: u64,
        expected_outbound_amount_msat: u64,
        payment_hash: PaymentHash,
    );

    /// Forward [`Event::ChannelReady`] into the LSPS2 service handler.
    /// Required so the handler unparks any HTLCs it intercepted.
    async fn forward_channel_ready(
        &self,
        user_channel_id: u128,
        channel_id: ChannelId,
        counterparty_node_id: PublicKey,
    );

    /// Forward [`Event::PaymentForwarded`] into the LSPS2 service
    /// handler so the LSP can record the opening-fee debit.
    async fn forward_payment_forwarded(&self, next_channel_id: ChannelId, skimmed_fee_msat: u64);

    /// Forward [`Event::HTLCHandlingFailed`] into the LSPS2 service
    /// handler so the LSP can release reservations + score the failure.
    async fn forward_htlc_handling_failed(&self, failure_type: HTLCHandlingFailureType);
}
