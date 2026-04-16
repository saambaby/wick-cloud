//! LDK event handler — per-tenant event dispatch into Postgres.
//!
//! Phase 3 scope: persist outcomes for the basic send/receive flow
//! (`PaymentSent`, `PaymentFailed`, `PaymentClaimable`, `PaymentClaimed`) and
//! auto-claim inbound HTLCs once preimage is available. Other event variants
//! are logged at `debug` and ignored until later phases (LSPS2 JIT, on-chain
//! sweep, splicing) wire the concrete handlers.
//!
//! The handler is owned by the per-tenant [`crate::Node`] and constructed by
//! [`crate::NodeBuilder`]. LDK's [`EventHandler`] trait is synchronous; we
//! bridge to async sqlx via `tokio::task::block_in_place` + `runtime.block_on`
//! the same way as [`crate::PgKvStore`].

use std::sync::Arc;

use lightning::events::{Event, EventHandler as LdkEventHandler, ReplayEvent};
use lightning::ln::channelmanager::ChannelManager;
use tokio::runtime::Handle;
use tracing::{debug, error, info, warn};

use crate::funding::FundingSource;
use crate::payment_store::{Direction, PaymentStatus, PaymentStore, PaymentWrite};

/// Capability contract for components the event handler reaches back into.
///
/// Abstracting `ChannelManager` behind a trait keeps [`EventHandler`]
/// non-generic over LDK's dense type parameters and lets tests swap in a
/// mock. Two operations are needed:
///
/// - `claim_funds(preimage)` — settle an inbound HTLC after
///   `PaymentClaimable`.
/// - `funding_transaction_generated(temp_id, counterparty, tx)` — feed a
///   signed funding tx back to LDK after `FundingGenerationReady`.
pub trait EventRuntimeOps: Send + Sync + 'static {
    /// Claim an inbound payment by revealing its preimage.
    fn claim_funds(&self, payment_preimage: lightning::types::payment::PaymentPreimage);

    /// Hand a signed funding tx back to the channel manager. Returns an
    /// error string suitable for logging if LDK rejects the tx.
    fn funding_transaction_generated(
        &self,
        temporary_channel_id: lightning::ln::types::ChannelId,
        counterparty_node_id: bitcoin::secp256k1::PublicKey,
        funding_transaction: bitcoin::Transaction,
    ) -> Result<(), String>;
}

/// Adapter so a real [`ChannelManager`] satisfies [`EventRuntimeOps`].
#[derive(Debug)]
pub struct ChannelManagerRuntimeOps<CM>(pub Arc<CM>);

impl<CM> EventRuntimeOps for ChannelManagerRuntimeOps<CM>
where
    CM: ChannelManagerOps + Send + Sync + 'static,
{
    fn claim_funds(&self, payment_preimage: lightning::types::payment::PaymentPreimage) {
        self.0.claim_funds(payment_preimage);
    }

    fn funding_transaction_generated(
        &self,
        temporary_channel_id: lightning::ln::types::ChannelId,
        counterparty_node_id: bitcoin::secp256k1::PublicKey,
        funding_transaction: bitcoin::Transaction,
    ) -> Result<(), String> {
        self.0.funding_transaction_generated(
            temporary_channel_id,
            counterparty_node_id,
            funding_transaction,
        )
    }
}

/// Thin trait over the two [`ChannelManager`] methods the event handler
/// needs, to avoid dragging its generic params into [`EventRuntimeOps`].
pub trait ChannelManagerOps {
    fn claim_funds(&self, payment_preimage: lightning::types::payment::PaymentPreimage);
    fn funding_transaction_generated(
        &self,
        temporary_channel_id: lightning::ln::types::ChannelId,
        counterparty_node_id: bitcoin::secp256k1::PublicKey,
        funding_transaction: bitcoin::Transaction,
    ) -> Result<(), String>;
}

/// Historic alias retained so external call sites that reference
/// [`ClaimFunds`] keep compiling. New code should use
/// [`ChannelManagerOps`].
pub use ChannelManagerOps as ClaimFunds;

impl<M, T, ES, NS, SP, F, R, MR, L> ChannelManagerOps
    for ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
where
    M: std::ops::Deref,
    T: std::ops::Deref,
    ES: std::ops::Deref,
    NS: std::ops::Deref,
    SP: std::ops::Deref,
    F: std::ops::Deref,
    R: std::ops::Deref,
    MR: std::ops::Deref,
    L: std::ops::Deref,
    M::Target: lightning::chain::Watch<<SP::Target as lightning::sign::SignerProvider>::EcdsaSigner>,
    T::Target: lightning::chain::chaininterface::BroadcasterInterface,
    ES::Target: lightning::sign::EntropySource,
    NS::Target: lightning::sign::NodeSigner,
    SP::Target: lightning::sign::SignerProvider,
    F::Target: lightning::chain::chaininterface::FeeEstimator,
    R::Target: lightning::routing::router::Router,
    MR::Target: lightning::onion_message::messenger::MessageRouter,
    L::Target: lightning::util::logger::Logger,
{
    fn claim_funds(&self, payment_preimage: lightning::types::payment::PaymentPreimage) {
        ChannelManager::claim_funds(self, payment_preimage);
    }

    fn funding_transaction_generated(
        &self,
        temporary_channel_id: lightning::ln::types::ChannelId,
        counterparty_node_id: bitcoin::secp256k1::PublicKey,
        funding_transaction: bitcoin::Transaction,
    ) -> Result<(), String> {
        ChannelManager::funding_transaction_generated(
            self,
            temporary_channel_id,
            counterparty_node_id,
            funding_transaction,
        )
        .map_err(|e| format!("{e:?}"))
    }
}

/// Per-tenant LDK event handler.
///
/// Wraps a [`PaymentStore`], a handle to the [`ChannelManager`] for claim +
/// funding callbacks, and an optional [`FundingSource`] that materialises
/// signed funding txs on `FundingGenerationReady`. Without a funding source
/// the event handler logs the event and lets LDK time out the channel.
pub struct EventHandler {
    payments: Arc<PaymentStore>,
    runtime: Handle,
    ops: Arc<dyn EventRuntimeOps>,
    funding: Option<Arc<dyn FundingSource>>,
}

impl std::fmt::Debug for EventHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventHandler")
            .field("has_funding_source", &self.funding.is_some())
            .finish_non_exhaustive()
    }
}

impl EventHandler {
    #[must_use]
    pub fn new(
        payments: Arc<PaymentStore>,
        runtime: Handle,
        ops: Arc<dyn EventRuntimeOps>,
    ) -> Self {
        Self {
            payments,
            runtime,
            ops,
            funding: None,
        }
    }

    /// Bind a [`FundingSource`]. Only needed for nodes that originate
    /// channel opens — counterparties don't receive `FundingGenerationReady`.
    #[must_use]
    pub fn with_funding_source(mut self, funding: Arc<dyn FundingSource>) -> Self {
        self.funding = Some(funding);
        self
    }

    fn block_on<F, T>(&self, fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::task::block_in_place(|| self.runtime.block_on(fut))
    }

    /// Async entry point consumed by `lightning_background_processor::
    /// process_events_async_with_kv_store_sync`.
    ///
    /// The background processor wants `Fn(Event) -> Future<Output = Result<(),
    /// ReplayEvent>>`. We delegate to the synchronous [`LdkEventHandler::handle_event`]
    /// inside a `spawn_blocking` so its `block_in_place` DB dispatch doesn't
    /// panic when called from the processor's own future.
    pub async fn handle(
        self: Arc<Self>,
        event: lightning::events::Event,
    ) -> Result<(), lightning::events::ReplayEvent> {
        let this = self.clone();
        match tokio::task::spawn_blocking(move || {
            <Self as lightning::events::EventHandler>::handle_event(&this, event)
        })
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    target: "wick_lightning",
                    error = %e,
                    "event handler task panicked — replaying"
                );
                Err(lightning::events::ReplayEvent())
            }
        }
    }
}

impl LdkEventHandler for EventHandler {
    fn handle_event(&self, event: Event) -> Result<(), ReplayEvent> {
        match event {
            Event::PaymentClaimable {
                payment_hash,
                amount_msat,
                purpose,
                ..
            } => {
                if let Some(preimage) = purpose.preimage() {
                    info!(
                        target: "wick_lightning",
                        hash = %hex::encode(payment_hash.0),
                        amount_msat,
                        "claiming inbound payment"
                    );
                    self.ops.claim_funds(preimage);
                } else {
                    warn!(
                        target: "wick_lightning",
                        hash = %hex::encode(payment_hash.0),
                        "PaymentClaimable without preimage — cannot auto-claim"
                    );
                }
            }

            Event::PaymentClaimed {
                payment_hash,
                amount_msat,
                ..
            } => {
                let write = PaymentWrite {
                    payment_hash: &payment_hash.0,
                    preimage: None,
                    direction: Direction::Inbound,
                    amount_msat,
                    fee_msat: 0,
                    status: PaymentStatus::Succeeded,
                };
                if let Err(e) = self.block_on(self.payments.upsert(write)) {
                    error!(target: "wick_lightning", error = %e, "PaymentClaimed: DB upsert failed");
                    return Err(ReplayEvent());
                }
            }

            Event::PaymentSent {
                payment_hash,
                fee_paid_msat,
                ..
            } => {
                let fee = fee_paid_msat.unwrap_or(0);
                if let Err(e) = self.block_on(self.payments.update_status(
                    &payment_hash.0,
                    PaymentStatus::Succeeded,
                    fee,
                )) {
                    error!(target: "wick_lightning", error = %e, "PaymentSent: DB update failed");
                    return Err(ReplayEvent());
                }
            }

            Event::PaymentFailed { payment_hash, .. } => {
                if let Some(hash) = payment_hash {
                    if let Err(e) = self.block_on(self.payments.update_status(
                        &hash.0,
                        PaymentStatus::Failed,
                        0,
                    )) {
                        error!(target: "wick_lightning", error = %e, "PaymentFailed: DB update failed");
                        return Err(ReplayEvent());
                    }
                }
            }

            Event::FundingGenerationReady {
                temporary_channel_id,
                counterparty_node_id,
                channel_value_satoshis,
                output_script,
                ..
            } => {
                let Some(funding) = self.funding.as_ref() else {
                    warn!(
                        target: "wick_lightning",
                        temp_id = ?temporary_channel_id,
                        "FundingGenerationReady received but no FundingSource bound — \
                         channel will time out"
                    );
                    // Don't replay — nothing changes by replaying without a funder.
                    return Ok(());
                };
                match funding.fund_channel(output_script, channel_value_satoshis) {
                    Ok(tx) => {
                        info!(
                            target: "wick_lightning",
                            temp_id = ?temporary_channel_id,
                            counterparty = %counterparty_node_id,
                            value_sats = channel_value_satoshis,
                            txid = %tx.compute_txid(),
                            "funding tx signed; handing to ChannelManager"
                        );
                        if let Err(e) = self.ops.funding_transaction_generated(
                            temporary_channel_id,
                            counterparty_node_id,
                            tx,
                        ) {
                            error!(
                                target: "wick_lightning",
                                error = %e,
                                temp_id = ?temporary_channel_id,
                                "funding_transaction_generated rejected"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            target: "wick_lightning",
                            error = %e,
                            temp_id = ?temporary_channel_id,
                            "FundingSource::fund_channel failed — channel will be abandoned"
                        );
                    }
                }
            }

            // ── Events we acknowledge but don't persist yet ─────────────────
            Event::ChannelReady { .. }
            | Event::ChannelPending { .. }
            | Event::ChannelClosed { .. }
            | Event::SpendableOutputs { .. }
            | Event::OpenChannelRequest { .. }
            | Event::PaymentPathSuccessful { .. }
            | Event::PaymentPathFailed { .. }
            | Event::ProbeSuccessful { .. }
            | Event::ProbeFailed { .. }
            | Event::HTLCIntercepted { .. }
            | Event::HTLCHandlingFailed { .. }
            | Event::BumpTransaction(..)
            | Event::DiscardFunding { .. }
            | Event::PaymentForwarded { .. }
            | Event::InvoiceReceived { .. }
            | Event::ConnectionNeeded { .. }
            | Event::OnionMessageIntercepted { .. }
            | Event::OnionMessagePeerConnected { .. } => {
                debug!(target: "wick_lightning", ?event, "event acknowledged (phase 3 stub)");
            }

            // Catch-all for any variants we haven't matched explicitly. LDK
            // may add new variants in future versions.
            other => {
                debug!(target: "wick_lightning", ?other, "unhandled event variant");
            }
        }
        Ok(())
    }
}
