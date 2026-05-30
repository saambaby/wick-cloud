//! Operator implementation of [`wick_lightning::LspServiceEventHandler`].
//!
//! Drives `LSPS2ServiceEvent::GetInfo` / `BuyRequest` / `OpenChannel`
//! responses against the LDK `lsps2_service_handler`, and forwards LDK
//! lifecycle events into the same handler so the LSPS2 protocol can
//! complete.
//!
//! Mirrors the pattern in ldk-node `src/liquidity.rs`. Channel-open
//! reservations + UTXO-pool selection are deferred to slice 3.3
//! hardening — for now `OpenChannel` calls
//! `ChannelManager::create_channel` with a stub channel size derived
//! from the requested forward amount + a fixed over-provisioning
//! constant. That suffices for the tenant-side integration test
//! (which exercises the gRPC + LSPS2 client path); a full operator
//! deployment requires the UTXO pool from slice 3.3.

use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::channelmanager::InterceptId;
use lightning::ln::types::ChannelId;
use lightning::types::payment::PaymentHash;
use lightning_liquidity::lsps2::event::LSPS2ServiceEvent;
use sqlx::PgPool;
use wick_lightning::{LnLiquidityManager, LocalKeysManager, LspServiceEventHandler, Node};

use crate::dispatcher::{LspDispatcher, OpenChannelRequest};
use crate::fee_params::FeeParamCache;
use crate::peer_registry::PeerRegistry;
use crate::unknown_scid_queue::UnknownScidQueue;

/// Over-provision the channel size by 5% above the forwarded amount
/// to absorb the LSP's opening fee + a small reserve. Operators
/// should tune via slice 3.3 config.
pub(crate) const CHANNEL_OVER_PROVISIONING_PPM: u64 = 50_000;

/// Operator-mode LSPS2 hook.
pub struct OperatorServiceHandler {
    node: Arc<Node<LocalKeysManager>>,
    fee_params: FeeParamCache,
    /// Bridge to the host (`wick-server`) used to wake the target
    /// tenant before the LSP fires `create_channel`. Without this,
    /// JIT opens to a parked tenant time out at the BOLT8 layer.
    dispatcher: Arc<dyn LspDispatcher>,
    /// SCID-keyed JIT request map. Authoritative on disk
    /// (`global.jit_requests`) — `register_buy` returns only after the
    /// row is committed, so the unknown-SCID queue's race window is
    /// bounded to the BuyRequest → htlc_intercepted ordering on the
    /// payer's side.
    peer_registry: Arc<PeerRegistry>,
    /// Bounded queue holding HTLCs whose intercept SCID is not yet in
    /// the registry. Drains when the matching `register_buy` lands or
    /// fails the HTLC after the configured retry window.
    unknown_scid_queue: Arc<UnknownScidQueue>,
    /// Direct pool handle so `register_buy` / `set_state` can persist
    /// without round-tripping the registry through wick-db's tenant_tx
    /// (this table is global, not tenant-scoped).
    pool: PgPool,
    /// Reorg-reserve guard. Caps total in-flight unconfirmed JIT
    /// exposure at `reorg_safety_threshold_sats`. Constructed per
    /// `OperatorServiceHandler` because `threshold_sats` may differ
    /// across deployments.
    reorg_guard: crate::reorg::ReorgGuard,
    /// Per-client grief scorer. Rejects BuyRequests from clients whose
    /// reputation has crossed the configured threshold; records
    /// fulfilments + rehydration-time grief events.
    grief_scorer: crate::grief::GriefScorer,
    /// Hard ceiling on any single JIT channel — taken from
    /// `LspConfig::max_jit_channel_sats`. Used to project the
    /// any-amount BuyRequest's worst-case capacity.
    max_jit_channel_sats: u64,
}

impl std::fmt::Debug for OperatorServiceHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorServiceHandler")
            .field("fee_params", &self.fee_params.current_params())
            .finish_non_exhaustive()
    }
}

impl OperatorServiceHandler {
    /// Construct from an already-built LSP node + the operator's fee
    /// param cache + the dispatcher used to wake target tenants. The
    /// node must have been built with
    /// `with_liquidity_service(promise_secret)` — otherwise its
    /// `lsps2_service_handler()` is `None` and every event handler
    /// here is a no-op.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node: Arc<Node<LocalKeysManager>>,
        fee_params: FeeParamCache,
        dispatcher: Arc<dyn LspDispatcher>,
        peer_registry: Arc<PeerRegistry>,
        pool: PgPool,
        reorg_safety_threshold_sats: u64,
        max_jit_channel_sats: u64,
        grief_scorer: crate::grief::GriefScorer,
    ) -> Self {
        let unknown_scid_queue = UnknownScidQueue::spawn(
            peer_registry.clone(),
            node.clone(),
            UnknownScidQueue::DEFAULT_RETRY_WINDOW,
        );
        let reorg_guard =
            crate::reorg::ReorgGuard::new(peer_registry.clone(), reorg_safety_threshold_sats);
        Self {
            node,
            fee_params,
            dispatcher,
            peer_registry,
            unknown_scid_queue,
            pool,
            reorg_guard,
            grief_scorer,
            max_jit_channel_sats,
        }
    }

    fn liquidity(&self) -> Arc<LnLiquidityManager<LocalKeysManager>> {
        self.node.liquidity_manager_arc()
    }
}

#[async_trait]
impl LspServiceEventHandler for OperatorServiceHandler {
    async fn handle_service_event(&self, event: LSPS2ServiceEvent) {
        let lm = self.liquidity();
        let Some(handler) = lm.lsps2_service_handler() else {
            tracing::warn!(
                target: "wick_lsp",
                "LSPS2 service event with no service handler installed"
            );
            return;
        };

        match event {
            LSPS2ServiceEvent::GetInfo {
                request_id,
                counterparty_node_id,
                token: _,
            } => {
                let menu = self.fee_params.menu();
                if let Err(e) =
                    handler.opening_fee_params_generated(&counterparty_node_id, request_id, menu)
                {
                    tracing::error!(
                        target: "wick_lsp",
                        error = ?e,
                        "lsps2 opening_fee_params_generated failed"
                    );
                }
            }
            LSPS2ServiceEvent::BuyRequest {
                request_id,
                counterparty_node_id,
                opening_fee_params,
                payment_size_msat,
            } => {
                // Grief gate (B3). Reject before reorg gate so a
                // griefer doesn't even count toward exposure.
                match self.grief_scorer.should_reject(&counterparty_node_id).await {
                    Ok(true) => {
                        tracing::warn!(
                            target: "wick_lsp",
                            peer = %counterparty_node_id,
                            threshold = self.grief_scorer.rejection_threshold(),
                            "rejecting LSPS2 BuyRequest — grief score above threshold"
                        );
                        let _ = request_id;
                        return;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        // Fail open: a Postgres blip shouldn't deny
                        // service to honest clients. Log loud so the
                        // operator notices the read path is broken.
                        tracing::error!(
                            target: "wick_lsp",
                            error = %e,
                            peer = %counterparty_node_id,
                            "grief_scorer.should_reject failed; admitting BuyRequest"
                        );
                    }
                }

                // Reorg-reserve gate (B2). Project the channel
                // capacity this BuyRequest would land in `Opened` at,
                // then refuse if it would push the LSP's running
                // unconfirmed exposure past the configured threshold.
                // Rejection here is silent (LSPS2 0.2 has no decline
                // message; the client times out and surfaces
                // LSP_CAPACITY_EXHAUSTED to its user).
                let projected_capacity = crate::reorg::projected_capacity_sat(
                    payment_size_msat,
                    CHANNEL_OVER_PROVISIONING_PPM,
                    self.max_jit_channel_sats,
                );
                if let Err(reason) = self.reorg_guard.check_capacity(projected_capacity) {
                    tracing::warn!(
                        target: "wick_lsp",
                        peer = %counterparty_node_id,
                        ?payment_size_msat,
                        projected_capacity_sat = projected_capacity,
                        rejection = %reason,
                        "rejecting LSPS2 BuyRequest — reorg reserve guard"
                    );
                    let _ = request_id;
                    return;
                }

                // LDK allocates the intercept SCID; HTLCs will route
                // through this id and fire `Event::HTLCIntercepted`.
                let scid = self.node.channel_manager_get_intercept_scid();
                let cltv_expiry_delta = self.fee_params_cltv_default();
                let user_channel_id: u128 = u128::from(scid);

                // Persist the JIT request *before* sending the buy
                // response. `register_buy` only returns after the row
                // commits to `global.jit_requests`, so a crash between
                // here and `invoice_parameters_generated` leaves the
                // registry honest and the (still-uncommunicated)
                // promise expires naturally via `valid_until`.
                let valid_until = opening_fee_params.valid_until.0;
                if let Err(e) = self
                    .peer_registry
                    .register_buy(
                        scid,
                        counterparty_node_id,
                        payment_size_msat,
                        valid_until,
                        &self.pool,
                    )
                    .await
                {
                    tracing::error!(
                        target: "wick_lsp",
                        error = %e,
                        intercept_scid = scid,
                        "peer_registry.register_buy failed; aborting LSPS2 buy"
                    );
                    return;
                }

                if let Err(e) = handler
                    .invoice_parameters_generated(
                        &counterparty_node_id,
                        request_id,
                        scid,
                        cltv_expiry_delta,
                        true, // client_trusts_lsp = true (Phase 3 default)
                        user_channel_id,
                    )
                    .await
                {
                    tracing::error!(
                        target: "wick_lsp",
                        error = ?e,
                        "lsps2 invoice_parameters_generated failed"
                    );
                } else {
                    tracing::debug!(
                        target: "wick_lsp",
                        intercept_scid = scid,
                        ?payment_size_msat,
                        "issued LSPS2 buy response"
                    );
                }
            }
            LSPS2ServiceEvent::OpenChannel {
                their_network_key,
                amt_to_forward_msat,
                opening_fee_msat,
                user_channel_id,
                intercept_scid,
            } => {
                let over = (amt_to_forward_msat * CHANNEL_OVER_PROVISIONING_PPM) / 1_000_000;
                let channel_amount_sats = (amt_to_forward_msat + over) / 1000;

                tracing::info!(
                    target: "wick_lsp",
                    peer = %their_network_key,
                    amt_to_forward_msat,
                    opening_fee_msat,
                    intercept_scid,
                    channel_amount_sats,
                    "lsps2 OpenChannel — waking tenant before opening JIT channel"
                );

                // Wake the target tenant (no-op if already ACTIVE) so
                // its PeerManager is alive when the BOLT8 channel-open
                // messages arrive. Bail before `create_channel` if the
                // tenant doesn't exist or wake fails — opening a
                // channel to a parked tenant just times out and burns
                // an intercept SCID.
                let req = OpenChannelRequest {
                    tenant_pubkey: their_network_key,
                    amt_to_forward_msat,
                    opening_fee_msat,
                    user_channel_id,
                    intercept_scid,
                };
                if let Err(e) = self.dispatcher.dispatch_open_channel(req).await {
                    tracing::error!(
                        target: "wick_lsp",
                        error = %e,
                        peer = %their_network_key,
                        intercept_scid,
                        "dispatcher.dispatch_open_channel failed; aborting JIT open"
                    );
                    return;
                }

                if let Err(e) = self.node.channel_manager_create_jit_channel(
                    their_network_key,
                    channel_amount_sats,
                    user_channel_id,
                ) {
                    tracing::error!(
                        target: "wick_lsp",
                        error = %e,
                        peer = %their_network_key,
                        "create_channel for LSPS2 OpenChannel failed"
                    );
                    if let Err(set_err) = self
                        .peer_registry
                        .set_state(
                            intercept_scid,
                            crate::peer_registry::JitRequestState::Failed,
                            &self.pool,
                        )
                        .await
                    {
                        tracing::warn!(
                            target: "wick_lsp",
                            error = %set_err,
                            intercept_scid,
                            "peer_registry set_state(Failed) failed after create_jit_channel error"
                        );
                    }
                } else if let Err(set_err) = self
                    .peer_registry
                    .mark_opened(intercept_scid, channel_amount_sats, &self.pool)
                    .await
                {
                    tracing::warn!(
                        target: "wick_lsp",
                        error = %set_err,
                        intercept_scid,
                        capacity_sat = channel_amount_sats,
                        "peer_registry mark_opened failed (in-memory state intact)"
                    );
                }
            }
        }
    }

    async fn forward_htlc_intercepted(
        &self,
        intercept_id: InterceptId,
        intercept_scid: u64,
        expected_outbound_amount_msat: u64,
        payment_hash: PaymentHash,
    ) {
        // Bounded race: the BOLT11 invoice ships with the intercept
        // SCID immediately after the LSPS2 buy response, so a payer
        // *can* route an HTLC before the local registry write commits.
        // Park unknown SCIDs in the retry queue; the queue's poll loop
        // releases them into `htlc_intercepted` once `register_buy`
        // catches up, or fails the HTLC with `UnknownNextPeer` after
        // the configured retry window.
        if self.peer_registry.lookup(intercept_scid).is_none() {
            self.unknown_scid_queue.park(crate::unknown_scid_queue::HtlcParkRequest {
                intercept_id,
                intercept_scid,
                expected_outbound_amount_msat,
                payment_hash,
                liquidity_manager: self.liquidity(),
            });
            return;
        }

        let lm = self.liquidity();
        let Some(handler) = lm.lsps2_service_handler() else {
            return;
        };
        if let Err(e) = handler
            .htlc_intercepted(
                intercept_scid,
                intercept_id,
                expected_outbound_amount_msat,
                payment_hash,
            )
            .await
        {
            tracing::error!(target: "wick_lsp", error = ?e, "lsps2 htlc_intercepted forward failed");
        }
    }

    async fn forward_channel_ready(
        &self,
        user_channel_id: u128,
        channel_id: ChannelId,
        counterparty_node_id: PublicKey,
    ) {
        // A JIT channel the LSP opened always carries `user_channel_id ==
        // u128::from(intercept_scid)`, and that scid is registered in the
        // peer_registry (from the LSPS2 `buy`). A tenant's *normal* channel
        // to the LSP (e.g. Alice's outbound channel) carries neither. Feeding
        // a non-JIT ChannelReady into the LSPS2 service handler is not just
        // useless — LDK returns `APIMisuseError("No counterparty state for …")`,
        // and the call does on-event-loop blocking work (per-peer state lookup
        // + KV persist) that ties up the single LSP event loop, starving
        // unrelated LSPS2 traffic (e.g. another tenant's `get_info`). Skip it.
        if user_channel_id > u128::from(u64::MAX) {
            return;
        }
        #[allow(clippy::cast_possible_truncation)]
        let scid = user_channel_id as u64;
        if self.peer_registry.lookup(scid).is_none() {
            // Not a JIT channel we minted — nothing for the LSPS2 handler to do.
            return;
        }

        // Recover the intercept scid and persist the LDK channel id against the
        // registry entry so `forward_payment_forwarded` can resolve client_pubkey.
        if let Err(e) = self
            .peer_registry
            .set_channel_id(scid, channel_id.0, &self.pool)
            .await
        {
            tracing::warn!(
                target: "wick_lsp",
                error = %e,
                intercept_scid = scid,
                "peer_registry.set_channel_id failed (grief reward attribution may miss)"
            );
        }

        let lm = self.liquidity();
        let Some(handler) = lm.lsps2_service_handler() else {
            return;
        };
        if let Err(e) = handler
            .channel_ready(user_channel_id, &channel_id, &counterparty_node_id)
            .await
        {
            tracing::error!(target: "wick_lsp", error = ?e, "lsps2 channel_ready forward failed");
        }
    }

    async fn forward_payment_forwarded(&self, next_channel_id: ChannelId, skimmed_fee_msat: u64) {
        let lm = self.liquidity();
        let Some(handler) = lm.lsps2_service_handler() else {
            return;
        };

        // Reward the client whose JIT channel just settled. Look the
        // tenant pubkey up via the registry: scan for an Opened entry
        // whose channel_id matches `next_channel_id`. The registry
        // stores `channel_id` as a `[u8; 32]` mirror of LDK's value;
        // see `set_channel_id`.
        if let Some(client_pubkey) = self
            .peer_registry
            .lookup_pubkey_by_channel_id(&next_channel_id.0)
        {
            if let Err(e) = self.grief_scorer.record_fulfilment(&client_pubkey).await {
                tracing::warn!(
                    target: "wick_lsp",
                    error = %e,
                    peer = %client_pubkey,
                    "grief_scorer.record_fulfilment failed (non-fatal)"
                );
            }
        }

        if let Err(e) = handler
            .payment_forwarded(next_channel_id, skimmed_fee_msat)
            .await
        {
            tracing::error!(target: "wick_lsp", error = ?e, "lsps2 payment_forwarded forward failed");
        }
    }

    async fn forward_htlc_handling_failed(
        &self,
        failure_type: lightning::events::HTLCHandlingFailureType,
    ) {
        tracing::debug!(
            target: "wick_lsp",
            failure = ?failure_type,
            "lsps2 HTLCHandlingFailed"
        );
    }
}

impl OperatorServiceHandler {
    fn fee_params_cltv_default(&self) -> u32 {
        // `lightning-liquidity::LSPS2_CHANNEL_CLTV_EXPIRY_DELTA` per
        // ldk-node — they use 72 for testnet/mainnet. The route hint
        // uses this same value so the tenant invoice's
        // `min_final_cltv_expiry_delta` accommodates the LSP hop.
        72
    }
}
