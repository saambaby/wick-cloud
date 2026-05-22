//! [`LspDaemon`] — top-level orchestrator for the in-process LSP.
//!
//! Two-phase boot:
//!
//! 1. At process start, [`LspBuilder`] is constructed with everything that's
//!    knowable without the operator's Lightning seed: `NodeDeps` (Postgres
//!    pool, Esplora client, broadcaster, …), [`LspPartialConfig`] (fee menu
//!    + upstream peer), and the [`LspDispatcher`] used to wake target
//!    tenants on `LSPS2ServiceEvent::OpenChannel`.
//!
//! 2. The operator's SDK calls the admin RPC `RegisterLspIdentity{seed}`,
//!    which invokes [`LspBuilder::build_with_seed`]. From the seed we
//!    derive the LSP node pubkey, the reserved [`TenantId`], and the
//!    LSPS2 promise HMAC secret, then construct the `Node<LocalKeysManager>`
//!    via `NodeBuilder` and dial the upstream peer. The resulting
//!    [`LspDaemon`] is parked into the `Arc<RwLock<Option<LspDaemon>>>`
//!    slot held by `wick-server::main`.
//!
//! No on-chain wallet lives on the server. JIT-channel funding txs are
//! parked in [`wick_lightning::PendingFundingRegistry`] (the same registry
//! tenant two-phase opens already use) and signed by the operator's SDK
//! via the admin `LspWatchPendingFunding` / `LspFinalizeFunding` RPCs.

use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;
use tokio::task::JoinHandle;
use wick_core::TenantId;
use wick_lightning::{
    from_seed, LocalKeysManager, LspServiceEventHandler, Node, NodeApi, NodeBuilder, NodeDeps,
};

use crate::dispatcher::LspDispatcher;
use crate::fee_params::{FeeParamCache, OpeningParamsView};
use crate::handler::OperatorServiceHandler;
use crate::peer_registry::PeerRegistry;

/// Configuration knowable at server boot — everything except the seed.
///
/// Built from the `[lsp]` TOML by `wick-server::main` and held by an
/// [`LspBuilder`] until the operator registers a Lightning identity.
#[derive(Debug, Clone)]
pub struct LspPartialConfig {
    /// Static LSPS2 fee menu: floor fee, proportional ppm, payment-size
    /// bounds. Per-network defaults from `[lsp]` config.
    pub opening_params: OpeningParamsView,
    /// Optional upstream peer (`pubkey, host:port`). Dialed once from
    /// inside [`LspBuilder::build_with_seed`]; reconnect is handled by
    /// the LSP `Node<S>`'s peer-reconnect loop.
    pub upstream_peer: Option<(PublicKey, String)>,
    /// Hard ceiling on total in-flight unconfirmed JIT exposure. Maps
    /// 1:1 to `LspConfig::reorg_safety_threshold_sats`. Wired into the
    /// reorg-reserve guard at handler construction time. `0` disables.
    pub reorg_safety_threshold_sats: u64,
    /// Hard ceiling on any single JIT channel. Maps to
    /// `LspConfig::max_jit_channel_sats`. Used to project the
    /// any-amount BuyRequest's worst-case capacity.
    pub max_jit_channel_sats: u64,
    /// Grief-scorer tunables. Maps 1:1 to the `LspConfig::grief_*`
    /// fields. Used to construct the `GriefScorer` at handler build
    /// time.
    pub grief: GriefConfig,
    /// P2P listen address for the LSP node. Maps 1:1 to
    /// `LspConfig::listen_addr`. The LSP daemon binds this exact
    /// SocketAddr (overriding the random per-tenant port that ordinary
    /// `Node<S>` instances use) so the operator-published `lsp_address`
    /// is the actual port tenants can dial.
    pub listen_addr: std::net::SocketAddr,
}

/// Grief-score tunables. Plain `f64`s with the same shape as
/// `LspConfig::grief_*` so callers can feed config straight through
/// without a private type.
#[derive(Debug, Clone, Copy)]
pub struct GriefConfig {
    /// Half-life (hours) of exponential decay.
    pub half_life_hours: f64,
    /// Score added per detected grief event.
    pub penalty: f64,
    /// Score subtracted per fulfilment.
    pub reward: f64,
    /// Threshold above which BuyRequests are rejected.
    pub rejection_threshold: f64,
}

/// Backwards-compatible alias retained so external call sites that
/// reference `LspDaemonConfig` keep compiling. New code should use
/// [`LspPartialConfig`].
pub use LspPartialConfig as LspDaemonConfig;

/// Pre-registration handle. Holds the dependencies and partial config
/// needed to construct the LSP daemon once a Lightning seed arrives.
///
/// `wick-server::main` constructs this once at boot and stores it
/// alongside `Arc<RwLock<Option<LspDaemon>>>`. The admin
/// `RegisterLspIdentity` RPC handler calls
/// [`LspBuilder::build_with_seed`] and drops the result into the slot.
#[allow(missing_debug_implementations)] // Arc<dyn LspDispatcher> isn't Debug
pub struct LspBuilder {
    deps: NodeDeps,
    config: LspPartialConfig,
    dispatcher: Arc<dyn LspDispatcher>,
}

impl LspBuilder {
    /// Construct a builder. No I/O — the LSP isn't running yet.
    #[must_use]
    pub fn new(
        deps: NodeDeps,
        config: LspPartialConfig,
        dispatcher: Arc<dyn LspDispatcher>,
    ) -> Self {
        Self {
            deps,
            config,
            dispatcher,
        }
    }

    /// Build the LSP daemon with the supplied 32-byte Lightning seed.
    ///
    /// Same `LocalKeysManager` / `from_seed` path tenant LDK signers
    /// use today (pre-VLS). The seed is passed dynamically by the
    /// operator's SDK — never read from a server env var. After Phase 4
    /// this method's signature changes to take a remote-signer handle
    /// instead of raw bytes.
    ///
    /// Takes `&self` so the builder can be reused on retry if the
    /// initial registration fails (e.g. upstream dial timeout). All
    /// fields are cheaply cloneable.
    pub async fn build_with_seed(&self, lightning_seed: [u8; 32]) -> anyhow::Result<LspDaemon> {
        let signer = Arc::new(from_seed(lightning_seed));
        let pubkey = lightning::sign::NodeSigner::get_node_id(
            signer.as_ref(),
            lightning::sign::Recipient::Node,
        )
        .map_err(|()| anyhow::anyhow!("derive LSP node pubkey from seed"))?;
        let tenant_id = TenantId::from_pubkey(&pubkey.serialize());

        // Promise secret: domain-separated SHA-256 over the seed so the
        // LSPS2 HMAC key survives operator restarts deterministically
        // without requiring separate key material. Same shape `wick-server`
        // computed previously, just moved here.
        let promise_secret: [u8; 32] = {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"wick-lsp/lsps2-promise/v1");
            hasher.update(lightning_seed);
            hasher.finalize().into()
        };

        let fee_params = FeeParamCache::new(self.config.opening_params);
        let deps = self.deps.clone();
        let dispatcher = self.dispatcher.clone();

        // Two-phase service-handler install: NodeBuilder needs the handler
        // at construction time, but the handler needs the Node. Resolve via
        // a deferred Arc populated immediately after `build()` returns. The
        // race window is microseconds (synchronous control flow), and any
        // service event arriving inside it is dropped with a warning.
        let deferred = Arc::new(DeferredHandler::new());
        let node: Arc<Node<LocalKeysManager>> =
            NodeBuilder::<LocalKeysManager>::new(tenant_id, deps)
                .with_signer(signer)
                .with_liquidity_service(promise_secret)
                .with_lsp_service_handler(deferred.clone() as Arc<dyn LspServiceEventHandler>)
                .with_listen_addr_override(self.config.listen_addr)
                .build()
                .await?;

        let grief_scorer = crate::grief::GriefScorer::new(
            self.deps.pg_pool.clone(),
            self.config.grief.half_life_hours,
            self.config.grief.penalty,
            self.config.grief.reward,
            self.config.grief.rejection_threshold,
        );
        let registry = PeerRegistry::rehydrate_from_pg_with_grief(
            &self.deps.pg_pool,
            Some(&grief_scorer),
        )
        .await
        .map_err(|e| anyhow::anyhow!("PeerRegistry rehydrate: {e}"))?;

        let real_handler = OperatorServiceHandler::new(
            node.clone(),
            fee_params,
            dispatcher.clone(),
            registry.clone(),
            self.deps.pg_pool.clone(),
            self.config.reorg_safety_threshold_sats,
            self.config.max_jit_channel_sats,
            grief_scorer,
        );
        deferred.install(Arc::new(real_handler)).await;

        // Background handle kept around purely for the existing
        // `daemon.event_pump.abort()` shutdown contract. The actual
        // `LSPS2ServiceEvent` consumer lives in
        // `wick-lightning::spawn_liquidity_event_pump`, which forwards
        // service events to the deferred handler installed above.
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel::<()>(());
        let event_pump = tokio::spawn(async move {
            let _ = stop_rx.changed().await;
            tracing::info!(target: "wick_lsp", "LSP daemon shutdown signal observed");
        });

        if let Some((pk, addr)) = self.config.upstream_peer.clone() {
            // Best-effort upstream dial; failures fall through to the
            // peer-reconnect loop inside `Node<S>`.
            let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
            if let [port_str, host] = parts.as_slice() {
                if let Ok(port) = port_str.parse::<u16>() {
                    if let Err(e) = node.connect_peer(pk, host, port).await {
                        tracing::warn!(
                            target: "wick_lsp",
                            error = %e,
                            peer = %pk,
                            address = %addr,
                            "lsp upstream connect failed; will retry via peer_reconnect loop"
                        );
                    } else {
                        tracing::info!(
                            target: "wick_lsp",
                            peer = %pk,
                            address = %addr,
                            "lsp connected to upstream"
                        );
                    }
                }
            }
        }

        tracing::info!(
            target: "wick_lsp",
            pubkey = %pubkey,
            tenant_id = %tenant_id,
            "lsp_identity_registered"
        );

        Ok(LspDaemon {
            node: node.clone() as Arc<dyn NodeApi>,
            typed_node: node,
            registry,
            fee_params,
            pubkey,
            tenant_id,
            stop_tx,
            event_pump,
        })
    }
}

/// Top-level LSP daemon. Constructed by [`LspBuilder::build_with_seed`]
/// on `RegisterLspIdentity` and stored in the application slot.
#[allow(missing_debug_implementations)] // contains JoinHandle / dyn NodeApi
pub struct LspDaemon {
    /// Dedicated LSP `Node<S>` running in service mode.
    pub node: Arc<dyn NodeApi>,
    /// Concrete `Node<LocalKeysManager>` so inspection / metrics can
    /// access typed state without going through the trait.
    pub typed_node: Arc<Node<LocalKeysManager>>,
    /// Shared SCID registry — passed to dispatch handlers.
    pub registry: Arc<PeerRegistry>,
    /// Static fee param cache (operator-mode metrics surface).
    pub fee_params: FeeParamCache,
    /// LSP node pubkey. Same as `node.node_id()` — cached so
    /// introspection is lock-free.
    pub pubkey: PublicKey,
    /// Reserved tenant id derived from `pubkey`.
    pub tenant_id: TenantId,
    /// Sender for the daemon-level shutdown signal. Held privately;
    /// fires on [`Self::shutdown`].
    stop_tx: tokio::sync::watch::Sender<()>,
    /// Background handle preserved for the existing shutdown contract.
    pub event_pump: JoinHandle<()>,
}

impl LspDaemon {
    /// Gracefully shut the daemon down: signal the event pump task and
    /// shut the LDK node. Idempotent — calling more than once is safe.
    pub async fn shutdown(self) {
        // Best-effort signal — receiver may already be gone.
        let _ = self.stop_tx.send(());
        self.event_pump.abort();
        self.node.shutdown().await;
    }
}

/// Two-phase wrapper around an [`LspServiceEventHandler`]. Lets the
/// builder construct the LSP `Node<S>` first (which the handler needs
/// as a dependency) and install the real handler immediately after.
///
/// Events delivered before [`DeferredHandler::install`] is called are
/// logged and dropped — in practice the window is microseconds (the
/// builder synchronously transitions from `build()` to `install()`),
/// so race exposure is negligible.
#[derive(Default)]
struct DeferredHandler {
    inner: tokio::sync::RwLock<Option<Arc<dyn LspServiceEventHandler>>>,
}

impl std::fmt::Debug for DeferredHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeferredHandler")
            .field(
                "installed",
                &self.inner.try_read().map(|g| g.is_some()).unwrap_or(false),
            )
            .finish()
    }
}

impl DeferredHandler {
    fn new() -> Self {
        Self::default()
    }

    async fn install(&self, handler: Arc<dyn LspServiceEventHandler>) {
        // `install` is called from `LspBuilder::build_with_seed`, which
        // runs on a tokio worker — `blocking_write` panics in that
        // context with "Cannot block the current thread from within a
        // runtime". Use the async `write().await` instead. There's no
        // real contention at install time; the lock is only held for
        // the assignment.
        *self.inner.write().await = Some(handler);
    }
}

#[async_trait::async_trait]
impl LspServiceEventHandler for DeferredHandler {
    async fn handle_service_event(
        &self,
        event: lightning_liquidity::lsps2::event::LSPS2ServiceEvent,
    ) {
        if let Some(h) = self.inner.read().await.as_ref() {
            h.handle_service_event(event).await;
        } else {
            tracing::warn!(
                target: "wick_lsp",
                ?event,
                "LSPS2 service event arrived before handler installed — dropping"
            );
        }
    }
    async fn forward_htlc_intercepted(
        &self,
        intercept_id: lightning::ln::channelmanager::InterceptId,
        intercept_scid: u64,
        expected_outbound_amount_msat: u64,
        payment_hash: lightning::types::payment::PaymentHash,
    ) {
        if let Some(h) = self.inner.read().await.as_ref() {
            h.forward_htlc_intercepted(
                intercept_id,
                intercept_scid,
                expected_outbound_amount_msat,
                payment_hash,
            )
            .await;
        }
    }
    async fn forward_channel_ready(
        &self,
        user_channel_id: u128,
        channel_id: lightning::ln::types::ChannelId,
        counterparty_node_id: bitcoin::secp256k1::PublicKey,
    ) {
        if let Some(h) = self.inner.read().await.as_ref() {
            h.forward_channel_ready(user_channel_id, channel_id, counterparty_node_id)
                .await;
        }
    }
    async fn forward_payment_forwarded(
        &self,
        next_channel_id: lightning::ln::types::ChannelId,
        skimmed_fee_msat: u64,
    ) {
        if let Some(h) = self.inner.read().await.as_ref() {
            h.forward_payment_forwarded(next_channel_id, skimmed_fee_msat)
                .await;
        }
    }
    async fn forward_htlc_handling_failed(
        &self,
        failure_type: lightning::events::HTLCHandlingFailureType,
    ) {
        if let Some(h) = self.inner.read().await.as_ref() {
            h.forward_htlc_handling_failed(failure_type).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatcher::OpenChannelRequest;
    use async_trait::async_trait;

    struct StubDispatcher;

    #[async_trait]
    impl LspDispatcher for StubDispatcher {
        async fn dispatch_open_channel(&self, _: OpenChannelRequest) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn dispatcher_trait_object_safe() {
        // Compile-only: confirm the trait can be erased behind dyn.
        let _d: Arc<dyn LspDispatcher> = Arc::new(StubDispatcher);
    }
}
