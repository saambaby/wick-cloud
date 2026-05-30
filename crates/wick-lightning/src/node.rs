//! `Node` — the real, per-tenant Lightning node backed by LDK 0.2.
//!
//! ## Assembly shape
//!
//! - [`Node`] is **generic over the signer** (`S: WickSigner`) because LDK's
//!   [`SignerProvider`] has an associated `EcdsaSigner` type that dynamic
//!   dispatch cannot name. Phase 1 binds `S = LocalKeysManager`; Phase 4
//!   flips to a remote VLS signer.
//! - [`Node`] implements [`crate::NodeApi`] (async, object-safe). The
//!   server's [`NodeActor`] holds a `Box<dyn NodeApi + Send>` so the actor
//!   itself is non-generic and the Phase-4 swap is transparent.
//!
//! ## Background tasks spawned by [`crate::NodeBuilder::build`]
//!
//! - P2P inbound listener (`TcpListener` on `NodeDeps::listen_addr_for`)
//! - SPV chain poll loop (`lightning_block_sync::SpvClient::poll_best_tip`)
//! - Fee estimate poll loop (refreshes `FeeEstimator` from Esplora every 60 s)
//! - LDK `process_events_async` (background persistence + event dispatch)
//! - Peer reconnect loop (every 30 s, replays the persistent [`PeerStore`])
//!
//! Each task watches a shared `watch::Sender<()>` stop signal so
//! [`NodeApi::shutdown`] can drain them deterministically.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use dashmap::DashMap;
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::chain::Filter;
use lightning::ln::channelmanager::{Bolt11InvoiceParameters, ChannelManager, PaymentId, Retry};
use lightning::ln::peer_handler::{IgnoringMessageHandler, PeerManager};
use lightning::ln::types::ChannelId;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::router::{DefaultRouter, RouteParametersConfig};
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters};
use lightning::routing::utxo::UtxoLookup;
use lightning::sign::SignerProvider;
use lightning::util::async_poll::{MaybeSend, MaybeSync};
use lightning::util::config::UserConfig;
use lightning::util::persist::KVStoreSyncWrapper;
use lightning_invoice::{Bolt11InvoiceDescription, Description};
use lightning_liquidity::utils::time::DefaultTimeProvider;
use lightning_liquidity::LiquidityManager;
use lightning_net_tokio::SocketDescriptor;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use wick_core::TenantId;

use crate::api::NodeApi;
use crate::chain::{EsploraBroadcaster, EsploraChainClient, FeeEstimator};
use crate::jit_registry::PendingJitRegistry;
use crate::logger::TracingLogger;
use crate::payment_store::{Direction, PaymentStatus, PaymentStore, PaymentWrite};
use crate::peer_store::{PeerInfo, PeerStore};
use crate::persistence::PgKvStore;
use crate::signer::WickSigner;

// ── Response types ────────────────────────────────────────────────────────────

/// Lightning + on-chain balance snapshot.
#[derive(Debug, Clone, Default)]
pub struct Balance {
    /// Spendable Lightning balance in millisatoshis (outbound capacity).
    pub lightning_balance_msat: u64,
    /// Inbound capacity in millisatoshis (maximum a counterparty can push).
    pub inbound_capacity_msat: u64,
    /// Funds claimable from `ChainMonitor::get_claimable_balances` for
    /// channels not currently active — i.e. closed channels whose outputs
    /// are spendable on-chain (cooperative close + force-close + revoked
    /// counterparty + HTLC timeouts/preimages). Excludes active channels
    /// to avoid double-counting `lightning_balance_msat`.
    pub onchain_balance_sats: u64,
    /// Closed-channel funds awaiting on-chain confirmation
    /// (`Balance::ClaimableAwaitingConfirmations` from LDK).
    pub onchain_unconfirmed_sats: u64,
    /// Sum of inflight outbound HTLC amounts in millisatoshis.
    pub pending_outbound_htlc_msat: u64,
}

/// Outcome of an outbound payment enqueue.
#[derive(Debug, Clone)]
pub struct PaymentResult {
    /// 32-byte payment hash (the BOLT11 hash).
    pub payment_hash: Vec<u8>,
    /// Routing fee paid, in millisatoshis. 0 at enqueue; updated by event handler.
    pub fee_paid_msat: u64,
    /// "pending" at enqueue; event handler advances to "succeeded" or "failed".
    pub status: String,
}

/// A single payment row.
#[derive(Debug, Clone)]
pub struct PaymentRecord {
    /// 32-byte payment hash.
    pub payment_hash: Vec<u8>,
    /// `true` = sent (outbound), `false` = received (inbound).
    pub is_outbound: bool,
    /// Amount in millisatoshis.
    pub amount_msat: u64,
    /// Routing fee in millisatoshis (0 for inbound).
    pub fee_msat: u64,
    /// "pending" | "succeeded" | "failed"
    pub status: String,
    /// Unix seconds.
    pub timestamp: i64,
    /// Optional invoice memo.
    pub memo: Option<String>,
}

/// LSPS2 fee quote returned by [`NodeApi::lsps2_get_info`].
///
/// Tenants surface this through the SDK so users can preview the JIT
/// channel opening fee before committing to an invoice.
#[derive(Debug, Clone)]
pub struct JitQuote {
    /// LSP node id that issued the quote.
    pub lsp_pubkey: PublicKey,
    /// Floor opening fee in millisatoshis.
    pub min_fee_msat: u64,
    /// Proportional fee in parts-per-million of the JIT payment size.
    pub proportional_ppm: u32,
    /// Minimum payment size (msat) the LSP will accept.
    pub min_payment_size_msat: u64,
    /// Maximum payment size (msat) the LSP will accept.
    pub max_payment_size_msat: u64,
    /// Quote expiry as Unix seconds. After this, the SDK must
    /// re-request before issuing an invoice.
    pub valid_until_unix: i64,
}

/// JIT-enabled BOLT11 invoice produced by [`NodeApi::receive_payment_jit`].
#[derive(Debug, Clone)]
pub struct JitInvoice {
    /// BOLT11 invoice string.
    pub bolt11: String,
    /// 32-byte payment hash from the BOLT11.
    pub payment_hash: [u8; 32],
    /// Quoted opening fee (msat) the LSP will deduct from the first
    /// inbound payment. Surfaced for UI display; the LSP enforces it
    /// independently on settlement.
    pub jit_fee_msat_quote: u64,
    /// LSP pubkey carried in the invoice's route hint.
    pub lsp_pubkey: PublicKey,
}

/// A channel summary for [`NodeApi::list_channels`].
#[derive(Debug, Clone)]
pub struct ChannelSummary {
    /// 32-byte channel id.
    pub channel_id: Vec<u8>,
    /// Counterparty Lightning node id.
    pub counterparty: PublicKey,
    /// Total channel capacity in sats.
    pub capacity_sat: u64,
    /// Outbound capacity in millisatoshis (local balance available to send).
    pub outbound_capacity_msat: u64,
    /// Inbound capacity in millisatoshis (remote balance available to receive).
    pub inbound_capacity_msat: u64,
    /// `true` once the funding tx is confirmed and the channel is usable.
    pub is_usable: bool,
    /// `true` while waiting for `channel_ready` (funding confirmations).
    pub is_pending: bool,
}

// ── LDK type aliases ──────────────────────────────────────────────────────────

pub type LnNetworkGraph = NetworkGraph<Arc<TracingLogger>>;

pub type LnScorer = Arc<RwLock<ProbabilisticScorer<Arc<LnNetworkGraph>, Arc<TracingLogger>>>>;

pub type LnChainMonitor<S> = ChainMonitor<
    <S as SignerProvider>::EcdsaSigner,
    Arc<dyn Filter + Send + Sync>,
    Arc<EsploraBroadcaster>,
    Arc<FeeEstimator>,
    Arc<TracingLogger>,
    Arc<PgKvStore>,
    Arc<S>,
>;

pub type LnRouter<S> = DefaultRouter<
    Arc<LnNetworkGraph>,
    Arc<TracingLogger>,
    Arc<S>,
    LnScorer,
    ProbabilisticScoringFeeParameters,
    ProbabilisticScorer<Arc<LnNetworkGraph>, Arc<TracingLogger>>,
>;

pub type LnMessageRouter<S> = lightning::onion_message::messenger::DefaultMessageRouter<
    Arc<LnNetworkGraph>,
    Arc<TracingLogger>,
    Arc<S>,
>;

pub type LnChannelManager<S> = ChannelManager<
    Arc<LnChainMonitor<S>>,
    Arc<EsploraBroadcaster>,
    Arc<S>,
    Arc<S>,
    Arc<S>,
    Arc<FeeEstimator>,
    Arc<LnRouter<S>>,
    Arc<LnMessageRouter<S>>,
    Arc<TracingLogger>,
>;

pub type LnGossipSync =
    P2PGossipSync<Arc<LnNetworkGraph>, Arc<dyn UtxoLookup + Send + Sync>, Arc<TracingLogger>>;

/// Trait-object alias for [`Filter`] passed into [`LiquidityManager`].
///
/// Phase 3 nodes pass `None::<Arc<LiquidityFilter>>` for the chain source —
/// LSPS2 client mode does not need it; LSPS2 service mode does its own
/// chain sourcing through the existing tenant `ChainMonitor`.
pub type LiquidityFilter = dyn Filter + Send + Sync;

/// Concrete instantiation of LDK's [`LiquidityManager`] for Wick nodes.
///
/// Both tenant-side (client config) and LSP-side (service config) Nodes
/// instantiate the same type — the difference is purely in which
/// `client_config` / `service_config` is populated at construction time.
pub type LnLiquidityManager<S> = LiquidityManager<
    Arc<S>,
    Arc<S>,
    Arc<LnChannelManager<S>>,
    Arc<LiquidityFilter>,
    KVStoreSyncWrapper<Arc<PgKvStore>>,
    DefaultTimeProvider,
    Arc<EsploraBroadcaster>,
>;

pub type LnPeerManager<S> = PeerManager<
    SocketDescriptor,
    Arc<LnChannelManager<S>>,
    Arc<LnGossipSync>,
    Arc<IgnoringMessageHandler>,
    Arc<TracingLogger>,
    Arc<LnLiquidityManager<S>>,
    Arc<S>,
    Arc<LnChainMonitor<S>>,
>;

// ── Node ──────────────────────────────────────────────────────────────────────

/// Real, per-tenant Lightning node.
///
/// Constructed by [`crate::NodeBuilder::build`]. All LDK primitives are
/// `Arc`-shared with background tasks.
pub struct Node<S: WickSigner>
where
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    pub(crate) tenant_id: TenantId,
    pub(crate) node_id: PublicKey,
    pub(crate) channel_manager: Arc<LnChannelManager<S>>,
    pub(crate) chain_monitor: Arc<LnChainMonitor<S>>,
    pub(crate) peer_manager: Arc<LnPeerManager<S>>,
    pub(crate) payments: Arc<PaymentStore>,
    pub(crate) peer_store: Arc<PeerStore>,
    // Lifetime anchors — none of these are read by Node's current impl
    // methods, but they must be held here to guarantee the underlying LDK
    // objects outlive the Node even if a background task drops its own Arc
    // clone early (e.g. on panic). They will be promoted to active use when
    // admin/inspection APIs are added (route scoring, graph queries, etc.).
    #[allow(dead_code)]
    pub(crate) signer: Arc<S>,
    #[allow(dead_code)]
    pub(crate) network_graph: Arc<LnNetworkGraph>,
    #[allow(dead_code)]
    pub(crate) gossip_sync: Arc<LnGossipSync>,
    #[allow(dead_code)]
    pub(crate) scorer: LnScorer,
    #[allow(dead_code)]
    pub(crate) broadcaster: Arc<EsploraBroadcaster>,
    #[allow(dead_code)]
    pub(crate) fee_estimator: Arc<FeeEstimator>,
    #[allow(dead_code)]
    pub(crate) logger: Arc<TracingLogger>,
    #[allow(dead_code)]
    pub(crate) chain: Arc<EsploraChainClient>,
    #[allow(dead_code)]
    pub(crate) kv_store: Arc<PgKvStore>,
    /// Actual port bound by the P2P listener (`None` until `start()` binds).
    pub(crate) listen_addr: RwLock<Option<std::net::SocketAddr>>,
    /// Shared stop signal for every background task this node spawns.
    pub(crate) stop_tx: watch::Sender<()>,
    pub(crate) runtime_started: AtomicBool,
    pub(crate) stopped: AtomicBool,
    pub(crate) bg_handles: Mutex<Vec<JoinHandle<()>>>,
    /// `payment_hash → sent_at_ms` — inserted by `send_payment`, consumed by
    /// the event handler on `PaymentSent` for latency metrics.
    pub(crate) pending_sent_at: Arc<DashMap<[u8; 32], u64>>,
    /// Parks `FundingGenerationReady` events for the self-custodial
    /// two-phase channel-open flow. Populated by the event handler;
    /// drained by [`NodeApi::open_channel_init`](crate::api::NodeApi::open_channel_init).
    pub(crate) funding_registry: Arc<crate::funding_registry::PendingFundingRegistry>,
    /// LDK [`LiquidityManager`] — wired as the `PeerManager`'s
    /// `CustomMessageHandler`. Held as an `Arc` so the event-pump
    /// background task and the [`NodeApi::receive_payment_jit`]
    /// gRPC-facing path can both reach the LSPS2 client handler.
    pub(crate) liquidity_manager: Arc<LnLiquidityManager<S>>,
    /// LSP peer pubkey used by [`NodeApi::receive_payment_jit`] when
    /// negotiating LSPS2 `get_info` / `buy`. `None` disables JIT for
    /// this node — `receive_payment_jit` returns an error if invoked.
    /// On tenant nodes this is set from `[lsp].listen_addr` of the
    /// in-process LSP; on the LSP node itself it is `None`.
    pub(crate) lsp_peer: Option<PublicKey>,
    /// Parks `LSPS2ClientEvent` responses awaiting a matching
    /// `request_id`. Mirrors [`PendingFundingRegistry`]: oneshot-per-key
    /// so there is no race between the event-pump task writing a
    /// response and the gRPC-facing future awaiting it.
    pub(crate) jit_registry: Arc<PendingJitRegistry>,
}

impl<S> std::fmt::Debug for Node<S>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("tenant_id", &self.tenant_id)
            .field("node_id", &self.node_id)
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl<S> Node<S>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    /// Tenant this node belongs to.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// `true` between `NodeBuilder::build` completing successfully and
    /// `shutdown()` being called.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.runtime_started.load(Ordering::Acquire) && !self.stopped.load(Ordering::Acquire)
    }

    /// Local listen address (populated by the builder after `TcpListener::bind`).
    #[must_use]
    pub fn local_listen_addr(&self) -> Option<std::net::SocketAddr> {
        self.listen_addr.read().ok().and_then(|g| *g)
    }

    /// Shared `Arc` to the inner [`LnLiquidityManager`]. Required by
    /// `wick-lsp`'s operator handler so it can call `lsps2_service_handler`
    /// methods (`opening_fee_params_generated`, `invoice_parameters_generated`,
    /// `htlc_intercepted`, `channel_ready`, `payment_forwarded`).
    #[must_use]
    pub fn liquidity_manager_arc(&self) -> Arc<LnLiquidityManager<S>> {
        self.liquidity_manager.clone()
    }

    /// Allocate a fresh intercept SCID for an LSPS2 buy response.
    /// Wraps `ChannelManager::get_intercept_scid()`.
    #[must_use]
    pub fn channel_manager_get_intercept_scid(&self) -> u64 {
        self.channel_manager.get_intercept_scid()
    }

    /// Fail an intercepted HTLC back upstream. Wraps
    /// `ChannelManager::fail_intercepted_htlc`. LDK 0.2 returns
    /// `unknown_next_peer` semantics regardless of caller intent — the
    /// LSP signals "no JIT channel exists for this SCID" and the payer
    /// retries via a different route.
    pub fn channel_manager_fail_intercepted_htlc(
        &self,
        intercept_id: lightning::ln::channelmanager::InterceptId,
    ) -> anyhow::Result<()> {
        self.channel_manager
            .fail_intercepted_htlc(intercept_id)
            .map_err(|e| anyhow::anyhow!("fail_intercepted_htlc: {e:?}"))
    }

    /// Create a JIT channel to `peer` for the LSPS2 service flow.
    /// Wraps `ChannelManager::create_channel(...)` with the LSP's
    /// `user_channel_id`. Channel config is left as default (Phase 3
    /// runs trusted-non-0conf channels; 0-conf is slice 3.3 work).
    pub fn channel_manager_create_jit_channel(
        &self,
        peer: PublicKey,
        channel_value_sat: u64,
        user_channel_id: u128,
    ) -> anyhow::Result<()> {
        // Stage `push_msat = 0` on the signer so VLS-backed signers see
        // the right `SetupChannel.push_value` when LDK calls
        // `generate_channel_keys_id(inbound=false, user_channel_id)`.
        // No-op for `KeysManager`-backed signers.
        self.signer
            .register_outbound_channel_open(user_channel_id, 0);
        let result = self
            .channel_manager
            .create_channel(
                peer,
                channel_value_sat,
                0,
                user_channel_id,
                None,
                Some(zero_counterparty_reserve_user_config()),
            )
            .map_err(|e| anyhow::anyhow!("create_channel: {e:?}"));
        if result.is_err() {
            self.signer.clear_outbound_channel_open(user_channel_id);
        }
        result?;
        Ok(())
    }

    /// Subscribe to newly-parked entries on this node's funding
    /// registry. Used by the LSP admin `LspWatchPendingFunding` RPC to
    /// stream parked funding requests to the operator's SDK for
    /// self-custodial signing.
    #[must_use]
    pub fn funding_registry_subscribe(
        &self,
    ) -> tokio::sync::broadcast::Receiver<(
        lightning::ln::types::ChannelId,
        crate::funding_registry::PendingFunding,
    )> {
        self.funding_registry.subscribe()
    }

    /// Snapshot of currently-parked funding requests on this node. Used
    /// by the LSP admin watch RPC to bootstrap the operator's stream
    /// at subscribe time before live broadcast events arrive.
    #[must_use]
    pub fn funding_registry_snapshot(
        &self,
    ) -> Vec<(
        lightning::ln::types::ChannelId,
        crate::funding_registry::PendingFunding,
    )> {
        self.funding_registry.snapshot()
    }

    /// Drain the parked funding entry for `temp_id` without waiting.
    /// Returns `None` if the entry was never parked or has already
    /// been taken. Used by the LSP admin `LspFinalizeFunding` RPC right
    /// before calling `funding_transaction_generated`.
    pub fn funding_registry_try_take(
        &self,
        temp_id: lightning::ln::types::ChannelId,
    ) -> Option<crate::funding_registry::PendingFunding> {
        self.funding_registry.try_take(temp_id)
    }
}

// ── NodeApi impl ─────────────────────────────────────────────────────────────

#[async_trait]
impl<S> NodeApi for Node<S>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    async fn get_balance(&self) -> anyhow::Result<Balance> {
        let channels = self.channel_manager.list_channels();
        let lightning_balance_msat: u64 = channels.iter().map(|c| c.outbound_capacity_msat).sum();
        let inbound_capacity_msat: u64 = channels.iter().map(|c| c.inbound_capacity_msat).sum();
        let pending_outbound_htlc_msat: u64 = channels
            .iter()
            .flat_map(|c| c.pending_outbound_htlcs.iter())
            .map(|h| h.amount_msat)
            .sum();

        // On-chain balance = sums of `ChainMonitor::get_claimable_balances`
        // EXCLUDING active channels (whose `ClaimableOnChannelClose` would
        // double-count `lightning_balance_msat`). Funds in
        // `ClaimableAwaitingConfirmations` are reported as unconfirmed; every
        // other claimable variant maps to confirmed.
        let active_refs: Vec<&_> = channels.iter().collect();
        let claimable = self.chain_monitor.get_claimable_balances(&active_refs);
        let (mut confirmed_sat, mut unconfirmed_sat) = (0u64, 0u64);
        for bal in claimable {
            let amt = bal.claimable_amount_satoshis();
            if matches!(
                bal,
                lightning::chain::channelmonitor::Balance::ClaimableAwaitingConfirmations { .. }
            ) {
                unconfirmed_sat = unconfirmed_sat.saturating_add(amt);
            } else {
                confirmed_sat = confirmed_sat.saturating_add(amt);
            }
        }

        Ok(Balance {
            lightning_balance_msat,
            inbound_capacity_msat,
            pending_outbound_htlc_msat,
            onchain_balance_sats: confirmed_sat,
            onchain_unconfirmed_sats: unconfirmed_sat,
        })
    }

    async fn send_payment(&self, bolt11: &str) -> anyhow::Result<PaymentResult> {
        let invoice: lightning_invoice::Bolt11Invoice = bolt11
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid bolt11: {e}"))?;
        let hash_bytes = *invoice.payment_hash().as_ref();
        let payment_id = PaymentId(hash_bytes);
        let route_params = RouteParametersConfig {
            max_total_cltv_expiry_delta: 12_000,
            ..Default::default()
        };

        // Pre-register the invoice with the signer's policy engine before LDK
        // adds the outbound HTLC. VLS validates that every offered HTLC is
        // backed by either a matching incoming HTLC (forwarding) or a
        // preapproved invoice (originating); without this the device rejects
        // the holder's own payment commitment with `policy-routing-balanced:
        // unbalanced payments`. No-op for KeysManager-backed signers.
        self.signer
            .preapprove_invoice(bolt11)
            .map_err(|e| anyhow::anyhow!("VLS preapprove_invoice: {e}"))?;

        self.channel_manager
            .pay_for_bolt11_invoice(
                &invoice,
                payment_id,
                None,
                route_params,
                Retry::Timeout(Duration::from_secs(60)),
            )
            .map_err(|e| anyhow::anyhow!("pay_for_bolt11_invoice: {e:?}"))?;

        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        self.pending_sent_at.insert(hash_bytes, now_ms);

        let amount_msat = invoice.amount_milli_satoshis().unwrap_or(0);
        let write = PaymentWrite {
            payment_hash: &hash_bytes,
            preimage: None,
            direction: Direction::Outbound,
            amount_msat,
            // Fee is unknown at send time — LDK hasn't selected a route yet.
            // The actual fee is written by the PaymentSent event handler once
            // the HTLC settles (event.rs PaymentSent arm, fee_paid_msat field).
            fee_msat: 0,
            status: PaymentStatus::Pending,
        };
        if let Err(e) = self.payments.upsert(write).await {
            tracing::warn!(
                target: "wick_lightning",
                tenant = %self.tenant_id,
                hash = %hex::encode(hash_bytes),
                error = %e,
                "send_payment: pending upsert failed (non-fatal)"
            );
        }

        Ok(PaymentResult {
            payment_hash: hash_bytes.to_vec(),
            // Fee is unknown until the payment settles. The caller should treat
            // this as a pending result and poll get_transactions for the final
            // fee once status transitions to "succeeded".
            fee_paid_msat: 0,
            status: "pending".to_owned(),
        })
    }

    async fn receive_payment(
        &self,
        amount_msat: Option<u64>,
        memo: &str,
    ) -> anyhow::Result<(String, Vec<u8>)> {
        const MIN_FINAL_CLTV_DEV: u16 = 72;
        let description =
            Description::new(memo.to_owned()).unwrap_or_else(|_| Description::empty());
        let params = Bolt11InvoiceParameters {
            amount_msats: amount_msat,
            description: Bolt11InvoiceDescription::Direct(description),
            invoice_expiry_delta_secs: Some(3600),
            min_final_cltv_expiry_delta: Some(MIN_FINAL_CLTV_DEV),
            ..Default::default()
        };
        let invoice = self
            .channel_manager
            .create_bolt11_invoice(params)
            .map_err(|e| anyhow::anyhow!("create_bolt11_invoice: {e:?}"))?;
        let hash_bytes: [u8; 32] = *invoice.payment_hash().as_ref();
        Ok((invoice.to_string(), hash_bytes.to_vec()))
    }

    async fn get_transactions(&self, limit: u32) -> anyhow::Result<Vec<PaymentRecord>> {
        Ok(self.payments.list(limit).await?)
    }

    async fn lsps2_get_info(&self, amount_msat: Option<u64>) -> anyhow::Result<JitQuote> {
        const TIMEOUT: Duration = Duration::from_secs(15);

        let lsp = self
            .lsp_peer
            .ok_or_else(|| anyhow::anyhow!("no LSP peer configured for this node"))?;
        let client = self
            .liquidity_manager
            .lsps2_client_handler()
            .ok_or_else(|| anyhow::anyhow!("LSPS2 client handler not enabled"))?;

        // The token field is reserved for operator-defined coupons / API keys;
        // we don't use it.
        let req_id = client.request_opening_params(lsp, None);
        let resp = self
            .jit_registry
            .take(req_id, TIMEOUT)
            .await
            .ok_or_else(|| anyhow::anyhow!("LSPS2 get_info timed out after {TIMEOUT:?}"))?;

        let menu = match resp {
            crate::jit_registry::JitResponse::OpeningParameters {
                opening_fee_params_menu,
                ..
            } => opening_fee_params_menu,
            crate::jit_registry::JitResponse::GetInfoFailed { message, .. } => {
                anyhow::bail!("LSPS2 get_info rejected: {message}");
            }
            other => anyhow::bail!("unexpected LSPS2 response shape: {other:?}"),
        };

        let chosen = pick_cheapest_fee_params(&menu, amount_msat).ok_or_else(|| {
            anyhow::anyhow!(
                "LSP returned no fee params matching the requested payment size {amount_msat:?}"
            )
        })?;

        Ok(JitQuote {
            lsp_pubkey: lsp,
            min_fee_msat: chosen.min_fee_msat,
            proportional_ppm: chosen.proportional,
            min_payment_size_msat: chosen.min_payment_size_msat,
            max_payment_size_msat: chosen.max_payment_size_msat,
            valid_until_unix: chosen.valid_until.0.timestamp(),
        })
    }

    async fn receive_payment_jit(
        &self,
        amount_msat: u64,
        memo: &str,
    ) -> anyhow::Result<JitInvoice> {
        const TIMEOUT: Duration = Duration::from_secs(15);

        if amount_msat == 0 {
            anyhow::bail!("receive_payment_jit requires amount_msat > 0");
        }

        let lsp = self
            .lsp_peer
            .ok_or_else(|| anyhow::anyhow!("no LSP peer configured for this node"))?;
        let client = self
            .liquidity_manager
            .lsps2_client_handler()
            .ok_or_else(|| anyhow::anyhow!("LSPS2 client handler not enabled"))?;

        // Step 1 — negotiate `get_info` to learn the fee menu.
        let info_id = client.request_opening_params(lsp, None);
        let info_resp = self
            .jit_registry
            .take(info_id, TIMEOUT)
            .await
            .ok_or_else(|| anyhow::anyhow!("LSPS2 get_info timed out after {TIMEOUT:?}"))?;
        let menu = match info_resp {
            crate::jit_registry::JitResponse::OpeningParameters {
                opening_fee_params_menu,
                ..
            } => opening_fee_params_menu,
            crate::jit_registry::JitResponse::GetInfoFailed { message, .. } => {
                anyhow::bail!("LSPS2 get_info rejected: {message}");
            }
            other => anyhow::bail!("unexpected get_info response: {other:?}"),
        };
        let chosen = pick_cheapest_fee_params(&menu, Some(amount_msat)).ok_or_else(|| {
            anyhow::anyhow!(
                "LSP returned no fee params matching the requested payment size {amount_msat}"
            )
        })?;
        let opening_fee_msat = compute_opening_fee_msat(amount_msat, &chosen);

        // Step 2 — `select_opening_params` to commit to the chosen menu
        // entry and learn the intercept SCID.
        let buy_id = client
            .select_opening_params(lsp, Some(amount_msat), chosen.clone())
            .map_err(|e| anyhow::anyhow!("LSPS2 select_opening_params: {e:?}"))?;
        let buy_resp = self
            .jit_registry
            .take(buy_id, TIMEOUT)
            .await
            .ok_or_else(|| anyhow::anyhow!("LSPS2 buy timed out after {TIMEOUT:?}"))?;
        let (intercept_scid, cltv_expiry_delta) = match buy_resp {
            crate::jit_registry::JitResponse::InvoiceParameters {
                intercept_scid,
                cltv_expiry_delta,
                ..
            } => (intercept_scid, cltv_expiry_delta),
            crate::jit_registry::JitResponse::BuyFailed { message, .. } => {
                anyhow::bail!("LSPS2 buy rejected: {message}");
            }
            other => anyhow::bail!("unexpected buy response: {other:?}"),
        };

        // Step 3 — build the BOLT11 by hand so we can inject the LSP's
        // intercept SCID as a private route hint. ChannelManager's
        // `create_bolt11_invoice` only emits hints for *real* channels;
        // for JIT we don't have one yet.
        build_jit_bolt11_invoice(
            self,
            lsp,
            intercept_scid,
            cltv_expiry_delta,
            amount_msat,
            memo,
            opening_fee_msat,
        )
    }

    fn node_id(&self) -> PublicKey {
        self.node_id
    }

    fn local_listen_addr(&self) -> Option<std::net::SocketAddr> {
        self.listen_addr.read().ok().and_then(|g| *g)
    }

    async fn connect_peer(&self, node_id: PublicKey, host: &str, port: u16) -> anyhow::Result<()> {
        if !self.is_running() {
            anyhow::bail!("node is not running");
        }
        let addr: std::net::SocketAddr = format!("{host}:{port}").parse()?;
        tracing::info!(
            target: "wick_lightning::connect_peer",
            tenant = %self.tenant_id,
            %node_id,
            %addr,
            "→ connect_outbound"
        );
        // `connect_outbound` returns `Option<impl Future>`; the outer Option
        // reports connect success, the inner future resolves on disconnect.
        // We drop it — we only want the handshake to complete.
        let setup =
            lightning_net_tokio::connect_outbound(self.peer_manager.clone(), node_id, addr).await;
        match setup {
            None => anyhow::bail!("connect_outbound to {node_id} at {addr} failed"),
            Some(fut) => drop(fut),
        }
        tracing::info!(
            target: "wick_lightning::connect_peer",
            tenant = %self.tenant_id,
            %node_id,
            "✓ connect_outbound returned; polling list_peers"
        );

        // Wait for the handshake to register in peer_manager.list_peers().
        let mut poll_n: u32 = 0;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let peers: Vec<_> = self
                    .peer_manager
                    .list_peers()
                    .into_iter()
                    .map(|p| p.counterparty_node_id)
                    .collect();
                if peers.iter().any(|p| *p == node_id) {
                    break;
                }
                if poll_n % 20 == 0 {
                    tracing::info!(
                        target: "wick_lightning::connect_peer",
                        tenant = %self.tenant_id,
                        target_peer = %node_id,
                        poll_n,
                        observed = ?peers.iter().map(|p| hex::encode(p.serialize())).collect::<Vec<_>>(),
                        "polling list_peers"
                    );
                }
                poll_n += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("timeout waiting for handshake with {node_id}"))?;

        // Persist for reconnect on restart.
        self.peer_store
            .upsert(&PeerInfo {
                node_id,
                address: addr,
            })
            .await?;

        Ok(())
    }

    async fn open_channel(
        &self,
        peer_id: PublicKey,
        channel_value_sat: u64,
        push_msat: u64,
    ) -> anyhow::Result<()> {
        if !self.is_running() {
            anyhow::bail!("node is not running");
        }
        // Stage `push_msat` on the signer (no-op for `KeysManager`,
        // real for `SignerSession` — feeds VLS's `SetupChannel.push_value`).
        let user_channel_id: u128 = rand::random();
        self.signer
            .register_outbound_channel_open(user_channel_id, push_msat);
        let result = self
            .channel_manager
            .create_channel(
                peer_id,
                channel_value_sat,
                push_msat,
                user_channel_id,
                None,
                Some(zero_counterparty_reserve_user_config()),
            )
            .map_err(|e| anyhow::anyhow!("create_channel: {e:?}"));
        if result.is_err() {
            self.signer.clear_outbound_channel_open(user_channel_id);
        }
        result?;
        Ok(())
    }

    async fn open_channel_init(
        &self,
        peer_id: PublicKey,
        channel_value_sat: u64,
        push_msat: u64,
        timeout: std::time::Duration,
    ) -> anyhow::Result<(ChannelId, crate::PendingFunding)> {
        if !self.is_running() {
            anyhow::bail!("node is not running");
        }

        // Stage `push_msat` against a fresh `user_channel_id` so VLS-backed
        // signers populate `SetupChannel.push_value` correctly. The same id
        // is passed to `create_channel` so LDK's `generate_channel_keys_id`
        // call (which drains the staging) sees a matching key.
        let user_channel_id: u128 = rand::random();
        self.signer
            .register_outbound_channel_open(user_channel_id, push_msat);

        // `create_channel` returns the temporary_channel_id LDK will use in
        // the later FundingGenerationReady event, so we know which key to
        // poll for in the registry.
        let t_create = std::time::Instant::now();
        tracing::info!(
            target: "wick_lightning::open_channel",
            value_sat = channel_value_sat,
            push_msat,
            user_channel_id,
            "→ ChannelManager::create_channel"
        );
        let temp_id = match self.channel_manager.create_channel(
            peer_id,
            channel_value_sat,
            push_msat,
            user_channel_id,
            None,
            Some(zero_counterparty_reserve_user_config()),
        ) {
            Ok(id) => id,
            Err(e) => {
                self.signer.clear_outbound_channel_open(user_channel_id);
                anyhow::bail!("create_channel: {e:?}");
            }
        };
        tracing::info!(
            target: "wick_lightning::open_channel",
            elapsed_ms = t_create.elapsed().as_millis() as u64,
            ?temp_id,
            "✓ ChannelManager::create_channel returned; awaiting FundingGenerationReady"
        );

        // FundingGenerationReady fires asynchronously after the peer accepts
        // the open_channel message. `take` polls the registry (which the
        // event handler writes into) up to `timeout`.
        let t_take = std::time::Instant::now();
        let pending = match self.funding_registry.take(temp_id, timeout).await {
            Some(p) => {
                tracing::info!(
                    target: "wick_lightning::open_channel",
                    elapsed_ms = t_take.elapsed().as_millis() as u64,
                    ?temp_id,
                    "✓ funding_registry.take returned PendingFunding"
                );
                p
            }
            None => {
                tracing::warn!(
                    target: "wick_lightning::open_channel",
                    elapsed_ms = t_take.elapsed().as_millis() as u64,
                    ?temp_id,
                    "✗ funding_registry.take timed out"
                );
                self.signer.clear_outbound_channel_open(user_channel_id);
                anyhow::bail!(
                    "timed out waiting for FundingGenerationReady for temp_id {temp_id:?}"
                );
            }
        };
        Ok((temp_id, pending))
    }

    async fn open_channel_finalize(
        &self,
        temp_channel_id: &ChannelId,
        counterparty: &PublicKey,
        funding_tx: bitcoin::Transaction,
    ) -> anyhow::Result<()> {
        if !self.is_running() {
            anyhow::bail!("node is not running");
        }
        self.channel_manager
            .funding_transaction_generated(*temp_channel_id, *counterparty, funding_tx)
            .map_err(|e| anyhow::anyhow!("funding_transaction_generated: {e:?}"))?;
        Ok(())
    }

    async fn close_channel(
        &self,
        channel_id: &ChannelId,
        counterparty: &PublicKey,
        force: bool,
    ) -> anyhow::Result<()> {
        if !self.is_running() {
            anyhow::bail!("node is not running");
        }
        if force {
            self.channel_manager
                .force_close_broadcasting_latest_txn(
                    channel_id,
                    counterparty,
                    "wick force_close".to_string(),
                )
                .map_err(|e| anyhow::anyhow!("force_close_broadcasting_latest_txn: {e:?}"))?;
        } else {
            self.channel_manager
                .close_channel(channel_id, counterparty)
                .map_err(|e| anyhow::anyhow!("close_channel: {e:?}"))?;
        }
        Ok(())
    }

    async fn list_channels(&self) -> anyhow::Result<Vec<ChannelSummary>> {
        Ok(self
            .channel_manager
            .list_channels()
            .into_iter()
            .map(|c| ChannelSummary {
                channel_id: c.channel_id.0.to_vec(),
                counterparty: c.counterparty.node_id,
                capacity_sat: c.channel_value_satoshis,
                outbound_capacity_msat: c.outbound_capacity_msat,
                inbound_capacity_msat: c.inbound_capacity_msat,
                is_usable: c.is_usable,
                is_pending: !c.is_channel_ready,
            })
            .collect())
    }

    async fn has_pending_htlcs(&self) -> anyhow::Result<bool> {
        Ok(self
            .channel_manager
            .list_channels()
            .iter()
            .any(|c| !c.pending_outbound_htlcs.is_empty() || !c.pending_inbound_htlcs.is_empty()))
    }

    async fn has_inflight_outbound(&self) -> anyhow::Result<bool> {
        Ok(self.payments.has_inflight_outbound().await?)
    }

    async fn has_unresolved_monitor_events(&self) -> anyhow::Result<bool> {
        // `list_pending_monitor_updates` returns channels with persisted
        // updates not yet acknowledged by the channel manager. Non-empty ⇒
        // the BackgroundProcessor has work to finish before park is safe.
        Ok(self
            .chain_monitor
            .list_pending_monitor_updates()
            .iter()
            .any(|(_, updates)| !updates.is_empty()))
    }

    async fn shutdown(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.stop_tx.send(());
        let handles = {
            let mut g = match self.bg_handles.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            std::mem::take(&mut *g)
        };
        for h in handles {
            if let Err(e) = tokio::time::timeout(Duration::from_secs(10), h).await {
                tracing::warn!(
                    target: "wick_lightning",
                    tenant = %self.tenant_id,
                    error = %e,
                    "shutdown: background task did not exit within 10s"
                );
            }
        }
    }
}

// ── JIT helpers ───────────────────────────────────────────────────────────────

/// Pick the cheapest viable [`LSPS2OpeningFeeParams`] from the menu the
/// LSP returned, applying the payment-size constraint when known.
fn pick_cheapest_fee_params(
    menu: &[lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams],
    amount_msat: Option<u64>,
) -> Option<lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams> {
    menu.iter()
        .filter(|p| match amount_msat {
            Some(a) => a >= p.min_payment_size_msat && a <= p.max_payment_size_msat,
            None => true,
        })
        .min_by_key(|p| p.min_fee_msat)
        .cloned()
}

/// Compute the JIT opening fee per LSPS2 §"client agrees to paying":
/// `max(min_fee_msat, proportional * (payment_size_msat / 1_000_000))`.
fn compute_opening_fee_msat(
    payment_size_msat: u64,
    params: &lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams,
) -> u64 {
    let proportional =
        (u128::from(params.proportional) * u128::from(payment_size_msat)) / 1_000_000u128;
    let proportional = u64::try_from(proportional).unwrap_or(u64::MAX);
    proportional.max(params.min_fee_msat)
}

/// Build + sign a JIT-enabled BOLT11 invoice with a private route hint
/// pointing at the LSP's intercept SCID.
///
/// Mirrors `ChannelManager::create_bolt11_invoice` (channelmanager.rs
/// L12543) but replaces auto-discovered channel hints with our single
/// LSP intercept hint — we have no real channel yet at invoice time.
fn build_jit_bolt11_invoice<S>(
    node: &Node<S>,
    lsp_pubkey: PublicKey,
    intercept_scid: u64,
    cltv_expiry_delta: u32,
    amount_msat: u64,
    memo: &str,
    opening_fee_msat: u64,
) -> anyhow::Result<JitInvoice>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    use bitcoin::hashes::sha256::Hash as Sha256Hash;
    use bitcoin::hashes::Hash;
    use lightning::ln::msgs::ChannelMessageHandler;
    use lightning::routing::gossip::RoutingFees;
    use lightning::routing::router::{RouteHint, RouteHintHop};
    use lightning::sign::{NodeSigner, Recipient};
    use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder};

    // The receiver never pays the LSP a forwarding fee on a JIT hop —
    // the opening_fee is deducted from the payment_size directly. Use
    // (0, 0) to keep the route-hint hop fee-free. `htlc_maximum_msat`
    // is `None` so MPP routing is not artificially capped; the LSP's
    // own size bounds (in `LSPS2OpeningFeeParams`) gate validity.
    let route_hint = RouteHint(vec![RouteHintHop {
        src_node_id: lsp_pubkey,
        short_channel_id: intercept_scid,
        fees: RoutingFees {
            base_msat: 0,
            proportional_millionths: 0,
        },
        cltv_expiry_delta: u16::try_from(cltv_expiry_delta).unwrap_or(u16::MAX),
        htlc_minimum_msat: None,
        htlc_maximum_msat: None,
    }]);

    // LSPS2 requires `min_final_cltv_expiry_delta` to be at least
    // 2 more than the LDK default — the LSP needs that headroom to
    // open the channel and forward the HTLC before the final hop's
    // CLTV elapses. See ldk-node `liquidity.rs::lsps2_create_jit_invoice`.
    let min_final_cltv = lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA + 2;

    let (payment_hash, payment_secret) = node
        .channel_manager
        .create_inbound_payment(Some(amount_msat), 3600, Some(min_final_cltv))
        .map_err(|()| anyhow::anyhow!("create_inbound_payment failed (invalid amount?)"))?;

    // `get_chain_hashes` returns Option<Vec<ChainHash>>: None for nodes
    // built without `ChainParameters` (LDK has no opinion); Some when
    // configured. Wick always builds with chain params, so unwrap is
    // safe. We use the first hash for currency selection.
    let chain_hash = node
        .channel_manager
        .get_chain_hashes()
        .and_then(|v| v.into_iter().next())
        .ok_or_else(|| anyhow::anyhow!("ChannelManager has no chain hash"))?;
    let network = if chain_hash == bitcoin::Network::Bitcoin.chain_hash() {
        Currency::Bitcoin
    } else if chain_hash == bitcoin::Network::Testnet.chain_hash() {
        Currency::BitcoinTestnet
    } else if chain_hash == bitcoin::Network::Signet.chain_hash() {
        Currency::Signet
    } else if chain_hash == bitcoin::Network::Regtest.chain_hash() {
        Currency::Regtest
    } else {
        Currency::Bitcoin
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system time before epoch: {e}"))?;

    let raw = InvoiceBuilder::new(network)
        .description(memo.to_owned())
        .duration_since_epoch(now)
        .payee_pub_key(node.channel_manager.get_our_node_id())
        .payment_hash(Sha256Hash::from_slice(&payment_hash.0).unwrap())
        .payment_secret(payment_secret)
        .basic_mpp()
        .min_final_cltv_expiry_delta(u64::from(min_final_cltv))
        .expiry_time(Duration::from_secs(3600))
        .amount_milli_satoshis(amount_msat)
        .private_route(route_hint)
        .build_raw()
        .map_err(|e| anyhow::anyhow!("InvoiceBuilder::build_raw: {e:?}"))?;

    let signer = node.signer.clone();
    let signature = NodeSigner::sign_invoice(signer.as_ref(), &raw, Recipient::Node)
        .map_err(|()| anyhow::anyhow!("NodeSigner::sign_invoice failed"))?;

    let signed = raw
        .sign::<_, ()>(|_| Ok(signature))
        .map_err(|e| anyhow::anyhow!("raw_invoice.sign: {e:?}"))?;
    let invoice = Bolt11Invoice::from_signed(signed)
        .map_err(|e| anyhow::anyhow!("Bolt11Invoice::from_signed: {e:?}"))?;

    Ok(JitInvoice {
        bolt11: invoice.to_string(),
        payment_hash: payment_hash.0,
        jit_fee_msat_quote: opening_fee_msat,
        lsp_pubkey,
    })
}

/// Per-channel `UserConfig` override used on every wick-initiated
/// `ChannelManager::create_channel` call.
///
/// Forces `their_channel_reserve_proportional_millionths = 0` so the
/// counterparty has no reserve carved out of the initial commitment. This
/// is what allows VLS's `SimpleValidator` to accept the funder's first
/// `sign_counterparty_commitment` — that policy enforces
/// `to_remote ≤ push_value_msat` on the initial commitment, and any
/// non-zero counterparty reserve appears as `to_remote > 0` even when
/// `push_msat = 0`.
///
/// Trade-off: the counterparty can spend a wick channel down to zero on
/// their side; the standard "reserve = small economic disincentive" stops
/// applying. Justice transactions and the broader force-close path are
/// unaffected. Self-custodial validation by VLS is more important here
/// than the ~1% economic cushion.
fn zero_counterparty_reserve_user_config() -> UserConfig {
    let mut cfg = UserConfig::default();
    cfg.channel_handshake_config
        .their_channel_reserve_proportional_millionths = 0;
    cfg
}
