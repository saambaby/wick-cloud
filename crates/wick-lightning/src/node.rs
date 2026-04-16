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
use lightning_block_sync::poll::ValidatedBlockHeader;
use lightning_invoice::{Bolt11InvoiceDescription, Description};
use lightning_net_tokio::SocketDescriptor;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use wick_core::TenantId;

use crate::api::NodeApi;
use crate::chain::{EsploraBroadcaster, EsploraChainClient, FeeEstimator};
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
    /// Confirmed on-chain balance in satoshis. Phase-1: always 0 (queried
    /// from Esplora by the testkit wallet, not by the Lightning node).
    pub onchain_balance_sats: u64,
    /// Unconfirmed on-chain balance in satoshis.
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

pub type LnPeerManager<S> = PeerManager<
    SocketDescriptor,
    Arc<LnChannelManager<S>>,
    Arc<LnGossipSync>,
    Arc<IgnoringMessageHandler>,
    Arc<TracingLogger>,
    Arc<IgnoringMessageHandler>,
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
    pub(crate) signer: Arc<S>,
    pub(crate) channel_manager: Arc<LnChannelManager<S>>,
    pub(crate) chain_monitor: Arc<LnChainMonitor<S>>,
    pub(crate) peer_manager: Arc<LnPeerManager<S>>,
    pub(crate) network_graph: Arc<LnNetworkGraph>,
    pub(crate) gossip_sync: Arc<LnGossipSync>,
    pub(crate) scorer: LnScorer,
    pub(crate) payments: Arc<PaymentStore>,
    pub(crate) peer_store: Arc<PeerStore>,
    pub(crate) broadcaster: Arc<EsploraBroadcaster>,
    pub(crate) fee_estimator: Arc<FeeEstimator>,
    pub(crate) logger: Arc<TracingLogger>,
    pub(crate) chain: Arc<EsploraChainClient>,
    pub(crate) kv_store: Arc<PgKvStore>,
    /// Last validated block header at construction time — used as the SPV
    /// poller's anchor.
    pub(crate) best_block_header: ValidatedBlockHeader,
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
        Ok(Balance {
            lightning_balance_msat,
            inbound_capacity_msat,
            pending_outbound_htlc_msat,
            onchain_balance_sats: 0,
            onchain_unconfirmed_sats: 0,
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
            fee_paid_msat: 0,
            status: "pending".to_owned(),
        })
    }

    async fn receive_payment(
        &self,
        amount_msat: Option<u64>,
        memo: &str,
    ) -> anyhow::Result<String> {
        const MIN_FINAL_CLTV_DEV: u16 = 72;
        let description = Description::new(memo.to_owned()).unwrap_or_else(|_| Description::empty());
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
        Ok(invoice.to_string())
    }

    async fn get_transactions(&self, limit: u32) -> anyhow::Result<Vec<PaymentRecord>> {
        Ok(self.payments.list(limit).await?)
    }

    fn node_id(&self) -> PublicKey {
        self.node_id
    }

    fn local_listen_addr(&self) -> Option<std::net::SocketAddr> {
        self.listen_addr.read().ok().and_then(|g| *g)
    }

    async fn connect_peer(
        &self,
        node_id: PublicKey,
        host: &str,
        port: u16,
    ) -> anyhow::Result<()> {
        if !self.is_running() {
            anyhow::bail!("node is not running");
        }
        let addr: std::net::SocketAddr = format!("{host}:{port}").parse()?;
        // `connect_outbound` returns `Option<impl Future>`; the outer Option
        // reports connect success, the inner future resolves on disconnect.
        // We drop it — we only want the handshake to complete.
        let setup =
            lightning_net_tokio::connect_outbound(self.peer_manager.clone(), node_id, addr).await;
        match setup {
            None => anyhow::bail!("connect_outbound to {node_id} at {addr} failed"),
            Some(fut) => drop(fut),
        }

        // Wait for the handshake to register in peer_manager.list_peers().
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if self
                    .peer_manager
                    .list_peers()
                    .iter()
                    .any(|p| p.counterparty_node_id == node_id)
                {
                    break;
                }
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
        self.channel_manager
            .create_channel(peer_id, channel_value_sat, push_msat, 0, None, None)
            .map_err(|e| anyhow::anyhow!("create_channel: {e:?}"))?;
        Ok(())
    }

    async fn close_channel(
        &self,
        channel_id: &ChannelId,
        counterparty: &PublicKey,
    ) -> anyhow::Result<()> {
        if !self.is_running() {
            anyhow::bail!("node is not running");
        }
        self.channel_manager
            .close_channel(channel_id, counterparty)
            .map_err(|e| anyhow::anyhow!("close_channel: {e:?}"))?;
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
