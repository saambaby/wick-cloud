//! [`NodeBuilder`] — constructs a real LDK-backed [`Node<S>`].
//!
//! Pipeline (mirrors `ldk-node`'s `Builder::build` + `Node::start` but folded
//! into a single async build for a per-tenant lifecycle):
//!
//! 1. Validate signer is present (seed never touches this crate).
//! 2. Open `PgKvStore` (Postgres VSS) + `PaymentStore` + `PeerStore` for the
//!    tenant's schema.
//! 3. Build `ChainMonitor`, `NetworkGraph`, `ProbabilisticScorer`,
//!    `DefaultRouter`, `OnionMessenger`.
//! 4. Validate Esplora's best block, load-or-init `ChannelManager` via
//!    `read_channel_monitors` + `read_channel_manager` from persistence.
//! 5. Build `PeerManager` around the channel manager + gossip handler.
//! 6. Bind P2P listener on `deps.listen_addr_for(tenant_id)`; spawn inbound
//!    accept loop.
//! 7. Spawn SPV poll loop, fee refresh loop, peer reconnect loop.
//! 8. Spawn LDK `process_events_async`.
//! 9. Reconnect to persisted peers.
//!
//! The resulting [`Node<S>`] is ready for `send_payment` / `receive_payment` /
//! `open_channel` as soon as this function returns.

use std::io::Cursor;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::secp256k1::PublicKey;
use dashmap::DashMap;
use lightning::chain;
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::chain::{BestBlock, Filter, Watch};
use lightning::ln::channelmanager::ChannelManagerReadArgs;
use lightning::ln::channelmanager::{ChainParameters, ChannelManager};
use lightning::ln::peer_handler::{
    IgnoringMessageHandler, MessageHandler, PeerDetails, PeerManager,
};
use lightning::routing::gossip::P2PGossipSync;
use lightning::routing::router::DefaultRouter;
use lightning::routing::scoring::ProbabilisticScoringFeeParameters;
use lightning::routing::utxo::UtxoLookup;
use lightning::sign::ChangeDestinationSourceSync;
use lightning::sign::{EntropySource, NodeSigner, Recipient, SignerProvider};
use lightning::util::async_poll::{MaybeSend, MaybeSync};
use lightning::util::config::UserConfig;
use lightning::util::persist::{
    read_channel_monitors, KVStoreSync, KVStoreSyncWrapper, CHANNEL_MANAGER_PERSISTENCE_KEY,
    CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
};
use lightning::util::ser::ReadableArgs;
use lightning::util::sweep::OutputSweeperSync;
use lightning_background_processor::{
    process_events_async_with_kv_store_sync, GossipSync, NO_LIQUIDITY_MANAGER, NO_ONION_MESSENGER,
};
use lightning_block_sync::init;
use lightning_block_sync::poll::{ChainPoller, ValidatedBlockHeader};
use lightning_block_sync::{SpvClient, UnboundedCache};
use lightning_liquidity::lsps2::client::LSPS2ClientConfig;
use lightning_liquidity::lsps2::service::LSPS2ServiceConfig;
use lightning_liquidity::{LiquidityClientConfig, LiquidityManager, LiquidityServiceConfig};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use wick_core::TenantId;

use crate::api::NodeApi;
use crate::channel_store::ChannelStore;
use crate::deps::NodeDeps;
use crate::error::{Result, WickLightningError};
use crate::event::EventHandler;
use crate::funding::FundingSource;
use crate::gossip;
use crate::jit_registry::PendingJitRegistry;
use crate::node::{
    LiquidityFilter, LnChainMonitor, LnChannelManager, LnGossipSync, LnLiquidityManager,
    LnMessageRouter, LnPeerManager, LnRouter, LnScorer, Node,
};
use crate::payment_store::PaymentStore;
use crate::peer_store::PeerStore;
use crate::peers::seed_peers_if_empty;
use crate::persistence::PgKvStore;
use crate::signer::WickSigner;

/// How often the peer-reconnect loop replays the persisted peer list.
const PEER_RECONNECT_INTERVAL: Duration = Duration::from_secs(30);
/// How often the fee-refresh loop polls Esplora.
const FEE_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
/// SPV chain poll cadence.
const CHAIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Max time the initial fee fetch retries on startup.
const INITIAL_FEE_RETRIES: u8 = 3;

/// Builder for a real LDK-backed [`Node<S>`].
pub struct NodeBuilder<S: WickSigner = lightning::sign::KeysManager>
where
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    tenant_id: TenantId,
    deps: NodeDeps,
    signer: Option<Arc<S>>,
    funding: Option<Arc<dyn FundingSource>>,
    change_destination: Option<bitcoin::ScriptBuf>,
    /// Per-node LSPS2 client config. `Some` ⇒ this node negotiates JIT
    /// channels via the configured LSP peer (LSPS2 client role). `None`
    /// ⇒ no JIT support.
    liquidity_client: Option<LSPS2ClientConfig>,
    /// Per-node LSPS2 service config. `Some` ⇒ this node *is* the LSP
    /// (LSPS2 service role). The 32-byte `promise_secret` is rotated by
    /// the operator on a schedule; we surface it as-is.
    liquidity_service: Option<LSPS2ServiceConfig>,
    /// LSP peer pubkey wired into [`Node::lsp_peer`] for tenant-side
    /// `receive_payment_jit`. `None` for the LSP itself + for nodes
    /// running without an upstream LSP.
    lsp_peer: Option<PublicKey>,
    /// Optional service-side event handler. Set on the LSP node to
    /// drive `LSPS2ServiceEvent::GetInfo`/`BuyRequest`/`OpenChannel`
    /// responses + forward LDK lifecycle events into the
    /// `lsps2_service_handler`.
    lsp_service_handler: Option<Arc<dyn crate::liquidity_hook::LspServiceEventHandler>>,
}

impl<S> NodeBuilder<S>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    /// Start a new builder for `tenant_id`.
    ///
    /// A signer must be bound before [`build`](Self::build) via
    /// [`with_signer`](Self::with_signer).
    #[must_use]
    pub fn new(tenant_id: TenantId, deps: NodeDeps) -> Self {
        Self {
            tenant_id,
            deps,
            signer: None,
            funding: None,
            change_destination: None,
            liquidity_client: None,
            liquidity_service: None,
            lsp_peer: None,
            lsp_service_handler: None,
        }
    }

    /// Bind the signer. Phase 1: a `LocalKeysManager`. Phase 4: a remote VLS signer.
    #[must_use]
    pub fn with_signer<S2: WickSigner>(self, signer: Arc<S2>) -> NodeBuilder<S2>
    where
        <S2 as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
    {
        NodeBuilder {
            tenant_id: self.tenant_id,
            deps: self.deps,
            signer: Some(signer),
            funding: self.funding,
            change_destination: self.change_destination,
            liquidity_client: self.liquidity_client,
            liquidity_service: self.liquidity_service,
            lsp_peer: self.lsp_peer,
            lsp_service_handler: self.lsp_service_handler,
        }
    }

    /// Install an LSP service-event handler. Required when this node
    /// runs in service mode (`with_liquidity_service`) — without a
    /// handler, `LSPS2ServiceEvent`s pile up and clients never get
    /// responses to `lsps2.get_info` / `lsps2.buy`.
    #[must_use]
    pub fn with_lsp_service_handler(
        mut self,
        handler: Arc<dyn crate::liquidity_hook::LspServiceEventHandler>,
    ) -> Self {
        self.lsp_service_handler = Some(handler);
        self
    }

    /// Enable LSPS2 client role: this node will negotiate JIT channels
    /// via `lsp_peer`. Pass the LSP's pubkey so [`Node::receive_payment_jit`]
    /// knows which counterparty to address.
    #[must_use]
    pub fn with_liquidity_client(mut self, lsp_peer: PublicKey) -> Self {
        self.liquidity_client = Some(LSPS2ClientConfig::default());
        self.lsp_peer = Some(lsp_peer);
        self
    }

    /// Enable LSPS2 service role: this node will accept JIT requests
    /// from clients. The 32-byte `promise_secret` is the HMAC key used
    /// to sign opening fee params; rotate it on a schedule (5-min
    /// recommended in the architecture spec).
    #[must_use]
    pub fn with_liquidity_service(mut self, promise_secret: [u8; 32]) -> Self {
        self.liquidity_service = Some(LSPS2ServiceConfig { promise_secret });
        self
    }

    /// Bind a [`FundingSource`]. Required for nodes that originate channel
    /// opens (they receive `Event::FundingGenerationReady`). Nodes that
    /// only accept inbound channels don't need one.
    #[must_use]
    pub fn with_funding_source(mut self, funding: Arc<dyn FundingSource>) -> Self {
        self.funding = Some(funding);
        self
    }

    /// Bind the script where the background [`OutputSweeperSync`] sends
    /// force-close residuals / HTLC timeouts / `SpendableOutputs`. Without
    /// this, sweepable outputs are parked in LDK state until replayed with
    /// a destination configured.
    ///
    /// Typically the scriptPubKey of a BDK-derived wpkh address owned by
    /// the same tenant's on-chain wallet.
    #[must_use]
    pub fn with_change_destination(mut self, script: bitcoin::ScriptBuf) -> Self {
        self.change_destination = Some(script);
        self
    }

    /// Build + start the node. Returns once every background task is live.
    pub async fn build(self) -> Result<Arc<Node<S>>> {
        let Self {
            tenant_id,
            deps,
            signer,
            funding,
            change_destination,
            liquidity_client,
            liquidity_service,
            lsp_peer,
            lsp_service_handler,
        } = self;

        let signer = signer.ok_or_else(|| {
            WickLightningError::Config(
                "NodeBuilder: signer is required — call with_signer() before build()".into(),
            )
        })?;

        let node_id = NodeSigner::get_node_id(signer.as_ref(), Recipient::Node)
            .map_err(|_| WickLightningError::Config("NodeBuilder: get_node_id failed".into()))?;

        // Tenant nodes (the ones wired with `with_liquidity_client(lsp_peer)`)
        // must manually accept inbound channels so the `OpenChannelRequest`
        // event fires — that's where `EventHandler` calls
        // `accept_inbound_channel_from_trusted_peer_0conf` for LSP-driven
        // 0-conf JIT channels. With LDK's default (auto-accept) the event
        // never fires and the 0-conf path is unreachable.
        //
        // The LSP node and any tenant without an upstream LSP keep the
        // default (auto-accept) — they accept normal Bob → LSP / peer →
        // tenant channels via LDK's built-in path.
        let mut user_config = UserConfig::default();
        // Phase-4 zero-counterparty-reserve policy. Required for VLS's
        // `SimpleValidator` to accept the initial counterparty
        // commitment — its `to_remote ≤ push_value_msat` check rejects
        // any non-zero counterparty reserve. Documented trade-off: the
        // counterparty can spend their side down to zero; force-close /
        // justice paths unaffected.
        //
        // - `their_channel_reserve_proportional_millionths = 0`: when WE
        //   open, ask the counterparty for zero reserve.
        // - `max_channel_reserve_satoshis = u64::MAX`: when counterparty
        //   opens to us, accept whatever reserve LDK negotiates. LDK
        //   enforces an internal floor (~1000 sats, derived from
        //   dust_limit + commitment headroom) so even a counterparty that
        //   sets proportional=0 will still propose a small absolute reserve
        //   — refuse-on-zero is too strict in practice.
        user_config
            .channel_handshake_config
            .their_channel_reserve_proportional_millionths = 0;
        user_config
            .channel_handshake_limits
            .max_channel_reserve_satoshis = u64::MAX;
        if lsp_peer.is_some() {
            user_config.manually_accept_inbound_channels = true;
        }

        // ── Stores ────────────────────────────────────────────────────────────
        let kv_store = Arc::new(PgKvStore::new(
            tenant_id,
            deps.pg_pool.clone(),
            deps.runtime.clone(),
        ));
        let payments = Arc::new(PaymentStore::new(tenant_id, deps.pg_pool.clone()));
        let channels = Arc::new(ChannelStore::new(tenant_id, deps.pg_pool.clone()));
        let peer_store = Arc::new(PeerStore::new(tenant_id, deps.pg_pool.clone()));
        seed_peers_if_empty(peer_store.as_ref(), deps.network).await;

        // ── Chain + routing ───────────────────────────────────────────────────
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| WickLightningError::Config(format!("SystemTime: {e}")))?;
        let starting_time_secs = u32::try_from(ts.as_secs()).unwrap_or(u32::MAX);

        let peer_storage_key = NodeSigner::get_peer_storage_key(signer.as_ref());
        let chain_monitor: Arc<LnChainMonitor<S>> = Arc::new(ChainMonitor::new(
            None::<Arc<dyn Filter + Send + Sync>>,
            deps.broadcaster.clone(),
            deps.logger.clone(),
            deps.fee_estimator.clone(),
            kv_store.clone(),
            signer.clone(),
            peer_storage_key,
        ));

        let rgs_url = deps.network.default_rgs().map(ToOwned::to_owned);
        let (network_graph, scorer) = gossip::init_gossip(
            kv_store.clone(),
            deps.network,
            rgs_url.as_deref(),
            deps.logger.clone(),
        )
        .await;

        let router: Arc<LnRouter<S>> = Arc::new(DefaultRouter::new(
            network_graph.clone(),
            deps.logger.clone(),
            signer.clone(),
            scorer.clone(),
            ProbabilisticScoringFeeParameters::default(),
        ));

        let msg_router: Arc<LnMessageRouter<S>> = Arc::new(
            lightning::onion_message::messenger::DefaultMessageRouter::new(
                network_graph.clone(),
                signer.clone(),
            ),
        );

        // ── ChannelManager (load-or-init) ────────────────────────────────────
        //
        // First-boot path: `PgKvStore::list(..., MONITOR_NS)` returns empty
        // and reading the `manager` key yields `ErrorKind::NotFound`, so we
        // fall through to `ChannelManager::new` and anchor SPV at the live
        // Esplora tip.
        //
        // Restart path: LDK wrote the serialised `ChannelManager` and every
        // active `ChannelMonitor` into Postgres on every event commit. We
        // deserialise both, then call `init::synchronize_listeners` to walk
        // every restored listener forward from its persisted block hash to
        // the current chain tip — without this, the SPV poller's first
        // `block_connected` panics with "Blocks must be connected in
        // chain-order" because the channel manager's view is anchored at
        // its persisted (older) tip while the SPV is at the live tip.
        let loaded_monitors =
            read_channel_monitors(kv_store.clone(), signer.clone(), signer.clone()).map_err(
                |e| {
                    // Monitors are the most dangerous thing to lose — without them
                    // the node can't claim on-chain outputs from its channels. Any
                    // undecodable monitor bytes must stop boot dead; an operator
                    // should restore from backup before the node is allowed to
                    // reconstruct channel state.
                    //
                    // `read_channel_monitors` reads raw bytes under
                    // (MONITORS_PERSISTENCE_PRIMARY_NAMESPACE, "", "<monitor_name>");
                    // on decode failure we don't have the individual bytes handy
                    // (the helper already consumed them), so quarantine is best
                    // effort via a marker row describing the failure for the
                    // operator to investigate.
                    let marker = format!("monitor decode failed: {e}").into_bytes();
                    let _ = kv_store.quarantine("monitors/<read_channel_monitors>", marker);
                    WickLightningError::PersistenceDecode {
                        what: "monitors",
                        err: format!("{e}"),
                    }
                },
            )?;

        let manager_bytes = match kv_store.read(
            CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
            CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
            CHANNEL_MANAGER_PERSISTENCE_KEY,
        ) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => None,
            Err(e) => {
                // Read error (not NotFound) — transient Postgres failure
                // or schema issue. Don't quarantine (no bytes to save);
                // just fail loud and let the recovery loop retry.
                return Err(WickLightningError::PersistenceDecode {
                    what: "channel_manager",
                    err: format!("{e}"),
                });
            }
        };

        let (channel_manager, owned_monitors, best_block_header): (
            Arc<LnChannelManager<S>>,
            Vec<ChannelMonitor<<S as SignerProvider>::EcdsaSigner>>,
            ValidatedBlockHeader,
        ) = if let Some(bytes) = manager_bytes {
            tracing::info!(
                target: "wick_lightning",
                tenant = %tenant_id,
                monitors = loaded_monitors.len(),
                "restoring ChannelManager from PgKvStore"
            );
            let monitor_refs: Vec<&ChannelMonitor<<S as SignerProvider>::EcdsaSigner>> =
                loaded_monitors.iter().map(|(_, m)| m).collect();
            let args = ChannelManagerReadArgs::new(
                signer.clone(),
                signer.clone(),
                signer.clone(),
                deps.fee_estimator.clone(),
                chain_monitor.clone(),
                deps.broadcaster.clone(),
                router.clone(),
                msg_router.clone(),
                deps.logger.clone(),
                user_config.clone(),
                monitor_refs,
            );
            let mut cursor = Cursor::new(&bytes);
            let (manager_block_hash, cm) =
                match <(bitcoin::BlockHash, Arc<LnChannelManager<S>>)>::read(&mut cursor, args) {
                    Ok(v) => v,
                    Err(e) => {
                        // Bytes exist but don't decode — typically an LDK
                        // version mismatch or real corruption. Preserve the
                        // original bytes in quarantine before bailing so an
                        // operator can diff them against a known-good backup.
                        let _ = kv_store.quarantine(CHANNEL_MANAGER_PERSISTENCE_KEY, bytes.clone());
                        return Err(WickLightningError::PersistenceDecode {
                            what: "channel_manager",
                            err: format!("{e:?}"),
                        });
                    }
                };
            // `args` is dropped here; the `&ChannelMonitor` borrows it held
            // expire, so we can now move the owned monitors out of
            // `loaded_monitors`.
            let owned_monitors: Vec<ChannelMonitor<<S as SignerProvider>::EcdsaSigner>> =
                loaded_monitors.into_iter().map(|(_, m)| m).collect();

            // Pair each monitor with its persisted block hash, then build
            // chain::Listen tuples that own the monitor (LDK's
            // `(ChannelMonitor, B, F, L): chain::Listen` impl requires the
            // first element by value). After `synchronize_listeners` we
            // move each monitor back out of its tuple and hand it to
            // `chain_monitor.watch_channel`.
            let monitor_tuples: Vec<(
                bitcoin::BlockHash,
                (
                    ChannelMonitor<<S as SignerProvider>::EcdsaSigner>,
                    Arc<crate::chain::EsploraBroadcaster>,
                    Arc<crate::chain::FeeEstimator>,
                    Arc<crate::logger::TracingLogger>,
                ),
            )> = owned_monitors
                .into_iter()
                .map(|m| {
                    let h = m.current_best_block().block_hash;
                    (
                        h,
                        (
                            m,
                            deps.broadcaster.clone(),
                            deps.fee_estimator.clone(),
                            deps.logger.clone(),
                        ),
                    )
                })
                .collect();

            let listeners: Vec<(bitcoin::BlockHash, &(dyn chain::Listen + Send + Sync))> =
                monitor_tuples
                    .iter()
                    .map(|(h, t)| (*h, t as &(dyn chain::Listen + Send + Sync)))
                    .chain(std::iter::once((
                        manager_block_hash,
                        &*cm as &(dyn chain::Listen + Send + Sync),
                    )))
                    .collect();

            let mut cache = UnboundedCache::new();
            let chain_tip = init::synchronize_listeners(
                deps.esplora.as_ref(),
                deps.network.into(),
                &mut cache,
                listeners,
            )
            .await
            .map_err(|e| WickLightningError::Config(format!("synchronize_listeners: {e:?}")))?;

            let recovered_monitors: Vec<ChannelMonitor<<S as SignerProvider>::EcdsaSigner>> =
                monitor_tuples.into_iter().map(|(_, t)| t.0).collect();

            (cm, recovered_monitors, chain_tip)
        } else {
            tracing::info!(
                target: "wick_lightning",
                tenant = %tenant_id,
                "first boot — constructing fresh ChannelManager"
            );
            let best_block_header: ValidatedBlockHeader =
                init::validate_best_block_header(deps.esplora.as_ref())
                    .await
                    .map_err(|e| {
                        WickLightningError::Config(format!("validate_best_block_header: {e:?}"))
                    })?;
            let chain_params = ChainParameters {
                network: deps.network.into(),
                best_block: BestBlock::new(
                    best_block_header.header.block_hash(),
                    best_block_header.height,
                ),
            };
            let cm = Arc::new(ChannelManager::new(
                deps.fee_estimator.clone(),
                chain_monitor.clone(),
                deps.broadcaster.clone(),
                router.clone(),
                msg_router.clone(),
                deps.logger.clone(),
                signer.clone(),
                signer.clone(),
                signer.clone(),
                user_config.clone(),
                chain_params,
                starting_time_secs,
            ));
            (cm, Vec::new(), best_block_header)
        };

        // Re-register each restored monitor with the chain monitor so the
        // SPV loop delivers block data to it. `chain::Watch::watch_channel`
        // is keyed by `ChannelId` in LDK 0.2 (not the funding `OutPoint`).
        for monitor in owned_monitors {
            let channel_id = monitor.channel_id();
            if chain_monitor.watch_channel(channel_id, monitor).is_err() {
                tracing::warn!(
                    target: "wick_lightning",
                    tenant = %tenant_id,
                    ?channel_id,
                    "watch_channel returned Err on restore — monitor already present?"
                );
            }
        }

        // ── Gossip + PeerManager ─────────────────────────────────────────────
        let gossip_sync: Arc<LnGossipSync> = Arc::new(P2PGossipSync::new(
            network_graph.clone(),
            None::<Arc<dyn UtxoLookup + Send + Sync>>,
            deps.logger.clone(),
        ));

        // LiquidityManager runs in every node, even ones without LSPS2.
        // Passing both configs as `None` leaves only LSPS0 transport
        // active — a no-op for protocols above. Cost is one Arc + a
        // few Mutexes.
        let liquidity_kv = KVStoreSyncWrapper(kv_store.clone());
        let liquidity_client_cfg =
            liquidity_client.map(|lsps2_client_config| LiquidityClientConfig {
                lsps1_client_config: None,
                lsps2_client_config: Some(lsps2_client_config),
                lsps5_client_config: None,
            });
        let liquidity_service_cfg =
            liquidity_service.map(|lsps2_service_config| LiquidityServiceConfig {
                lsps2_service_config: Some(lsps2_service_config),
                lsps5_service_config: None,
                advertise_service: true,
            });
        let liquidity_manager: Arc<LnLiquidityManager<S>> = Arc::new(
            LiquidityManager::new(
                signer.clone(),
                signer.clone(),
                channel_manager.clone(),
                None::<Arc<LiquidityFilter>>,
                None,
                liquidity_kv,
                deps.broadcaster.clone(),
                liquidity_service_cfg,
                liquidity_client_cfg,
            )
            .await
            .map_err(|e| WickLightningError::Config(format!("LiquidityManager::new: {e}")))?,
        );

        let ephemeral = EntropySource::get_secure_random_bytes(signer.as_ref());
        let peer_manager: Arc<LnPeerManager<S>> = Arc::new(PeerManager::new(
            MessageHandler {
                chan_handler: channel_manager.clone(),
                route_handler: gossip_sync.clone(),
                onion_message_handler: Arc::new(IgnoringMessageHandler {}),
                custom_message_handler: liquidity_manager.clone(),
                send_only_message_handler: chain_monitor.clone(),
            },
            starting_time_secs,
            &ephemeral,
            deps.logger.clone(),
            signer.clone(),
        ));

        // ── Background signals ────────────────────────────────────────────────
        let (stop_tx, _) = watch::channel::<()>(());
        let (conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel::<(
            bitcoin::secp256k1::PublicKey,
            std::net::SocketAddr,
        )>();
        let pending_sent_at: Arc<DashMap<[u8; 32], u64>> = Arc::new(DashMap::new());
        // Registry that parks FundingGenerationReady events for the
        // self-custodial two-phase channel-open flow. Shared between the
        // Node<S> (NodeApi::open_channel_init reads from it) and the
        // EventHandler (FundingGenerationReady writes to it). Backed by
        // Postgres so an actor crash between park and take leaves a
        // rehydratable row.
        let funding_store = Arc::new(crate::funding_store::FundingStore::new(
            tenant_id,
            deps.pg_pool.clone(),
        ));
        let funding_registry =
            crate::funding_registry::PendingFundingRegistry::with_store(funding_store);
        funding_registry.rehydrate_from_store().await;

        // JIT registry — in-memory only. LSPS2 client events do not
        // persist across restarts per the lightning-liquidity docs;
        // the SDK re-issues `lsps2.get_info` after a tenant restart.
        let jit_registry = PendingJitRegistry::new();

        // ── Bind P2P listener ────────────────────────────────────────────────
        let listen_bind = deps.listen_addr_for(tenant_id);
        let listener = TcpListener::bind(listen_bind).await.map_err(|e| {
            WickLightningError::Config(format!(
                "TcpListener::bind({listen_bind}): {e} — port in use?"
            ))
        })?;
        let local_listen = listener
            .local_addr()
            .map_err(|e| WickLightningError::Config(format!("listener.local_addr: {e}")))?;

        // ── Construct the Node ───────────────────────────────────────────────
        let node = Arc::new(Node::<S> {
            tenant_id,
            node_id,
            signer: signer.clone(),
            channel_manager: channel_manager.clone(),
            chain_monitor: chain_monitor.clone(),
            peer_manager: peer_manager.clone(),
            network_graph: network_graph.clone(),
            gossip_sync: gossip_sync.clone(),
            scorer: scorer.clone(),
            payments: payments.clone(),
            peer_store: peer_store.clone(),
            broadcaster: deps.broadcaster.clone(),
            fee_estimator: deps.fee_estimator.clone(),
            logger: deps.logger.clone(),
            chain: deps.esplora.clone(),
            kv_store: kv_store.clone(),
            listen_addr: RwLock::new(Some(local_listen)),
            stop_tx: stop_tx.clone(),
            runtime_started: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            bg_handles: Mutex::new(Vec::new()),
            pending_sent_at: pending_sent_at.clone(),
            funding_registry: funding_registry.clone(),
            liquidity_manager: liquidity_manager.clone(),
            lsp_peer,
            jit_registry: jit_registry.clone(),
        });

        // Wire signer-unblock callback. LDK 0.2's async-signer protocol
        // marks a channel as "signer pending" whenever any `ChannelSigner`
        // method returns `Err(())`, and only retries when the user calls
        // `ChannelManager::signer_unblocked`. Our VLS-backed signer can
        // legitimately error on the `get_per_commitment_point` ↔
        // `SetupChannel` race during channel-open; the signer fires this
        // callback once `SetupChannel` lands so LDK retries the parked
        // call without the previous timer-driven nudge. No-op for
        // local-keys signers (default trait impl).
        {
            let channel_manager_for_unblock = Arc::clone(&channel_manager);
            signer.set_signer_unblock_callback(Box::new(move || {
                channel_manager_for_unblock.signer_unblocked(None);
            }));
        }

        // ── Spawn tasks ──────────────────────────────────────────────────────
        let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(5);

        // P2P inbound accept loop.
        handles.push(spawn_p2p_accept(
            listener,
            peer_manager.clone(),
            stop_tx.subscribe(),
        ));

        // SPV chain poll loop.
        handles.push(spawn_chain_poll(
            deps.esplora.clone(),
            channel_manager.clone(),
            chain_monitor.clone(),
            best_block_header,
            stop_tx.subscribe(),
        ));

        // Fee estimate refresh loop (one retry on startup, then periodic).
        prime_fee_cache(&deps).await;
        handles.push(spawn_fee_refresh(
            deps.esplora.clone(),
            deps.fee_estimator.clone(),
            stop_tx.subscribe(),
        ));

        // Peer reconnect loop.
        handles.push(spawn_peer_reconnect(
            peer_store.clone(),
            peer_manager.clone(),
            stop_tx.subscribe(),
        ));

        // ConnectionNeeded dispatch — drives outbound dials requested by LDK.
        handles.push(spawn_connection_dispatch(
            conn_rx,
            peer_manager.clone(),
            stop_tx.subscribe(),
        ));

        // Gossip background: RGS re-sync every 24h + scorer persist every 10min.
        handles.push(gossip::spawn_gossip_tasks(
            rgs_url,
            network_graph.clone(),
            scorer.clone(),
            kv_store.clone(),
            deps.logger.clone(),
            stop_tx.subscribe(),
        ));

        // LDK `process_events_async`.
        let mut event_handler = EventHandler::new(
            payments.clone(),
            channels.clone(),
            deps.runtime.clone(),
            Arc::new(crate::event::ChannelManagerRuntimeOps(
                channel_manager.clone(),
            )),
            funding_registry.clone(),
        )
        .with_connection_dispatch(conn_tx);
        if let Some(f) = funding {
            event_handler = event_handler.with_funding_source(f);
        }
        if let Some(ref h) = lsp_service_handler {
            event_handler = event_handler.with_lsp_service_handler(h.clone());
        }
        if let Some(pk) = lsp_peer {
            event_handler = event_handler.with_lsp_peer(pk);
        }
        let event_handler = Arc::new(event_handler);

        // Build a real OutputSweeperSync when a change destination is
        // available; otherwise pass `None` and park any SpendableOutputs
        // in LDK's monitor state until a destination is configured.
        //
        // Resolution order:
        //   1. Signer-supplied source (`WickSigner::change_destination_source`).
        //      VLS-backed signers return a `VlsChangeDestination` that asks
        //      the SDK for a fresh BIP84 change address per sweep — Phase-4
        //      promise that refunds land on the user's on-device BDK wallet.
        //   2. Caller-supplied fixed script (`with_change_destination`). Used
        //      by `KeysManager`-backed dev / regtest signers + tests.
        //   3. None — sweeper disabled, outputs park in LDK monitor state.
        let change_source: Option<Arc<dyn ChangeDestinationSourceSync + Send + Sync>> =
            signer.change_destination_source().or_else(|| {
                change_destination.map(|script| {
                    Arc::new(FixedChangeDest(script))
                        as Arc<dyn ChangeDestinationSourceSync + Send + Sync>
                })
            });
        let sweeper: Option<Arc<LnOutputSweeper<S>>> = change_source.map(|src| {
            let best_block_for_sweeper = BestBlock::new(
                best_block_header.header.block_hash(),
                best_block_header.height,
            );
            Arc::new(OutputSweeperSync::new(
                best_block_for_sweeper,
                deps.broadcaster.clone(),
                deps.fee_estimator.clone(),
                None::<Arc<dyn Filter + Send + Sync>>,
                signer.clone(),
                src,
                kv_store.clone(),
                deps.logger.clone(),
            ))
        });

        handles.push(spawn_process_events(
            channel_manager.clone(),
            chain_monitor.clone(),
            peer_manager.clone(),
            gossip_sync.clone(),
            scorer.clone(),
            kv_store.clone(),
            deps.logger.clone(),
            event_handler,
            sweeper,
            liquidity_manager.clone(),
            stop_tx.clone(),
        ));

        // LiquidityManager event pump: drain LSPS2 client/service events
        // into the JIT registry so `receive_payment_jit` callers can
        // await their request_id. When `lsp_service_handler` is set
        // (LSP service mode), service events are forwarded into the
        // operator-supplied handler.
        handles.push(spawn_liquidity_event_pump(
            liquidity_manager.clone(),
            jit_registry.clone(),
            tenant_id,
            lsp_peer,
            lsp_service_handler.clone(),
            stop_tx.subscribe(),
        ));

        // Install handles into the node.
        {
            let mut g = node
                .bg_handles
                .lock()
                .map_err(|e| WickLightningError::Config(format!("bg_handles: {e}")))?;
            *g = handles;
        }
        node.runtime_started
            .store(true, std::sync::atomic::Ordering::Release);

        // Reconnect to persisted peers (best-effort; failures are logged).
        reconnect_persisted_peers(peer_store.as_ref(), peer_manager.clone()).await;

        tracing::info!(
            target: "wick_lightning",
            tenant = %tenant_id,
            node_id = %node_id,
            listen = %local_listen,
            "Node<S> started"
        );

        Ok(node)
    }
}

impl<S> std::fmt::Debug for NodeBuilder<S>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeBuilder")
            .field("tenant_id", &self.tenant_id)
            .field("has_signer", &self.signer.is_some())
            .finish_non_exhaustive()
    }
}

// ── Background task spawners ──────────────────────────────────────────────────

fn spawn_p2p_accept<S>(
    listener: TcpListener,
    peer_manager: Arc<LnPeerManager<S>>,
    mut stop_rx: watch::Receiver<()>,
) -> JoinHandle<()>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            match stream.into_std() {
                                Ok(std_stream) => {
                                    lightning_net_tokio::setup_inbound(
                                        peer_manager.clone(),
                                        std_stream,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        target: "wick_lightning",
                                        error = %e,
                                        "setup_inbound: into_std failed"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "wick_lightning",
                                error = %e,
                                "P2P accept failed — exiting accept loop"
                            );
                            break;
                        }
                    }
                }
                _ = stop_rx.changed() => break,
            }
        }
    })
}

fn spawn_chain_poll<S>(
    chain: Arc<crate::chain::EsploraChainClient>,
    channel_manager: Arc<LnChannelManager<S>>,
    chain_monitor: Arc<LnChainMonitor<S>>,
    best_block_header: ValidatedBlockHeader,
    mut stop_rx: watch::Receiver<()>,
) -> JoinHandle<()>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    tokio::spawn(async move {
        let network = chain.network();
        let chain_listener = Arc::new((channel_manager, chain_monitor));
        let mut cache = UnboundedCache::new();
        let poller = ChainPoller::new(chain.as_ref(), network);
        let mut spv = SpvClient::new(best_block_header, poller, &mut cache, chain_listener);
        loop {
            tokio::select! {
                _ = tokio::time::sleep(CHAIN_POLL_INTERVAL) => {
                    if let Err(e) = spv.poll_best_tip().await {
                        tracing::debug!(
                            target: "wick_lightning",
                            ?e,
                            "SPV poll_best_tip failed (will retry)"
                        );
                    }
                }
                _ = stop_rx.changed() => break,
            }
        }
    })
}

async fn prime_fee_cache(deps: &NodeDeps) {
    for attempt in 0..INITIAL_FEE_RETRIES {
        match deps.esplora.fetch_fee_estimates().await {
            Ok(estimates) => {
                deps.fee_estimator.update(&estimates);
                return;
            }
            Err(e) => {
                if attempt + 1 == INITIAL_FEE_RETRIES {
                    tracing::warn!(
                        target: "wick_lightning",
                        error = %e,
                        "initial fee fetch failed after retries; using seeded defaults"
                    );
                } else {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }
}

fn spawn_fee_refresh(
    chain: Arc<crate::chain::EsploraChainClient>,
    fee_estimator: Arc<crate::chain::FeeEstimator>,
    mut stop_rx: watch::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(FEE_REFRESH_INTERVAL) => {
                    match chain.fetch_fee_estimates().await {
                        Ok(estimates) => fee_estimator.update(&estimates),
                        Err(e) => tracing::debug!(
                            target: "wick_lightning",
                            error = %e,
                            "fee refresh failed (will retry)"
                        ),
                    }
                }
                _ = stop_rx.changed() => break,
            }
        }
    })
}

fn spawn_connection_dispatch<S>(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<(
        bitcoin::secp256k1::PublicKey,
        std::net::SocketAddr,
    )>,
    peer_manager: Arc<LnPeerManager<S>>,
    mut stop_rx: watch::Receiver<()>,
) -> JoinHandle<()>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    let Some((node_id, addr)) = msg else { break };
                    tracing::debug!(
                        target: "wick_lightning",
                        peer = %node_id,
                        address = %addr,
                        "ConnectionNeeded: dialing outbound"
                    );
                    if let Some(fut) =
                        lightning_net_tokio::connect_outbound(peer_manager.clone(), node_id, addr).await
                    {
                        drop(fut);
                    }
                }
                _ = stop_rx.changed() => break,
            }
        }
    })
}

fn spawn_peer_reconnect<S>(
    peer_store: Arc<PeerStore>,
    peer_manager: Arc<LnPeerManager<S>>,
    mut stop_rx: watch::Receiver<()>,
) -> JoinHandle<()>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(PEER_RECONNECT_INTERVAL) => {}
                _ = stop_rx.changed() => break,
            }
            let persisted = match peer_store.list().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(
                        target: "wick_lightning",
                        error = %e,
                        "peer_store.list failed; skipping reconnect tick"
                    );
                    continue;
                }
            };
            let connected: std::collections::HashSet<PublicKey> = peer_manager
                .list_peers()
                .into_iter()
                .map(|d: PeerDetails| d.counterparty_node_id)
                .collect();
            for peer in persisted {
                if !connected.contains(&peer.node_id) {
                    if let Some(fut) = lightning_net_tokio::connect_outbound(
                        peer_manager.clone(),
                        peer.node_id,
                        peer.address,
                    )
                    .await
                    {
                        drop(fut);
                    }
                }
            }
        }
    })
}

async fn reconnect_persisted_peers<S>(peer_store: &PeerStore, peer_manager: Arc<LnPeerManager<S>>)
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    let persisted = match peer_store.list().await {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(
                target: "wick_lightning",
                error = %e,
                "startup peer reconnect skipped (peer_store.list failed)"
            );
            return;
        }
    };
    for peer in persisted {
        if let Some(fut) =
            lightning_net_tokio::connect_outbound(peer_manager.clone(), peer.node_id, peer.address)
                .await
        {
            drop(fut);
        }
    }
}

/// [`ChangeDestinationSourceSync`] backed by a caller-supplied fixed
/// script. All swept outputs (force-close residuals, HTLC timeouts, etc.)
/// land at this single address. For regtest integration tests this is a
/// BDK-derived wpkh address; in production it's the user's on-chain
/// wallet's next-unused address, updated by the SDK on cadence.
#[derive(Debug)]
struct FixedChangeDest(bitcoin::ScriptBuf);

impl ChangeDestinationSourceSync for FixedChangeDest {
    fn get_change_destination_script(&self) -> std::result::Result<bitcoin::ScriptBuf, ()> {
        Ok(self.0.clone())
    }
}

/// Concrete [`OutputSweeperSync`] type over our signer `S`.
///
/// The change-destination slot is a runtime-pluggable trait object so the
/// same `OutputSweeperSync<...>` type covers both:
///   * `FixedChangeDest` (caller-supplied script, dev / regtest path), and
///   * [`wick_vls::VlsChangeDestination`] (Phase-4 SDK BDK path).
type LnOutputSweeper<S> = OutputSweeperSync<
    Arc<crate::chain::EsploraBroadcaster>,
    Arc<dyn ChangeDestinationSourceSync + Send + Sync>,
    Arc<crate::chain::FeeEstimator>,
    Arc<dyn Filter + Send + Sync>,
    Arc<PgKvStore>,
    Arc<crate::logger::TracingLogger>,
    Arc<S>,
>;

#[allow(clippy::too_many_arguments)]
fn spawn_process_events<S>(
    channel_manager: Arc<LnChannelManager<S>>,
    chain_monitor: Arc<LnChainMonitor<S>>,
    peer_manager: Arc<LnPeerManager<S>>,
    gossip_sync: Arc<LnGossipSync>,
    scorer: LnScorer,
    kv_store: Arc<PgKvStore>,
    logger: Arc<crate::logger::TracingLogger>,
    event_handler: Arc<EventHandler>,
    sweeper: Option<Arc<LnOutputSweeper<S>>>,
    liquidity_manager: Arc<LnLiquidityManager<S>>,
    stop_tx: watch::Sender<()>,
) -> JoinHandle<()>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    tokio::spawn(async move {
        let sleeper_stop = stop_tx.clone();
        let sleeper = move |dur: Duration| {
            let mut stop_rx = sleeper_stop.subscribe();
            Box::pin(async move {
                tokio::select! {
                    _ = tokio::time::sleep(dur) => false,
                    _ = stop_rx.changed() => true,
                }
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        };
        let _ = NO_LIQUIDITY_MANAGER; // keep import alive on no-LSPS path
        if let Err(e) = process_events_async_with_kv_store_sync(
            kv_store,
            move |event| {
                let h = event_handler.clone();
                async move { h.handle(event).await }
            },
            chain_monitor,
            channel_manager,
            NO_ONION_MESSENGER,
            GossipSync::p2p(gossip_sync),
            peer_manager,
            Some(liquidity_manager),
            sweeper,
            logger,
            Some(scorer),
            sleeper,
            false,
            || {
                Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default(),
                )
            },
        )
        .await
        {
            tracing::error!(
                target: "wick_lightning",
                ?e,
                "process_events_async exited with error"
            );
        }
    })
}

/// Helper re-export so `wick-server` can resolve the concrete `Node<S>` type
/// without importing both crates' signer traits.
pub use crate::node::Node as BuiltNode;

/// Drain LSPS2 events from [`LiquidityManager`] and route client-side
/// responses into [`PendingJitRegistry`].
///
/// `lightning-liquidity` emits events asynchronously via
/// `next_event_async()`. We loop on it, mapping `LSPS2ClientEvent`
/// variants to [`crate::jit_registry::JitResponse`] and parking them
/// keyed by `request_id`. When `expected_lsp` is `Some(_)`, every
/// client response's `counterparty_node_id` is matched against it —
/// responses from any other peer are logged + dropped (defense in
/// depth; the message routing layer should already enforce this).
///
/// Service-side events (`LSPS2ServiceEvent`) drive LDK's built-in
/// `lsps2_service_handler` directly — `wick-lsp::daemon` handles
/// `GetInfo`/`BuyRequest`/`OpenChannel` here and the LSP's
/// EventHandler forwards the corresponding LDK lifecycle events
/// (`HTLCIntercepted`, `ChannelReady`, `PaymentForwarded`) to
/// complete the protocol.
#[allow(clippy::too_many_lines)]
fn spawn_liquidity_event_pump<S>(
    liquidity_manager: Arc<LnLiquidityManager<S>>,
    jit_registry: Arc<PendingJitRegistry>,
    tenant_id: TenantId,
    expected_lsp: Option<PublicKey>,
    service_handler: Option<Arc<dyn crate::liquidity_hook::LspServiceEventHandler>>,
    mut stop_rx: watch::Receiver<()>,
) -> JoinHandle<()>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    use crate::jit_registry::JitResponse;
    use lightning_liquidity::events::LiquidityEvent;
    use lightning_liquidity::lsps2::event::LSPS2ClientEvent;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    tracing::info!(
                        target: "wick_lightning",
                        tenant = %tenant_id,
                        "liquidity_event_pump: stopping"
                    );
                    return;
                }
                ev = liquidity_manager.next_event_async() => {
                    match ev {
                        LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
                            request_id,
                            counterparty_node_id,
                            opening_fee_params_menu,
                        }) => {
                            if !validate_counterparty(expected_lsp, counterparty_node_id, "OpeningParametersReady", tenant_id) {
                                continue;
                            }
                            jit_registry.park(request_id, JitResponse::OpeningParameters {
                                counterparty_node_id,
                                opening_fee_params_menu,
                            });
                        }
                        LiquidityEvent::LSPS2Client(LSPS2ClientEvent::InvoiceParametersReady {
                            request_id,
                            counterparty_node_id,
                            intercept_scid,
                            cltv_expiry_delta,
                            payment_size_msat,
                        }) => {
                            if !validate_counterparty(expected_lsp, counterparty_node_id, "InvoiceParametersReady", tenant_id) {
                                continue;
                            }
                            jit_registry.park(request_id, JitResponse::InvoiceParameters {
                                counterparty_node_id,
                                intercept_scid,
                                cltv_expiry_delta,
                                payment_size_msat,
                            });
                        }
                        LiquidityEvent::LSPS2Client(LSPS2ClientEvent::GetInfoFailed {
                            request_id,
                            counterparty_node_id,
                            error,
                        }) => {
                            if !validate_counterparty(expected_lsp, counterparty_node_id, "GetInfoFailed", tenant_id) {
                                continue;
                            }
                            jit_registry.park(request_id, JitResponse::GetInfoFailed {
                                counterparty_node_id,
                                message: format!("{}: {}", error.code, error.message),
                            });
                        }
                        LiquidityEvent::LSPS2Client(LSPS2ClientEvent::BuyRequestFailed {
                            request_id,
                            counterparty_node_id,
                            error,
                        }) => {
                            if !validate_counterparty(expected_lsp, counterparty_node_id, "BuyRequestFailed", tenant_id) {
                                continue;
                            }
                            jit_registry.park(request_id, JitResponse::BuyFailed {
                                counterparty_node_id,
                                message: format!("{}: {}", error.code, error.message),
                            });
                        }
                        // Service events — delegated to the operator-supplied
                        // handler when one is wired in. Without a handler the
                        // event is logged and dropped (clients will time out).
                        LiquidityEvent::LSPS2Service(svc) => {
                            match service_handler.as_ref() {
                                Some(h) => h.handle_service_event(svc).await,
                                None => tracing::debug!(
                                    target: "wick_lightning",
                                    tenant = %tenant_id,
                                    event = ?svc,
                                    "LSPS2Service event with no operator handler installed"
                                ),
                            }
                        }
                        other => {
                            tracing::debug!(
                                target: "wick_lightning",
                                tenant = %tenant_id,
                                event = ?other,
                                "liquidity_event_pump: unhandled event (LSPS0/LSPS1/LSPS5)"
                            );
                        }
                    }
                }
            }
        }
    })
}

/// Validate that an LSPS2 client response came from the configured LSP.
/// Logs + drops on mismatch.
fn validate_counterparty(
    expected: Option<PublicKey>,
    actual: PublicKey,
    event: &'static str,
    tenant_id: TenantId,
) -> bool {
    match expected {
        Some(exp) if exp != actual => {
            tracing::warn!(
                target: "wick_lightning",
                tenant = %tenant_id,
                event,
                expected = %exp,
                actual = %actual,
                "liquidity_event_pump: dropping LSPS2 response from unexpected counterparty"
            );
            false
        }
        _ => true,
    }
}

// Ensure Node<S> is both NodeApi *and* Send+Sync so the server can box it as
// `Arc<dyn NodeApi>`. The compile-time check keeps us honest.
#[allow(dead_code)]
fn _assert_node_is_api<S>(n: Arc<Node<S>>) -> Arc<dyn NodeApi>
where
    S: WickSigner,
    <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync,
{
    n
}
