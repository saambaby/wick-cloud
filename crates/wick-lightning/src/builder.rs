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
use std::sync::{ Arc, Mutex, RwLock };
use std::time::{ Duration, SystemTime, UNIX_EPOCH };

use bitcoin::secp256k1::PublicKey;
use dashmap::DashMap;
use lightning::chain;
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::chain::{ BestBlock, Filter, Watch };
use lightning::ln::channelmanager::ChannelManagerReadArgs;
use lightning::ln::channelmanager::{ ChainParameters, ChannelManager };
use lightning::ln::peer_handler::{
    IgnoringMessageHandler,
    MessageHandler,
    PeerDetails,
    PeerManager,
};
use lightning::routing::gossip::P2PGossipSync;
use lightning::routing::router::DefaultRouter;
use lightning::routing::scoring::ProbabilisticScoringFeeParameters;
use lightning::routing::utxo::UtxoLookup;
use lightning::sign::ChangeDestinationSourceSync;
use lightning::sign::{ EntropySource, NodeSigner, Recipient, SignerProvider };
use lightning::util::async_poll::{ MaybeSend, MaybeSync };
use lightning::util::config::UserConfig;
use lightning::util::persist::{
    read_channel_monitors,
    KVStoreSync,
    CHANNEL_MANAGER_PERSISTENCE_KEY,
    CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
    CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
};
use lightning::util::ser::ReadableArgs;
use lightning::util::sweep::OutputSweeperSync;
use lightning_background_processor::{
    process_events_async_with_kv_store_sync,
    GossipSync,
    NO_LIQUIDITY_MANAGER,
    NO_ONION_MESSENGER,
};
use lightning_block_sync::init;
use lightning_block_sync::poll::{ ChainPoller, ValidatedBlockHeader };
use lightning_block_sync::{ SpvClient, UnboundedCache };
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use wick_core::TenantId;

use crate::api::NodeApi;
use crate::channel_store::ChannelStore;
use crate::deps::NodeDeps;
use crate::error::{ Result, WickLightningError };
use crate::event::EventHandler;
use crate::funding::FundingSource;
use crate::gossip;
use crate::node::{
    LnChainMonitor,
    LnChannelManager,
    LnGossipSync,
    LnMessageRouter,
    LnPeerManager,
    LnRouter,
    LnScorer,
    Node,
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
    where <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync {
    tenant_id: TenantId,
    deps: NodeDeps,
    signer: Option<Arc<S>>,
    funding: Option<Arc<dyn FundingSource>>,
    change_destination: Option<bitcoin::ScriptBuf>,
}

impl<S> NodeBuilder<S>
    where S: WickSigner, <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync
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
        }
    }

    /// Bind the signer. Phase 1: a `LocalKeysManager` built by
    /// `wick-testkit::signer::from_seed`. Phase 4: a remote VLS signer.
    #[must_use]
    pub fn with_signer<S2: WickSigner>(self, signer: Arc<S2>) -> NodeBuilder<S2>
        where <S2 as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync
    {
        NodeBuilder {
            tenant_id: self.tenant_id,
            deps: self.deps,
            signer: Some(signer),
            funding: self.funding,
            change_destination: self.change_destination,
        }
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
        let Self { tenant_id, deps, signer, funding, change_destination } = self;

        let signer = signer.ok_or_else(|| {
            WickLightningError::Config(
                "NodeBuilder: signer is required — call with_signer() before build()".into()
            )
        })?;

        let node_id = NodeSigner::get_node_id(signer.as_ref(), Recipient::Node).map_err(|_|
            WickLightningError::Config("NodeBuilder: get_node_id failed".into())
        )?;

        // ── Stores ────────────────────────────────────────────────────────────
        let kv_store = Arc::new(
            PgKvStore::new(tenant_id, deps.pg_pool.clone(), deps.runtime.clone())
        );
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
        let chain_monitor: Arc<LnChainMonitor<S>> = Arc::new(
            ChainMonitor::new(
                None::<Arc<dyn Filter + Send + Sync>>,
                deps.broadcaster.clone(),
                deps.logger.clone(),
                deps.fee_estimator.clone(),
                kv_store.clone(),
                signer.clone(),
                peer_storage_key
            )
        );

        let rgs_url = deps.network.default_rgs().map(ToOwned::to_owned);
        let (network_graph, scorer) = gossip::init_gossip(
            kv_store.clone(),
            deps.network.into(),
            rgs_url.as_deref(),
            deps.logger.clone()
        ).await;

        let router: Arc<LnRouter<S>> = Arc::new(
            DefaultRouter::new(
                network_graph.clone(),
                deps.logger.clone(),
                signer.clone(),
                scorer.clone(),
                ProbabilisticScoringFeeParameters::default()
            )
        );

        let msg_router: Arc<LnMessageRouter<S>> = Arc::new(
            lightning::onion_message::messenger::DefaultMessageRouter::new(
                network_graph.clone(),
                signer.clone()
            )
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
        let loaded_monitors = read_channel_monitors(
            kv_store.clone(),
            signer.clone(),
            signer.clone()
        ).map_err(|e| WickLightningError::PersistenceDecode {
            what: "monitors",
            err: format!("{e}"),
        })?;

        let manager_bytes = match
            kv_store.read(
                CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
                CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
                CHANNEL_MANAGER_PERSISTENCE_KEY
            )
        {
            Ok(b) => Some(b),
            Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => None,
            Err(e) => {
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
                loaded_monitors
                    .iter()
                    .map(|(_, m)| m)
                    .collect();
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
                UserConfig::default(),
                monitor_refs
            );
            let mut cursor = Cursor::new(&bytes);
            let (manager_block_hash, cm) = <(bitcoin::BlockHash, Arc<LnChannelManager<S>>)>
                ::read(&mut cursor, args)
                .map_err(|e| WickLightningError::PersistenceDecode {
                    what: "channel_manager",
                    err: format!("{e:?}"),
                })?;
            // `args` is dropped here; the `&ChannelMonitor` borrows it held
            // expire, so we can now move the owned monitors out of
            // `loaded_monitors`.
            let owned_monitors: Vec<ChannelMonitor<<S as SignerProvider>::EcdsaSigner>> =
                loaded_monitors
                    .into_iter()
                    .map(|(_, m)| m)
                    .collect();

            // Pair each monitor with its persisted block hash, then build
            // chain::Listen tuples that own the monitor (LDK's
            // `(ChannelMonitor, B, F, L): chain::Listen` impl requires the
            // first element by value). After `synchronize_listeners` we
            // move each monitor back out of its tuple and hand it to
            // `chain_monitor.watch_channel`.
            let monitor_tuples: Vec<
                (
                    bitcoin::BlockHash,
                    (
                        ChannelMonitor<<S as SignerProvider>::EcdsaSigner>,
                        Arc<crate::chain::EsploraBroadcaster>,
                        Arc<crate::chain::FeeEstimator>,
                        Arc<crate::logger::TracingLogger>,
                    ),
                )
            > = owned_monitors
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

            let listeners: Vec<
                (bitcoin::BlockHash, &(dyn chain::Listen + Send + Sync))
            > = monitor_tuples
                .iter()
                .map(|(h, t)| (*h, t as &(dyn chain::Listen + Send + Sync)))
                .chain(
                    std::iter::once((
                        manager_block_hash,
                        &*cm as &(dyn chain::Listen + Send + Sync),
                    ))
                )
                .collect();

            let mut cache = UnboundedCache::new();
            let chain_tip = init
                ::synchronize_listeners(
                    deps.esplora.as_ref(),
                    deps.network.into(),
                    &mut cache,
                    listeners
                ).await
                .map_err(|e| {
                    WickLightningError::Config(format!("synchronize_listeners: {e:?}"))
                })?;

            let recovered_monitors: Vec<ChannelMonitor<<S as SignerProvider>::EcdsaSigner>> =
                monitor_tuples
                    .into_iter()
                    .map(|(_, t)| t.0)
                    .collect();

            (cm, recovered_monitors, chain_tip)
        } else {
            tracing::info!(
                target: "wick_lightning",
                tenant = %tenant_id,
                "first boot — constructing fresh ChannelManager"
            );
            let best_block_header: ValidatedBlockHeader = init
                ::validate_best_block_header(deps.esplora.as_ref()).await
                .map_err(|e| {
                    WickLightningError::Config(format!("validate_best_block_header: {e:?}"))
                })?;
            let chain_params = ChainParameters {
                network: deps.network.into(),
                best_block: BestBlock::new(
                    best_block_header.header.block_hash(),
                    best_block_header.height
                ),
            };
            let cm = Arc::new(
                ChannelManager::new(
                    deps.fee_estimator.clone(),
                    chain_monitor.clone(),
                    deps.broadcaster.clone(),
                    router.clone(),
                    msg_router.clone(),
                    deps.logger.clone(),
                    signer.clone(),
                    signer.clone(),
                    signer.clone(),
                    UserConfig::default(),
                    chain_params,
                    starting_time_secs
                )
            );
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
        let gossip_sync: Arc<LnGossipSync> = Arc::new(
            P2PGossipSync::new(
                network_graph.clone(),
                None::<Arc<dyn UtxoLookup + Send + Sync>>,
                deps.logger.clone()
            )
        );

        let ephemeral = EntropySource::get_secure_random_bytes(signer.as_ref());
        let peer_manager: Arc<LnPeerManager<S>> = Arc::new(
            PeerManager::new(
                MessageHandler {
                    chan_handler: channel_manager.clone(),
                    route_handler: gossip_sync.clone(),
                    onion_message_handler: Arc::new(IgnoringMessageHandler {}),
                    custom_message_handler: Arc::new(IgnoringMessageHandler {}),
                    send_only_message_handler: chain_monitor.clone(),
                },
                starting_time_secs,
                &ephemeral,
                deps.logger.clone(),
                signer.clone()
            )
        );

        // ── Background signals ────────────────────────────────────────────────
        let (stop_tx, _) = watch::channel::<()>(());
        let (conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel::<
            (bitcoin::secp256k1::PublicKey, std::net::SocketAddr)
        >();
        let pending_sent_at: Arc<DashMap<[u8; 32], u64>> = Arc::new(DashMap::new());

        // ── Bind P2P listener ────────────────────────────────────────────────
        let listen_bind = deps.listen_addr_for(tenant_id);
        let listener = TcpListener::bind(listen_bind).await.map_err(|e| {
            WickLightningError::Config(
                format!("TcpListener::bind({listen_bind}): {e} — port in use?")
            )
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
        });

        // ── Spawn tasks ──────────────────────────────────────────────────────
        let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(5);

        // P2P inbound accept loop.
        handles.push(spawn_p2p_accept(listener, peer_manager.clone(), stop_tx.subscribe()));

        // SPV chain poll loop.
        handles.push(
            spawn_chain_poll(
                deps.esplora.clone(),
                channel_manager.clone(),
                chain_monitor.clone(),
                best_block_header,
                stop_tx.subscribe()
            )
        );

        // Fee estimate refresh loop (one retry on startup, then periodic).
        prime_fee_cache(&deps).await;
        handles.push(
            spawn_fee_refresh(deps.esplora.clone(), deps.fee_estimator.clone(), stop_tx.subscribe())
        );

        // Peer reconnect loop.
        handles.push(
            spawn_peer_reconnect(peer_store.clone(), peer_manager.clone(), stop_tx.subscribe())
        );

        // ConnectionNeeded dispatch — drives outbound dials requested by LDK.
        handles.push(spawn_connection_dispatch(conn_rx, peer_manager.clone(), stop_tx.subscribe()));

        // Gossip background: RGS re-sync every 24h + scorer persist every 10min.
        handles.push(
            gossip::spawn_gossip_tasks(
                rgs_url,
                network_graph.clone(),
                scorer.clone(),
                kv_store.clone(),
                deps.logger.clone(),
                stop_tx.subscribe()
            )
        );

        // LDK `process_events_async`.
        let mut event_handler = EventHandler::new(
            payments.clone(),
            channels.clone(),
            deps.runtime.clone(),
            Arc::new(crate::event::ChannelManagerRuntimeOps(channel_manager.clone()))
        ).with_connection_dispatch(conn_tx);
        if let Some(f) = funding {
            event_handler = event_handler.with_funding_source(f);
        }
        let event_handler = Arc::new(event_handler);

        // Build a real OutputSweeperSync when a change destination is
        // configured; otherwise pass `None` and park any SpendableOutputs
        // in LDK's monitor state until a destination is configured.
        let sweeper: Option<Arc<LnOutputSweeper<S>>> = change_destination.map(|script| {
            let best_block_for_sweeper = BestBlock::new(
                best_block_header.header.block_hash(),
                best_block_header.height
            );
            Arc::new(
                OutputSweeperSync::new(
                    best_block_for_sweeper,
                    deps.broadcaster.clone(),
                    deps.fee_estimator.clone(),
                    None::<Arc<dyn Filter + Send + Sync>>,
                    signer.clone(),
                    Arc::new(FixedChangeDest(script)),
                    kv_store.clone(),
                    deps.logger.clone()
                )
            )
        });

        handles.push(
            spawn_process_events(
                channel_manager.clone(),
                chain_monitor.clone(),
                peer_manager.clone(),
                gossip_sync.clone(),
                scorer.clone(),
                kv_store.clone(),
                deps.logger.clone(),
                event_handler,
                sweeper,
                stop_tx.clone()
            )
        );

        // Install handles into the node.
        {
            let mut g = node.bg_handles
                .lock()
                .map_err(|e| WickLightningError::Config(format!("bg_handles: {e}")))?;
            *g = handles;
        }
        node.runtime_started.store(true, std::sync::atomic::Ordering::Release);

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

impl<S> std::fmt::Debug
    for NodeBuilder<S>
    where S: WickSigner, <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync
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
    mut stop_rx: watch::Receiver<()>
)
    -> JoinHandle<()>
    where S: WickSigner, <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync
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
    mut stop_rx: watch::Receiver<()>
)
    -> JoinHandle<()>
    where S: WickSigner, <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync
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
    mut stop_rx: watch::Receiver<()>
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
    mut rx: tokio::sync::mpsc::UnboundedReceiver<
        (bitcoin::secp256k1::PublicKey, std::net::SocketAddr)
    >,
    peer_manager: Arc<LnPeerManager<S>>,
    mut stop_rx: watch::Receiver<()>
)
    -> JoinHandle<()>
    where S: WickSigner, <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync
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
    mut stop_rx: watch::Receiver<()>
)
    -> JoinHandle<()>
    where S: WickSigner, <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync
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
                    if
                        let Some(fut) = lightning_net_tokio::connect_outbound(
                            peer_manager.clone(),
                            peer.node_id,
                            peer.address
                        ).await
                    {
                        drop(fut);
                    }
                }
            }
        }
    })
}

async fn reconnect_persisted_peers<S>(peer_store: &PeerStore, peer_manager: Arc<LnPeerManager<S>>)
    where S: WickSigner, <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync
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
        if
            let Some(fut) = lightning_net_tokio::connect_outbound(
                peer_manager.clone(),
                peer.node_id,
                peer.address
            ).await
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
/// `NoChangeDest` is kept here (as a dead struct) as a compatibility
/// placeholder for paths that still construct the type for `None::<_>`
/// inference — but the real instance uses `FixedChangeDest`. We declare
/// `LnOutputSweeper` with `FixedChangeDest` so the `Some(sweeper)` branch
/// types cleanly.
type LnOutputSweeper<S> = OutputSweeperSync<
    Arc<crate::chain::EsploraBroadcaster>,
    Arc<FixedChangeDest>,
    Arc<crate::chain::FeeEstimator>,
    Arc<dyn Filter + Send + Sync>,
    Arc<PgKvStore>,
    Arc<crate::logger::TracingLogger>,
    Arc<S>
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
    stop_tx: watch::Sender<()>
)
    -> JoinHandle<()>
    where S: WickSigner, <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync
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
        if
            let Err(e) = process_events_async_with_kv_store_sync(
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
                NO_LIQUIDITY_MANAGER,
                sweeper,
                logger,
                Some(scorer),
                sleeper,
                false,
                || { Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()) }
            ).await
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

// Ensure Node<S> is both NodeApi *and* Send+Sync so the server can box it as
// `Arc<dyn NodeApi>`. The compile-time check keeps us honest.
#[allow(dead_code)]
fn _assert_node_is_api<S>(n: Arc<Node<S>>) -> Arc<dyn NodeApi>
    where S: WickSigner, <S as SignerProvider>::EcdsaSigner: MaybeSend + MaybeSync
{
    n
}
