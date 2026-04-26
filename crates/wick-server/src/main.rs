//! `wick-server` binary entry point.
//!
//! Phase 2: park/wake lifecycle — activity poller, memory evictor, and error
//! recovery loops run in the background.
//! Boots the `NodeManager`, gRPC server, and Prometheus metrics endpoint.
//!
//! All application logic lives in `lib.rs`; this file is a thin boot shim.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{ Context, Result };
use serde::Deserialize;
use tokio::sync::RwLock;
use tonic::transport::Server;
use tracing::{ info, warn };
use wick_core::{ config, metrics, tracing_init, LspConfig, WickIdentity, WickNetwork };
use wick_db::Pool;
use wick_proto::wick::wallet_service_server::WalletServiceServer;

use wick_lightning::{
    EsploraBroadcaster,
    EsploraChainClient,
    FeeEstimator,
    NodeDeps,
    TracingLogger,
};

use wick_lsp::{ LspBuilder, LspDaemon, LspPartialConfig, OpeningParamsView };
use wick_lsp::daemon::GriefConfig;
use wick_proto::wick::admin_service_server::AdminServiceServer;
use wick_proto::wick::signer_service_server::SignerServiceServer;
use wick_vls::SignerSessionRegistry;
use wick_server::{
    factory,
    grpc::{ LspInfo, WickAdminGrpcService, WickGrpcService },
    lsp_bridge::ManagerLspBridge,
    node::manager::{ ManagerConfig, NodeManager },
    signer_service::WickSignerGrpcService,
};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Config {
    database_url: String,
    #[serde(default = "default_max_db_connections")]
    max_db_connections: u32,
    #[serde(default = "default_metrics_addr")]
    metrics_addr: SocketAddr,
    #[serde(default = "default_grpc_addr")]
    grpc_addr: SocketAddr,
    /// Total memory budget for node actors (bytes). Default: 512 MiB.
    #[serde(default = "default_memory_budget_bytes")]
    memory_budget_bytes: usize,
    /// Bitcoin network (`regtest` / `signet` / `mutinynet`). Default: `mutinynet`.
    ///
    /// Per-network defaults (Esplora URL, RGS URL, seed peers) are derived from
    /// [`WickNetwork`] and can be overridden individually.
    #[serde(default)]
    network: WickNetwork,
    /// Esplora HTTP endpoint. Omit to use the per-network default from
    /// [`WickNetwork::default_esplora`].
    #[serde(default)]
    esplora_url: Option<String>,
    /// BIP39 mnemonic for the server master seed (12 or 24 words).
    ///
    /// The master seed is the first 32 bytes of `mnemonic.to_seed("")`.
    /// Phase 4 replaces this entirely with a remote VLS signer handle.
    server_mnemonic: String,
    /// Base port for per-tenant P2P Lightning listeners. Each tenant binds
    /// `0.0.0.0:{base + tenant_id}`. `0` means let the OS pick a port.
    #[serde(default)]
    listen_port_base: Option<u16>,
    /// Phase-2 park/wake tuning. All fields are optional; defaults in
    /// [`ManagerConfig::default()`] are used for any omitted key.
    #[serde(default)]
    park_wake: ParkWakeConfig,
    /// Phase-3 LSP daemon configuration. When `[lsp].enabled = false`
    /// (the default) the server boots without an in-process LSP and
    /// behaves identically to a Phase 2 deployment.
    #[serde(default)]
    lsp: LspConfig,
    /// Shared secret used to authenticate the operator's admin gRPC
    /// calls (`RegisterLspIdentity`, `LspWatchPendingFunding`,
    /// `LspFinalizeFunding`). Required when `[lsp].enabled = true` —
    /// the admin RPCs reject every call when the secret is missing or
    /// empty. Read from `WICK_ADMIN_SECRET` env var if not set in
    /// config; admin RPCs gate on a metadata header equal to this.
    /// Macaroon scope plumbing replaces this in slice 3.3c.
    #[serde(default)]
    admin_secret: Option<String>,
}

/// Phase-2 park/wake tuning knobs exposed through TOML. Maps 1-to-1 onto
/// [`ManagerConfig`] fields; all are optional with sensible defaults.
#[derive(Debug, Default, Deserialize)]
struct ParkWakeConfig {
    /// Maximum wall-clock duration for a single wake (seconds). Default: 2.
    #[serde(default)]
    wake_deadline_secs: Option<u64>,
    /// Interval between activity-poller ticks (seconds). Default: 30.
    #[serde(default)]
    activity_poll_interval_secs: Option<u64>,
    /// Minimum idle duration before a tenant becomes a park candidate (seconds). Default: 300.
    #[serde(default)]
    idle_threshold_secs: Option<u64>,
    /// Max consecutive failed wakes before transitioning to ERROR. Default: 5.
    #[serde(default)]
    max_error_attempts: Option<u8>,
    /// Interval between error-recovery probe ticks (seconds). Default: 60.
    #[serde(default)]
    error_recovery_interval_secs: Option<u64>,
    /// Interval between memory-evictor ticks (seconds). Default: 10.
    #[serde(default)]
    memory_evictor_interval_secs: Option<u64>,
    /// LRU eviction pressure threshold (0.0–1.0). Default: 0.80.
    #[serde(default)]
    lru_eviction_threshold: Option<f64>,
    /// Emergency eviction pressure threshold (0.0–1.0). Default: 0.95.
    #[serde(default)]
    emergency_eviction_threshold: Option<f64>,
    /// Target pressure the evictor aims for after a tick (0.0–1.0). Default: 0.70.
    #[serde(default)]
    evictor_target_pressure: Option<f64>,
}

impl ParkWakeConfig {
    fn apply(&self, base: ManagerConfig, memory_budget_bytes: usize) -> ManagerConfig {
        use std::time::Duration;
        ManagerConfig {
            memory_budget_bytes,
            wake_deadline: self.wake_deadline_secs
                .map(Duration::from_secs)
                .unwrap_or(base.wake_deadline),
            activity_poll_interval: self.activity_poll_interval_secs
                .map(Duration::from_secs)
                .unwrap_or(base.activity_poll_interval),
            idle_threshold: self.idle_threshold_secs
                .map(Duration::from_secs)
                .unwrap_or(base.idle_threshold),
            max_error_attempts: self.max_error_attempts.unwrap_or(base.max_error_attempts),
            error_recovery_interval: self.error_recovery_interval_secs
                .map(Duration::from_secs)
                .unwrap_or(base.error_recovery_interval),
            memory_evictor_interval: self.memory_evictor_interval_secs
                .map(Duration::from_secs)
                .unwrap_or(base.memory_evictor_interval),
            lru_eviction_threshold: self.lru_eviction_threshold.unwrap_or(
                base.lru_eviction_threshold
            ),
            emergency_eviction_threshold: self.emergency_eviction_threshold.unwrap_or(
                base.emergency_eviction_threshold
            ),
            evictor_target_pressure: self.evictor_target_pressure.unwrap_or(
                base.evictor_target_pressure
            ),
            ..base
        }
    }
}

fn default_max_db_connections() -> u32 {
    16
}

#[allow(clippy::expect_used)]
fn default_metrics_addr() -> SocketAddr {
    "0.0.0.0:9464".parse().expect("valid default socket addr")
}

#[allow(clippy::expect_used)]
fn default_grpc_addr() -> SocketAddr {
    "0.0.0.0:50051".parse().expect("valid default socket addr")
}

fn default_memory_budget_bytes() -> usize {
    512 * 1024 * 1024 // 512 MiB
}

/// Resolve the 32-byte master seed from the configured BIP39 mnemonic.
fn resolve_master_seed(cfg: &Config) -> Result<[u8; 32]> {
    let identity = WickIdentity::from_phrase(&cfg.server_mnemonic, cfg.network).context(
        "server_mnemonic is not a valid BIP39 phrase"
    )?;
    Ok(identity.seed)
}

/// Bundle returned from [`resolve_lsp_identity`] when the operator-mode
/// LSP is enabled.
struct ResolvedLsp {
    pubkey: bitcoin::secp256k1::PublicKey,
    address: String,
}

/// Resolve the LSP's *public* identity from config.
///
/// The pubkey is read from `[lsp].pubkey_hex` (operators publish this
/// at deployment so tenants know which counterparty to expect LSPS2
/// messages from). The matching signing seed is supplied at runtime by
/// the operator's SDK via the admin `RegisterLspIdentity` RPC and is
/// never read by the server itself — this function does no key
/// derivation.
fn resolve_lsp_identity(cfg: &Config) -> Result<ResolvedLsp> {
    let pk_hex = cfg.lsp.pubkey_hex
        .as_deref()
        .ok_or_else(|| {
            anyhow::anyhow!("lsp.pubkey_hex must be set when [lsp].enabled = true")
        })?;
    let bytes = hex::decode(pk_hex).context("lsp.pubkey_hex is not valid hex")?;
    let pubkey = bitcoin::secp256k1::PublicKey
        ::from_slice(&bytes)
        .context("lsp.pubkey_hex is not a valid 33-byte compressed secp256k1 pubkey")?;
    Ok(ResolvedLsp {
        pubkey,
        address: cfg.lsp.listen_addr.to_string(),
    })
}

// ── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_init::install();

    let config_path = std::env
        ::args()
        .nth(2)
        .or_else(|| std::env::var("WICK_CONFIG").ok())
        .unwrap_or_else(|| "deploy/docker/config.dev.toml".to_owned());

    let cfg: Config = config::load(&config_path)?;
    metrics::install(cfg.metrics_addr)?;

    let pool = Pool::connect(&cfg.database_url, cfg.max_db_connections).await?;

    // Build the shared LDK dependencies once. Per-tenant nodes clone these
    // Arcs — see `wick_lightning::NodeDeps`.
    let esplora_url = cfg.esplora_url.as_deref().unwrap_or(cfg.network.default_esplora());
    let esplora = Arc::new(EsploraChainClient::new(esplora_url, cfg.network)?);
    let broadcaster = Arc::new(EsploraBroadcaster::new(esplora.esplora()));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let logger = Arc::new(TracingLogger);

    // `wick-lightning` no longer carries seed material. The master seed
    // is resolved from `server_mnemonic` below and flows to the node
    // factory, which derives per-tenant seeds; Phase 4 replaces the
    // factory with a VLS-backed closure and removes seed-at-rest entirely.
    let deps = NodeDeps {
        pg_pool: pool.raw().clone(),
        network: cfg.network,
        esplora,
        broadcaster,
        fee_estimator,
        logger,
        runtime: tokio::runtime::Handle::current(),
        listen_port_base: cfg.listen_port_base.unwrap_or(wick_lightning::DEFAULT_LISTEN_PORT_BASE),
    };

    let master_seed = resolve_master_seed(&cfg)?;

    // Resolve the in-process LSP identity (if enabled) so tenant nodes
    // can be wired as LSPS2 clients pointing at it. The actual LSP
    // *node* (a second Lightning identity running the LSPS2 service
    // role + UTXO pool + webhook dispatcher) is bootstrapped by the
    // wick-lsp daemon (slice 3.2). At this layer we only need the
    // operator's published pubkey + listen address.
    let lsp_state = if cfg.lsp.enabled {
        match resolve_lsp_identity(&cfg) {
            Ok(state) => Some(state),
            Err(e) => {
                warn!(error = %e, "lsp.enabled = true but identity resolution failed; LSP disabled");
                None
            }
        }
    } else {
        None
    };
    let lsp_peer_for_tenants = lsp_state.as_ref().map(|s| s.pubkey);

    let factory = factory::node_factory_with_lsp(master_seed, deps, lsp_peer_for_tenants);

    let manager_config = cfg.park_wake.apply(ManagerConfig::default(), cfg.memory_budget_bytes);
    info!(
        grpc = %cfg.grpc_addr,
        metrics = %cfg.metrics_addr,
        memory_budget_mib = manager_config.memory_budget_bytes / (1024 * 1024),
        idle_threshold_secs = manager_config.idle_threshold.as_secs(),
        wake_deadline_ms = manager_config.wake_deadline.as_millis(),
        activity_poll_secs = manager_config.activity_poll_interval.as_secs(),
        error_recovery_secs = manager_config.error_recovery_interval.as_secs(),
        "wick-server online (phase 2 — park/wake lifecycle)"
    );

    let manager = Arc::new(NodeManager::new(manager_config, factory));

    // Phase-2 background loops. Retained so they can be aborted on shutdown.
    let poller_handle = manager.clone().spawn_activity_poller();
    let evictor_handle = manager.clone().spawn_memory_evictor();
    let recovery_handle = manager.clone().spawn_error_recovery();

    // Phase-3 LSP. Boots into a *pending* slot — no LDK signing
    // material is read at this point. The operator's SDK installs the
    // signing seed dynamically via the admin `RegisterLspIdentity` RPC,
    // which fills the slot. Failures during builder construction are
    // logged and the server continues without an LSP — same behaviour
    // as Phase 2.
    let (lsp_builder, lsp_daemon_slot) = if let Some(ref state) = lsp_state {
        match build_lsp_builder(&cfg, manager.clone()).await {
            Ok(builder) => {
                info!(
                    lsp_pubkey = %state.pubkey,
                    lsp_address = %state.address,
                    "lsp slot ready, awaiting RegisterLspIdentity"
                );
                let slot: Arc<RwLock<Option<LspDaemon>>> = Arc::new(RwLock::new(None));
                (Some(Arc::new(builder)), Some(slot))
            }
            Err(e) => {
                warn!(error = %e, "lsp builder construction failed; serving without LSP");
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    let grpc_service = if let (Some(state), Some(slot)) = (&lsp_state, &lsp_daemon_slot) {
        WickGrpcService::with_lsp(
            manager.clone(),
            pool.clone(),
            LspInfo {
                pubkey: state.pubkey,
                address: state.address.clone(),
                ready: false,
            },
            slot.clone()
        )
    } else {
        WickGrpcService::new(manager.clone(), pool.clone())
    };

    // Admin service — only mounted when both an LSP slot and a builder
    // exist. Auth gate is the configured `admin_secret` (or
    // `WICK_ADMIN_SECRET` env var). Empty / missing secret leaves the
    // admin service unmounted entirely so it's impossible to reach
    // without explicit operator opt-in.
    let admin_service = match (lsp_builder.clone(), lsp_daemon_slot.clone()) {
        (Some(builder), Some(slot)) => {
            let secret = cfg.admin_secret
                .clone()
                .or_else(|| std::env::var("WICK_ADMIN_SECRET").ok())
                .filter(|s| !s.is_empty());
            match secret {
                Some(secret) =>
                    Some(
                        WickAdminGrpcService::new(
                            builder,
                            slot,
                            lsp_state.as_ref().map(|s| s.pubkey),
                            secret
                        )
                    ),
                None => {
                    warn!(
                        "[lsp].enabled = true but admin_secret / WICK_ADMIN_SECRET is unset — \
                         admin service will not be mounted; LSP cannot be registered"
                    );
                    None
                }
            }
        }
        _ => None,
    };

    // Phase-4 remote-signer registry. Shared between (a) the per-tenant
    // node factory (so each Node holds a `wick_vls::SignerSession` that
    // resolves the live SDK connection on every signer call) and (b) the
    // gRPC `SignerService.Attach` handler (which installs the SDK side of
    // the bidi stream on connect). Most-recent-wins on reconnect is
    // implemented inside `SignerSessionRegistry::register`.
    let signer_registry = Arc::new(SignerSessionRegistry::new());
    let signer_service = WickSignerGrpcService::new(pool.raw().clone(), signer_registry.clone());

    let server = Server::builder()
        .add_service(WalletServiceServer::new(grpc_service))
        .add_service(SignerServiceServer::new(signer_service));
    let server = if let Some(svc) = admin_service {
        server.add_service(AdminServiceServer::new(svc))
    } else {
        server
    };

    tokio::select! {
        result = server.serve(cfg.grpc_addr) => {
            result?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("wick-server shutting down");
        }
    }

    // Stop background loops before shutting down actors.
    poller_handle.abort();
    evictor_handle.abort();
    recovery_handle.abort();
    if let Some(slot) = lsp_daemon_slot {
        if let Some(daemon) = slot.write().await.take() {
            daemon.shutdown().await;
        }
    }

    manager.shutdown_all().await;
    info!("all node actors stopped — goodbye");
    Ok(())
}

/// Build the LSP daemon *builder* — a pre-registration handle that
/// holds the dependencies and partial config needed to construct the
/// daemon once a Lightning seed arrives via the admin
/// `RegisterLspIdentity` RPC.
///
/// No seed material is read here. The server's role is to assemble the
/// chain plumbing (`NodeDeps`), the LSPS2 fee menu, the upstream peer
/// hint, and the dispatcher; everything else (signing keys, promise
/// secret, tenant id) is derived inside [`LspBuilder::build_with_seed`]
/// at registration time from the seed the operator's SDK supplies.
async fn build_lsp_builder(cfg: &Config, manager: Arc<NodeManager>) -> Result<LspBuilder> {
    use bitcoin::secp256k1::PublicKey;

    let pool = wick_db::Pool::connect(&cfg.database_url, cfg.max_db_connections).await?;
    let esplora_url = cfg.esplora_url.as_deref().unwrap_or(cfg.network.default_esplora());
    let esplora = Arc::new(EsploraChainClient::new(esplora_url, cfg.network)?);
    let broadcaster = Arc::new(EsploraBroadcaster::new(esplora.esplora()));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let logger = Arc::new(TracingLogger);
    let lsp_deps = NodeDeps {
        pg_pool: pool.raw().clone(),
        network: cfg.network,
        esplora,
        broadcaster,
        fee_estimator,
        logger,
        runtime: tokio::runtime::Handle::current(),
        listen_port_base: cfg.listen_port_base.unwrap_or(wick_lightning::DEFAULT_LISTEN_PORT_BASE),
    };

    let resolved_upstream = cfg.lsp.resolved_upstream(cfg.network);
    let upstream_peer = match resolved_upstream {
        Some((pk_hex, addr)) => {
            match PublicKey::from_slice(&hex::decode(&pk_hex).unwrap_or_default()) {
                Ok(pk) => Some((pk, addr)),
                Err(_) => {
                    warn!(pubkey = %pk_hex, "lsp upstream pubkey is not valid hex/secp256k1; skipping");
                    None
                }
            }
        }
        None => None,
    };

    let opening_params = OpeningParamsView {
        min_fee_msat: cfg.lsp.min_fee_msat,
        proportional_ppm: cfg.lsp.proportional_ppm,
        min_payment_size_msat: cfg.lsp.min_payment_size_msat,
        max_payment_size_msat: cfg.lsp.max_payment_size_msat,
    };

    let bridge = Arc::new(ManagerLspBridge::new(manager));
    Ok(
        LspBuilder::new(
            lsp_deps,
            LspPartialConfig {
                opening_params,
                upstream_peer,
                reorg_safety_threshold_sats: cfg.lsp.reorg_safety_threshold_sats,
                max_jit_channel_sats: cfg.lsp.max_jit_channel_sats,
                grief: GriefConfig {
                    half_life_hours: cfg.lsp.grief_half_life_hours,
                    penalty: cfg.lsp.grief_penalty,
                    reward: cfg.lsp.grief_reward,
                    rejection_threshold: cfg.lsp.grief_rejection_threshold,
                },
            },
            bridge
        )
    )
}
