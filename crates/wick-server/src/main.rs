//! `wick-server` binary entry point.
//!
//! Phase 2: park/wake lifecycle — activity poller, memory evictor, and error
//! recovery loops run in the background.
//! Boots the `NodeManager`, gRPC server, and Prometheus metrics endpoint.
//!
//! All application logic lives in `lib.rs`; this file is a thin boot shim.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Deserialize;
use tonic::transport::Server;
use tracing::info;
use wick_core::{config, metrics, tracing_init, WickIdentity, WickNetwork};
use wick_db::Pool;
use wick_proto::wick::wallet_service_server::WalletServiceServer;

use wick_lightning::{EsploraBroadcaster, EsploraChainClient, FeeEstimator, NodeDeps, TracingLogger};

use wick_server::{
    factory,
    grpc::WickGrpcService,
    node::manager::{ManagerConfig, NodeManager},
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
            wake_deadline: self
                .wake_deadline_secs
                .map(Duration::from_secs)
                .unwrap_or(base.wake_deadline),
            activity_poll_interval: self
                .activity_poll_interval_secs
                .map(Duration::from_secs)
                .unwrap_or(base.activity_poll_interval),
            idle_threshold: self
                .idle_threshold_secs
                .map(Duration::from_secs)
                .unwrap_or(base.idle_threshold),
            max_error_attempts: self.max_error_attempts.unwrap_or(base.max_error_attempts),
            error_recovery_interval: self
                .error_recovery_interval_secs
                .map(Duration::from_secs)
                .unwrap_or(base.error_recovery_interval),
            memory_evictor_interval: self
                .memory_evictor_interval_secs
                .map(Duration::from_secs)
                .unwrap_or(base.memory_evictor_interval),
            lru_eviction_threshold: self
                .lru_eviction_threshold
                .unwrap_or(base.lru_eviction_threshold),
            emergency_eviction_threshold: self
                .emergency_eviction_threshold
                .unwrap_or(base.emergency_eviction_threshold),
            evictor_target_pressure: self
                .evictor_target_pressure
                .unwrap_or(base.evictor_target_pressure),
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
    let identity = WickIdentity::from_phrase(&cfg.server_mnemonic, cfg.network)
        .context("server_mnemonic is not a valid BIP39 phrase")?;
    Ok(identity.seed)
}

// ── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_init::install();

    let config_path = std::env::args()
        .nth(2)
        .or_else(|| std::env::var("WICK_CONFIG").ok())
        .unwrap_or_else(|| "deploy/docker/config.dev.toml".to_owned());

    let cfg: Config = config::load(&config_path)?;
    metrics::install(cfg.metrics_addr)?;

    let pool = Pool::connect(&cfg.database_url, cfg.max_db_connections).await?;

    // Build the shared LDK dependencies once. Per-tenant nodes clone these
    // Arcs — see `wick_lightning::NodeDeps`.
    let esplora_url = cfg.esplora_url
        .as_deref()
        .unwrap_or(cfg.network.default_esplora());
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
    let factory = factory::node_factory(master_seed, deps);

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

    let grpc_service = WickGrpcService::new(manager.clone(), pool.clone());

    tokio::select! {
        result = Server::builder()
            .add_service(WalletServiceServer::new(grpc_service))
            .serve(cfg.grpc_addr) =>
        {
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

    manager.shutdown_all().await;
    info!("all node actors stopped — goodbye");
    Ok(())
}
