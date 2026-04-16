//! `wick-server` binary entry point.
//!
//! Phase 1: multi-tenant actor model.
//! Boots the `NodeManager`, gRPC server, and Prometheus metrics endpoint.
//!
//! All application logic lives in `lib.rs`; this file is a thin boot shim.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;
use tonic::transport::Server;
use tracing::info;
use wick_core::{config, metrics, tracing_init};
use wick_db::Pool;
use wick_proto::wick::wallet_service_server::WalletServiceServer;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use wick_lightning::{
    from_seed, EsploraBroadcaster, EsploraChainClient, FeeEstimator, LocalKeysManager, NodeApi,
    NodeBuilder, NodeDeps, TracingLogger,
};
use wick_server::{
    grpc::WickGrpcService,
    node::manager::{ManagerConfig, NodeFactory, NodeManager},
};
use wick_core::TenantId;

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
    /// Esplora HTTP endpoint. Regtest default is a local compose service.
    #[serde(default = "default_esplora_url")]
    esplora_url: String,
    /// Bitcoin network (`mainnet` / `testnet` / `signet` / `regtest`).
    #[serde(default = "default_network")]
    network: String,
    /// 32-byte hex master seed. The server derives per-tenant seeds as
    /// `HMAC-SHA256(master_seed, tenant_id.to_string())` → the first 32
    /// bytes of the output. Required — the binary refuses to boot without
    /// it. Phase 4 replaces this with a remote VLS signer handle.
    regtest_seed_hex: String,
    /// Base port for per-tenant P2P Lightning listeners. Each tenant binds
    /// `0.0.0.0:{base + tenant_id}`. `0` means let the OS pick a port.
    #[serde(default)]
    listen_port_base: Option<u16>,
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

fn default_esplora_url() -> String {
    "http://localhost:3002".to_owned()
}

fn default_network() -> String {
    "regtest".to_owned()
}

/// Parse a hex-encoded 32-byte master seed.
fn parse_master_seed(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| anyhow::anyhow!("regtest_seed_hex must be valid hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("regtest_seed_hex must decode to exactly 32 bytes"))
}

/// Derive a deterministic per-tenant 32-byte seed from a master seed.
///
/// Uses HMAC-SHA256 keyed on the master seed with the tenant id as
/// message. The resulting tag is already 32 bytes, so we return it
/// directly. Distinct tenants → distinct seeds → distinct Lightning node
/// ids; same (master_seed, tenant_id) always reproduces the same signer,
/// which is what lets `NodeBuilder`'s restart load path reattach to
/// previously-persisted channel state.
fn derive_tenant_seed(master_seed: &[u8; 32], tenant_id: TenantId) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(master_seed).expect("HMAC accepts any key length");
    mac.update(tenant_id.to_string().as_bytes());
    mac.finalize().into_bytes().into()
}

fn parse_network(s: &str) -> Result<bitcoin::Network> {
    match s.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Ok(bitcoin::Network::Bitcoin),
        "testnet" => Ok(bitcoin::Network::Testnet),
        "signet" => Ok(bitcoin::Network::Signet),
        "regtest" => Ok(bitcoin::Network::Regtest),
        other => Err(anyhow::anyhow!("unsupported network: {other}")),
    }
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
    let network = parse_network(&cfg.network)?;
    let esplora = Arc::new(EsploraChainClient::new(&cfg.esplora_url, network)?);
    let broadcaster = Arc::new(EsploraBroadcaster::new(esplora.esplora()));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let logger = Arc::new(TracingLogger);

    // NOTE: `wick-lightning` no longer carries seed material. For regtest /
    // staging the seed-to-signer construction happens at tenant provisioning
    // via `wick-testkit::signer` (Phase-1 path) or a VLS signer in Phase-4.
    // Any `regtest_seed_hex` field in config is now ignored at the server
    // boundary — the seed flows through the provisioner, not the shared deps.
    let deps = NodeDeps {
        pg_pool: pool.raw().clone(),
        esplora,
        broadcaster,
        fee_estimator,
        logger,
        runtime: tokio::runtime::Handle::current(),
        listen_port_base: cfg.listen_port_base.unwrap_or(wick_lightning::DEFAULT_LISTEN_PORT_BASE),
    };

    // Real LocalKeysManager-backed factory. Derives a per-tenant 32-byte
    // seed via HMAC-SHA256(master_seed, tenant_id) so every tenant has a
    // distinct, deterministic signer without the server persisting any
    // per-tenant key material. Phase 4 flips this to a remote VLS signer
    // factory — the `NodeFactory` closure shape is unchanged.
    let master_seed = parse_master_seed(&cfg.regtest_seed_hex)?;
    let factory: NodeFactory = Arc::new(move |tenant_id, deps| {
        let tenant_seed = derive_tenant_seed(&master_seed, tenant_id);
        Box::pin(async move {
            let signer = Arc::new(from_seed(tenant_seed));
            let node = NodeBuilder::<LocalKeysManager>::new(tenant_id, deps)
                .with_signer(signer)
                .build()
                .await?;
            let node: Arc<dyn NodeApi> = node;
            Ok(node)
        })
    });

    let manager = Arc::new(NodeManager::new(
        ManagerConfig {
            memory_budget_bytes: cfg.memory_budget_bytes,
            ..ManagerConfig::default()
        },
        deps,
        factory,
    ));

    let grpc_service = WickGrpcService::new(manager.clone(), pool.clone());

    info!(
        grpc = %cfg.grpc_addr,
        metrics = %cfg.metrics_addr,
        "wick-server online (phase 1 — multi-tenant actor model)"
    );

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

    manager.shutdown_all().await;
    info!("all node actors stopped — goodbye");
    Ok(())
}
