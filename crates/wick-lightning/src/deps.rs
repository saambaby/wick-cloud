//! Shared-resource bundle consumed by [`crate::NodeBuilder`].
//!
//! The server builds each `Arc` once at startup and clones them into every
//! [`crate::Node`] it spawns. Per-tenant state (channel manager, chain
//! monitor, peer manager, event handler, `PgKvStore`) is constructed fresh
//! per tenant.

use std::net::SocketAddr;
use std::sync::Arc;

use sqlx::PgPool;
use tokio::runtime::Handle;
use wick_core::{TenantId, WickNetwork};

use crate::chain::{EsploraBroadcaster, EsploraChainClient, FeeEstimator};
use crate::logger::TracingLogger;

/// Default starting port for per-tenant Lightning P2P listeners.
///
/// Actual port bound is `listen_port_base + tenant_id`. Set to `0` to have the
/// OS pick a free port (useful in tests, each tenant gets a unique random
/// port).
pub const DEFAULT_LISTEN_PORT_BASE: u16 = 9735;

/// Dependencies shared across all tenants.
///
/// All heavy fields are `Arc`-wrapped — cheap to clone per tenant.
#[derive(Debug, Clone)]
pub struct NodeDeps {
    /// Postgres pool. Each tenant's schema is isolated but shares the pool.
    pub pg_pool: PgPool,
    /// Which network the server is running against.
    pub network: WickNetwork,
    /// Esplora chain client (`BlockSource`).
    pub esplora: Arc<EsploraChainClient>,
    /// Transaction broadcaster.
    pub broadcaster: Arc<EsploraBroadcaster>,
    /// Fee estimator — a single polling task fills this for the whole process.
    pub fee_estimator: Arc<FeeEstimator>,
    /// LDK logger bridging to `tracing`.
    pub logger: Arc<TracingLogger>,
    /// Handle to the Tokio runtime the node will spawn background tasks on.
    ///
    /// Must be a multi-threaded runtime (the default `#[tokio::main]`);
    /// synchronous LDK callbacks bridge to async via `block_in_place`.
    pub runtime: Handle,
    /// Base port for per-tenant P2P listeners.
    ///
    /// Each tenant binds `0.0.0.0:{base + tenant_id}`. Set `base = 0` for tests
    /// to let the OS assign a random free port per tenant.
    pub listen_port_base: u16,
}

impl NodeDeps {
    /// Compute the listen [`SocketAddr`] for a given tenant.
    ///
    /// Uses `listen_port_base + offset` on `0.0.0.0`. If
    /// `listen_port_base == 0`, returns `0.0.0.0:0` (OS-assigned port) — the
    /// builder will read back the bound port after `TcpListener::bind`.
    ///
    /// The port offset is derived from the last two bytes of the UUID so it
    /// is stable per tenant but unpredictable to external observers.
    #[must_use]
    pub fn listen_addr_for(&self, tenant_id: TenantId) -> SocketAddr {
        let port = if self.listen_port_base == 0 {
            0
        } else {
            let uuid = tenant_id.as_uuid();
            let b = uuid.as_bytes();
            let offset = u16::from_le_bytes([b[14], b[15]]);
            self.listen_port_base.saturating_add(offset)
        };
        SocketAddr::from(([0, 0, 0, 0], port))
    }
}
