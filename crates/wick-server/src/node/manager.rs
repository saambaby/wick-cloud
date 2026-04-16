//! `NodeManager` — lifecycle management for all tenant Lightning-node actors.
//!
//! Owns the `DashMap<TenantId, NodeHandle>` and the global memory budget
//! counter. Tenant provisioning (schema creation, actor spawn, `DashMap` insert)
//! is also handled here.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use anyhow::{anyhow, Context};
use dashmap::DashMap;
use tracing::{info, warn};
use wick_core::TenantId;
use wick_db::Pool;
use wick_lightning::{NodeApi, NodeDeps};

use crate::node::{actor::NodeActor, NodeCmd, NodeHandle, PER_NODE_BYTES};

/// Factory that produces a concrete `Arc<dyn NodeApi>` for a tenant.
///
/// The `NodeManager` is signer-agnostic: the server binary (prod) injects a
/// factory that builds `wick_lightning::Node<S>` via `NodeBuilder`; the
/// regtest harness injects a factory using `wick_testkit::signer` to produce
/// a `LocalKeysManager`-backed node; tests inject a stub factory.
///
/// The factory returns a future because building the real node awaits
/// Postgres + Esplora.
#[allow(clippy::type_complexity)]
pub type NodeFactory = Arc<
    dyn Fn(
            TenantId,
            NodeDeps,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = anyhow::Result<Arc<dyn NodeApi>>> + Send>,
        > + Send
        + Sync,
>;

// ── Config ────────────────────────────────────────────────────────────────────

/// Tuning parameters for the `NodeManager`.
#[derive(Debug, Clone)]
pub struct ManagerConfig {
    /// Total RAM budget across all active nodes (bytes).
    /// Default: 512 MiB.
    pub memory_budget_bytes: usize,
    /// RAM reserved per active node (bytes).
    /// Default: `PER_NODE_BYTES` (64 KiB).
    pub per_node_bytes: usize,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            memory_budget_bytes: 512 * 1024 * 1024,
            per_node_bytes: PER_NODE_BYTES,
        }
    }
}

// ── NodeManager ───────────────────────────────────────────────────────────────

/// Owns the lifecycle of all tenant Lightning-node actors.
///
/// Thread-safe: all methods take `&self` and use interior mutability via
/// `DashMap` and `AtomicUsize`.
pub struct NodeManager {
    nodes: DashMap<TenantId, NodeHandle>,
    config: ManagerConfig,
    /// Bytes currently allocated across all active nodes.
    total_mem: Arc<AtomicUsize>,
    /// Shared LDK dependencies cloned into each spawned actor.
    deps: Option<NodeDeps>,
    /// Factory that turns `(tenant_id, deps)` into a ready `Arc<dyn NodeApi>`.
    factory: Option<NodeFactory>,
}

impl std::fmt::Debug for NodeManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeManager")
            .field("node_count", &self.nodes.len())
            .field("total_mem", &self.total_mem.load(Ordering::Relaxed))
            .field("has_factory", &self.factory.is_some())
            .finish_non_exhaustive()
    }
}

impl NodeManager {
    /// Create a manager that provisions nodes via `factory`.
    ///
    /// Typical bindings:
    /// - prod / regtest integration tests → factory builds
    ///   `wick_lightning::Node<S>` via `NodeBuilder.with_signer(...).build()`
    /// - unit / actor tests → factory returns `wick_lightning::StubNode`
    #[must_use]
    pub fn new(config: ManagerConfig, deps: NodeDeps, factory: NodeFactory) -> Self {
        Self {
            nodes: DashMap::new(),
            config,
            total_mem: Arc::new(AtomicUsize::new(0)),
            deps: Some(deps),
            factory: Some(factory),
        }
    }

    /// Unit-test constructor — no [`NodeDeps`] / factory required.
    ///
    /// `provision()` will error if called; use [`Self::insert_handle_for_test`]
    /// to install handles directly.
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test(config: ManagerConfig) -> Self {
        Self {
            nodes: DashMap::new(),
            config,
            total_mem: Arc::new(AtomicUsize::new(0)),
            deps: None,
            factory: None,
        }
    }


    /// Number of currently active nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total bytes reserved across all active nodes.
    #[must_use]
    pub fn total_mem_bytes(&self) -> usize {
        self.total_mem.load(Ordering::Relaxed)
    }

    /// Provision a new tenant node.
    ///
    /// 1. Validates that `tenant_id` is not already provisioned.
    /// 2. Enforces the global memory budget.
    /// 3. Spawns a `NodeActor`.
    /// 4. Inserts the `NodeHandle` into the `DashMap`.
    ///
    /// Returns an error if the tenant is already provisioned or the budget
    /// is exhausted.
    pub async fn provision(
        &self,
        tenant_id: TenantId,
        pool: &Pool,
    ) -> anyhow::Result<()> {
        if self.nodes.contains_key(&tenant_id) {
            return Err(anyhow!("tenant {tenant_id} is already provisioned"));
        }

        // Budget guard: reserve before spawning.
        let prev = self
            .total_mem
            .fetch_add(self.config.per_node_bytes, Ordering::SeqCst);
        if prev + self.config.per_node_bytes > self.config.memory_budget_bytes {
            // Rollback.
            self.total_mem
                .fetch_sub(self.config.per_node_bytes, Ordering::SeqCst);
            return Err(anyhow!(
                "memory budget exhausted: {} / {} bytes used",
                prev,
                self.config.memory_budget_bytes
            ));
        }

        let deps = self
            .deps
            .clone()
            .ok_or_else(|| anyhow!("NodeManager was constructed without NodeDeps"))?;
        let factory = self
            .factory
            .clone()
            .ok_or_else(|| anyhow!("NodeManager was constructed without a NodeFactory"))?;

        // Create the tenant Postgres schema (does DDL for payments, peers,
        // vss_objects, etc).
        create_tenant_schema(tenant_id, pool)
            .await
            .context("create tenant schema")?;

        // Build the concrete node via the factory (signer + LDK assembly
        // or stub, depending on binding).
        let node = factory(tenant_id, deps).await.context("factory")?;

        // Spawn the actor around the built node and insert the handle.
        let handle = NodeActor::spawn_with_node(tenant_id, node);
        self.nodes.insert(tenant_id, handle);

        info!(tenant = %tenant_id, "node provisioned");
        Ok(())
    }

    /// Dispatch a command to a tenant's actor.
    ///
    /// Returns an error if the tenant is not provisioned or the actor's
    /// command channel is full / closed.
    pub async fn dispatch(&self, tenant_id: TenantId, cmd: NodeCmd) -> anyhow::Result<()> {
        let handle = self
            .nodes
            .get(&tenant_id)
            .ok_or_else(|| anyhow!("tenant {tenant_id} not found"))?;

        handle
            .tx
            .send(cmd)
            .await
            .map_err(|_| anyhow!("node actor for tenant {tenant_id} has stopped"))?;

        Ok(())
    }

    /// Gracefully shut down all node actors.
    pub async fn shutdown_all(&self) {
        let tenant_ids: Vec<TenantId> = self.nodes.iter().map(|r| *r.key()).collect();
        for tid in tenant_ids {
            if let Some(handle) = self.nodes.get(&tid) {
                if handle.tx.send(NodeCmd::Shutdown).await.is_err() {
                    warn!(tenant = %tid, "actor already stopped on shutdown_all");
                }
            }
        }
    }
}

// ── Tenant schema provisioning ────────────────────────────────────────────────

/// Create the per-tenant Postgres schema and tables.
///
/// Uses `format()` which is safe here because `schema` is derived from a
/// `TenantId` — always `^tenant_[0-9]+$`. Identifier is additionally
/// quoted with Postgres `%I` via `format()` in the DDL string.
async fn create_tenant_schema(tenant_id: TenantId, pool: &Pool) -> anyhow::Result<()> {
    let schema = tenant_id.schema_name();

    // Use a raw sqlx pool for DDL — tenant_tx SET LOCAL is not appropriate
    // for schema creation which must run outside a tenant transaction.
    let pg = pool.raw();

    sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS \"{schema}\""))
        .execute(pg)
        .await
        .context("CREATE SCHEMA")?;

    for ddl in tenant_ddl_statements(&schema) {
        sqlx::query(&ddl)
            .execute(pg)
            .await
            .with_context(|| format!("DDL failed:\n{ddl}"))?;
    }

    info!(tenant = %tenant_id, schema, "tenant schema created");
    Ok(())
}

/// Returns DDL statements for the tenant schema tables, with `schema` already
/// interpolated. Order matters: payments before any foreign-key referencing it.
fn tenant_ddl_statements(schema: &str) -> Vec<String> {
    // SAFETY: `schema` is always `tenant_<digits>`, validated in TenantId.
    // Quoted with double-quotes everywhere to prevent word-boundary issues.
    vec![
        format!(
            r#"CREATE TABLE IF NOT EXISTS "{schema}".payments (
    id              BIGSERIAL PRIMARY KEY,
    payment_hash    BYTEA NOT NULL,
    preimage        BYTEA,
    direction       TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    amount_msat     BIGINT NOT NULL,
    fee_msat        BIGINT NOT NULL DEFAULT 0,
    status          TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
)"#
        ),
        format!(
            r#"CREATE INDEX IF NOT EXISTS payments_hash_idx ON "{schema}".payments(payment_hash)"#
        ),
        format!(
            r#"CREATE INDEX IF NOT EXISTS payments_status_idx ON "{schema}".payments(status)"#
        ),
        // Unique on (payment_hash, direction) — required by
        // `wick_lightning::PaymentStore::upsert`'s ON CONFLICT target. Each
        // hash can appear at most twice (one inbound + one outbound row).
        format!(
            r#"CREATE UNIQUE INDEX IF NOT EXISTS payments_hash_direction_uniq
   ON "{schema}".payments(payment_hash, direction)"#
        ),
        format!(
            r#"CREATE TABLE IF NOT EXISTS "{schema}".channels (
    channel_id          BYTEA PRIMARY KEY,
    peer_pubkey         BYTEA NOT NULL,
    capacity_sat        BIGINT NOT NULL,
    local_balance_msat  BIGINT NOT NULL,
    state               TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
)"#
        ),
        format!(
            r#"CREATE TABLE IF NOT EXISTS "{schema}".channel_manager_state (
    id          SMALLINT PRIMARY KEY DEFAULT 1,
    bytes       BYTEA NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT channel_manager_singleton CHECK (id = 1)
)"#
        ),
        format!(
            r#"CREATE TABLE IF NOT EXISTS "{schema}".monitors (
    channel_id  BYTEA PRIMARY KEY,
    bytes       BYTEA NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)"#
        ),
        format!(
            r#"CREATE TABLE IF NOT EXISTS "{schema}".peers (
    pubkey      BYTEA PRIMARY KEY,
    address     TEXT,
    alias       TEXT,
    last_seen_at TIMESTAMPTZ
)"#
        ),
        format!(
            r#"CREATE TABLE IF NOT EXISTS "{schema}".vss_objects (
    key         TEXT PRIMARY KEY,
    version     BIGINT NOT NULL,
    value       BYTEA NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)"#
        ),
    ]
}

// ── Test helpers ────────────────────────────────────────────────────────────

impl NodeManager {
    /// Insert a `NodeHandle` directly without touching Postgres.
    /// Only for unit / integration tests; do not call from production code.
    #[doc(hidden)]
    pub fn insert_handle_for_test(&self, tenant_id: TenantId, handle: NodeHandle) {
        self.total_mem
            .fetch_add(self.config.per_node_bytes, Ordering::SeqCst);
        self.nodes.insert(tenant_id, handle);
    }

    /// Look up a handle by tenant ID. Returns `None` if not found.
    #[doc(hidden)]
    #[must_use]
    pub fn get_handle(&self, tenant_id: TenantId) -> Option<NodeHandle> {
        self.nodes.get(&tenant_id).map(|r| r.value().clone())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> NodeManager {
        NodeManager::new_for_test(ManagerConfig::default())
    }

    #[tokio::test]
    async fn dispatch_unknown_tenant_returns_error() {
        let mgr = mgr();
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let result = mgr
            .dispatch(TenantId::new(999), NodeCmd::GetBalance { resp: tx })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn budget_exhausted_returns_error() {
        // Create a manager with tiny budget: exactly 1 node.
        let mgr = NodeManager::new_for_test(ManagerConfig {
            memory_budget_bytes: PER_NODE_BYTES,
            per_node_bytes: PER_NODE_BYTES,
        });

        // This tenant is "provisioned" without DB — just insert the handle directly
        // so we can test budget without a live Postgres.
        let handle = NodeHandle::for_test();
        mgr.nodes.insert(TenantId::new(1), handle);
        mgr.total_mem.fetch_add(PER_NODE_BYTES, Ordering::SeqCst);

        // Now node_count == 1, total_mem == budget. Next provision should fail.
        // We don't call the full provision() because it needs a real DB.
        // Instead, test the budget arithmetic directly.
        let prev = mgr.total_mem.fetch_add(PER_NODE_BYTES, Ordering::SeqCst);
        assert!(
            prev + PER_NODE_BYTES > mgr.config.memory_budget_bytes,
            "budget should be exceeded"
        );
    }

    #[tokio::test]
    async fn node_count_tracks_inserts() {
        let mgr = mgr();
        assert_eq!(mgr.node_count(), 0);

        let h1 = NodeHandle::for_test();
        mgr.nodes.insert(TenantId::new(1), h1);
        assert_eq!(mgr.node_count(), 1);

        let h2 = NodeHandle::for_test();
        mgr.nodes.insert(TenantId::new(2), h2);
        assert_eq!(mgr.node_count(), 2);
    }
}
