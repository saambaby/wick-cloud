//! `NodeManager` — lifecycle management for all tenant Lightning-node actors.
//!
//! Owns the `DashMap<TenantId, NodeHandle>` and the global memory budget
//! counter. Tenant provisioning (schema creation, actor spawn, `DashMap` insert)
//! is also handled here.

use std::sync::{ atomic::{ AtomicUsize, Ordering }, Arc };
use std::time::{ Duration, Instant };

use anyhow::{ anyhow, Context };
use dashmap::DashMap;
use metrics::{ counter, gauge, histogram };
use tokio::sync::oneshot;
use tracing::{ debug, info, warn };
use wick_core::TenantId;
use wick_db::Pool;
use wick_lightning::NodeApi;

use crate::node::{
    actor::NodeActor,
    admission::{ WakeAdmission, WakePriority },
    state,
    ErrorReason,
    ErrorState,
    NodeCmd,
    NodeHandle,
    NodeInner,
    ParkOutcome,
    PER_NODE_BYTES,
};

/// Typed error returned by [`NodeManager::provision`].
///
/// `grpc::WickGrpcService::create_tenant` matches on this to distinguish
/// idempotent re-registration (`AlreadyProvisioned`, swallowed) from a real
/// failure (`Other`, surfaced as `Status::internal`).
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// Tenant is already registered with this manager.
    #[error("tenant {0} is already provisioned")]
    AlreadyProvisioned(TenantId),
    /// Any other failure during provisioning — schema DDL, factory build,
    /// memory admission, etc.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Typed error returned by [`NodeManager::dispatch`]. Each variant maps
/// to a specific gRPC `Status` code in [`crate::grpc`] so clients can
/// distinguish "tenant doesn't exist" from "tenant is waking" from
/// "tenant is rate-limited".
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// Tenant is not registered with this manager.
    #[error("tenant {0} not found")]
    NotFound(TenantId),
    /// Tenant is in [`state::ERROR`] — the recovery loop will retry; the
    /// client should retry later.
    #[error("tenant {0} is in ERROR state")]
    InErrorState(TenantId),
    /// Wake took longer than [`ManagerConfig::wake_deadline`].
    #[error("wake for tenant {0} exceeded deadline")]
    WakeTimeout(TenantId),
    /// Per-tenant wake rate limit exhausted (User priority only).
    #[error("tenant {0} wake rate-limited")]
    RateLimited(TenantId),
    /// Memory pressure above `lru_eviction_threshold`; User wakes are
    /// denied to protect headroom.
    #[error("tenant {0} denied: memory pressure above headroom")]
    HeadroomDenied(TenantId),
    /// Node actor's mpsc closed between state check and send.
    #[error("tenant {0} actor stopped")]
    ActorStopped(TenantId),
    /// Internal error — factory failure, invariant violation, etc.
    #[error("internal: {0}")]
    Internal(#[source] anyhow::Error),
}

/// Factory that produces a concrete `Arc<dyn NodeApi>` for a tenant.
///
/// The `NodeManager` is signer-agnostic: the server binary (prod) injects a
/// factory that captures the master seed + [`NodeDeps`] and builds
/// `wick_lightning::Node<S>` via `NodeBuilder`; the regtest harness /
/// integration tests inject factories with the same shape that produce
/// `Node<LocalKeysManager>` from a test seed.
///
/// Deps are captured by the closure rather than passed per call — this lets
/// unit tests inject lightweight factories (e.g. `|_tid| async { Ok(mock) }`)
/// without having to synthesise a real [`NodeDeps`] (Postgres pool, Esplora
/// client). Production factories capture `NodeDeps` via `move` at
/// construction time.
#[allow(clippy::type_complexity)]
pub type NodeFactory = Arc<
    dyn (Fn(
        TenantId
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Arc<dyn NodeApi>>> + Send>
    >) +
        Send +
        Sync
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
    /// Maximum wall-clock duration allowed for a single wake path
    /// (look-up → factory build → actor spawn → CAS to `ACTIVE`).
    /// CLTV-bound dispatch paths rely on this as their timeout.
    /// Default: 2 seconds.
    pub wake_deadline: Duration,
    /// Interval between activity-poller ticks.
    /// Default: 30 seconds.
    pub activity_poll_interval: Duration,
    /// Minimum idle duration before a tenant becomes a park candidate.
    /// The poller considers `ACTIVE` handles whose `last_active` is older
    /// than `now - idle_threshold`.
    /// Default: 5 minutes.
    pub idle_threshold: Duration,
    /// Max consecutive failed wakes before a tenant transitions to
    /// `state::ERROR`. Every wake failure increments the counter; a
    /// successful wake resets it to 0.
    /// Default: 5.
    pub max_error_attempts: u8,
    /// Interval between error-recovery probe ticks.
    /// Default: 60 seconds.
    pub error_recovery_interval: Duration,
    /// Interval between memory-evictor ticks.
    /// Default: 10 seconds.
    pub memory_evictor_interval: Duration,
    /// Pressure ratio (`total_mem / memory_budget`) above which the LRU
    /// evictor starts parking idle tenants.
    /// Default: 0.80.
    pub lru_eviction_threshold: f64,
    /// Pressure ratio at which the emergency evictor kicks in and
    /// force-parks (Shutdown) the oldest tenants regardless of activity.
    /// Default: 0.95.
    pub emergency_eviction_threshold: f64,
    /// Target pressure the evictor aims for after a tick.
    /// Default: 0.70.
    pub evictor_target_pressure: f64,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            memory_budget_bytes: 512 * 1024 * 1024,
            per_node_bytes: PER_NODE_BYTES,
            wake_deadline: Duration::from_secs(2),
            activity_poll_interval: Duration::from_secs(30),
            idle_threshold: Duration::from_secs(300),
            max_error_attempts: 5,
            error_recovery_interval: Duration::from_secs(60),
            memory_evictor_interval: Duration::from_secs(10),
            lru_eviction_threshold: 0.8,
            emergency_eviction_threshold: 0.95,
            evictor_target_pressure: 0.7,
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
    /// Factory that turns `tenant_id` into a ready `Arc<dyn NodeApi>`.
    /// Captures `NodeDeps` internally at construction time.
    factory: Option<NodeFactory>,
    /// Phase-2 wake admission: global concurrency bound + per-tenant
    /// rate limit + priority for `Payment` wakes.
    admission: WakeAdmission,
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
    /// The factory is expected to capture `NodeDeps` internally so callers
    /// don't plumb it through every `provision` / `wake`.
    #[must_use]
    pub fn new(config: ManagerConfig, factory: NodeFactory) -> Self {
        let admission_permits = (config.memory_budget_bytes / config.per_node_bytes.max(1) / 2).max(
            1
        );
        Self {
            nodes: DashMap::new(),
            admission: WakeAdmission::new(admission_permits),
            config,
            total_mem: Arc::new(AtomicUsize::new(0)),
            factory: Some(factory),
        }
    }

    /// Unit-test constructor — no factory required.
    ///
    /// `provision()` / `wake()` will error if called; use
    /// [`Self::insert_handle_for_test`] to install handles directly.
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test(config: ManagerConfig) -> Self {
        Self::new_for_test_inner(config, None)
    }

    /// Unit-test constructor that accepts a factory — lets tests inject
    /// a closure that produces whatever `Arc<dyn NodeApi>` they need.
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test_with_factory(config: ManagerConfig, factory: NodeFactory) -> Self {
        Self::new_for_test_inner(config, Some(factory))
    }

    fn new_for_test_inner(config: ManagerConfig, factory: Option<NodeFactory>) -> Self {
        let admission_permits = (config.memory_budget_bytes / config.per_node_bytes.max(1) / 2).max(
            1
        );
        Self {
            nodes: DashMap::new(),
            admission: WakeAdmission::new(admission_permits),
            config,
            total_mem: Arc::new(AtomicUsize::new(0)),
            factory,
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
    /// Returns [`ProvisionError::AlreadyProvisioned`] when the tenant is
    /// already registered (callers can swallow this for idempotent flows);
    /// [`ProvisionError::Other`] for schema DDL, factory, or memory failures.
    pub async fn provision(&self, tenant_id: TenantId, pool: &Pool) -> Result<(), ProvisionError> {
        if self.nodes.contains_key(&tenant_id) {
            return Err(ProvisionError::AlreadyProvisioned(tenant_id));
        }

        // Create the tenant Postgres schema (DDL for payments, peers, vss_objects, etc).
        Self::create_tenant_schema(tenant_id, pool).await.context("create tenant schema")?;

        // Spawn a long-lived actor starting in PARKED state (no node yet,
        // no memory reserved). The first wake_loading call below reserves
        // memory and installs the node via NodeCmd::Activate.
        let handle = NodeActor::spawn(tenant_id);
        self.nodes.insert(tenant_id, handle);

        // Immediately activate — builds the node via factory and brings the
        // tenant to ACTIVE. Returns an error if the factory fails.
        self.wake(tenant_id).await.context("initial node activation")?;

        info!(tenant = %tenant_id, "node provisioned and active");
        Ok(())
    }

    /// Dispatch a command to a tenant's actor.
    ///
    /// Wake-on-demand: if the tenant is `PARKED` or `LOADING`, the dispatch
    /// transparently triggers/awaits a wake (under `wake_deadline`) before
    /// forwarding the cmd. `ERROR` returns immediately so clients don't
    /// block behind the 60s error-recovery loop.
    ///
    /// Returns a [`DispatchError`] that the gRPC layer maps to a specific
    /// `Status` code.
    pub async fn dispatch(&self, tenant_id: TenantId, cmd: NodeCmd) -> Result<(), DispatchError> {
        let handle = self.nodes.get(&tenant_id).ok_or(DispatchError::NotFound(tenant_id))?.clone();

        let current_state = handle.state.load(Ordering::SeqCst);
        match current_state {
            state::ACTIVE => {}
            state::ERROR => {
                return Err(DispatchError::InErrorState(tenant_id));
            }
            state::PARKED | state::LOADING => {
                let priority = classify_priority(&cmd);
                match
                    tokio::time::timeout(
                        self.config.wake_deadline,
                        self.wake_with_priority(tenant_id, priority)
                    ).await
                {
                    Err(_) => {
                        return Err(DispatchError::WakeTimeout(tenant_id));
                    }
                    Ok(Err(e)) => {
                        return Err(classify_wake_error(tenant_id, e.to_string()));
                    }
                    Ok(Ok(())) => {}
                }
            }
            unexpected => {
                return Err(
                    DispatchError::Internal(
                        anyhow!("tenant {tenant_id} in unexpected state {unexpected}")
                    )
                );
            }
        }

        let tx = handle.tx().ok_or(DispatchError::ActorStopped(tenant_id))?;
        tx.send(cmd).await.map_err(|_| DispatchError::ActorStopped(tenant_id))?;

        Ok(())
    }

    /// Gracefully shut down all node actors.
    ///
    /// Actors persist across park/wake cycles, so Shutdown is sent to every
    /// handle that has a live mpsc sender — regardless of lifecycle state
    /// (ACTIVE, PARKED, LOADING, or ERROR).
    pub async fn shutdown_all(&self) {
        let tenant_ids: Vec<TenantId> = self.nodes
            .iter()
            .map(|r| *r.key())
            .collect();
        for tid in tenant_ids {
            let Some(handle) = self.nodes.get(&tid).map(|r| r.clone()) else {
                continue;
            };
            let Some(tx) = handle.tx() else {
                continue;
            };
            if tx.send(NodeCmd::Shutdown).await.is_err() {
                warn!(tenant = %tid, "actor already stopped on shutdown_all");
            }
        }
    }
}

// ── Phase-2 park / wake ──────────────────────────────────────────────────────

impl NodeManager {
    /// Wake a `PARKED` tenant back to `ACTIVE` state.
    ///
    /// Convenience wrapper that defaults to [`WakePriority::User`]. Payment
    /// dispatch paths (`SendPayment`, `ReceivePayment`) should call
    /// [`Self::wake_with_priority`] directly so they bypass the per-tenant
    /// rate limit.
    pub async fn wake(&self, tenant_id: TenantId) -> anyhow::Result<()> {
        self.wake_with_priority(tenant_id, WakePriority::User).await
    }

    /// Wake with explicit priority.
    ///
    /// See [`WakePriority`]. `Payment` bypasses the per-tenant rate limit;
    /// `User` respects it.
    pub async fn wake_with_priority(
        &self,
        tenant_id: TenantId,
        priority: WakePriority
    ) -> anyhow::Result<()> {
        let handle = self.nodes
            .get(&tenant_id)
            .ok_or_else(|| anyhow!("tenant {tenant_id} not found"))?
            .clone();

        loop {
            let current = handle.state.load(Ordering::SeqCst);
            match current {
                state::ACTIVE => {
                    handle.last_active.store(Self::now_secs(), Ordering::SeqCst);
                    return Ok(());
                }
                state::ERROR => {
                    return Err(anyhow!("tenant {tenant_id} is in ERROR state"));
                }
                state::LOADING => {
                    // Another waker is in flight; wait for completion.
                    // `Notified` is lazily registered on first poll, so
                    // pin + `enable()` before re-checking state — otherwise
                    // a `notify_waiters()` that fires between creation and
                    // await is lost and we stall until `wake_deadline`.
                    let notified = handle.wake_notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if handle.state.load(Ordering::SeqCst) != state::LOADING {
                        continue;
                    }
                    if tokio::time::timeout(self.config.wake_deadline, notified).await.is_err() {
                        return Err(anyhow!("wake for tenant {tenant_id} timed out"));
                    }
                    // Loop back to re-check final state.
                }
                state::PARKED => {
                    // 20% headroom reservation: if pressure is already
                    // above the LRU threshold, deny User-priority wakes so
                    // Payment wakes and in-flight actors keep their slot.
                    if
                        priority == WakePriority::User &&
                        self.memory_pressure() >= self.config.lru_eviction_threshold
                    {
                        return Err(
                            anyhow!(
                                "wake denied: memory pressure {:.2} above headroom threshold {:.2}",
                                self.memory_pressure(),
                                self.config.lru_eviction_threshold
                            )
                        );
                    }

                    // Admission gate: global concurrency + per-tenant
                    // rate-limit (User only). Acquired *before* CAS so a
                    // rate-limited tenant doesn't ping-pong state.
                    let _permit = self.admission.acquire(tenant_id, priority).await.map_err(|e| {
                        counter!("wick_wake_rate_limited_total").increment(1);
                        anyhow!("wake admission denied: {e}")
                    })?;

                    if
                        handle.state
                            .compare_exchange(
                                state::PARKED,
                                state::LOADING,
                                Ordering::SeqCst,
                                Ordering::SeqCst
                            )
                            .is_err()
                    {
                        // Lost the race; another waker won. Loop to re-observe.
                        continue;
                    }
                    let r = self.wake_loading(tenant_id, handle).await;
                    drop(_permit);
                    return r;
                }
                unexpected => {
                    return Err(anyhow!("tenant {tenant_id} in unexpected state {unexpected}"));
                }
            }
        }
    }

    /// Internal: called after the winning CAS moved state to `LOADING`.
    /// Uses a RAII [`WakeGuard`] to roll back state + memory on any failure.
    async fn wake_loading(&self, tenant_id: TenantId, handle: NodeHandle) -> anyhow::Result<()> {
        let wake_started = Instant::now();
        let factory = self.factory
            .clone()
            .ok_or_else(|| anyhow!("NodeManager has no NodeFactory (test-only constructor?)"))?;

        // Reserve memory up front so the evictor sees consistent accounting.
        let prev = self.total_mem.fetch_add(self.config.per_node_bytes, Ordering::SeqCst);
        if prev + self.config.per_node_bytes > self.config.memory_budget_bytes {
            self.total_mem.fetch_sub(self.config.per_node_bytes, Ordering::SeqCst);
            // Revert state — the evictor will try again on the next tick.
            handle.state.store(state::PARKED, Ordering::SeqCst);
            handle.wake_notify.notify_waiters();
            return Err(
                anyhow!(
                    "wake denied: memory budget exhausted ({prev}/{budget})",
                    budget = self.config.memory_budget_bytes
                )
            );
        }

        // RAII rollback on any early-return below. Records the failure
        // into `ErrorState` and, after `max_error_attempts`, flips state
        // to `ERROR` so the recovery loop can probe it.
        let mut guard = WakeGuard::new(
            handle.clone(),
            self.total_mem.clone(),
            self.config.per_node_bytes,
            self.config.max_error_attempts
        );

        // Build a fresh node for this tenant. Factory is idempotent — it
        // re-loads ChannelManager + monitors from Postgres and walks them
        // forward to the chain tip.
        let node = match factory(tenant_id).await {
            Ok(n) => n,
            Err(e) => {
                guard.mark_factory_error(e.to_string());
                return Err(anyhow!("factory failed during wake of tenant {tenant_id}: {e}"));
            }
        };

        // Send NodeCmd::Activate to the persistent actor. The actor installs
        // the node, publishes it to NodeInner, and acks. This is the
        // spec-compliant `Activate { node }` path — tasks are owned by the
        // node itself (BackgroundProcessor, SPV loop, peer-reconnect loop).
        let (act_tx, act_rx) = oneshot::channel();
        let actor_tx = handle
            .tx()
            .ok_or_else(|| anyhow!("actor channel gone for tenant {tenant_id}"))?;
        if actor_tx.send(NodeCmd::Activate { node, resp: act_tx }).await.is_err() {
            // Actor channel closed unexpectedly — guard will roll back.
            return Err(anyhow!("actor channel closed during wake of tenant {tenant_id}"));
        }
        match act_rx.await {
            Err(_) => {
                return Err(anyhow!("actor dropped Activate response for tenant {tenant_id}"));
            }
            Ok(Err(e)) => {
                return Err(anyhow!("actor failed to install node for tenant {tenant_id}: {e}"));
            }
            Ok(Ok(())) => {}
        }
        // NodeInner.node and last_active are now set by the actor's handle_activate.

        // Flip state LOADING → ACTIVE. At this point any dispatch observers
        // will succeed (inner.node is already published by the actor).
        if
            handle.state
                .compare_exchange(state::LOADING, state::ACTIVE, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            // Extremely rare — state was concurrently moved (e.g. emergency
            // park). The actor already installed the node via handle_activate,
            // so we must ask it to shut the node down before bailing or the
            // BackgroundProcessor / SPV loop / peer-reconnect loop leak.
            // Best-effort: on failure, log and accept the leak (the actor
            // is already broken in some way the manager can't repair).
            match
                tokio::time::timeout(
                    self.config.wake_deadline,
                    self.force_park(tenant_id)
                ).await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    tracing::error!(tenant = %tenant_id, error = %e,
                        "wake_loading rollback: force_park failed; node may be leaked");
                }
                Err(_) => {
                    tracing::error!(tenant = %tenant_id,
                        "wake_loading rollback: force_park timed out; node may be leaked");
                }
            }
            return Err(anyhow!("state moved out of LOADING before wake could publish"));
        }

        handle.wake_notify.notify_waiters();
        guard.commit();
        counter!("wick_wake_total").increment(1);
        histogram!("wick_wake_latency_seconds").record(wake_started.elapsed().as_secs_f64());
        debug!(tenant = %tenant_id, "wake complete");
        Ok(())
    }

    /// Request a tenant park itself (polite path; safety checks apply).
    ///
    /// Sends [`NodeCmd::Park`] with `force = false`. The actor's post-drain
    /// recheck can refuse with [`ParkOutcome::RequeuedDueToActivity`] if
    /// HTLCs are pending, an outbound payment is in flight, or monitor
    /// events are unresolved. Errors if the tenant is not provisioned or
    /// not `ACTIVE`.
    pub async fn park(&self, tenant_id: TenantId) -> anyhow::Result<ParkOutcome> {
        self.park_inner(tenant_id, false).await
    }

    /// Force a tenant to park, skipping the three park-safety checks.
    ///
    /// Used by the emergency evictor and by `wake_loading`'s defensive
    /// rollback path. The actor always responds [`ParkOutcome::Parked`]
    /// when it has a node to shut down; in-flight HTLCs may time out.
    /// The actor task stays alive (it is not a `Shutdown`) so subsequent
    /// wakes can re-activate the tenant.
    pub async fn force_park(&self, tenant_id: TenantId) -> anyhow::Result<ParkOutcome> {
        self.park_inner(tenant_id, true).await
    }

    async fn park_inner(
        &self,
        tenant_id: TenantId,
        force: bool
    ) -> anyhow::Result<ParkOutcome> {
        let handle = self.nodes
            .get(&tenant_id)
            .ok_or_else(|| anyhow!("tenant {tenant_id} not found"))?
            .clone();
        // Allow force-park from LOADING too — wake_loading's rollback path
        // uses it to clean up after a failed CAS while the actor already
        // installed the node.
        let s = handle.state.load(Ordering::SeqCst);
        if !force && s != state::ACTIVE {
            return Err(anyhow!("tenant {tenant_id} not ACTIVE"));
        }
        if force && s != state::ACTIVE && s != state::LOADING {
            return Err(anyhow!("tenant {tenant_id} not ACTIVE or LOADING"));
        }
        let tx = handle.tx().ok_or_else(|| anyhow!("tenant {tenant_id} has no active sender"))?;

        let (resp_tx, resp_rx) = oneshot::channel();
        tx
            .send(NodeCmd::Park { force, resp: resp_tx }).await
            .map_err(|_| anyhow!("actor closed before Park accepted"))?;

        let outcome = resp_rx.await.map_err(|_| anyhow!("actor dropped Park response"))?;

        if matches!(outcome, ParkOutcome::Parked) {
            // The actor already cleared inner.node in try_park. Re-publish
            // to make the clear authoritative (preserving tx so the actor's
            // mpsc channel stays live for the next wake's Activate).
            // Release memory and CAS state *after* inner is settled —
            // concurrent dispatch that sees PARKED will try to wake, not dispatch.
            let current_tx = handle.inner.load().tx.clone();
            handle.inner.store(
                Arc::new(NodeInner {
                    tx: current_tx,
                    node: None,
                })
            );
            self.total_mem.fetch_sub(self.config.per_node_bytes, Ordering::SeqCst);
            handle.state.store(state::PARKED, Ordering::SeqCst);
            counter!("wick_park_total").increment(1);
            if force {
                counter!("wick_forced_park_with_inflight_total").increment(1);
            }
            info!(tenant = %tenant_id, force, "park complete — memory released");
        }

        Ok(outcome)
    }

    /// Snapshot current gauges — active/parked/error counts and memory
    /// pressure ratio. Exposed so background loops (poller, evictor) can
    /// call it on each tick to keep Prometheus fresh.
    pub fn update_gauges(&self) {
        let (mut active, mut parked, mut loading, mut errored) = (0u64, 0u64, 0u64, 0u64);
        for r in self.nodes.iter() {
            match r.value().state.load(Ordering::SeqCst) {
                state::ACTIVE => {
                    active += 1;
                }
                state::PARKED => {
                    parked += 1;
                }
                state::LOADING => {
                    loading += 1;
                }
                state::ERROR => {
                    errored += 1;
                }
                _ => {}
            }
        }
        #[allow(clippy::cast_precision_loss)]
        let pressure =
            (self.total_mem.load(Ordering::Relaxed) as f64) /
            (self.config.memory_budget_bytes.max(1) as f64);
        gauge!("wick_active_nodes").set(active as f64);
        gauge!("wick_parked_nodes").set(parked as f64);
        gauge!("wick_loading_nodes").set(loading as f64);
        gauge!("wick_error_nodes").set(errored as f64);
        gauge!("wick_memory_pressure_ratio").set(pressure);
    }

    fn now_secs() -> u64 {
        std::time::SystemTime
            ::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

// ── Phase-2 activity poller ──────────────────────────────────────────────────

impl NodeManager {
    /// Run a single pass of the activity poller: every `ACTIVE` tenant whose
    /// `last_active` is older than `idle_threshold` receives a `Park`
    /// request. The actor's post-drain recheck rejects if pending HTLCs /
    /// inflight payments / monitor events exist, so this is safe to call at
    /// any cadence.
    ///
    /// Exposed separately from [`Self::spawn_activity_poller`] so tests can
    /// drive a single tick deterministically.
    pub async fn park_idle_tenants(&self) {
        let idle_cutoff = Self::now_secs().saturating_sub(self.config.idle_threshold.as_secs());

        let candidates: Vec<TenantId> = self.nodes
            .iter()
            .filter_map(|r| {
                let h = r.value();
                if h.state.load(Ordering::SeqCst) != state::ACTIVE {
                    return None;
                }
                if h.last_active.load(Ordering::SeqCst) > idle_cutoff {
                    return None;
                }
                Some(*r.key())
            })
            .collect();

        for tid in candidates {
            match self.park(tid).await {
                Ok(ParkOutcome::Parked) => {
                    debug!(tenant = %tid, "poller parked idle tenant");
                }
                Ok(ParkOutcome::RequeuedDueToActivity) => {
                    debug!(tenant = %tid, "poller park requeued — activity detected");
                }
                Err(e) => {
                    warn!(tenant = %tid, error = %e, "poller park failed");
                }
            }
        }
    }

    /// Spawn a background task that periodically calls
    /// [`Self::park_idle_tenants`]. Returns a [`tokio::task::JoinHandle`]
    /// the caller can abort to stop polling (e.g. on process shutdown).
    #[must_use]
    pub fn spawn_activity_poller(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = self.config.activity_poll_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip the immediate first tick — no one has become idle yet.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                self.park_idle_tenants().await;
            }
        })
    }
}

// ── Phase-2 memory pressure evictor ──────────────────────────────────────────

impl NodeManager {
    /// Current memory pressure ratio (`total_mem / memory_budget_bytes`).
    #[must_use]
    pub fn memory_pressure(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let used = self.total_mem.load(Ordering::Relaxed) as f64;
        #[allow(clippy::cast_precision_loss)]
        let budget = self.config.memory_budget_bytes.max(1) as f64;
        used / budget
    }

    /// Single-pass memory eviction:
    ///
    /// - `pressure < lru_eviction_threshold` → no-op.
    /// - `pressure ∈ [lru, emergency)` → gracefully `Park` LRU tenants
    ///   until pressure drops below `evictor_target_pressure`.
    /// - `pressure ≥ emergency_eviction_threshold` → emergency `Shutdown`
    ///   the LRU tenants (doesn't respect the post-drain recheck —
    ///   accept that in-flight HTLCs may time out).
    ///
    /// Exposed separately from [`Self::spawn_memory_evictor`] so tests
    /// can drive ticks deterministically.
    pub async fn evict_under_pressure(&self) {
        let pressure = self.memory_pressure();
        if pressure < self.config.lru_eviction_threshold {
            return;
        }

        let emergency = pressure >= self.config.emergency_eviction_threshold;

        // LRU order: oldest `last_active` first. Only ACTIVE handles.
        let mut candidates: Vec<(u64, TenantId)> = self.nodes
            .iter()
            .filter_map(|r| {
                let h = r.value();
                if h.state.load(Ordering::SeqCst) != state::ACTIVE {
                    return None;
                }
                Some((h.last_active.load(Ordering::SeqCst), *r.key()))
            })
            .collect();
        candidates.sort_by_key(|(la, _)| *la);

        for (_, tid) in candidates {
            if self.memory_pressure() <= self.config.evictor_target_pressure {
                break;
            }
            if emergency {
                // Force-park: skip safety checks but keep the actor task
                // alive so the next wake can re-activate the tenant.
                // Never send Shutdown — that would leave the tenant
                // permanently unreachable until process restart.
                match self.force_park(tid).await {
                    Ok(ParkOutcome::Parked) => {
                        warn!(tenant = %tid, pressure, "emergency evict: force-parked tenant");
                    }
                    Ok(ParkOutcome::RequeuedDueToActivity) => {
                        // Unexpected for force-park; actor only returns
                        // RequeuedDueToActivity when it had no node or saw
                        // a Shutdown during drain.
                        debug!(tenant = %tid, "emergency evict: actor requeued force-park");
                    }
                    Err(e) => {
                        debug!(tenant = %tid, error = %e, "emergency evict force_park failed");
                    }
                }
            } else {
                // Polite park — actor's post-drain recheck can refuse.
                if let Err(e) = self.park(tid).await {
                    debug!(tenant = %tid, error = %e, "LRU evict park failed");
                }
            }
        }
    }

    /// Spawn a background task that periodically calls
    /// [`Self::evict_under_pressure`] and [`Self::update_gauges`].
    #[must_use]
    pub fn spawn_memory_evictor(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = self.config.memory_evictor_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                self.update_gauges();
                self.evict_under_pressure().await;
            }
        })
    }
}

// ── Phase-2 error recovery loop ──────────────────────────────────────────────

impl NodeManager {
    /// Run a single pass of the error-recovery probe: every handle in
    /// [`state::ERROR`] gets a health check (a cheap wake attempt). A
    /// successful wake clears the error and returns the tenant to service.
    /// A failed wake increments the attempt counter via [`WakeGuard`]; the
    /// tenant remains in ERROR state.
    ///
    /// Exposed separately from [`Self::spawn_error_recovery`] so tests can
    /// drive a single tick deterministically.
    pub async fn recover_errored_tenants(&self) {
        let candidates: Vec<TenantId> = self.nodes
            .iter()
            .filter_map(|r| {
                if r.value().state.load(Ordering::SeqCst) == state::ERROR {
                    Some(*r.key())
                } else {
                    None
                }
            })
            .collect();

        for tid in candidates {
            // Reset state to PARKED so `wake()` can CAS PARKED→LOADING.
            // This is the health probe: if the factory now succeeds, the
            // tenant is back in service; if it fails again, the WakeGuard
            // rollback path will put it back into ERROR with an incremented
            // counter.
            if let Some(handle) = self.nodes.get(&tid).map(|r| r.clone()) {
                handle.state.store(state::PARKED, Ordering::SeqCst);
                // Payment priority skips the per-tenant token bucket so a
                // failing tenant doesn't PARKED↔ERROR ping-pong every tick
                // just because User-priority capacity is exhausted. The
                // global admission semaphore still bounds concurrency.
                match self.wake_with_priority(tid, WakePriority::Payment).await {
                    Ok(()) => {
                        info!(tenant = %tid, "error recovery: tenant restored to ACTIVE");
                    }
                    Err(e) => {
                        debug!(tenant = %tid, error = %e, "error recovery probe failed; remaining in ERROR");
                    }
                }
            }
        }
    }

    /// Spawn a background task that periodically calls
    /// [`Self::recover_errored_tenants`].
    #[must_use]
    pub fn spawn_error_recovery(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = self.config.error_recovery_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                self.recover_errored_tenants().await;
            }
        })
    }
}

/// Classify a `NodeCmd` into a wake priority. Lightning-facing cmds that
/// could be CLTV-bound go through `Payment`; user-facing introspection
/// (`GetBalance`, `GetTransactions`) is `User` and subject to rate
/// limiting.
fn classify_priority(cmd: &NodeCmd) -> WakePriority {
    match cmd {
        NodeCmd::SendPayment { .. } | NodeCmd::ReceivePayment { .. } => WakePriority::Payment,
        _ => WakePriority::User,
    }
}

/// Map an `anyhow::Error` returned by `wake` into a typed
/// [`DispatchError`]. Inspects the error message to pick the right
/// variant — the alternative (threading a typed error through
/// `wake`/`wake_loading`) would require a much wider refactor; given
/// wake errors come from a small, well-known set of call sites, the
/// string inspection is acceptable and covered by tests.
///
/// Uses specific phrases rather than single words so unrelated messages
/// that happen to contain "rate" or "ERROR" substrings don't misclassify.
fn classify_wake_error(tenant_id: TenantId, msg: String) -> DispatchError {
    if msg.contains("rate limit") || msg.contains("admission") {
        DispatchError::RateLimited(tenant_id)
    } else if msg.contains("headroom threshold") {
        DispatchError::HeadroomDenied(tenant_id)
    } else if msg.contains("in ERROR state") {
        DispatchError::InErrorState(tenant_id)
    } else {
        DispatchError::Internal(anyhow!(msg))
    }
}

/// RAII guard that rolls back a wake attempt if the happy path doesn't
/// `commit()` before drop. Used inside [`NodeManager::wake_loading`].
///
/// On rollback, records an [`ErrorState`] and — if the attempt counter
/// reaches `max_attempts` — transitions the tenant to [`state::ERROR`]
/// instead of [`state::PARKED`] so the error-recovery loop picks it up.
struct WakeGuard {
    handle: NodeHandle,
    total_mem: Arc<AtomicUsize>,
    per_node_bytes: usize,
    max_attempts: u8,
    committed: bool,
    factory_error: Option<String>,
}

impl WakeGuard {
    fn new(
        handle: NodeHandle,
        total_mem: Arc<AtomicUsize>,
        per_node_bytes: usize,
        max_attempts: u8
    ) -> Self {
        Self {
            handle,
            total_mem,
            per_node_bytes,
            max_attempts,
            committed: false,
            factory_error: None,
        }
    }

    /// Record that the factory returned an error. Used as the `reason`
    /// when rollback later populates [`ErrorState`].
    fn mark_factory_error(&mut self, msg: String) {
        self.factory_error = Some(msg);
    }

    /// Called on the happy path — suppresses rollback and clears any
    /// previously-recorded error on the handle.
    fn commit(&mut self) {
        self.committed = true;
        if let Ok(mut guard) = self.handle.error.write() {
            *guard = None;
        }
    }
}

impl Drop for WakeGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Roll back memory allocation first.
        self.total_mem.fetch_sub(self.per_node_bytes, Ordering::SeqCst);
        // Preserve tx (actor persists across park/wake); clear node only.
        let current_tx = self.handle.inner.load().tx.clone();
        self.handle.inner.store(
            Arc::new(NodeInner {
                tx: current_tx,
                node: None,
            })
        );

        // Bump the attempt counter on ErrorState (creating one if needed).
        let reason = self.factory_error
            .take()
            .map(ErrorReason::FactoryFailed)
            .unwrap_or(ErrorReason::ShutdownTimeout);
        let attempts = match self.handle.error.write() {
            Ok(mut guard) => {
                let attempts =
                    guard
                        .as_ref()
                        .map(|e| e.attempts)
                        .unwrap_or(0) + 1;
                *guard = Some(ErrorState {
                    reason,
                    since: Instant::now(),
                    attempts,
                });
                attempts
            }
            Err(_) => 1,
        };

        let next_state = if attempts >= self.max_attempts { state::ERROR } else { state::PARKED };
        self.handle.state.store(next_state, Ordering::SeqCst);
        self.handle.wake_notify.notify_waiters();

        counter!("wick_wake_failures_total").increment(1);
        if next_state == state::ERROR {
            counter!("wick_error_state_transitions_total").increment(1);
        }
    }
}

// ── Tenant schema provisioning ────────────────────────────────────────────────

impl NodeManager {
    /// Create the per-tenant Postgres schema and tables.
    ///
    /// Uses `format()` which is safe here because `schema` is derived from a
    /// `TenantId` — always `^tenant_[0-9]+$`.
    async fn create_tenant_schema(tenant_id: TenantId, pool: &Pool) -> anyhow::Result<()> {
        let schema = tenant_id.schema_name();

        // Use a raw sqlx pool for DDL — tenant_tx SET LOCAL is not appropriate
        // for schema creation which must run outside a tenant transaction.
        let pg = pool.raw();

        sqlx
            ::query(&format!("CREATE SCHEMA IF NOT EXISTS \"{schema}\""))
            .execute(pg).await
            .context("CREATE SCHEMA")?;

        for ddl in Self::tenant_ddl_statements(&schema) {
            sqlx
                ::query(&ddl)
                .execute(pg).await
                .with_context(|| format!("DDL failed:\n{ddl}"))?;
        }

        info!(tenant = %tenant_id, schema, "tenant schema created");
        Ok(())
    }

    /// Returns DDL statements for the tenant schema tables, with `schema`
    /// already interpolated. Order matters: payments before any foreign-key
    /// referencing it.
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
            )
        ]
    }
}

// ── Test helpers ────────────────────────────────────────────────────────────

impl NodeManager {
    /// Insert a `NodeHandle` directly without touching Postgres.
    /// Only for unit / integration tests; do not call from production code.
    #[doc(hidden)]
    pub fn insert_handle_for_test(&self, tenant_id: TenantId, handle: NodeHandle) {
        self.total_mem.fetch_add(self.config.per_node_bytes, Ordering::SeqCst);
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
        let result = mgr.dispatch(TenantId::generate(), NodeCmd::GetBalance { resp: tx }).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn node_count_tracks_inserts() {
        let mgr = mgr();
        assert_eq!(mgr.node_count(), 0);

        let h1 = NodeHandle::for_test();
        mgr.nodes.insert(TenantId::generate(), h1);
        assert_eq!(mgr.node_count(), 1);

        let h2 = NodeHandle::for_test();
        mgr.nodes.insert(TenantId::generate(), h2);
        assert_eq!(mgr.node_count(), 2);
    }

    // ── Park-safety proptest ────────────────────────────────────────────────
    //
    // Stub `NodeApi` driven by three `AtomicBool`s. Only the park-path methods
    // (`has_*`, `shutdown`) are real; the rest panic via `unimplemented!()`
    // since the park path never calls them. Used by both the proptest below
    // and the Notify-race regression test.
    //
    // `NodeApi` requires `Debug`, and `shutdown` is a no-op — the actor still
    // drops the `Arc<dyn NodeApi>` afterwards but the stub holds no resources.

    use std::sync::atomic::AtomicBool;
    use std::time::Duration;
    use crate::node::actor::NodeActor;
    use wick_lightning::{Balance, ChannelSummary, NodeApi, PaymentRecord, PaymentResult};

    #[derive(Debug)]
    struct StubNode {
        has_htlcs: AtomicBool,
        has_inflight: AtomicBool,
        has_monitor: AtomicBool,
    }

    impl StubNode {
        fn with_flags(has_htlcs: bool, has_inflight: bool, has_monitor: bool) -> Self {
            Self {
                has_htlcs: AtomicBool::new(has_htlcs),
                has_inflight: AtomicBool::new(has_inflight),
                has_monitor: AtomicBool::new(has_monitor),
            }
        }
    }

    #[async_trait::async_trait]
    impl NodeApi for StubNode {
        async fn get_balance(&self) -> anyhow::Result<Balance> {
            unimplemented!("StubNode: not used by park path")
        }
        async fn send_payment(&self, _: &str) -> anyhow::Result<PaymentResult> {
            unimplemented!("StubNode: not used by park path")
        }
        async fn receive_payment(
            &self,
            _: Option<u64>,
            _: &str
        ) -> anyhow::Result<(String, Vec<u8>)> {
            unimplemented!("StubNode: not used by park path")
        }
        async fn get_transactions(&self, _: u32) -> anyhow::Result<Vec<PaymentRecord>> {
            unimplemented!("StubNode: not used by park path")
        }
        fn node_id(&self) -> bitcoin::secp256k1::PublicKey {
            unimplemented!("StubNode: not used by park path")
        }
        fn local_listen_addr(&self) -> Option<std::net::SocketAddr> {
            None
        }
        async fn connect_peer(
            &self,
            _: bitcoin::secp256k1::PublicKey,
            _: &str,
            _: u16
        ) -> anyhow::Result<()> {
            unimplemented!("StubNode: not used by park path")
        }
        async fn open_channel(
            &self,
            _: bitcoin::secp256k1::PublicKey,
            _: u64,
            _: u64
        ) -> anyhow::Result<()> {
            unimplemented!("StubNode: not used by park path")
        }
        async fn open_channel_init(
            &self,
            _: bitcoin::secp256k1::PublicKey,
            _: u64,
            _: u64,
            _: Duration
        ) -> anyhow::Result<(lightning::ln::types::ChannelId, wick_lightning::PendingFunding)> {
            unimplemented!("StubNode: not used by park path")
        }
        async fn open_channel_finalize(
            &self,
            _: &lightning::ln::types::ChannelId,
            _: &bitcoin::secp256k1::PublicKey,
            _: bitcoin::Transaction
        ) -> anyhow::Result<()> {
            unimplemented!("StubNode: not used by park path")
        }
        async fn close_channel(
            &self,
            _: &lightning::ln::types::ChannelId,
            _: &bitcoin::secp256k1::PublicKey
        ) -> anyhow::Result<()> {
            unimplemented!("StubNode: not used by park path")
        }
        async fn list_channels(&self) -> anyhow::Result<Vec<ChannelSummary>> {
            unimplemented!("StubNode: not used by park path")
        }
        async fn has_pending_htlcs(&self) -> anyhow::Result<bool> {
            Ok(self.has_htlcs.load(Ordering::SeqCst))
        }
        async fn has_inflight_outbound(&self) -> anyhow::Result<bool> {
            Ok(self.has_inflight.load(Ordering::SeqCst))
        }
        async fn has_unresolved_monitor_events(&self) -> anyhow::Result<bool> {
            Ok(self.has_monitor.load(Ordering::SeqCst))
        }
        async fn shutdown(&self) {}
    }

    fn stub_factory(
        has_htlcs: bool,
        has_inflight: bool,
        has_monitor: bool
    ) -> NodeFactory {
        Arc::new(move |_tid| {
            let stub: Arc<dyn NodeApi> = Arc::new(
                StubNode::with_flags(has_htlcs, has_inflight, has_monitor)
            );
            Box::pin(async move { Ok(stub) })
        })
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(256))]

        /// Core Phase-2 safety invariant: `Park` must never transition the
        /// tenant to `PARKED` while any of the three activity predicates
        /// (pending HTLCs, in-flight outbound, unresolved monitor events)
        /// returns `true`.
        ///
        /// Runs 256 randomised cases over the 2^3 = 8 combinations of the
        /// three flags. Each case drives the full PARKED → LOADING → ACTIVE
        /// wake, then issues a polite park and asserts the expected outcome
        /// and final state.
        #[test]
        fn park_never_parks_with_pending_activity(
            has_htlcs in proptest::prelude::any::<bool>(),
            has_inflight in proptest::prelude::any::<bool>(),
            has_monitor in proptest::prelude::any::<bool>(),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let (outcome, final_state) = rt.block_on(async move {
                let mgr = NodeManager::new_for_test_with_factory(
                    ManagerConfig::default(),
                    stub_factory(has_htlcs, has_inflight, has_monitor),
                );
                let tid = TenantId::generate();
                let handle = NodeActor::spawn(tid);
                mgr.nodes.insert(tid, handle);

                mgr.wake(tid).await.expect("wake must succeed");
                let outcome = mgr.park(tid).await.expect("park must not error");
                let state = mgr.get_handle(tid).unwrap().state.load(Ordering::SeqCst);
                (outcome, state)
            });

            let any_activity = has_htlcs || has_inflight || has_monitor;
            if any_activity {
                proptest::prop_assert_eq!(outcome, ParkOutcome::RequeuedDueToActivity);
                proptest::prop_assert_eq!(final_state, state::ACTIVE);
            } else {
                proptest::prop_assert_eq!(outcome, ParkOutcome::Parked);
                proptest::prop_assert_eq!(final_state, state::PARKED);
            }
        }
    }

    // ── Notify-race regression ──────────────────────────────────────────────

    /// Guards the `notified.as_mut().enable()` call in `wake_with_priority`'s
    /// LOADING branch. Without it, a `notify_waiters()` fired between
    /// `notified()` creation and first poll is lost to lazy registration;
    /// the waiter then stalls until `wake_deadline`.
    ///
    /// Setup: handle is forced into LOADING with no actor node. Task A calls
    /// `wake` and enters the LOADING branch. After a short yield the test
    /// task transitions state to ACTIVE and fires `notify_waiters`. The
    /// fixed code captures the notify (directly via `enable()` if A is
    /// between create and await, or as a normal wakeup otherwise) and A
    /// loops to see ACTIVE and returns.
    ///
    /// The assertion is bounded-latency: if `enable()` is removed, the
    /// waiter can miss the notify and stall to the 2s `wake_deadline`,
    /// which trips the 500 ms outer timeout and fails the test. The check
    /// is one-sided (passing does not prove absence of the race), but any
    /// failure is always a real regression.
    #[tokio::test]
    async fn wake_while_loading_completes_when_state_transitions() {
        let factory: NodeFactory = Arc::new(|_| {
            Box::pin(async { Err(anyhow!("factory not expected to run")) })
        });
        let mgr = Arc::new(NodeManager::new_for_test_with_factory(
            ManagerConfig::default(),
            factory,
        ));
        let tid = TenantId::generate();
        let handle = NodeActor::spawn(tid);
        handle.state.store(state::LOADING, Ordering::SeqCst);
        mgr.nodes.insert(tid, handle.clone());

        let mgr_a = mgr.clone();
        let waker = tokio::spawn(async move { mgr_a.wake(tid).await });

        // Let the waker reach the LOADING branch's `.await`.
        tokio::time::sleep(Duration::from_millis(5)).await;

        handle.state.store(state::ACTIVE, Ordering::SeqCst);
        handle.wake_notify.notify_waiters();

        let res = tokio::time::timeout(Duration::from_millis(500), waker)
            .await
            .expect("wake did not complete within 500ms — Notify race regressed");
        let join = res.expect("waker task panicked");
        join.expect("wake returned error");
    }
}
