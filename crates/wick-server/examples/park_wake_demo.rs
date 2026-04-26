//! Phase 2 acceptance demo: park/wake concurrency + latency snapshot.
//!
//! Spawns a `NodeManager` with a stub factory (no real LDK / Postgres /
//! Esplora — this is a pure actor-layer demo), provisions `N` tenants,
//! parks them, then drives `N/2` concurrent wakes and prints p50/p95/p99
//! wake latency plus the final gauge counts.
//!
//! Not a benchmark — no warm-up, no statistical rigor. The purpose is to
//! demonstrate the Phase 2 invariants end-to-end: park respects safety
//! checks, wake completes within `wake_deadline`, admission bounds
//! concurrency, the manager's state gauges stay consistent.
//!
//! Run via `just park-wake-demo` or
//! `cargo run --release --example park_wake_demo -p wick-server`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::secp256k1::PublicKey;
use lightning::ln::types::ChannelId;
use wick_core::TenantId;
use wick_lightning::{
    Balance, ChannelSummary, NodeApi, PaymentRecord, PaymentResult, PendingFunding,
};
use wick_server::node::{
    actor::NodeActor,
    manager::{ManagerConfig, NodeFactory, NodeManager},
    state,
};

const TENANT_COUNT: usize = 100;
const CONCURRENT_WAKES: usize = 50;

#[tokio::main]
async fn main() {
    println!("== wick park-wake demo ==");
    println!("tenants: {TENANT_COUNT}, concurrent wakes: {CONCURRENT_WAKES}\n");

    let config = ManagerConfig {
        // Large enough to fit every tenant so we exercise the pure
        // park/wake path without triggering eviction.
        memory_budget_bytes: 512 * 1024 * 1024,
        // 20 s wake_deadline — generous for a single-process demo where
        // the factory is synchronous.
        wake_deadline: Duration::from_secs(20),
        ..ManagerConfig::default()
    };

    let factory: NodeFactory = Arc::new(|_tid| {
        let stub: Arc<dyn NodeApi> = Arc::new(StubNode::default());
        Box::pin(async move { Ok(stub) })
    });
    let mgr = Arc::new(NodeManager::new_for_test_with_factory(config, factory));

    // 1 — spawn actors, insert handles (no Postgres).
    let tenants: Vec<TenantId> = (0..TENANT_COUNT).map(|_| TenantId::generate()).collect();
    for tid in &tenants {
        let handle = NodeActor::spawn(*tid);
        mgr.insert_handle_for_test(*tid, handle);
    }
    println!("spawned {} actors", mgr.node_count());

    // 2 — wake them all (PARKED → ACTIVE via the stub factory).
    let wake_all_started = Instant::now();
    for tid in &tenants {
        mgr.wake(*tid).await.expect("initial wake must succeed");
    }
    println!(
        "waked {} tenants in {:?}",
        TENANT_COUNT,
        wake_all_started.elapsed()
    );

    // 3 — park them all politely (stub's has_* all return false → Parked).
    let park_all_started = Instant::now();
    for tid in &tenants {
        let _ = mgr.park(*tid).await;
    }
    println!(
        "parked {} tenants in {:?}\n",
        TENANT_COUNT,
        park_all_started.elapsed()
    );

    mgr.update_gauges();

    // 4 — concurrent wake storm: drive N/2 wakes in parallel, measure latency.
    let mut wake_handles = Vec::with_capacity(CONCURRENT_WAKES);
    let storm_started = Instant::now();
    for tid in tenants.iter().take(CONCURRENT_WAKES).copied() {
        let mgr = mgr.clone();
        wake_handles.push(tokio::spawn(async move {
            let t0 = Instant::now();
            mgr.wake(tid).await.expect("concurrent wake must succeed");
            t0.elapsed()
        }));
    }

    let mut latencies: Vec<Duration> = Vec::with_capacity(CONCURRENT_WAKES);
    for h in wake_handles {
        latencies.push(h.await.expect("wake task panicked"));
    }
    let storm_total = storm_started.elapsed();
    latencies.sort_unstable();

    let p = |q: f64| latencies[((latencies.len() as f64 * q) as usize).min(latencies.len() - 1)];
    println!("-- concurrent-wake latency ({} wakes) --", CONCURRENT_WAKES);
    println!("p50: {:?}", p(0.50));
    println!("p95: {:?}", p(0.95));
    println!("p99: {:?}", p(0.99));
    println!("max: {:?}", latencies.last().copied().unwrap_or_default());
    println!("wall:  {:?}\n", storm_total);

    // 5 — final state snapshot.
    mgr.update_gauges();
    let (mut active, mut parked, mut loading, mut errored) = (0, 0, 0, 0);
    for tid in &tenants {
        if let Some(h) = mgr.get_handle(*tid) {
            match h.state.load(Ordering::SeqCst) {
                state::ACTIVE => active += 1,
                state::PARKED => parked += 1,
                state::LOADING => loading += 1,
                state::ERROR => errored += 1,
                _ => {}
            }
        }
    }
    println!("-- final state --");
    println!("active:  {active}");
    println!("parked:  {parked}");
    println!("loading: {loading}");
    println!("error:   {errored}");
    println!("mem:     {} bytes", mgr.total_mem_bytes());

    assert_eq!(active + parked, TENANT_COUNT, "lost tenants");
    assert_eq!(loading, 0, "tenants stuck in LOADING");
    assert_eq!(errored, 0, "tenants in ERROR");

    println!("\nacceptance: ok");
}

// ── Stub NodeApi for the demo ────────────────────────────────────────────────
//
// Mirror of the #[cfg(test)] stub in `manager.rs::tests`. Duplicated so the
// example stays self-contained (the test stub is gated behind `#[cfg(test)]`
// and can't be reused from an `examples/` binary).

#[derive(Debug, Default)]
struct StubNode {
    has_htlcs: AtomicBool,
    has_inflight: AtomicBool,
    has_monitor: AtomicBool,
}

#[async_trait::async_trait]
impl NodeApi for StubNode {
    async fn get_balance(&self) -> anyhow::Result<Balance> {
        unimplemented!("stub")
    }
    async fn send_payment(&self, _: &str) -> anyhow::Result<PaymentResult> {
        unimplemented!("stub")
    }
    async fn receive_payment(&self, _: Option<u64>, _: &str) -> anyhow::Result<(String, Vec<u8>)> {
        unimplemented!("stub")
    }
    async fn get_transactions(&self, _: u32) -> anyhow::Result<Vec<PaymentRecord>> {
        unimplemented!("stub")
    }
    fn node_id(&self) -> PublicKey {
        unimplemented!("stub")
    }
    fn local_listen_addr(&self) -> Option<std::net::SocketAddr> {
        None
    }
    async fn connect_peer(&self, _: PublicKey, _: &str, _: u16) -> anyhow::Result<()> {
        unimplemented!("stub")
    }
    async fn open_channel(&self, _: PublicKey, _: u64, _: u64) -> anyhow::Result<()> {
        unimplemented!("stub")
    }
    async fn open_channel_init(
        &self,
        _: PublicKey,
        _: u64,
        _: u64,
        _: Duration,
    ) -> anyhow::Result<(ChannelId, PendingFunding)> {
        unimplemented!("stub")
    }
    async fn open_channel_finalize(
        &self,
        _: &ChannelId,
        _: &PublicKey,
        _: bitcoin::Transaction,
    ) -> anyhow::Result<()> {
        unimplemented!("stub")
    }
    async fn close_channel(&self, _: &ChannelId, _: &PublicKey) -> anyhow::Result<()> {
        unimplemented!("stub")
    }
    async fn list_channels(&self) -> anyhow::Result<Vec<ChannelSummary>> {
        unimplemented!("stub")
    }
    async fn lsps2_get_info(&self, _: Option<u64>) -> anyhow::Result<wick_lightning::JitQuote> {
        unimplemented!("stub")
    }
    async fn receive_payment_jit(
        &self,
        _: u64,
        _: &str,
    ) -> anyhow::Result<wick_lightning::JitInvoice> {
        unimplemented!("stub")
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
