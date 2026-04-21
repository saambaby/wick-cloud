//! Rapid Gossip Sync + `NetworkGraph` / `ProbabilisticScorer` persistence.
//!
//! On first boot the graph is seeded from an RGS snapshot so the node can
//! pathfind immediately. Subsequent boots use the persisted graph and fetch
//! a delta snapshot (using the stored `last_sync_ts` as the starting point).
//!
//! The scorer is loaded from Postgres on startup and periodically
//! written back so route-quality information survives restarts.
//!
//! Namespace layout inside `PgKvStore`:
//!   `gossip/""/network_graph`    — serialised `NetworkGraph`
//!   `gossip/""/last_sync_ts`     — big-endian u32 RGS timestamp
//!   `scorer/""/scorer`           — serialised `ProbabilisticScorer`

use std::io::Cursor;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bitcoin::Network;
use lightning::routing::gossip::NetworkGraph;
use lightning::routing::scoring::{
    ProbabilisticScorer, ProbabilisticScoringDecayParameters,
};
use lightning::util::ser::{ReadableArgs, Writeable};
use lightning_rapid_gossip_sync::RapidGossipSync;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::logger::TracingLogger;
use crate::node::{LnNetworkGraph, LnScorer};
use crate::persistence::PgKvStore;

/// `PgKvStore` primary namespace for graph bytes + `last_sync_ts`.
pub const GOSSIP_NS: &str = "gossip";
/// `PgKvStore` primary namespace for scorer bytes.
pub const SCORER_NS: &str = "scorer";

const GRAPH_KEY: &str = "network_graph";
const LAST_SYNC_KEY: &str = "last_sync_ts";
const SCORER_KEY: &str = "scorer";

/// How often to re-apply an RGS delta snapshot.
const RGS_INTERVAL: Duration = Duration::from_secs(86_400); // 24 h
/// How often to persist the scorer to Postgres.
const SCORER_INTERVAL: Duration = Duration::from_secs(600); // 10 min

// ── Graph ─────────────────────────────────────────────────────────────────────

/// Load a persisted `NetworkGraph` from `kv_store`, or construct a fresh one.
pub fn load_or_init_graph(
    kv_store: &PgKvStore,
    network: Network,
    logger: Arc<TracingLogger>,
) -> Arc<LnNetworkGraph> {
    use lightning::io::ErrorKind;
    use lightning::util::persist::KVStoreSync;

    match kv_store.read(GOSSIP_NS, "", GRAPH_KEY) {
        Ok(bytes) => {
            match NetworkGraph::read(&mut Cursor::new(bytes), logger.clone()) {
                Ok(g) => {
                    tracing::info!(target: "wick_lightning", "loaded persisted NetworkGraph");
                    return Arc::new(g);
                }
                Err(e) => {
                    tracing::warn!(
                        target: "wick_lightning",
                        error = ?e,
                        "persisted NetworkGraph failed to decode; starting fresh"
                    );
                }
            }
        }
        Err(ref e) if e.kind() == ErrorKind::NotFound => {
            tracing::info!(target: "wick_lightning", "no persisted NetworkGraph; starting fresh");
        }
        Err(e) => {
            tracing::warn!(
                target: "wick_lightning",
                error = %e,
                "error reading NetworkGraph; starting fresh"
            );
        }
    }
    Arc::new(NetworkGraph::new(network, logger))
}

/// Read `last_sync_ts` from `kv_store`, or return `0` (full-snapshot fetch).
pub fn load_last_sync_ts(kv_store: &PgKvStore) -> u32 {
    use lightning::io::ErrorKind;
    use lightning::util::persist::KVStoreSync;

    match kv_store.read(GOSSIP_NS, "", LAST_SYNC_KEY) {
        Ok(bytes) if bytes.len() == 4 => {
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }
        Ok(_) => 0,
        Err(ref e) if e.kind() == ErrorKind::NotFound => 0,
        Err(e) => {
            tracing::warn!(
                target: "wick_lightning",
                error = %e,
                "error reading last_sync_ts; will fetch full snapshot"
            );
            0
        }
    }
}

fn persist_graph(kv_store: &PgKvStore, graph: &LnNetworkGraph) {
    use lightning::util::persist::KVStoreSync;
    use lightning::util::ser::Writeable;

    let mut buf = Vec::new();
    if graph.write(&mut buf).is_err() {
        tracing::warn!(target: "wick_lightning", "failed to serialise NetworkGraph; skipping persist");
        return;
    }
    if let Err(e) = kv_store.write(GOSSIP_NS, "", GRAPH_KEY, buf) {
        tracing::warn!(
            target: "wick_lightning",
            error = %e,
            "failed to persist NetworkGraph"
        );
    }
}

fn persist_last_sync_ts(kv_store: &PgKvStore, ts: u32) {
    use lightning::util::persist::KVStoreSync;

    if let Err(e) = kv_store.write(GOSSIP_NS, "", LAST_SYNC_KEY, ts.to_be_bytes().to_vec()) {
        tracing::warn!(
            target: "wick_lightning",
            error = %e,
            "failed to persist last_sync_ts"
        );
    }
}

// ── Scorer ────────────────────────────────────────────────────────────────────

/// Load a persisted `ProbabilisticScorer`, or construct a fresh one.
pub fn load_or_init_scorer(
    kv_store: &PgKvStore,
    graph: Arc<LnNetworkGraph>,
    logger: Arc<TracingLogger>,
) -> LnScorer {
    use lightning::io::ErrorKind;
    use lightning::util::persist::KVStoreSync;

    let decay = ProbabilisticScoringDecayParameters::default();
    match kv_store.read(SCORER_NS, "", SCORER_KEY) {
        Ok(bytes) => {
            let args = (decay, graph.clone(), logger.clone());
            match ProbabilisticScorer::read(&mut Cursor::new(bytes), args) {
                Ok(s) => {
                    tracing::info!(target: "wick_lightning", "loaded persisted ProbabilisticScorer");
                    return Arc::new(RwLock::new(s));
                }
                Err(e) => {
                    tracing::warn!(
                        target: "wick_lightning",
                        error = ?e,
                        "persisted scorer failed to decode; starting fresh"
                    );
                }
            }
        }
        Err(ref e) if e.kind() == ErrorKind::NotFound => {
            tracing::info!(target: "wick_lightning", "no persisted scorer; starting fresh");
        }
        Err(e) => {
            tracing::warn!(
                target: "wick_lightning",
                error = %e,
                "error reading scorer; starting fresh"
            );
        }
    }

    Arc::new(RwLock::new(ProbabilisticScorer::new(
        decay,
        graph,
        logger,
    )))
}

pub fn persist_scorer(kv_store: &PgKvStore, scorer: &LnScorer) {
    use lightning::util::persist::KVStoreSync;

    let guard = match scorer.read() {
        Ok(g) => g,
        Err(_) => {
            tracing::warn!(target: "wick_lightning", "scorer RwLock poisoned; skipping persist");
            return;
        }
    };
    let mut buf = Vec::new();
    if guard.write(&mut buf).is_err() {
        tracing::warn!(target: "wick_lightning", "failed to serialise scorer; skipping persist");
        return;
    }
    if let Err(e) = kv_store.write(SCORER_NS, "", SCORER_KEY, buf) {
        tracing::warn!(
            target: "wick_lightning",
            error = %e,
            "failed to persist scorer"
        );
    }
}

// ── RGS apply ─────────────────────────────────────────────────────────────────

/// Fetch an RGS snapshot and apply it to `graph`.
///
/// On success, persists the updated graph and the new `last_sync_ts`.
/// Returns the new timestamp so the caller can use it for the next delta.
/// Returns `None` if the RGS URL is unset, the fetch fails, or apply fails.
pub async fn apply_rgs(
    rgs_base_url: &str,
    last_sync_ts: u32,
    graph: Arc<LnNetworkGraph>,
    kv_store: &PgKvStore,
    logger: Arc<TracingLogger>,
) -> Option<u32> {
    let url = format!("{rgs_base_url}/{last_sync_ts}");
    tracing::info!(
        target: "wick_lightning",
        url = %url,
        "fetching RGS snapshot"
    );

    let bytes = match reqwest::get(&url).await {
        Ok(resp) => match resp.bytes().await {
            Ok(b) => b.to_vec(),
            Err(e) => {
                tracing::warn!(
                    target: "wick_lightning",
                    url = %url,
                    error = %e,
                    "RGS response body read failed"
                );
                return None;
            }
        },
        Err(e) => {
            tracing::warn!(
                target: "wick_lightning",
                url = %url,
                error = %e,
                "RGS fetch failed"
            );
            return None;
        }
    };

    let rgs = RapidGossipSync::new(graph.clone(), logger);
    match rgs.update_network_graph(&bytes) {
        Ok(new_ts) => {
            let channels = graph.read_only().channels().len();
            tracing::info!(
                target: "wick_lightning",
                new_ts,
                channels,
                "RGS snapshot applied"
            );
            persist_graph(kv_store, graph.as_ref());
            persist_last_sync_ts(kv_store, new_ts);
            Some(new_ts)
        }
        Err(e) => {
            tracing::warn!(
                target: "wick_lightning",
                error = ?e,
                "RGS apply failed"
            );
            None
        }
    }
}

// ── Background tasks ──────────────────────────────────────────────────────────

/// Spawn a gossip background task that:
/// - Re-applies an RGS delta snapshot every 24 h.
/// - Persists the scorer every 10 min.
///
/// `rgs_url` is the base URL without the trailing `/{ts}` (e.g.
/// `"https://rgs.mutinynet.com/snapshot"`). Pass `None` for regtest.
pub fn spawn_gossip_tasks(
    rgs_url: Option<String>,
    graph: Arc<LnNetworkGraph>,
    scorer: LnScorer,
    kv_store: Arc<PgKvStore>,
    logger: Arc<TracingLogger>,
    mut stop_rx: watch::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut rgs_interval = tokio::time::interval(RGS_INTERVAL);
        rgs_interval.tick().await; // skip the immediate first tick
        let mut scorer_interval = tokio::time::interval(SCORER_INTERVAL);
        scorer_interval.tick().await;

        loop {
            tokio::select! {
                _ = rgs_interval.tick() => {
                    if let Some(ref url) = rgs_url {
                        let ts = load_last_sync_ts(kv_store.as_ref());
                        apply_rgs(url, ts, graph.clone(), kv_store.as_ref(), logger.clone()).await;
                    }
                }
                _ = scorer_interval.tick() => {
                    persist_scorer(kv_store.as_ref(), &scorer);
                }
                _ = stop_rx.changed() => break,
            }
        }

        // Persist scorer on graceful shutdown.
        persist_scorer(kv_store.as_ref(), &scorer);
    })
}

// ── Startup helper ────────────────────────────────────────────────────────────

/// Build and initialise the gossip layer for a node boot:
/// 1. Load or init `NetworkGraph` from Postgres.
/// 2. Load or init `ProbabilisticScorer` from Postgres.
/// 3. If `rgs_url` is set, fetch + apply a fresh RGS snapshot now (startup).
///
/// Returns `(graph, scorer)` ready for use by `DefaultRouter`.
pub async fn init_gossip(
    kv_store: Arc<PgKvStore>,
    network: Network,
    rgs_url: Option<&str>,
    logger: Arc<TracingLogger>,
) -> (Arc<LnNetworkGraph>, LnScorer) {
    let graph = load_or_init_graph(kv_store.as_ref(), network, logger.clone());
    let scorer = load_or_init_scorer(kv_store.as_ref(), graph.clone(), logger.clone());

    if let Some(url) = rgs_url {
        let ts = load_last_sync_ts(kv_store.as_ref());
        apply_rgs(url, ts, graph.clone(), kv_store.as_ref(), logger).await;
    }

    (graph, scorer)
}
