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

use lightning::routing::gossip::NetworkGraph;
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringDecayParameters};
use lightning::util::ser::{ReadableArgs, Writeable};
use lightning_rapid_gossip_sync::RapidGossipSync;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use wick_core::WickNetwork;

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

/// How often to re-apply an RGS delta snapshot when the previous apply
/// succeeded.
const RGS_INTERVAL: Duration = Duration::from_secs(86_400); // 24 h
/// How often to persist the scorer to Postgres.
const SCORER_INTERVAL: Duration = Duration::from_secs(600); // 10 min

/// Back-off schedule when an RGS fetch or apply fails. After the last
/// entry the loop falls back to the normal [`RGS_INTERVAL`] cadence —
/// at that point the failure has persisted long enough that more
/// aggressive retries are just wasted requests on a broken endpoint.
/// Each entry is the delay *after* the corresponding failure count
/// (`0`-indexed: first failure → wait `RGS_BACKOFF[0]`).
const RGS_BACKOFF: [Duration; 4] = [
    Duration::from_secs(60),        // 1 min
    Duration::from_secs(5 * 60),    // 5 min
    Duration::from_secs(30 * 60),   // 30 min
    Duration::from_secs(2 * 3_600), // 2 h
];

// ── Decay tuning ──────────────────────────────────────────────────────────────

/// Per-network [`ProbabilisticScoringDecayParameters`].
///
/// LDK's defaults (30 min / 14 days) are tuned for Bitcoin mainnet's
/// ~10-minute block interval and slow-moving payment graphs. Signet
/// matches that cadence closely enough to reuse defaults, but regtest
/// (sub-second blocks) and mutinynet (30-second blocks) churn their
/// graphs fast enough that 30-minute liquidity decay and 14-day
/// historical decay hold onto wrong answers for far too long —
/// throughput tests run against stale probes and pathfind around
/// channels that no longer exist.
///
/// **Regtest** → 5 min / 30 min. Tests are over in seconds; anything
/// beyond the last couple of minutes is noise.
///
/// **Mutinynet** → 10 min / 2 days. The 30-second block cadence is
/// roughly 20× faster than mainnet, so decay is roughly 3× faster than
/// default. Not 20× — mutinynet's graph is small and relatively stable
/// once a node has warm peers, so the historical learning window
/// shouldn't collapse entirely.
///
/// **Signet** → LDK defaults. Public signet mirrors mainnet block
/// cadence; the conservative defaults are still the right call.
#[must_use]
pub fn decay_params_for(network: WickNetwork) -> ProbabilisticScoringDecayParameters {
    match network {
        WickNetwork::Regtest => ProbabilisticScoringDecayParameters {
            liquidity_offset_half_life: Duration::from_secs(5 * 60),
            historical_no_updates_half_life: Duration::from_secs(30 * 60),
        },
        WickNetwork::Mutinynet => ProbabilisticScoringDecayParameters {
            liquidity_offset_half_life: Duration::from_secs(10 * 60),
            historical_no_updates_half_life: Duration::from_secs(2 * 24 * 60 * 60),
        },
        WickNetwork::Signet => ProbabilisticScoringDecayParameters::default(),
    }
}

// ── Graph ─────────────────────────────────────────────────────────────────────

/// Load a persisted `NetworkGraph` from `kv_store`, or construct a fresh one.
pub fn load_or_init_graph(
    kv_store: &PgKvStore,
    network: bitcoin::Network,
    logger: Arc<TracingLogger>,
) -> Arc<LnNetworkGraph> {
    use lightning::io::ErrorKind;
    use lightning::util::persist::KVStoreSync;

    match kv_store.read(GOSSIP_NS, "", GRAPH_KEY) {
        Ok(bytes) => match NetworkGraph::read(&mut Cursor::new(bytes), logger.clone()) {
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
        },
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
///
/// `network` picks the per-network decay parameters — see
/// [`decay_params_for`] for the rationale. The same parameters are
/// passed to `ProbabilisticScorer::read` when rehydrating a persisted
/// scorer, which is required by LDK's deserialisation API.
pub fn load_or_init_scorer(
    kv_store: &PgKvStore,
    graph: Arc<LnNetworkGraph>,
    network: WickNetwork,
    logger: Arc<TracingLogger>,
) -> LnScorer {
    use lightning::io::ErrorKind;
    use lightning::util::persist::KVStoreSync;

    let decay = decay_params_for(network);
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

    Arc::new(RwLock::new(ProbabilisticScorer::new(decay, graph, logger)))
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
        let mut scorer_interval = tokio::time::interval(SCORER_INTERVAL);
        scorer_interval.tick().await;

        // Consecutive RGS failures drive the back-off schedule. A single
        // success resets it so transient blips don't permanently slow
        // the cadence.
        let mut rgs_failures: u32 = 0;
        let rgs_sleep = tokio::time::sleep(RGS_INTERVAL);
        tokio::pin!(rgs_sleep);

        loop {
            tokio::select! {
                _ = &mut rgs_sleep => {
                    if let Some(ref url) = rgs_url {
                        let ts = load_last_sync_ts(kv_store.as_ref());
                        let applied = apply_rgs(
                            url,
                            ts,
                            graph.clone(),
                            kv_store.as_ref(),
                            logger.clone(),
                        )
                        .await;
                        if applied.is_some() {
                            rgs_failures = 0;
                        } else {
                            rgs_failures = rgs_failures.saturating_add(1);
                        }
                    }
                    let next = rgs_next_delay(rgs_failures, rgs_url.is_some());
                    rgs_sleep.as_mut().reset(tokio::time::Instant::now() + next);
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

/// Choose the delay before the next RGS attempt.
///
/// `failures == 0` → the normal 24 h cadence (the last attempt
/// succeeded, or there have been no attempts yet).
///
/// `failures >= 1` → step through [`RGS_BACKOFF`]. Beyond the last
/// entry we fall back to the normal cadence so we don't spin forever
/// retrying against a permanently broken endpoint.
///
/// If `rgs_enabled` is false (e.g. regtest with no RGS URL), the
/// caller still needs *some* delay so the select loop keeps running
/// without busy-waiting — [`RGS_INTERVAL`] is as good as any.
fn rgs_next_delay(failures: u32, rgs_enabled: bool) -> Duration {
    if !rgs_enabled || failures == 0 {
        return RGS_INTERVAL;
    }
    let idx = (failures as usize).saturating_sub(1);
    if idx < RGS_BACKOFF.len() {
        RGS_BACKOFF[idx]
    } else {
        RGS_INTERVAL
    }
}

#[cfg(test)]
mod rgs_backoff_tests {
    use super::*;

    #[test]
    fn success_uses_normal_cadence() {
        assert_eq!(rgs_next_delay(0, true), RGS_INTERVAL);
    }

    #[test]
    fn failures_step_through_backoff() {
        assert_eq!(rgs_next_delay(1, true), RGS_BACKOFF[0]);
        assert_eq!(rgs_next_delay(2, true), RGS_BACKOFF[1]);
        assert_eq!(rgs_next_delay(3, true), RGS_BACKOFF[2]);
        assert_eq!(rgs_next_delay(4, true), RGS_BACKOFF[3]);
    }

    #[test]
    fn beyond_backoff_falls_back_to_normal() {
        assert_eq!(rgs_next_delay(5, true), RGS_INTERVAL);
        assert_eq!(rgs_next_delay(u32::MAX, true), RGS_INTERVAL);
    }

    #[test]
    fn disabled_rgs_uses_normal_cadence() {
        // Regtest: no URL, still want the select loop to idle at a
        // sensible cadence rather than busy-waiting.
        assert_eq!(rgs_next_delay(0, false), RGS_INTERVAL);
        assert_eq!(rgs_next_delay(3, false), RGS_INTERVAL);
    }
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
    network: WickNetwork,
    rgs_url: Option<&str>,
    logger: Arc<TracingLogger>,
) -> (Arc<LnNetworkGraph>, LnScorer) {
    let graph = load_or_init_graph(kv_store.as_ref(), network.into(), logger.clone());
    let scorer = load_or_init_scorer(kv_store.as_ref(), graph.clone(), network, logger.clone());

    if let Some(url) = rgs_url {
        let ts = load_last_sync_ts(kv_store.as_ref());
        apply_rgs(url, ts, graph.clone(), kv_store.as_ref(), logger).await;
    }

    (graph, scorer)
}
