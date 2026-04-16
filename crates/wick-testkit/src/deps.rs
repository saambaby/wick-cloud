//! Test-only [`NodeDeps`] builder.
//!
//! Produces a `NodeDeps` bundle using:
//! - `PgPool::connect_lazy` against an env-configured `DATABASE_URL` (no actual
//!   connection until first use — tests that don't touch Postgres can still
//!   instantiate this).
//! - A regtest Esplora endpoint (default `http://localhost:3002`).
//! - A deterministic zero seed so `LocalKeysManager` construction is stable.
//!
//! Real integration tests should override via [`StubDepsConfig`]; unit tests
//! typically want [`stub()`] with defaults.

use std::sync::Arc;

use anyhow::Result;
use bitcoin::Network;
use sqlx::postgres::PgPoolOptions;
use wick_lightning::{
    EsploraBroadcaster, EsploraChainClient, FeeEstimator, NodeDeps, TracingLogger,
};

/// Test knobs for [`stub_deps`].
///
/// `regtest_seed` is no longer part of [`wick_lightning::NodeDeps`] — the
/// signer is always injected via `NodeBuilder::with_signer`. The regtest seed
/// used to build a `LocalKeysManager` for tests lives in
/// [`crate::signer`](super::signer), not in the deps bundle.
#[derive(Debug, Clone)]
pub struct StubDepsConfig {
    /// Postgres connection string. Default: `DATABASE_URL` env var, falling
    /// back to `postgres://wick:wick@localhost:5432/wick_dev`.
    pub database_url: String,
    /// Esplora REST URL used by LDK for chain sync (fee estimates, tx
    /// broadcast, SPV headers). Default: `ESPLORA_URL` env var, falling back
    /// to `http://localhost:3002` (Electrs REST port in docker-compose).
    pub esplora_url: String,
    /// Electrum TCP URL used by [`crate::TestWallet`] for UTXO scanning.
    /// Points at the same Electrs instance via its Electrum protocol port.
    /// Default: `ELECTRUM_URL` env var, falling back to
    /// `tcp://localhost:50001` (Electrs Electrum port in docker-compose).
    pub electrum_url: String,
    /// Bitcoin network. Default: `Network::Regtest`.
    pub network: Network,
    /// Base port for per-tenant P2P listeners. `0` → OS assigns a free port
    /// per tenant (the right default for parallel tests).
    pub listen_port_base: u16,
}

impl Default for StubDepsConfig {
    fn default() -> Self {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://wick:wick@localhost:5432/wick_dev".to_owned()
        });
        Self {
            database_url,
            esplora_url: std::env::var("ESPLORA_URL")
                .unwrap_or_else(|_| "http://localhost:3002".to_owned()),
            electrum_url: std::env::var("ELECTRUM_URL")
                .unwrap_or_else(|_| "tcp://localhost:50001".to_owned()),
            network: Network::Regtest,
            listen_port_base: 0,
        }
    }
}

/// Build a [`NodeDeps`] for tests.
///
/// Uses a lazily-connected Postgres pool so tests that don't touch Postgres
/// don't require a live DB. The Esplora client is constructed eagerly (it
/// only dials on first request).
///
/// # Errors
/// Returns an error if the Postgres URL fails to parse or the Esplora client
/// builder rejects the URL.
pub fn stub_deps(cfg: &StubDepsConfig) -> Result<NodeDeps> {
    let pg_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_lazy(&cfg.database_url)?;

    let esplora = Arc::new(EsploraChainClient::new(&cfg.esplora_url, cfg.network)?);
    let broadcaster = Arc::new(EsploraBroadcaster::new(esplora.esplora()));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let logger = Arc::new(TracingLogger);

    Ok(NodeDeps {
        pg_pool,
        esplora,
        broadcaster,
        fee_estimator,
        logger,
        runtime: tokio::runtime::Handle::current(),
        listen_port_base: cfg.listen_port_base,
    })
}

/// Convenience — [`stub_deps`] with all defaults.
///
/// # Errors
/// See [`stub_deps`].
pub fn stub() -> Result<NodeDeps> {
    stub_deps(&StubDepsConfig::default())
}
