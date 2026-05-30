//! Connection pool with `AfterRelease` reset.
//!
//! The pool is configured so every connection released back to the pool has
//! its session state reset with `RESET ALL`. This is belt-and-braces on top
//! of the `SET LOCAL` transaction discipline used by [`crate::tenant_tx`] —
//! we never rely on either mechanism alone.

use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Executor, PgPool,
};
use tracing::debug;

use wick_core::error::{Result, WickError};

/// Thin wrapper around [`PgPool`]. Exists so future hooks (tracing, metrics,
/// connection limits per tenant, etc.) can be added without touching callers.
#[derive(Debug, Clone)]
pub struct Pool {
    inner: PgPool,
}

impl Pool {
    /// Connect to `database_url` with the Wick tenant-isolation settings.
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self> {
        let opts: PgConnectOptions = database_url
            .parse()
            .map_err(|e: sqlx::Error| WickError::Config(format!("bad DATABASE_URL: {e}")))?;
        let opts = opts.log_statements(tracing::log::LevelFilter::Debug);

        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            // Fail an acquire after 10s instead of the 30s default. Under a
            // persistence burst the LDK event loop would otherwise stall 30s
            // per blocked write before surfacing the error; failing fast lets
            // the store's retry + the loop's supervised restart recover sooner.
            .acquire_timeout(std::time::Duration::from_secs(10))
            .after_release(|conn, _meta| {
                Box::pin(async move {
                    // Defence-in-depth reset. `SET LOCAL` already scopes the
                    // tenant settings to their transaction, but if a handler
                    // ever forgot to open a transaction, this still catches
                    // it by wiping any bare `SET` that leaked.
                    conn.execute("RESET ALL").await?;
                    Ok(true)
                })
            })
            .connect_with(opts)
            .await
            .map_err(|e| WickError::Dependency(format!("pg connect: {e}")))?;

        debug!(max_connections, "postgres pool online");
        Ok(Self { inner: pool })
    }

    /// Borrow the inner `sqlx` pool — only for code that needs the raw API
    /// (e.g. migrations). New code should go through [`crate::tenant_tx`].
    #[must_use]
    pub fn raw(&self) -> &PgPool {
        &self.inner
    }
}

impl Pool {
    /// Construct from an existing [`PgPool`]. Used by tests.
    #[must_use]
    pub fn from_sqlx(inner: PgPool) -> Self {
        Self { inner }
    }
}

/// Type hint so downstream crates can write `fn take_pool(p: &impl SqlxPool)`.
pub trait SqlxPool: Send + Sync {
    /// Access the underlying pool.
    fn pg(&self) -> &PgPool;
}

impl SqlxPool for Pool {
    fn pg(&self) -> &PgPool {
        &self.inner
    }
}
