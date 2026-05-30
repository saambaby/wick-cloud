//! Postgres-backed [`KVStoreSync`] for per-tenant LDK state.
//!
//! All writes live in `{tenant_schema}.vss_objects` (DDL in
//! `wick_server::node::manager`). A single Postgres row corresponds to one
//! LDK key, addressed by the concatenation
//! `{primary_namespace}/{secondary_namespace}/{key}`. `/` is safe as a
//! separator because LDK restricts namespaces and keys to the alphabet
//! `[a-zA-Z0-9_-]`.
//!
//! ## Sync → async bridge
//!
//! LDK's [`KVStoreSync`] trait is synchronous, but sqlx is not. Each call uses
//! [`tokio::task::block_in_place`] + `runtime.block_on(..)` to drive the async
//! work to completion without starving the scheduler. This requires a
//! **multi-threaded Tokio runtime** (the default of `#[tokio::main]`). Calling
//! from a single-threaded runtime will panic.
//!
//! The phase-3 architecture assumes every [`crate::Node`] lives inside a
//! [`wick_server::node::actor::NodeActor`] task on the main multi-threaded
//! runtime, which satisfies that requirement.
//!
//! ## Phase 4 swap-out
//!
//! Phase 4 replaces this store with an end-to-end encrypted VSS client. The
//! [`KVStoreSync`] seam means `Node` construction flips which store it wraps
//! and nothing else changes.

use std::sync::Arc;
use std::sync::OnceLock;

use lightning::io;
use lightning::util::persist::KVStoreSync;
use sqlx::{PgPool, Row};
use tokio::runtime::Handle;
use wick_core::TenantId;

/// Dedicated runtime for driving KVStore sqlx futures, isolated from the
/// main application runtime.
///
/// LDK calls [`KVStoreSync`] methods synchronously from the process-events
/// loop and actor tasks, all on the **main** multi-threaded runtime. Bridging
/// each call to async by spawning the sqlx future *on that same runtime* and
/// then `block_in_place(rx.recv())` deadlocks under a persistence burst (e.g.
/// a channel open, which persists the ChannelManager + every ChannelMonitor +
/// the liquidity EventQueue in quick succession): enough main-runtime workers
/// end up parked in `block_in_place(rx.recv())` that none remain to *poll* the
/// spawned sqlx futures, so they never send and every waiter hangs forever
/// (observed: the whole runtime wedges, even timers stop firing).
///
/// Running the sqlx futures on a separate runtime whose workers never call
/// `block_in_place` breaks the cycle: those workers are always free to drive
/// the Postgres IO to completion, so `rx.recv()` on the main side always
/// unblocks. `block_in_place` is still used on the caller side so the *main*
/// runtime spins up a replacement worker while this one waits.
fn kv_runtime() -> &'static Handle {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("wick-kvstore")
            .enable_all()
            .build()
            .expect("build dedicated KVStore runtime")
    })
    .handle()
}

/// Postgres-backed KV store for a single tenant.
///
/// Cloning is cheap — the pool and schema are behind `Arc` indirections.
#[derive(Debug, Clone)]
pub struct PgKvStore {
    pool: PgPool,
    schema: Arc<String>,
}

impl PgKvStore {
    /// Construct a store bound to `tenant_id`'s schema on `pool`.
    #[must_use]
    pub fn new(tenant_id: TenantId, pool: PgPool) -> Self {
        Self {
            pool,
            schema: Arc::new(tenant_id.schema_name()),
        }
    }

    /// Compose the Postgres row key from an LDK namespace tuple.
    fn encode_key(primary: &str, secondary: &str, key: &str) -> String {
        format!("{primary}/{secondary}/{key}")
    }

    /// Prefix used by [`KVStoreSync::list`] to scope a `LIKE` query.
    fn namespace_prefix(primary: &str, secondary: &str) -> String {
        format!("{primary}/{secondary}/")
    }

    /// Drive `fut` to completion synchronously from a main-runtime worker
    /// without deadlocking the main runtime's worker pool.
    ///
    /// `fut` is spawned on the **dedicated** [`kv_runtime`] (not the main
    /// runtime), whose workers never call `block_in_place` and are therefore
    /// always available to poll it to completion. `block_in_place` on the
    /// caller side releases this main-runtime worker (the runtime spins up a
    /// replacement) so the main runtime keeps making progress while we wait
    /// on the cross-runtime channel. See [`kv_runtime`] for the deadlock this
    /// avoids — an earlier version spawned `fut` on the main runtime and hung
    /// the whole process under a channel-open persistence burst.
    fn block_on<F, T>(&self, fut: F) -> T
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::sync_channel::<T>(1);
        kv_runtime().spawn(async move {
            let _ = tx.send(fut.await);
        });
        tokio::task::block_in_place(|| {
            rx.recv()
                .expect("PgKvStore::block_on: spawned future panicked or runtime dropped")
        })
    }

    async fn read_async(&self, row_key: &str) -> Result<Vec<u8>, io::Error> {
        // Schema is derived from TenantId which enforces `^[0-9]+$` — safe to
        // interpolate. Double-quote so Postgres treats it as a valid ident.
        let sql = format!(
            r#"SELECT value FROM "{}".vss_objects WHERE key = $1"#,
            self.schema
        );
        let row = sqlx::query(&sql)
            .bind(row_key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| sqlx_to_io(&e))?;

        match row {
            Some(r) => Ok(r
                .try_get::<Vec<u8>, _>("value")
                .map_err(|e| sqlx_to_io(&e))?),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "key not in store")),
        }
    }

    async fn write_async(&self, row_key: &str, buf: Vec<u8>) -> Result<(), io::Error> {
        let sql = format!(
            r#"
INSERT INTO "{}".vss_objects (key, version, value, updated_at)
VALUES ($1, 1, $2, now())
ON CONFLICT (key) DO UPDATE
  SET version = "{}".vss_objects.version + 1,
      value   = EXCLUDED.value,
      updated_at = now()
"#,
            self.schema, self.schema
        );
        sqlx::query(&sql)
            .bind(row_key)
            .bind(&buf)
            .execute(&self.pool)
            .await
            .map_err(|e| sqlx_to_io(&e))?;
        Ok(())
    }

    async fn remove_async(&self, row_key: &str) -> Result<(), io::Error> {
        let sql = format!(
            r#"DELETE FROM "{}".vss_objects WHERE key = $1"#,
            self.schema
        );
        sqlx::query(&sql)
            .bind(row_key)
            .execute(&self.pool)
            .await
            .map_err(|e| sqlx_to_io(&e))?;
        Ok(())
    }

    /// Move a value whose bytes failed to decode into a quarantine slot so
    /// an operator can inspect it later without the boot path tripping on
    /// the same row on every restart attempt.
    ///
    /// Writes `bytes` to `quarantine/<rfc3339_ts>/<original_key>`. Does
    /// **not** delete the original — the caller decides whether the
    /// corrupt row should be overwritten or left intact for forensics. In
    /// practice `wick-lightning::builder` returns `PersistenceDecode`
    /// immediately after quarantining, so the tenant stays in ERROR until
    /// manual intervention; the original row is kept so a matching pair
    /// (live row + quarantine row) survives in Postgres.
    ///
    /// The timestamp in the secondary namespace means repeated quarantine
    /// attempts (rare, but possible if the operator restarts the node
    /// several times before clearing state) don't clobber each other.
    pub fn quarantine(&self, original_key: &str, bytes: Vec<u8>) -> Result<(), io::Error> {
        use lightning::util::persist::KVStoreSync;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let secondary = ts.to_string();
        tracing::error!(
            target: "wick_lightning",
            schema = %self.schema,
            original_key,
            quarantine_ts = secondary,
            bytes_len = bytes.len(),
            "quarantining undecodable LDK state — operator intervention required"
        );
        self.write("quarantine", &secondary, original_key, bytes)
    }

    async fn list_async(&self, prefix: &str) -> Result<Vec<String>, io::Error> {
        let sql = format!(
            r#"SELECT key FROM "{}".vss_objects WHERE key LIKE $1"#,
            self.schema
        );
        let like = format!("{prefix}%");
        let rows = sqlx::query(&sql)
            .bind(&like)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| sqlx_to_io(&e))?;

        let mut keys = Vec::with_capacity(rows.len());
        for row in rows {
            let full: String = row.try_get("key").map_err(|e| sqlx_to_io(&e))?;
            if let Some(stripped) = full.strip_prefix(prefix) {
                keys.push(stripped.to_owned());
            }
        }
        Ok(keys)
    }
}

impl KVStoreSync for PgKvStore {
    fn read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Result<Vec<u8>, io::Error> {
        let row_key = Self::encode_key(primary_namespace, secondary_namespace, key);
        let me = self.clone();
        self.block_on(async move { me.read_async(&row_key).await })
    }

    fn write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        buf: Vec<u8>,
    ) -> Result<(), io::Error> {
        let row_key = Self::encode_key(primary_namespace, secondary_namespace, key);
        let me = self.clone();
        self.block_on(async move { me.write_async(&row_key, buf).await })
    }

    fn remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        _lazy: bool,
    ) -> Result<(), io::Error> {
        // `lazy` is a hint; Postgres DELETE is cheap enough that we always
        // execute eagerly — simpler consistency and avoids resurrecting rows
        // via a deferred batch.
        let row_key = Self::encode_key(primary_namespace, secondary_namespace, key);
        let me = self.clone();
        self.block_on(async move { me.remove_async(&row_key).await })
    }

    fn list(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
    ) -> Result<Vec<String>, io::Error> {
        let prefix = Self::namespace_prefix(primary_namespace, secondary_namespace);
        let me = self.clone();
        self.block_on(async move { me.list_async(&prefix).await })
    }
}

/// Map sqlx errors to the LDK `io::Error` alias so the trait can consume them.
fn sqlx_to_io(e: &sqlx::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("sqlx: {e}").as_str())
}
