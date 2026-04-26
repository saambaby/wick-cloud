//! Persistent buffer for events that arrive while a tenant is parked.
//!
//! **Phase 2 scaffold — no live producers yet.** Phase 3's LSP event loop
//! will push `LspEvent` payloads here when the target tenant is parked;
//! the wake path will drain the buffer and forward each event to the
//! newly-active actor via its mpsc channel. Landing the type + DDL now
//! so Phase 3 can wire consumers without also migrating schema state.
//!
//! Ordering guarantees:
//! - Events are stored in a `BIGSERIAL` column, so `ORDER BY id ASC`
//!   is a valid per-tenant insertion-order replay.
//! - [`PendingEventStore::ack`] must run **after** the mpsc send to the
//!   active actor succeeds. Acking before delivery risks silently
//!   dropping events if the actor task is cancelled mid-drain.

use anyhow::Context;
use wick_core::TenantId;
use wick_db::Pool;

/// Stateless Postgres-backed buffer.
///
/// No struct fields — all methods are associated and take `&Pool` +
/// `TenantId`. Reserved as a type so Phase 3 can add per-tenant caches
/// or batching without a source-breaking API change.
#[derive(Debug)]
pub struct PendingEventStore;

impl PendingEventStore {
    /// Enqueue one event payload for `tenant_id`. Returns the serial id
    /// Postgres assigned so callers can correlate it back to [`Self::ack`].
    pub async fn push(pool: &Pool, tenant_id: TenantId, payload: &[u8]) -> anyhow::Result<i64> {
        let schema = tenant_id.schema_name();
        let sql =
            format!(r#"INSERT INTO "{schema}".pending_events (payload) VALUES ($1) RETURNING id"#);
        let id: (i64,) = sqlx::query_as(&sql)
            .bind(payload)
            .fetch_one(pool.raw())
            .await
            .context("insert pending_events row")?;
        Ok(id.0)
    }

    /// Read up to `limit` oldest events for `tenant_id` without deleting
    /// them. Callers hand the payloads to the active actor's mpsc and
    /// then call [`Self::ack`] once the sends succeed.
    pub async fn drain(
        pool: &Pool,
        tenant_id: TenantId,
        limit: i64,
    ) -> anyhow::Result<Vec<(i64, Vec<u8>)>> {
        let schema = tenant_id.schema_name();
        let sql = format!(
            r#"SELECT id, payload FROM "{schema}".pending_events
               ORDER BY id ASC LIMIT $1"#
        );
        let rows = sqlx::query_as::<_, (i64, Vec<u8>)>(&sql)
            .bind(limit)
            .fetch_all(pool.raw())
            .await
            .context("select pending_events")?;
        Ok(rows)
    }

    /// Delete the given event ids after the active actor has received
    /// them. Idempotent — acking an id that's already gone is a no-op.
    pub async fn ack(pool: &Pool, tenant_id: TenantId, ids: &[i64]) -> anyhow::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let schema = tenant_id.schema_name();
        let sql = format!(r#"DELETE FROM "{schema}".pending_events WHERE id = ANY($1)"#);
        sqlx::query(&sql)
            .bind(ids)
            .execute(pool.raw())
            .await
            .context("delete pending_events rows")?;
        Ok(())
    }

    /// Count buffered events for `tenant_id`. Used by the wake path to
    /// short-circuit empty drains and by the evictor to avoid parking
    /// tenants with backlog (a park-with-backlog isn't wrong, but the
    /// events stay unprocessed longer than necessary).
    pub async fn len(pool: &Pool, tenant_id: TenantId) -> anyhow::Result<i64> {
        let schema = tenant_id.schema_name();
        let sql = format!(r#"SELECT COUNT(*)::bigint FROM "{schema}".pending_events"#);
        let (n,): (i64,) = sqlx::query_as(&sql)
            .fetch_one(pool.raw())
            .await
            .context("count pending_events")?;
        Ok(n)
    }
}
