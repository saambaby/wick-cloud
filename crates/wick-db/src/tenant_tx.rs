//! Tenant-scoped transaction helper.
//!
//! This is the *only* supported way to run queries against tenant data.
//! It enforces the four-layer discipline from `docs/wick_architecture.md` §4.1:
//!
//! 1. Open an explicit transaction.
//! 2. `SET LOCAL search_path TO tenant_{id}, global;`
//! 3. `SET LOCAL app.current_tenant_id = '{id}';`
//! 4. Assert `current_setting('app.current_tenant_id')` matches the caller's
//!    expected tenant — aborts with `tenant_guard_mismatch_total` on mismatch.
//!
//! Callers pass an async closure that receives a [`sqlx::PgTransaction`] and
//! returns the query result. The helper commits on success, rolls back on
//! error, and records metrics either way.

use std::future::Future;

use metrics::counter;
use sqlx::{Executor, PgPool, Row, Transaction};
use tracing::{debug, warn};

use wick_core::error::{Result, WickError};
use wick_core::tenant::TenantId;

/// Run `f` inside a tenant-scoped transaction.
///
/// # Errors
/// - `WickError::Dependency` on Postgres I/O errors.
/// - `WickError::TenantGuardMismatch` if the runtime guard fires.
pub async fn tenant_tx<'a, T, F, Fut>(pool: &'a PgPool, tenant: TenantId, f: F) -> Result<T>
where
    F: for<'c> FnOnce(&'c mut Transaction<'a, sqlx::Postgres>) -> Fut,
    Fut: Future<Output = Result<T>> + Send + 'a,
    T: Send + 'a,
{
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| WickError::Dependency(format!("begin tx: {e}")))?;

    // Validated id → schema name. Formatting uses only ascii digits so this
    // string is safe to interpolate into DDL-adjacent contexts, but we use
    // bound parameters for the current_tenant_id setting anyway.
    let schema = tenant.schema_name();

    // Schema-name components cannot be parameterised by libpq, so we splice
    // the validated string. `TenantId` construction guarantees `^[0-9]+$`.
    let set_search_path = format!("SET LOCAL search_path TO \"{schema}\", global");
    tx.execute(sqlx::query(&set_search_path))
        .await
        .map_err(|e| WickError::Dependency(format!("set search_path: {e}")))?;

    sqlx::query("SELECT set_config('app.current_tenant_id', $1::text, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| WickError::Dependency(format!("set current_tenant_id: {e}")))?;

    // Runtime guard — the first real statement in every tenant tx.
    let row = sqlx::query("SELECT current_setting('app.current_tenant_id', true)")
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| WickError::Dependency(format!("guard read: {e}")))?;
    let actual: Option<String> = row.try_get(0).ok();
    let expected = tenant.to_string();
    if actual.as_deref() != Some(expected.as_str()) {
        counter!("tenant_guard_mismatch_total").increment(1);
        warn!(?actual, %expected, "tenant guard mismatch");
        return Err(WickError::TenantGuardMismatch {
            expected,
            actual: actual.unwrap_or_default(),
        });
    }

    debug!(%tenant, "tenant tx open");

    let outcome = f(&mut tx).await;

    match outcome {
        Ok(v) => {
            tx.commit()
                .await
                .map_err(|e| WickError::Dependency(format!("commit: {e}")))?;
            counter!("tenant_tx_commit_total").increment(1);
            Ok(v)
        }
        Err(e) => {
            // Rollback is best-effort; if it fails we still surface the
            // original error to the caller.
            let _ = tx.rollback().await;
            counter!("tenant_tx_rollback_total").increment(1);
            Err(e)
        }
    }
}
