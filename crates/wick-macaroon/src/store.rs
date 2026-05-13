//! Postgres-backed glue for the macaroon revocation set and spend-window cap.
//!
//! Only compiled with `feature = "postgres"`. M1 ships the in-memory math
//! (`WindowState`, `check_spend`, `VerifyContext::revoked_nonces`); this
//! module owns the durable side:
//!
//! * [`RevocationSet`] — process-local `HashSet<[u8;16]>` bootstrapped from
//!   `global.revoked_macaroons` and kept fresh via `LISTEN wick_macaroon_revoked`.
//!   The architecture target is p99 < 1s end-to-end (gotcha #383).
//! * [`SpendWindowStore`] — `try_spend` performs an atomic INSERT … ON
//!   CONFLICT DO UPDATE … WHERE upsert against `global.macaroon_spend_window`
//!   so multiple wick-server processes cannot race-double-count under the
//!   per-macaroon cap.
//!
//! M3's gRPC interceptor wires these into the request path; nothing in M2
//! touches gRPC.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use sqlx::postgres::PgListener;
use sqlx::{PgPool, Row};
use tokio::task::JoinHandle;

/// Postgres NOTIFY channel name. Trigger in `0006_macaroon.sql` fires the
/// nonce as a lowercase hex string of exactly 32 chars.
pub const REVOKED_CHANNEL: &str = "wick_macaroon_revoked";

const RECONNECT_BACKOFF: Duration = Duration::from_secs(1);

/// Wall-clock interval for the full re-bootstrap safety net. M3
/// research finding: LISTEN/NOTIFY can silently drop notifications
/// between reconnects (typically a sub-second drop is invisible to
/// `PgListener`), so even without an observed connection drop we
/// re-query `global.revoked_macaroons` on this cadence to fold any
/// missed rows into the in-memory set. The query is bounded to the
/// last hour, so it stays cheap regardless of total revocation count.
const FULL_REBOOTSTRAP_INTERVAL: Duration = Duration::from_secs(300);

/// Bound on the lookback window for the periodic re-bootstrap query.
/// One hour comfortably covers any plausible LISTEN drop without
/// scanning the whole revocation table.
const REBOOTSTRAP_LOOKBACK_SECS: u32 = 3_600;

/// In-memory mirror of `global.revoked_macaroons`, kept current by
/// LISTEN/NOTIFY. Cheap to `clone` (Arc'd internally) and safe to read
/// from many request handlers concurrently.
#[derive(Debug, Clone, Default)]
pub struct RevocationSet {
    inner: Arc<RwLock<HashSet<[u8; 16]>>>,
}

impl RevocationSet {
    /// Empty set — useful for tests that don't need a Postgres backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` if `nonce` is in the revoked set.
    #[must_use]
    pub fn contains(&self, nonce: &[u8; 16]) -> bool {
        self.inner.read().contains(nonce)
    }

    /// Number of revoked nonces currently cached. For metrics/debug.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Snapshot the current set — useful for plumbing into
    /// [`crate::VerifyContext::revoked_nonces`] without holding the lock
    /// across an await point. Cheap relative to the verify HMAC chain.
    #[must_use]
    pub fn snapshot(&self) -> HashSet<[u8; 16]> {
        self.inner.read().clone()
    }

    /// Bootstrap from `global.revoked_macaroons` then spawn a background
    /// task that listens on `wick_macaroon_revoked`. The returned join
    /// handle lets the caller cancel the listener at shutdown.
    ///
    /// Re-bootstrap discipline (two layers):
    ///
    /// 1. **On reconnect.** After a listener drop we re-run the bootstrap
    ///    SELECT. `pg_notify` does **not** guarantee delivery across
    ///    connection loss, so missing rows during the gap would otherwise
    ///    silently break revocation. The price is one extra query per
    ///    reconnect, negligible against a ≤100k worst-case row count.
    ///
    /// 2. **Wall-clock 5-minute safety net.** Even without an observed
    ///    drop, `PgListener` can lose notifications during transient
    ///    network blips that fall inside its internal reconnect window
    ///    (D3 M3 research finding — see
    ///    `<vault>/research/concepts/macaroons-auto-rotate.md`). A
    ///    bounded SELECT against the last `REBOOTSTRAP_LOOKBACK_SECS`
    ///    runs every [`FULL_REBOOTSTRAP_INTERVAL`] and folds in any rows
    ///    we missed. Cheap because of the window predicate.
    ///
    /// `PgListener` from sqlx uses its own dedicated connection (the
    /// pool's `acquire` here returns a fresh one that never runs a user
    /// transaction). LISTEN is autocommit by construction — sqlx never
    /// wraps it in BEGIN/COMMIT — so no extra configuration is needed.
    pub async fn start(pool: PgPool) -> sqlx::Result<(Self, JoinHandle<()>)> {
        let set = Self::default();
        bootstrap(&pool, &set.inner).await?;

        let inner = Arc::clone(&set.inner);
        let handle = tokio::spawn(async move {
            run_revocation_listener(pool, inner).await;
        });

        Ok((set, handle))
    }

    /// Revoke a macaroon in one round-trip: INSERT … ON CONFLICT DO
    /// NOTHING, then mirror the row into the local cache. Idempotent —
    /// re-revoking a nonce that is already in the table succeeds.
    ///
    /// Adding to the local cache directly (rather than waiting for our
    /// own NOTIFY round-trip to arrive) means the issuing process sees
    /// the revocation immediately; other processes pick it up via LISTEN.
    pub async fn revoke(
        &self,
        pool: &PgPool,
        nonce: [u8; 16],
        reason: Option<&str>,
    ) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO global.revoked_macaroons (nonce, reason) \
             VALUES ($1, $2) \
             ON CONFLICT (nonce) DO NOTHING",
        )
        .bind(&nonce[..])
        .bind(reason)
        .execute(pool)
        .await?;
        self.inner.write().insert(nonce);
        Ok(())
    }

    /// Revoke a nonce with a finite TTL — `valid_until = now() + ttl`.
    ///
    /// D3 M3 rotation grace: when a macaroon is rotated, the old nonce
    /// must reject **replays** while in-flight RPCs that hold the old
    /// macaroon still finish. We insert the nonce into the global set
    /// with a short TTL (`30s` by convention) so a Phase-7 ops sweep
    /// can drop the row later. The in-memory `RevocationSet`
    /// deliberately ignores TTL — once a nonce is in the cache, it's
    /// revoked even if Postgres would later cull the row. That makes
    /// rotation safe under all eventually-consistent caches without
    /// adding a clock-dependent fast-path.
    pub async fn revoke_with_ttl(
        &self,
        pool: &PgPool,
        nonce: [u8; 16],
        ttl: Duration,
        reason: Option<&str>,
    ) -> sqlx::Result<()> {
        // sqlx PG INTERVAL bind is awkward; encode the TTL as seconds and
        // construct the interval inline. `make_interval` accepts a `secs`
        // double-precision argument and produces a real INTERVAL.
        let ttl_secs = f64::from(u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX));
        sqlx::query(
            "INSERT INTO global.revoked_macaroons (nonce, reason, valid_until) \
             VALUES ($1, $2, now() + make_interval(secs => $3)) \
             ON CONFLICT (nonce) DO UPDATE \
             SET valid_until = EXCLUDED.valid_until, \
                 reason = COALESCE(global.revoked_macaroons.reason, EXCLUDED.reason)",
        )
        .bind(&nonce[..])
        .bind(reason)
        .bind(ttl_secs)
        .execute(pool)
        .await?;
        self.inner.write().insert(nonce);
        Ok(())
    }
}

/// Outer task body for the listener spawned in [`RevocationSet::start`].
///
/// Combines the reconnect-bootstrap and the wall-clock periodic
/// re-bootstrap (see `FULL_REBOOTSTRAP_INTERVAL`) in a single
/// `tokio::select!` arm so neither path can starve the other.
async fn run_revocation_listener(pool: PgPool, inner: Arc<RwLock<HashSet<[u8; 16]>>>) {
    let mut tick = tokio::time::interval(FULL_REBOOTSTRAP_INTERVAL);
    // First tick fires immediately; skip so we don't re-bootstrap right
    // after `RevocationSet::start` already did one.
    tick.tick().await;

    loop {
        tokio::select! {
            biased;
            // Wall-clock safety net — runs even when the LISTEN
            // connection is healthy. The lookback window keeps the
            // query cheap (≤1h of revocations).
            _ = tick.tick() => {
                if let Err(err) = rebootstrap_recent(&pool, &inner).await {
                    tracing::warn!(
                        target: "wick_macaroon::store",
                        error = %err,
                        "periodic revocation re-bootstrap failed; will retry on next tick"
                    );
                }
            }
            res = listen_loop(&pool, &inner) => {
                match res {
                    Ok(()) => {
                        // Listener exited cleanly (e.g. pool closed).
                        return;
                    }
                    Err(err) => {
                        tracing::warn!(
                            target: "wick_macaroon::store",
                            error = %err,
                            "revocation listener dropped; reconnecting after backoff"
                        );
                        tokio::time::sleep(RECONNECT_BACKOFF).await;
                        // On reconnect, re-bootstrap to fill the NOTIFY gap.
                        if let Err(boot_err) = bootstrap(&pool, &inner).await {
                            tracing::warn!(
                                target: "wick_macaroon::store",
                                error = %boot_err,
                                "revocation re-bootstrap failed; will retry"
                            );
                            tokio::time::sleep(RECONNECT_BACKOFF).await;
                        }
                    }
                }
            }
        }
    }
}

/// Bounded re-bootstrap query — pulls only the last
/// `REBOOTSTRAP_LOOKBACK_SECS` worth of revocations to fold in any
/// rows missed by a silent LISTEN drop.
async fn rebootstrap_recent(
    pool: &PgPool,
    inner: &Arc<RwLock<HashSet<[u8; 16]>>>,
) -> sqlx::Result<()> {
    let rows = sqlx::query(
        "SELECT nonce FROM global.revoked_macaroons \
         WHERE revoked_at > now() - make_interval(secs => $1)",
    )
    .bind(f64::from(REBOOTSTRAP_LOOKBACK_SECS))
    .fetch_all(pool)
    .await?;
    let mut guard = inner.write();
    for row in rows {
        let bytes: Vec<u8> = row.try_get("nonce")?;
        if bytes.len() == 16 {
            let mut n = [0u8; 16];
            n.copy_from_slice(&bytes);
            guard.insert(n);
        }
    }
    Ok(())
}

async fn bootstrap(pool: &PgPool, inner: &Arc<RwLock<HashSet<[u8; 16]>>>) -> sqlx::Result<()> {
    let rows = sqlx::query("SELECT nonce FROM global.revoked_macaroons")
        .fetch_all(pool)
        .await?;
    let mut next: HashSet<[u8; 16]> = HashSet::with_capacity(rows.len());
    for row in rows {
        let bytes: Vec<u8> = row.try_get("nonce")?;
        if bytes.len() == 16 {
            let mut n = [0u8; 16];
            n.copy_from_slice(&bytes);
            next.insert(n);
        }
    }
    let mut guard = inner.write();
    // Union, never shrink — local `revoke()` may have populated entries
    // that haven't yet round-tripped through SELECT (or were inserted
    // during the bootstrap query window).
    for n in next {
        guard.insert(n);
    }
    Ok(())
}

async fn listen_loop(
    pool: &PgPool,
    inner: &Arc<RwLock<HashSet<[u8; 16]>>>,
) -> sqlx::Result<()> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(REVOKED_CHANNEL).await?;
    loop {
        // `recv` returns `Err` on connection drop; the outer task
        // re-bootstraps on reconnect.
        let notification = listener.recv().await?;
        let payload = notification.payload();
        if let Some(nonce) = decode_hex_nonce(payload) {
            inner.write().insert(nonce);
        }
    }
}

fn decode_hex_nonce(s: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Atomic per-macaroon 24h spend-window store backed by
/// `global.macaroon_spend_window`.
#[derive(Debug, Clone)]
pub struct SpendWindowStore {
    pool: PgPool,
}

/// Errors returned by [`SpendWindowStore::try_spend`].
#[derive(Debug, thiserror::Error)]
pub enum SpendWindowError {
    /// Authorizing the spend would push the running total above `cap_msat`.
    /// The stored total was **not** bumped.
    #[error(
        "spend cap exceeded: spent {spent_msat} + requested {requested_msat} > cap {cap_msat}"
    )]
    CapExceeded {
        /// Total already spent in the current window, post-rollover.
        spent_msat: u64,
        /// The amount the caller tried to charge.
        requested_msat: u64,
        /// The configured per-window cap.
        cap_msat: u64,
    },
    /// Underlying Postgres error.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

/// SQL for `try_spend`. Single round-trip atomic upsert:
///
/// * If no row exists, insert one with `spent_msat = $4`, `window_start = now()`.
/// * If a row exists and its window has elapsed (`window_start + window_secs
///   < now()`), reset both `spent_msat` and `window_start`.
/// * Otherwise add `$4` to the existing `spent_msat`.
///
/// The WHERE clause on the UPDATE branch enforces the cap atomically: the
/// row is only updated if the post-bump total is ≤ `cap_msat`. We use
/// `RETURNING spent_msat` so a zero-row result indicates the WHERE filtered
/// the bump out (i.e. cap would be exceeded); the caller then re-SELECTs to
/// produce the precise `CapExceeded` error. The INSERT path of ON CONFLICT
/// is unconditional, but the cap is enforced separately at the caller for
/// the no-existing-row case — see `try_spend` body.
const TRY_SPEND_SQL: &str = r#"
INSERT INTO global.macaroon_spend_window (nonce, spent_msat, window_start, window_secs)
VALUES ($1, $4, now(), $3)
ON CONFLICT (nonce) DO UPDATE
    SET spent_msat = CASE
            WHEN global.macaroon_spend_window.window_start
                 + (global.macaroon_spend_window.window_secs || ' seconds')::interval < now()
                THEN EXCLUDED.spent_msat
            ELSE global.macaroon_spend_window.spent_msat + EXCLUDED.spent_msat
        END,
        window_start = CASE
            WHEN global.macaroon_spend_window.window_start
                 + (global.macaroon_spend_window.window_secs || ' seconds')::interval < now()
                THEN now()
            ELSE global.macaroon_spend_window.window_start
        END,
        window_secs = EXCLUDED.window_secs
    WHERE
        CASE
            WHEN global.macaroon_spend_window.window_start
                 + (global.macaroon_spend_window.window_secs || ' seconds')::interval < now()
                THEN EXCLUDED.spent_msat
            ELSE global.macaroon_spend_window.spent_msat + EXCLUDED.spent_msat
        END <= $2
RETURNING spent_msat
"#;

const SELECT_SPEND_SQL: &str = r#"
SELECT
    CASE
        WHEN window_start + (window_secs || ' seconds')::interval < now()
            THEN 0::BIGINT
        ELSE spent_msat
    END AS effective_spent
FROM global.macaroon_spend_window
WHERE nonce = $1
"#;

impl SpendWindowStore {
    /// Wrap a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Reference to the underlying pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Attempt to charge `amount_msat` against the macaroon `nonce`'s
    /// current `window_secs`-long window. Returns `Ok(())` and bumps the
    /// stored total atomically when under `cap_msat`. Returns
    /// [`SpendWindowError::CapExceeded`] without bumping the total when
    /// the charge would cross the cap.
    ///
    /// The whole bump-or-reject decision happens inside the single
    /// `INSERT … ON CONFLICT DO UPDATE … WHERE … RETURNING` round-trip so
    /// concurrent wick-server processes cannot race past the cap.
    pub async fn try_spend(
        &self,
        nonce: [u8; 16],
        cap_msat: u64,
        window_secs: u32,
        amount_msat: u64,
    ) -> Result<(), SpendWindowError> {
        // Reject up-front when the requested amount alone is over the cap.
        // The INSERT branch of the upsert is unconditional (no WHERE), so we
        // can't rely on the SQL to fail-closed in the no-existing-row case.
        if amount_msat > cap_msat {
            return Err(SpendWindowError::CapExceeded {
                spent_msat: 0,
                requested_msat: amount_msat,
                cap_msat,
            });
        }

        let cap_i64 = i64::try_from(cap_msat).unwrap_or(i64::MAX);
        let amount_i64 = i64::try_from(amount_msat).unwrap_or(i64::MAX);
        let window_i32 = i32::try_from(window_secs).unwrap_or(i32::MAX);

        let row = sqlx::query(TRY_SPEND_SQL)
            .bind(&nonce[..])
            .bind(cap_i64)
            .bind(window_i32)
            .bind(amount_i64)
            .fetch_optional(&self.pool)
            .await?;

        if row.is_some() {
            return Ok(());
        }

        // WHERE on the UPDATE branch filtered the bump — cap would be
        // exceeded. Re-SELECT to report the current effective spent.
        let spent_row = sqlx::query(SELECT_SPEND_SQL)
            .bind(&nonce[..])
            .fetch_optional(&self.pool)
            .await?;
        let spent_msat = match spent_row {
            Some(r) => {
                let v: i64 = r.try_get("effective_spent")?;
                u64::try_from(v).unwrap_or(0)
            }
            None => 0,
        };

        Err(SpendWindowError::CapExceeded {
            spent_msat,
            requested_msat: amount_msat,
            cap_msat,
        })
    }

    /// Two-row atomic spend: charges both the per-nonce window AND the
    /// per-scope window in a single transaction. Both succeed or both
    /// fail.
    ///
    /// D3 M3 research finding (`macaroons-auto-rotate`): the user-facing
    /// payment cap must follow the user across rotations, so it's keyed
    /// on `(tenant_id, scope_kind)` rather than the per-token nonce.
    /// The nonce-keyed allowance from M2 remains, so every spend bumps
    /// both rows. Either branch's cap can reject the whole charge.
    ///
    /// Same atomic semantics as [`Self::try_spend`]: under-cap → bump,
    /// over-cap → no rows mutated and `CapExceeded` returned.
    #[allow(clippy::too_many_arguments)]
    pub async fn try_spend_two_row(
        &self,
        nonce: [u8; 16],
        tenant_id: uuid::Uuid,
        scope_kind: i16,
        cap_msat: u64,
        window_secs: u32,
        amount_msat: u64,
    ) -> Result<(), SpendWindowError> {
        if amount_msat > cap_msat {
            return Err(SpendWindowError::CapExceeded {
                spent_msat: 0,
                requested_msat: amount_msat,
                cap_msat,
            });
        }

        let cap_i64 = i64::try_from(cap_msat).unwrap_or(i64::MAX);
        let amount_i64 = i64::try_from(amount_msat).unwrap_or(i64::MAX);
        let window_i32 = i32::try_from(window_secs).unwrap_or(i32::MAX);

        let mut tx = self.pool.begin().await?;

        // Per-nonce row.
        let nonce_row = sqlx::query(TRY_SPEND_SQL)
            .bind(&nonce[..])
            .bind(cap_i64)
            .bind(window_i32)
            .bind(amount_i64)
            .fetch_optional(&mut *tx)
            .await?;
        if nonce_row.is_none() {
            // Re-SELECT current effective spent before rolling back so
            // the error carries an accurate `spent_msat`.
            let spent_row = sqlx::query(SELECT_SPEND_SQL)
                .bind(&nonce[..])
                .fetch_optional(&mut *tx)
                .await?;
            let spent_msat = spent_row
                .map(|r| r.try_get::<i64, _>("effective_spent").unwrap_or(0))
                .map(|v| u64::try_from(v).unwrap_or(0))
                .unwrap_or(0);
            // Rollback — neither row will be bumped.
            tx.rollback().await?;
            return Err(SpendWindowError::CapExceeded {
                spent_msat,
                requested_msat: amount_msat,
                cap_msat,
            });
        }

        // Per-(tenant, scope) row.
        let scope_row = sqlx::query(TRY_SPEND_BY_SCOPE_SQL)
            .bind(tenant_id)
            .bind(scope_kind)
            .bind(cap_i64)
            .bind(window_i32)
            .bind(amount_i64)
            .fetch_optional(&mut *tx)
            .await?;
        if scope_row.is_none() {
            let spent_row = sqlx::query(SELECT_SPEND_BY_SCOPE_SQL)
                .bind(tenant_id)
                .bind(scope_kind)
                .fetch_optional(&mut *tx)
                .await?;
            let spent_msat = spent_row
                .map(|r| r.try_get::<i64, _>("effective_spent").unwrap_or(0))
                .map(|v| u64::try_from(v).unwrap_or(0))
                .unwrap_or(0);
            tx.rollback().await?;
            return Err(SpendWindowError::CapExceeded {
                spent_msat,
                requested_msat: amount_msat,
                cap_msat,
            });
        }

        tx.commit().await?;
        Ok(())
    }
}

/// Scope-keyed companion to [`TRY_SPEND_SQL`] — same atomic upsert
/// shape against `global.macaroon_spend_window_by_scope`.
const TRY_SPEND_BY_SCOPE_SQL: &str = r#"
INSERT INTO global.macaroon_spend_window_by_scope (tenant_id, scope_kind, spent_msat, window_start, window_secs)
VALUES ($1, $2, $5, now(), $4)
ON CONFLICT (tenant_id, scope_kind) DO UPDATE
    SET spent_msat = CASE
            WHEN global.macaroon_spend_window_by_scope.window_start
                 + (global.macaroon_spend_window_by_scope.window_secs || ' seconds')::interval < now()
                THEN EXCLUDED.spent_msat
            ELSE global.macaroon_spend_window_by_scope.spent_msat + EXCLUDED.spent_msat
        END,
        window_start = CASE
            WHEN global.macaroon_spend_window_by_scope.window_start
                 + (global.macaroon_spend_window_by_scope.window_secs || ' seconds')::interval < now()
                THEN now()
            ELSE global.macaroon_spend_window_by_scope.window_start
        END,
        window_secs = EXCLUDED.window_secs
    WHERE
        CASE
            WHEN global.macaroon_spend_window_by_scope.window_start
                 + (global.macaroon_spend_window_by_scope.window_secs || ' seconds')::interval < now()
                THEN EXCLUDED.spent_msat
            ELSE global.macaroon_spend_window_by_scope.spent_msat + EXCLUDED.spent_msat
        END <= $3
RETURNING spent_msat
"#;

const SELECT_SPEND_BY_SCOPE_SQL: &str = r#"
SELECT
    CASE
        WHEN window_start + (window_secs || ' seconds')::interval < now()
            THEN 0::BIGINT
        ELSE spent_msat
    END AS effective_spent
FROM global.macaroon_spend_window_by_scope
WHERE tenant_id = $1 AND scope_kind = $2
"#;

// ---------- unit tests ----------
//
// Integration tests against a real Postgres land in D3 M3 alongside the
// gRPC interceptor. Here we only sanity-check the SQL strings and the
// pure-Rust helpers: the SQL is load-bearing for the atomic upsert
// invariant, and a string-substring check is cheap insurance against a
// future refactor accidentally dropping the cap WHERE clause.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn revocation_set_default_is_empty() {
        let s = RevocationSet::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(!s.contains(&[0u8; 16]));
    }

    #[test]
    fn revocation_set_snapshot_is_independent() {
        let s = RevocationSet::new();
        s.inner.write().insert([1u8; 16]);
        let snap = s.snapshot();
        assert!(snap.contains(&[1u8; 16]));
        s.inner.write().insert([2u8; 16]);
        // snapshot taken before second insert
        assert!(!snap.contains(&[2u8; 16]));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn decode_hex_nonce_roundtrip() {
        let n = [0xabu8; 16];
        let hex = hex::encode(n);
        assert_eq!(decode_hex_nonce(&hex), Some(n));
        assert_eq!(decode_hex_nonce("not hex"), None);
        assert_eq!(decode_hex_nonce("ab"), None); // wrong length
    }

    #[test]
    fn try_spend_sql_atomic_upsert_with_cap_where_clause() {
        // The single-statement INSERT … ON CONFLICT DO UPDATE … WHERE …
        // RETURNING shape is what makes the cap enforcement race-free
        // across processes. Guard against accidental refactors that
        // would split it into multiple statements or drop the cap clause.
        assert!(TRY_SPEND_SQL.contains("INSERT INTO global.macaroon_spend_window"));
        assert!(TRY_SPEND_SQL.contains("ON CONFLICT (nonce) DO UPDATE"));
        assert!(TRY_SPEND_SQL.contains("WHERE"));
        assert!(TRY_SPEND_SQL.contains("<= $2"));
        assert!(TRY_SPEND_SQL.contains("RETURNING spent_msat"));
        // Window reset branch — second CASE on `window_start`.
        assert!(TRY_SPEND_SQL.contains("window_start = CASE"));
    }

    #[test]
    fn select_spend_sql_collapses_expired_window_to_zero() {
        assert!(SELECT_SPEND_SQL.contains("global.macaroon_spend_window"));
        assert!(SELECT_SPEND_SQL.contains("WHERE nonce = $1"));
        assert!(SELECT_SPEND_SQL.contains("THEN 0::BIGINT"));
    }

    #[test]
    fn try_spend_by_scope_sql_atomic_upsert_with_cap_where_clause() {
        // Same atomic-cap invariant as TRY_SPEND_SQL — see M3 research:
        // user-facing cap rides scope-keyed (rotation survival).
        assert!(TRY_SPEND_BY_SCOPE_SQL
            .contains("INSERT INTO global.macaroon_spend_window_by_scope"));
        assert!(TRY_SPEND_BY_SCOPE_SQL.contains("ON CONFLICT (tenant_id, scope_kind) DO UPDATE"));
        assert!(TRY_SPEND_BY_SCOPE_SQL.contains("WHERE"));
        assert!(TRY_SPEND_BY_SCOPE_SQL.contains("<= $3"));
        assert!(TRY_SPEND_BY_SCOPE_SQL.contains("RETURNING spent_msat"));
        assert!(SELECT_SPEND_BY_SCOPE_SQL
            .contains("global.macaroon_spend_window_by_scope"));
        assert!(SELECT_SPEND_BY_SCOPE_SQL.contains("THEN 0::BIGINT"));
    }

    #[test]
    fn rebootstrap_constants_are_sane() {
        // Document the M3 research finding: 5-min wall-clock safety net
        // on top of reconnect-bootstrap. Changing this is a deliberate
        // ops trade-off (query frequency vs lost-notification window).
        assert_eq!(FULL_REBOOTSTRAP_INTERVAL.as_secs(), 300);
        assert_eq!(REBOOTSTRAP_LOOKBACK_SECS, 3_600);
    }

    #[test]
    fn revoked_channel_name_is_stable() {
        // Migration trigger encodes this exact channel; changing it is a
        // wire-compat break with deployed wick-server processes.
        assert_eq!(REVOKED_CHANNEL, "wick_macaroon_revoked");
    }
}
