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
    /// Re-bootstrap discipline: on every reconnect after a listener drop
    /// we re-run the bootstrap SELECT. `pg_notify` does **not** guarantee
    /// delivery across connection loss, so missing rows during the gap
    /// would otherwise silently break revocation. The price is one extra
    /// query per reconnect, which is negligible — target row count is
    /// ≤100k worst-case.
    pub async fn start(pool: PgPool) -> sqlx::Result<(Self, JoinHandle<()>)> {
        let set = Self::default();
        bootstrap(&pool, &set.inner).await?;

        let inner = Arc::clone(&set.inner);
        let handle = tokio::spawn(async move {
            loop {
                match listen_loop(&pool, &inner).await {
                    Ok(()) => {
                        // Listener exited cleanly (e.g. pool closed).
                        break;
                    }
                    Err(err) => {
                        #[cfg(feature = "postgres")]
                        tracing::warn!(
                            target: "wick_macaroon::store",
                            error = %err,
                            "revocation listener dropped; reconnecting after backoff"
                        );
                        let _ = err; // silence unused if tracing somehow not on
                        tokio::time::sleep(RECONNECT_BACKOFF).await;
                        // On reconnect, re-bootstrap to fill the NOTIFY gap.
                        if let Err(boot_err) = bootstrap(&pool, &inner).await {
                            #[cfg(feature = "postgres")]
                            tracing::warn!(
                                target: "wick_macaroon::store",
                                error = %boot_err,
                                "revocation re-bootstrap failed; will retry"
                            );
                            let _ = boot_err;
                            tokio::time::sleep(RECONNECT_BACKOFF).await;
                            continue;
                        }
                    }
                }
            }
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
}

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
    fn revoked_channel_name_is_stable() {
        // Migration trigger encodes this exact channel; changing it is a
        // wire-compat break with deployed wick-server processes.
        assert_eq!(REVOKED_CHANNEL, "wick_macaroon_revoked");
    }
}
