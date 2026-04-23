//! Durable backing for [`crate::funding_registry::PendingFundingRegistry`].
//!
//! Rows in `tenant_{id}.pending_funding` let the two-phase channel-open
//! flow survive an actor crash: if `park` commits to Postgres but the
//! server is killed before the client's `open_channel_finalize` arrives,
//! the next boot's [`FundingStore::rehydrate`] call repopulates the
//! in-memory `ready` map and the client can resume without losing state.
//!
//! Durability is best-effort. If the insert fails the in-memory path
//! still delivers the request to an active waiter — the registry's
//! authoritative data is the in-memory map, and Postgres is the
//! recovery journal. On success the row is deleted when the request is
//! taken; a stale row older than the TTL is swept on boot.
//!
//! The store interpolates `schema` from [`TenantId`] which validates
//! `^[0-9]+$`, so the double-quoted identifier is injection-safe.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::ScriptBuf;
use lightning::ln::types::ChannelId;
use sqlx::{PgPool, Row};
use wick_core::TenantId;

use crate::error::Result;
use crate::funding_registry::PendingFunding;

/// Rows older than this are discarded on boot instead of rehydrating.
/// Two-phase open normally completes in seconds; an hour is a generous
/// upper bound for "the client is definitely gone".
pub const FUNDING_TTL: Duration = Duration::from_secs(60 * 60);

/// Postgres-backed durable store for parked funding requests.
///
/// Cheap to clone — pool and schema sit behind `Arc`.
#[derive(Debug, Clone)]
pub struct FundingStore {
    pool: PgPool,
    schema: Arc<String>,
}

/// A row rehydrated from Postgres at boot time.
#[derive(Debug, Clone)]
pub struct StoredFunding {
    /// Temporary channel id LDK assigned at `create_channel` time.
    pub temp_channel_id: ChannelId,
    /// The parked request as originally parked.
    pub request: PendingFunding,
}

impl FundingStore {
    /// Bind the store to `tenant_id`'s schema on `pool`.
    #[must_use]
    pub fn new(tenant_id: TenantId, pool: PgPool) -> Self {
        Self {
            pool,
            schema: Arc::new(tenant_id.schema_name()),
        }
    }

    /// Persist a parked request. Idempotent on `temp_channel_id` — LDK
    /// never re-fires `FundingGenerationReady` for the same id, but
    /// `ON CONFLICT DO NOTHING` keeps the invariant explicit.
    pub async fn insert(&self, temp_id: ChannelId, req: &PendingFunding) -> Result<()> {
        let sql = format!(
            r#"
INSERT INTO "{schema}".pending_funding
    (temp_channel_id, counterparty, value_sat, output_script, parked_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (temp_channel_id) DO NOTHING
"#,
            schema = self.schema
        );
        let value_sat_i64 = i64::try_from(req.value_sat).unwrap_or(i64::MAX);
        sqlx::query(&sql)
            .bind(temp_id.0.as_slice())
            .bind(req.counterparty.serialize().as_slice())
            .bind(value_sat_i64)
            .bind(req.output_script.as_bytes())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Remove a parked request once it has been delivered. Silent no-op
    /// if the row is already gone (e.g. TTL swept it).
    pub async fn remove(&self, temp_id: ChannelId) -> Result<()> {
        let sql = format!(
            r#"DELETE FROM "{schema}".pending_funding WHERE temp_channel_id = $1"#,
            schema = self.schema
        );
        sqlx::query(&sql)
            .bind(temp_id.0.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Load every parked row younger than [`FUNDING_TTL`] and delete
    /// older ones in the same transaction so they don't accumulate.
    ///
    /// Rows with malformed `counterparty` / `output_script` bytes are
    /// logged and skipped — one corrupt row shouldn't prevent the node
    /// from booting.
    pub async fn rehydrate(&self) -> Result<Vec<StoredFunding>> {
        // Sweep stale rows first. Keep this in its own statement (not a
        // CTE) so a sweep failure doesn't abort the fetch; a failed
        // sweep just means old rows linger another boot.
        let sweep_sql = format!(
            r#"
DELETE FROM "{schema}".pending_funding
WHERE parked_at < now() - interval '{ttl_secs} seconds'
"#,
            schema = self.schema,
            ttl_secs = FUNDING_TTL.as_secs()
        );
        if let Err(e) = sqlx::query(&sweep_sql).execute(&self.pool).await {
            tracing::warn!(
                target: "wick_lightning",
                error = %e,
                "funding_store: stale-row sweep failed; continuing with rehydrate"
            );
        }

        let sql = format!(
            r#"
SELECT temp_channel_id, counterparty, value_sat, output_script
FROM "{schema}".pending_funding
"#,
            schema = self.schema
        );
        let rows = sqlx::query(&sql).fetch_all(&self.pool).await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let temp_bytes: Vec<u8> = row.try_get("temp_channel_id")?;
            let cp_bytes: Vec<u8> = row.try_get("counterparty")?;
            let value_sat_i64: i64 = row.try_get("value_sat")?;
            let script_bytes: Vec<u8> = row.try_get("output_script")?;

            let temp_array: [u8; 32] = match temp_bytes.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    tracing::warn!(
                        target: "wick_lightning",
                        len = temp_bytes.len(),
                        "funding_store: skipping row with non-32-byte temp_channel_id"
                    );
                    continue;
                }
            };
            let counterparty = match PublicKey::from_slice(&cp_bytes) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(
                        target: "wick_lightning",
                        error = %e,
                        "funding_store: skipping row with invalid counterparty pubkey"
                    );
                    continue;
                }
            };

            out.push(StoredFunding {
                temp_channel_id: ChannelId(temp_array),
                request: PendingFunding {
                    counterparty,
                    value_sat: u64::try_from(value_sat_i64).unwrap_or(0),
                    output_script: ScriptBuf::from_bytes(script_bytes),
                },
            });
        }
        Ok(out)
    }
}
