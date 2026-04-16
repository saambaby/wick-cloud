//! Per-tenant payment history, persisted in Postgres (`tenant_{id}.payments`).
//!
//! The DDL lives in `wick_server::node::manager::tenant_ddl_statements` and is
//! part of tenant provisioning — this module just reads and writes existing
//! rows. Every mutation goes through this type so the serialised status string
//! stays consistent with the `status` CHECK constraint on the table.

use std::sync::Arc;

use sqlx::PgPool;
use wick_core::TenantId;

use crate::error::{Result, WickLightningError};
use crate::node::PaymentRecord;

/// Status values accepted by the `payments.status` CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatus {
    /// HTLC is in flight.
    Pending,
    /// Payment settled.
    Succeeded,
    /// Payment failed (no retry pending).
    Failed,
}

impl PaymentStatus {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

/// Direction of a payment from the tenant's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Payment going out (tenant pays someone).
    Outbound,
    /// Payment coming in (tenant receives).
    Inbound,
}

impl Direction {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Inbound => "inbound",
        }
    }
}

/// Fields accepted by [`PaymentStore::upsert`].
#[derive(Debug, Clone)]
pub struct PaymentWrite<'a> {
    /// 32-byte payment hash.
    pub payment_hash: &'a [u8],
    /// 32-byte preimage once revealed. `None` while pending.
    pub preimage: Option<&'a [u8]>,
    pub direction: Direction,
    pub amount_msat: u64,
    pub fee_msat: u64,
    pub status: PaymentStatus,
}

/// Postgres-backed payment history.
#[derive(Debug, Clone)]
pub struct PaymentStore {
    pool: PgPool,
    schema: Arc<String>,
}

impl PaymentStore {
    /// Bind a store to `tenant_id`'s schema.
    #[must_use]
    pub fn new(tenant_id: TenantId, pool: PgPool) -> Self {
        Self {
            pool,
            schema: Arc::new(tenant_id.schema_name()),
        }
    }

    /// Insert or update a payment row keyed by `(payment_hash, direction)`.
    ///
    /// Uses a partial unique index approach: each `(payment_hash, direction)`
    /// gets at most one row. Re-firing the same event should update status,
    /// fee, and preimage in place.
    pub async fn upsert(&self, w: PaymentWrite<'_>) -> Result<()> {
        // Amounts are always non-negative — safe cast for storage, which uses
        // BIGINT (i64). Values larger than i64::MAX would indicate bugs.
        let amount = i64::try_from(w.amount_msat)
            .map_err(|_| WickLightningError::Ldk("amount_msat exceeds i64".into()))?;
        let fee = i64::try_from(w.fee_msat)
            .map_err(|_| WickLightningError::Ldk("fee_msat exceeds i64".into()))?;

        // Real upsert against the `payments_hash_direction_uniq` unique index
        // added in `tenant_ddl_statements`. `status = 'succeeded'` is terminal
        // — event handlers must not regress a succeeded payment to pending /
        // failed, which would happen if a stale `PaymentClaimable` arrived
        // after `PaymentClaimed`.
        let sql = format!(
            r#"
INSERT INTO "{schema}".payments
    (payment_hash, preimage, direction, amount_msat, fee_msat, status)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (payment_hash, direction) DO UPDATE
    SET preimage    = COALESCE(EXCLUDED.preimage, "{schema}".payments.preimage),
        amount_msat = EXCLUDED.amount_msat,
        fee_msat    = EXCLUDED.fee_msat,
        status      = CASE
            WHEN "{schema}".payments.status = 'succeeded' THEN "{schema}".payments.status
            ELSE EXCLUDED.status
        END,
        updated_at  = now()
"#,
            schema = self.schema
        );

        sqlx::query(&sql)
            .bind(w.payment_hash)
            .bind(w.preimage)
            .bind(w.direction.as_sql())
            .bind(amount)
            .bind(fee)
            .bind(w.status.as_sql())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Update the status of an existing row. No-op if the row doesn't exist.
    pub async fn update_status(
        &self,
        payment_hash: &[u8],
        status: PaymentStatus,
        fee_msat: u64,
    ) -> Result<()> {
        let fee = i64::try_from(fee_msat)
            .map_err(|_| WickLightningError::Ldk("fee_msat exceeds i64".into()))?;
        let sql = format!(
            r#"
UPDATE "{schema}".payments
    SET status = $2, fee_msat = $3, updated_at = now()
    WHERE payment_hash = $1
"#,
            schema = self.schema
        );
        sqlx::query(&sql)
            .bind(payment_hash)
            .bind(status.as_sql())
            .bind(fee)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Resolve the current status of a payment by hash, preferring outbound
    /// rows (callers that care about inbound receipt already know the
    /// direction and can inspect `list` output).
    ///
    /// Returns `PaymentStatus::Pending` if no row exists — `send_payment`
    /// inserts the pending row before returning, and the event loop updates
    /// it asynchronously, so "row missing" effectively means "not yet
    /// enqueued".
    pub async fn payment_status(&self, payment_hash: &[u8]) -> Result<PaymentStatus> {
        let sql = format!(
            r#"
SELECT status FROM "{schema}".payments
WHERE payment_hash = $1
ORDER BY CASE direction WHEN 'outbound' THEN 0 ELSE 1 END, id DESC
LIMIT 1
"#,
            schema = self.schema
        );
        let row: Option<(String,)> = sqlx::query_as(&sql)
            .bind(payment_hash)
            .fetch_optional(&self.pool)
            .await?;
        Ok(match row {
            Some((s,)) => match s.as_str() {
                "succeeded" => PaymentStatus::Succeeded,
                "failed" => PaymentStatus::Failed,
                _ => PaymentStatus::Pending,
            },
            None => PaymentStatus::Pending,
        })
    }

    /// Return the most recent `limit` payments in descending-time order.
    pub async fn list(&self, limit: u32) -> Result<Vec<PaymentRecord>> {
        let limit_i = i64::from(limit.clamp(1, 1000));
        let sql = format!(
            r#"
SELECT payment_hash, direction, amount_msat, fee_msat, status,
       EXTRACT(EPOCH FROM created_at)::BIGINT AS ts,
       NULL::text AS memo
FROM "{schema}".payments
ORDER BY id DESC
LIMIT $1
"#,
            schema = self.schema
        );
        let rows: Vec<(Vec<u8>, String, i64, i64, String, i64, Option<String>)> =
            sqlx::query_as(&sql)
                .bind(limit_i)
                .fetch_all(&self.pool)
                .await?;

        Ok(rows
            .into_iter()
            .map(|(hash, dir, amt, fee, status, ts, memo)| PaymentRecord {
                payment_hash: hash,
                is_outbound: dir == "outbound",
                amount_msat: u64::try_from(amt).unwrap_or(0),
                fee_msat: u64::try_from(fee).unwrap_or(0),
                status,
                timestamp: ts,
                memo,
            })
            .collect())
    }
}
