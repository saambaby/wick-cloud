//! Per-tenant channel index, persisted in Postgres (`tenant_{id}.channels`).
//!
//! The DDL lives in `wick_server::node::manager` and is part of tenant
//! provisioning — this module just reads and writes existing rows. Mirrors
//! [`crate::PaymentStore`] so both Lightning state caches share one shape.
//!
//! Source of truth for a channel's live state remains LDK's `ChannelManager`;
//! this table is for restart-time observability and operator queries
//! (e.g. "list every channel a tenant has ever opened, including closed
//! ones"). The `state` column transitions `pending` → `ready` → `closed`
//! and is never deleted — closures are recorded with `state = 'closed'`.

use std::sync::Arc;

use sqlx::PgPool;
use wick_core::TenantId;

use crate::error::{Result, WickLightningError};

/// Lifecycle state of a channel mirrored from LDK events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Funding tx broadcast; awaiting confirmations.
    Pending,
    /// `channel_ready` exchanged; channel is usable.
    Ready,
    /// Channel closed (cooperative or force).
    Closed,
}

impl ChannelState {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Closed => "closed",
        }
    }
}

/// Fields accepted by [`ChannelStore::upsert`].
#[derive(Debug, Clone)]
pub struct ChannelUpsert<'a> {
    /// 32-byte LDK `ChannelId`.
    pub channel_id: &'a [u8],
    /// 33-byte SEC1-compressed counterparty pubkey.
    pub peer_pubkey: &'a [u8],
    /// Total channel capacity in sats.
    pub capacity_sat: u64,
    /// Local outbound capacity in millisatoshis.
    pub local_balance_msat: u64,
    pub state: ChannelState,
}

/// Postgres-backed channel index.
#[derive(Debug, Clone)]
pub struct ChannelStore {
    pool: PgPool,
    schema: Arc<String>,
}

impl ChannelStore {
    /// Bind a store to `tenant_id`'s schema.
    #[must_use]
    pub fn new(tenant_id: TenantId, pool: PgPool) -> Self {
        Self {
            pool,
            schema: Arc::new(tenant_id.schema_name()),
        }
    }

    /// Insert or update a channel row keyed by `channel_id`.
    ///
    /// Once a row reaches `state = 'closed'` it stays closed — re-emitted
    /// `ChannelReady` / `ChannelPending` events for an already-closed channel
    /// are ignored (the `CASE` clause below preserves the terminal state).
    pub async fn upsert(&self, w: ChannelUpsert<'_>) -> Result<()> {
        let capacity = i64::try_from(w.capacity_sat)
            .map_err(|_| WickLightningError::Ldk("capacity_sat exceeds i64".into()))?;
        let local = i64::try_from(w.local_balance_msat)
            .map_err(|_| WickLightningError::Ldk("local_balance_msat exceeds i64".into()))?;

        let sql = format!(
            r#"
INSERT INTO "{schema}".channels
    (channel_id, peer_pubkey, capacity_sat, local_balance_msat, state)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (channel_id) DO UPDATE
    SET peer_pubkey        = EXCLUDED.peer_pubkey,
        capacity_sat       = EXCLUDED.capacity_sat,
        local_balance_msat = EXCLUDED.local_balance_msat,
        state              = CASE
            WHEN "{schema}".channels.state = 'closed' THEN "{schema}".channels.state
            ELSE EXCLUDED.state
        END,
        updated_at         = now()
"#,
            schema = self.schema
        );

        sqlx::query(&sql)
            .bind(w.channel_id)
            .bind(w.peer_pubkey)
            .bind(capacity)
            .bind(local)
            .bind(w.state.as_sql())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Mark an existing channel row as closed. No-op if the row doesn't exist.
    pub async fn mark_closed(&self, channel_id: &[u8]) -> Result<()> {
        let sql = format!(
            r#"
UPDATE "{schema}".channels
    SET state = 'closed', updated_at = now()
    WHERE channel_id = $1
"#,
            schema = self.schema
        );
        sqlx::query(&sql)
            .bind(channel_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
