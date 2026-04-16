//! Per-tenant Lightning-peer persistence.
//!
//! Rows in `tenant_{id}.peers` are keyed by peer pubkey (`BYTEA PRIMARY KEY`)
//! and carry the canonical `host:port` address the node last used to reach
//! them.  The [`crate::NodeBuilder`] flushes this store after a successful
//! `connect_peer`, then replays every row on startup to auto-reconnect.
//!
//! All queries interpolate the schema name from the validated [`TenantId`]
//! and use the double-quoted identifier form — the `TenantId` validator
//! guarantees `^[0-9]+$` so interpolation is safe.

use std::net::SocketAddr;
use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;
use sqlx::{PgPool, Row};
use wick_core::TenantId;

use crate::error::{Result, WickLightningError};

/// A Lightning peer entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// Counterparty Lightning node id.
    pub node_id: PublicKey,
    /// Resolved socket address last used for this peer.
    pub address: SocketAddr,
}

/// Postgres-backed peer store for a single tenant.
///
/// Cheap to clone — pool and schema sit behind `Arc`.
#[derive(Debug, Clone)]
pub struct PeerStore {
    pool: PgPool,
    schema: Arc<String>,
}

impl PeerStore {
    /// Bind a store to `tenant_id`'s schema on `pool`.
    #[must_use]
    pub fn new(tenant_id: TenantId, pool: PgPool) -> Self {
        Self {
            pool,
            schema: Arc::new(tenant_id.schema_name()),
        }
    }

    /// Insert or update a peer keyed by pubkey.
    ///
    /// `last_seen_at` is refreshed to `now()` on every call so restart
    /// reconnect ordering can prefer recently-active peers later.
    pub async fn upsert(&self, peer: &PeerInfo) -> Result<()> {
        let sql = format!(
            r#"
INSERT INTO "{schema}".peers (pubkey, address, last_seen_at)
VALUES ($1, $2, now())
ON CONFLICT (pubkey) DO UPDATE
    SET address      = EXCLUDED.address,
        last_seen_at = now()
"#,
            schema = self.schema
        );
        sqlx::query(&sql)
            .bind(peer.node_id.serialize().as_slice())
            .bind(peer.address.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Remove a peer by pubkey. Silent no-op if absent.
    pub async fn remove(&self, node_id: &PublicKey) -> Result<()> {
        let sql = format!(
            r#"DELETE FROM "{schema}".peers WHERE pubkey = $1"#,
            schema = self.schema
        );
        sqlx::query(&sql)
            .bind(node_id.serialize().as_slice())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Return every known peer for this tenant, most-recently-seen first.
    ///
    /// Rows with malformed address strings are logged and skipped — one
    /// corrupt row shouldn't take the reconnect loop offline.
    pub async fn list(&self) -> Result<Vec<PeerInfo>> {
        let sql = format!(
            r#"
SELECT pubkey, address
FROM "{schema}".peers
WHERE address IS NOT NULL
ORDER BY last_seen_at DESC NULLS LAST
"#,
            schema = self.schema
        );
        let rows = sqlx::query(&sql).fetch_all(&self.pool).await?;

        let mut peers = Vec::with_capacity(rows.len());
        for row in rows {
            let pubkey_bytes: Vec<u8> = row.try_get("pubkey")?;
            let address_str: String = row.try_get("address")?;

            let node_id = match PublicKey::from_slice(&pubkey_bytes) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(
                        target: "wick_lightning",
                        error = %e,
                        "peer_store: skipping row with invalid pubkey"
                    );
                    continue;
                }
            };
            let address: SocketAddr = match address_str.parse() {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(
                        target: "wick_lightning",
                        error = %e,
                        address = %address_str,
                        pubkey = %node_id,
                        "peer_store: skipping row with invalid address"
                    );
                    continue;
                }
            };

            peers.push(PeerInfo { node_id, address });
        }
        Ok(peers)
    }

    /// Look up a peer by pubkey.
    pub async fn get(&self, node_id: &PublicKey) -> Result<Option<PeerInfo>> {
        let sql = format!(
            r#"SELECT address FROM "{schema}".peers WHERE pubkey = $1"#,
            schema = self.schema
        );
        let row = sqlx::query(&sql)
            .bind(node_id.serialize().as_slice())
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let address_str: String = row.try_get("address")?;
        let address: SocketAddr = address_str
            .parse()
            .map_err(|e| WickLightningError::Config(format!("bad peer address: {e}")))?;
        Ok(Some(PeerInfo {
            node_id: *node_id,
            address,
        }))
    }
}
