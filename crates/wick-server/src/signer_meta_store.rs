//! Postgres backing for [`wick_vls::ChannelMetaStore`].
//!
//! Each tenant's signer state lives in `tenant_<id>.signer_channel_meta`
//! (DDL in `crate::node::manager::tenant_ddl_statements` + the
//! `tenant_template/0001_init.sql` migration template). The schema name is
//! derived from `TenantId` which validates `^[0-9]+$`, so the
//! double-quoted identifier is injection-safe.
//!
//! All writes are upserts on `channel_keys_id`. The session's write-through
//! path runs on a `tokio::spawn` from the LDK signer thread — failures are
//! logged + swallowed, never propagated, because the in-memory map is
//! authoritative for live calls and Postgres is just the recovery journal.

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use wick_core::TenantId;
use wick_vls::{ChannelMetaStore, StoredChannelMeta};

/// Postgres-backed [`ChannelMetaStore`] for one tenant's schema.
///
/// Cheap to clone — pool + schema sit behind `Arc`.
#[derive(Debug, Clone)]
pub struct PgChannelMetaStore {
    pool: PgPool,
    schema: Arc<String>,
}

impl PgChannelMetaStore {
    #[must_use]
    pub fn new(tenant_id: TenantId, pool: PgPool) -> Self {
        Self {
            pool,
            schema: Arc::new(tenant_id.schema_name()),
        }
    }
}

#[async_trait]
impl ChannelMetaStore for PgChannelMetaStore {
    async fn load_all(&self) -> anyhow::Result<Vec<StoredChannelMeta>> {
        let sql = format!(
            r#"
SELECT channel_keys_id, dbid, peer_id,
       setup_funding_txid, setup_funding_index,
       push_value_msat, pubkeys
FROM "{schema}".signer_channel_meta
"#,
            schema = self.schema
        );
        let rows = sqlx::query(&sql)
            .fetch_all(&self.pool)
            .await
            .context("signer_channel_meta: load_all")?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let keys_id_bytes: Vec<u8> = row.try_get("channel_keys_id")?;
            let keys_id: [u8; 32] = match keys_id_bytes.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    tracing::warn!(
                        target: "wick_server",
                        len = keys_id_bytes.len(),
                        "signer_channel_meta: skipping row with non-32-byte channel_keys_id"
                    );
                    continue;
                }
            };
            let dbid_i64: i64 = row.try_get("dbid")?;
            let peer_bytes: Vec<u8> = row.try_get("peer_id")?;
            let peer_id: [u8; 33] = match peer_bytes.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    tracing::warn!(
                        target: "wick_server",
                        ?keys_id,
                        len = peer_bytes.len(),
                        "signer_channel_meta: skipping row with non-33-byte peer_id"
                    );
                    continue;
                }
            };
            let txid_opt: Option<Vec<u8>> = row.try_get("setup_funding_txid")?;
            let idx_opt: Option<i32> = row.try_get("setup_funding_index")?;
            let setup_funding = match (txid_opt, idx_opt) {
                (Some(txid_bytes), Some(idx_i32)) => {
                    use bitcoin::hashes::Hash as _;
                    let txid_hash =
                        match bitcoin::hashes::sha256d::Hash::from_slice(&txid_bytes) {
                            Ok(h) => h,
                            Err(_) => {
                                tracing::warn!(
                                    target: "wick_server",
                                    ?keys_id,
                                    "signer_channel_meta: skipping row with malformed setup_funding_txid"
                                );
                                continue;
                            }
                        };
                    let txid = bitcoin::Txid::from_raw_hash(txid_hash);
                    let idx = u16::try_from(idx_i32).unwrap_or(0);
                    Some((txid, idx))
                }
                _ => None,
            };
            let push_msat_i64: i64 = row.try_get("push_value_msat")?;
            let pubkeys_blob: Option<Vec<u8>> = row.try_get("pubkeys")?;
            let pubkeys = pubkeys_blob.and_then(|v| {
                if v.len() == 165 {
                    let mut arr = [0u8; 165];
                    arr.copy_from_slice(&v);
                    Some(arr)
                } else {
                    tracing::warn!(
                        target: "wick_server",
                        ?keys_id,
                        len = v.len(),
                        "signer_channel_meta: dropping pubkeys blob with unexpected length"
                    );
                    None
                }
            });

            out.push(StoredChannelMeta {
                channel_keys_id: keys_id,
                dbid: u64::try_from(dbid_i64).unwrap_or(0),
                peer_id,
                setup_funding,
                push_value_msat: u64::try_from(push_msat_i64).unwrap_or(0),
                pubkeys,
            });
        }
        Ok(out)
    }

    async fn upsert(&self, meta: StoredChannelMeta) -> anyhow::Result<()> {
        // `pubkeys = COALESCE(EXCLUDED.pubkeys, signer_channel_meta.pubkeys)`
        // preserves a previously-persisted pubkeys blob when a later
        // upsert (e.g. the post-`SetupChannel` write) doesn't supply one.
        // The session always supplies the blob when it has it, so this
        // is purely defensive — in practice every successful
        // `derive_channel_signer` writes pubkeys then promotion-upserts
        // do too.
        let sql = format!(
            r#"
INSERT INTO "{schema}".signer_channel_meta
    (channel_keys_id, dbid, peer_id, setup_funding_txid,
     setup_funding_index, push_value_msat, pubkeys, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (channel_keys_id) DO UPDATE SET
    dbid = EXCLUDED.dbid,
    peer_id = EXCLUDED.peer_id,
    setup_funding_txid = EXCLUDED.setup_funding_txid,
    setup_funding_index = EXCLUDED.setup_funding_index,
    push_value_msat = EXCLUDED.push_value_msat,
    pubkeys = COALESCE(EXCLUDED.pubkeys, "{schema}".signer_channel_meta.pubkeys),
    updated_at = now()
"#,
            schema = self.schema
        );

        let dbid_i64 = i64::try_from(meta.dbid).unwrap_or(i64::MAX);
        let push_i64 = i64::try_from(meta.push_value_msat).unwrap_or(i64::MAX);
        let (txid_opt, idx_opt): (Option<Vec<u8>>, Option<i32>) = match meta.setup_funding {
            Some((txid, idx)) => {
                use bitcoin::hashes::Hash as _;
                let raw = txid.to_raw_hash();
                (Some(raw.as_byte_array().to_vec()), Some(i32::from(idx)))
            }
            None => (None, None),
        };
        let pubkeys_vec = meta.pubkeys.map(|a| a.to_vec());

        sqlx::query(&sql)
            .bind(meta.channel_keys_id.as_slice())
            .bind(dbid_i64)
            .bind(meta.peer_id.as_slice())
            .bind(txid_opt)
            .bind(idx_opt)
            .bind(push_i64)
            .bind(pubkeys_vec)
            .execute(&self.pool)
            .await
            .context("signer_channel_meta: upsert")?;
        Ok(())
    }
}
