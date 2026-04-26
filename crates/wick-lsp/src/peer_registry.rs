//! [`PeerRegistry`] — SCID-keyed JIT request map with monotonic epoch.
//!
//! Implements the architecture's "dispatch by SCID, not peer_pubkey"
//! rule. Every LSPS2 `buy` allocation goes through
//! [`PeerRegistry::register_buy`] which follows strict ordering:
//! alloc SCID → bump epoch → INSERT to Postgres → insert into the
//! in-memory map → return.
//!
//! Postgres is **authoritative on disk** (`global.jit_requests`):
//! `register_buy` returns only after the row is committed. This is
//! intentionally heavier than [`wick_lightning::PendingFundingRegistry`]
//! (which mirrors fire-and-forget) because we restart-rehydrate from
//! this table — losing a row means losing a JIT request a payer is
//! actively routing to.
//!
//! On boot, [`PeerRegistry::rehydrate_from_pg`] sweeps expired rows
//! (`valid_until < now()`), then SELECTs the survivors back into the
//! in-memory map and bumps the epoch counter past the highest seen.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;
use dashmap::DashMap;
use sqlx::PgPool;
use wick_core::TenantId;

/// Monotonic generation counter. Bumped once per `lsps2.buy`. Used by
/// the dispatcher to reject stale SCID lookups.
pub type Epoch = u64;

/// State of a registered JIT request. Wire-aligned with the
/// `state TEXT CHECK (...)` column in `global.jit_requests`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitRequestState {
    /// SCID allocated; awaiting incoming HTLC.
    Pending,
    /// HTLC arrived; channel is being opened to the tenant.
    Opened,
    /// HTLC settled; channel funded; payment forwarded.
    Fulfilled,
    /// Request failed (fee mismatch, channel-open rejection, etc.).
    Failed,
    /// Request expired (`valid_until` elapsed).
    Expired,
}

impl JitRequestState {
    #[must_use]
    fn as_pg_text(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Opened => "opened",
            Self::Fulfilled => "fulfilled",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    fn from_pg_text(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "opened" => Some(Self::Opened),
            "fulfilled" => Some(Self::Fulfilled),
            "failed" => Some(Self::Failed),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// A registered JIT request. The DashMap value type.
#[derive(Debug, Clone)]
pub struct RegisteredJit {
    /// The tenant this SCID was allocated for. Derived deterministically
    /// from `tenant_pubkey` via [`TenantId::from_pubkey`] — no separate
    /// lookup needed at register time.
    pub tenant_id: TenantId,
    /// Tenant's Lightning node pubkey (= LSPS2 `counterparty_node_id`).
    pub tenant_pubkey: PublicKey,
    /// Monotonic epoch at registration time.
    pub epoch: Epoch,
    /// Payment size (msat). `None` for any-amount JIT requests.
    pub amount_msat: Option<u64>,
    /// Current state.
    pub state: JitRequestState,
    /// Channel capacity in sats — populated at `Opened` transition,
    /// `None` while still `Pending`. Sum across `Opened` entries is
    /// the reorg-reserve guard's "unconfirmed exposure" input.
    pub capacity_sat: Option<u64>,
    /// LDK-assigned channel id. Populated by
    /// [`PeerRegistry::set_channel_id`] when the open negotiation
    /// completes (`Event::ChannelPending` / `forward_channel_ready`)
    /// and looked up on `forward_payment_forwarded` so the grief
    /// scorer can credit the right pubkey.
    pub channel_id: Option<[u8; 32]>,
}

/// SCID-keyed JIT registry shared between the LSP service handler and
/// the HTLC-intercept dispatch path.
#[derive(Debug)]
pub struct PeerRegistry {
    /// Active map: scid → request. `pub(crate)` so the reorg-guard
    /// tests in the same crate can hand-build registry state without
    /// reaching for a Postgres pool.
    pub(crate) inner: DashMap<u64, RegisteredJit>,
    /// Monotonic epoch counter. Bumped on every `register_buy`.
    epoch: AtomicU64,
}

impl PeerRegistry {
    /// Test-only accessor for hand-building registry state in unit tests
    /// (production paths go through `register_buy` / `mark_opened`).
    #[cfg(test)]
    #[doc(hidden)]
    pub fn inner_mut_for_test(&self) -> &DashMap<u64, RegisteredJit> {
        &self.inner
    }
}

impl PeerRegistry {
    /// Construct an empty in-memory registry. Tests only — production
    /// boots through [`Self::rehydrate_from_pg`].
    #[must_use]
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            inner: DashMap::new(),
            epoch: AtomicU64::new(0),
        })
    }

    /// Boot-time rehydration. Sweeps expired rows, then loads surviving
    /// `pending` / `opened` rows back into the in-memory map and bumps
    /// the epoch counter past the highest one observed.
    ///
    /// Errors propagate as `sqlx::Error`; the daemon turns these into
    /// startup failures because a partially-rehydrated registry would
    /// silently lose JIT requests.
    pub async fn rehydrate_from_pg(pool: &PgPool) -> Result<Arc<Self>, sqlx::Error> {
        Self::rehydrate_from_pg_with_grief(pool, None).await
    }

    /// As [`Self::rehydrate_from_pg`] but applies a grief penalty for
    /// every expired `Pending` row before deletion. Wire this when the
    /// daemon constructs the registry so client pubkeys that grabbed
    /// SCIDs without ever paying take a reputation hit even if the
    /// daemon was offline when the promise expired.
    pub async fn rehydrate_from_pg_with_grief(
        pool: &PgPool,
        grief: Option<&crate::grief::GriefScorer>,
    ) -> Result<Arc<Self>, sqlx::Error> {
        // 1. TTL sweep — drop expired *Pending* rows. First read their
        //    client_pubkeys so the grief scorer can record one penalty
        //    per griefer (caller-supplied — `None` skips scoring,
        //    useful in tests).
        if let Some(scorer) = grief {
            let expired: Vec<(Vec<u8>,)> = sqlx::query_as(
                r"SELECT client_pubkey
                  FROM global.jit_requests
                  WHERE state = 'pending'
                    AND valid_until < now()",
            )
            .fetch_all(pool)
            .await?;
            for (bytes,) in &expired {
                let Ok(pk) = PublicKey::from_slice(bytes) else {
                    continue;
                };
                if let Err(e) = scorer.record_grief(&pk).await {
                    tracing::warn!(
                        target: "wick_lsp",
                        error = %e,
                        "grief scorer record_grief failed during rehydrate sweep"
                    );
                }
            }
        }
        let swept = sqlx::query(
            r"DELETE FROM global.jit_requests
              WHERE state = 'pending'
                AND valid_until < now()",
        )
        .execute(pool)
        .await?;

        // 2. Load survivors that still need an SCID lookup. Pending
        //    requires a future-valid promise; Opened survives unconditionally.
        //    Terminal states (fulfilled / failed / expired) stay in the
        //    table for audit but aren't loaded into memory.
        let rows: Vec<JitRow> = sqlx::query_as::<_, JitRow>(
            r"SELECT scid, epoch, tenant_id, client_pubkey, amount_msat, state, capacity_sat,
                     channel_id
              FROM global.jit_requests
              WHERE (state = 'pending' AND valid_until > now())
                 OR state = 'opened'",
        )
        .fetch_all(pool)
        .await?;

        let inner: DashMap<u64, RegisteredJit> = DashMap::with_capacity(rows.len());
        let mut max_epoch: u64 = 0;
        let mut decoded = 0usize;
        for row in &rows {
            let Some(jit) = row.into_registered() else {
                tracing::warn!(
                    target: "wick_lsp",
                    scid = row.scid,
                    "rehydrate: row had unrecognised state or pubkey; skipping"
                );
                continue;
            };
            #[allow(clippy::cast_sign_loss)]
            let epoch = row.epoch.max(0) as u64;
            max_epoch = max_epoch.max(epoch);
            #[allow(clippy::cast_sign_loss)]
            inner.insert(row.scid as u64, jit);
            decoded += 1;
        }

        tracing::info!(
            target: "wick_lsp",
            swept = swept.rows_affected(),
            rehydrated = decoded,
            max_epoch,
            "PeerRegistry rehydrated from global.jit_requests"
        );

        Ok(Arc::new(Self {
            inner,
            epoch: AtomicU64::new(max_epoch),
        }))
    }

    /// Register a `lsps2.buy` allocation.
    ///
    /// The SCID is supplied by the caller (LDK's
    /// `ChannelManager::get_intercept_scid`) — this method only owns
    /// the epoch counter + persistence.
    ///
    /// **Strict ordering** (per architecture §"Dispatch ordering invariant"):
    /// 1. Bump epoch via `fetch_add`.
    /// 2. INSERT row into `global.jit_requests` (commit-before-return).
    /// 3. Insert into in-memory map.
    /// 4. Return epoch.
    ///
    /// If the INSERT fails the epoch is *not* rolled back — counter
    /// monotonicity matters more than density (the dispatcher's
    /// staleness check tolerates gaps). The in-memory map is never
    /// touched on the error path.
    pub async fn register_buy(
        &self,
        scid: u64,
        tenant_pubkey: PublicKey,
        amount_msat: Option<u64>,
        valid_until: chrono::DateTime<chrono::Utc>,
        pool: &PgPool,
    ) -> Result<Epoch, sqlx::Error> {
        let epoch = self.epoch.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        let tenant_id = TenantId::from_pubkey(&tenant_pubkey.serialize());
        let state = JitRequestState::Pending;

        sqlx::query(
            r"INSERT INTO global.jit_requests
                (scid, epoch, tenant_id, client_pubkey, amount_msat, state, valid_until)
              VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(i64::try_from(scid).unwrap_or(i64::MAX))
        .bind(i64::try_from(epoch).unwrap_or(i64::MAX))
        .bind(tenant_id.as_uuid())
        .bind(&tenant_pubkey.serialize()[..])
        .bind(amount_msat.and_then(|m| i64::try_from(m).ok()))
        .bind(state.as_pg_text())
        .bind(valid_until)
        .execute(pool)
        .await?;

        self.inner.insert(
            scid,
            RegisteredJit {
                tenant_id,
                tenant_pubkey,
                epoch,
                amount_msat,
                state,
                capacity_sat: None,
                channel_id: None,
            },
        );

        Ok(epoch)
    }

    /// Atomically transition a row to `Opened` and record the channel's
    /// real capacity (known only after the operator's `create_jit_channel`
    /// returns). Used by the reorg-reserve guard to sum unconfirmed
    /// exposure across in-flight JIT channels.
    pub async fn mark_opened(
        &self,
        scid: u64,
        capacity_sat: u64,
        pool: &PgPool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r"UPDATE global.jit_requests
              SET state = 'opened', capacity_sat = $1, updated_at = now()
              WHERE scid = $2",
        )
        .bind(i64::try_from(capacity_sat).unwrap_or(i64::MAX))
        .bind(i64::try_from(scid).unwrap_or(i64::MAX))
        .execute(pool)
        .await?;

        if let Some(mut entry) = self.inner.get_mut(&scid) {
            entry.state = JitRequestState::Opened;
            entry.capacity_sat = Some(capacity_sat);
        }
        Ok(())
    }

    /// Persist the LDK-assigned `channel_id` against an existing SCID
    /// and mirror to in-memory state. Called from the LSP node's
    /// `Event::ChannelPending` handler so subsequent
    /// `forward_payment_forwarded` lookups can map LDK's channel-id
    /// back to a client pubkey for grief-scorer reward attribution.
    pub async fn set_channel_id(
        &self,
        scid: u64,
        channel_id: [u8; 32],
        pool: &PgPool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r"UPDATE global.jit_requests
              SET channel_id = $1, updated_at = now()
              WHERE scid = $2",
        )
        .bind(&channel_id[..])
        .bind(i64::try_from(scid).unwrap_or(i64::MAX))
        .execute(pool)
        .await?;
        if let Some(mut entry) = self.inner.get_mut(&scid) {
            entry.channel_id = Some(channel_id);
        }
        Ok(())
    }

    /// Reverse lookup: given an LDK channel id, return the registered
    /// tenant pubkey if any in-memory entry matches. Used by the grief
    /// scorer's `record_fulfilment` path on `forward_payment_forwarded`.
    /// Linear scan — small N (in-flight JIT count, typically << 100).
    #[must_use]
    pub fn lookup_pubkey_by_channel_id(&self, channel_id: &[u8; 32]) -> Option<PublicKey> {
        self.inner
            .iter()
            .find(|e| e.value().channel_id.as_ref() == Some(channel_id))
            .map(|e| e.value().tenant_pubkey)
    }

    /// Sum capacities of in-flight `Opened` JIT channels — the
    /// reorg-reserve guard's "unconfirmed exposure" input. Pure
    /// in-memory walk; no I/O.
    #[must_use]
    pub fn unconfirmed_exposure_sats(&self) -> u64 {
        self.inner
            .iter()
            .filter(|e| matches!(e.value().state, JitRequestState::Opened))
            .filter_map(|e| e.value().capacity_sat)
            .fold(0u64, u64::saturating_add)
    }

    /// Look up the JIT request for `scid`. Returns `None` when the SCID
    /// is unknown (the [`crate::unknown_scid_queue::UnknownScidQueue`]
    /// holds the HTLC for a brief window in case `register_buy` is
    /// still in flight).
    #[must_use]
    pub fn lookup(&self, scid: u64) -> Option<RegisteredJit> {
        self.inner.get(&scid).map(|r| r.clone())
    }

    /// Update the `state` field for an existing entry **and** mirror
    /// the change to Postgres. Best-effort on the in-memory side
    /// (silently no-ops on missing entries — the row may have been
    /// fulfilled and dropped already); errors on the Postgres side
    /// propagate so callers can decide whether to retry.
    pub async fn set_state(
        &self,
        scid: u64,
        state: JitRequestState,
        pool: &PgPool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r"UPDATE global.jit_requests
              SET state = $1, updated_at = now()
              WHERE scid = $2",
        )
        .bind(state.as_pg_text())
        .bind(i64::try_from(scid).unwrap_or(i64::MAX))
        .execute(pool)
        .await?;

        if let Some(mut entry) = self.inner.get_mut(&scid) {
            entry.state = state;
        }
        Ok(())
    }

    /// Current epoch counter. Used by the dispatcher staleness check
    /// and by the unknown-SCID queue to time out lookups.
    #[must_use]
    pub fn current_epoch(&self) -> Epoch {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Number of in-memory entries. Test-only inspection.
    #[doc(hidden)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if no entries are registered. Test-only inspection.
    #[doc(hidden)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[derive(sqlx::FromRow)]
struct JitRow {
    scid: i64,
    epoch: i64,
    tenant_id: uuid::Uuid,
    client_pubkey: Vec<u8>,
    amount_msat: Option<i64>,
    state: String,
    capacity_sat: Option<i64>,
    channel_id: Option<Vec<u8>>,
}

impl JitRow {
    fn into_registered(&self) -> Option<RegisteredJit> {
        let pubkey = PublicKey::from_slice(&self.client_pubkey).ok()?;
        let state = JitRequestState::from_pg_text(&self.state)?;
        let tenant_id = TenantId::from_uuid(self.tenant_id);
        #[allow(clippy::cast_sign_loss)]
        let epoch = self.epoch.max(0) as u64;
        #[allow(clippy::cast_sign_loss)]
        let amount_msat = self.amount_msat.map(|m| m.max(0) as u64);
        #[allow(clippy::cast_sign_loss)]
        let capacity_sat = self.capacity_sat.map(|c| c.max(0) as u64);
        let channel_id = self
            .channel_id
            .as_ref()
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut out = [0u8; 32];
                out.copy_from_slice(b);
                out
            });
        Some(RegisteredJit {
            tenant_id,
            tenant_pubkey: pubkey,
            epoch,
            amount_msat,
            state,
            capacity_sat,
            channel_id,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    fn dummy_pubkey(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    /// In-memory registry exposes the `lookup`/`set_state` *in-memory*
    /// half without touching Postgres. Persistence-level behaviour is
    /// covered by the regtest integration tests in slice 3.3b PR 5.
    #[test]
    fn empty_registry_lookup_returns_none() {
        let reg = PeerRegistry::empty();
        assert!(reg.lookup(42).is_none());
        assert_eq!(reg.current_epoch(), 0);
        assert!(reg.is_empty());
    }

    /// `JitRequestState` round-trips through its PG text representation
    /// for every variant. Catches typos in the CHECK constraint.
    #[test]
    fn state_pg_text_round_trip() {
        for s in [
            JitRequestState::Pending,
            JitRequestState::Opened,
            JitRequestState::Fulfilled,
            JitRequestState::Failed,
            JitRequestState::Expired,
        ] {
            assert_eq!(JitRequestState::from_pg_text(s.as_pg_text()), Some(s));
        }
    }

    /// `lookup` is a cheap clone of the DashMap entry — confirm it
    /// doesn't observe stale data after `set_state`'s in-memory
    /// half runs (the actual UPDATE is exercised in the regtest path).
    #[test]
    fn in_memory_state_visibility() {
        let reg = PeerRegistry::empty();
        let scid = 0xDEAD_BEEF_u64;
        let pk = dummy_pubkey(1);
        let tenant_id = TenantId::from_pubkey(&pk.serialize());
        // Bypass `register_buy` (which needs a pool) by hand-inserting
        // — this test exercises the in-memory map invariants only.
        reg.inner.insert(
            scid,
            RegisteredJit {
                tenant_id,
                tenant_pubkey: pk,
                epoch: 1,
                amount_msat: Some(1000),
                state: JitRequestState::Pending,
                capacity_sat: None,
                channel_id: None,
            },
        );
        let entry = reg.lookup(scid).unwrap();
        assert_eq!(entry.tenant_pubkey, pk);
        assert!(matches!(entry.state, JitRequestState::Pending));
        // In-memory side of `set_state`.
        if let Some(mut e) = reg.inner.get_mut(&scid) {
            e.state = JitRequestState::Opened;
        }
        assert!(matches!(
            reg.lookup(scid).unwrap().state,
            JitRequestState::Opened
        ));
    }
}
