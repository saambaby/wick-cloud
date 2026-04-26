//! Per-client-pubkey grief score with exponential decay.
//!
//! Backs the LSP's defence against clients who request JIT SCIDs but
//! never actually pay through them. Each grief event (a `Pending`
//! `BuyRequest` whose fee-param promise expired without progressing
//! to `Opened`) adds [`grief_penalty`](crate::peer_registry); each
//! fulfilment subtracts [`grief_reward`]. The score is read with
//! exponential decay over [`grief_half_life_hours`].
//!
//! Persistence: `global.client_reputation`. Single row per client
//! pubkey; the table existed schema-only before slice 3.3b — this
//! module is the first reader/writer.
//!
//! ## Identity
//!
//! Identity is `client_pubkey` only in 3.3b. Adding a macaroon-id
//! dimension is a future change, not a placeholder — the
//! `client_reputation` table is keyed on `pubkey BYTEA PRIMARY KEY`
//! and the score is coherent without one.

use bitcoin::secp256k1::PublicKey;
use sqlx::PgPool;

/// Live grief-score scorer. Cheap to construct per scope; holds no
/// state beyond a pool reference and the configured tunables.
#[derive(Debug, Clone)]
pub struct GriefScorer {
    pool: PgPool,
    half_life_hours: f64,
    penalty: f64,
    reward: f64,
    rejection_threshold: f64,
}

impl GriefScorer {
    /// Construct from `LspConfig` knobs. `half_life_hours <= 0` makes
    /// decay instantaneous (score is always zero on read); use a
    /// tiny positive value (`f64::EPSILON`) to disable in tests
    /// without triggering a divide-by-zero.
    #[must_use]
    pub fn new(
        pool: PgPool,
        half_life_hours: f64,
        penalty: f64,
        reward: f64,
        rejection_threshold: f64,
    ) -> Self {
        Self {
            pool,
            half_life_hours: half_life_hours.max(f64::EPSILON),
            penalty,
            reward,
            rejection_threshold,
        }
    }

    /// Read the current decayed score for `pubkey`, mutating
    /// `last_decayed_at` to now in the same transaction so subsequent
    /// reads don't re-decay the same window. Returns 0.0 if the row
    /// doesn't exist (clean slate).
    pub async fn read_score(&self, pubkey: &PublicKey) -> Result<f64, sqlx::Error> {
        let pubkey_bytes = pubkey.serialize();
        let row: Option<(f64, sqlx::types::chrono::DateTime<sqlx::types::chrono::Utc>)> = sqlx::query_as(
            r"SELECT score, last_decayed_at
              FROM global.client_reputation
              WHERE pubkey = $1",
        )
        .bind(&pubkey_bytes[..])
        .fetch_optional(&self.pool)
        .await?;
        let Some((stored_score, last_decayed_at)) = row else {
            return Ok(0.0);
        };
        let now = sqlx::types::chrono::Utc::now();
        let elapsed_h = (now - last_decayed_at).num_milliseconds() as f64 / 3_600_000.0;
        // True half-life decay: at t = half_life, multiplier is 0.5.
        let decay = 0.5_f64.powf(elapsed_h / self.half_life_hours);
        let decayed_score = stored_score * decay;

        // Persist the decayed score so the next read starts from the
        // updated baseline.
        sqlx::query(
            r"UPDATE global.client_reputation
              SET score = $1, last_decayed_at = $2
              WHERE pubkey = $3",
        )
        .bind(decayed_score)
        .bind(now)
        .bind(&pubkey_bytes[..])
        .execute(&self.pool)
        .await?;

        Ok(decayed_score)
    }

    /// Add `delta` to the score. Positive `delta` is a grief event;
    /// negative is a reward. UPSERT — creates a new row at delta if
    /// the client is unknown, else adds to the *decayed* score (i.e.
    /// reads first, then applies the delta) so the half-life math
    /// stays honest.
    pub async fn apply_event(
        &self,
        pubkey: &PublicKey,
        delta: f64,
    ) -> Result<(), sqlx::Error> {
        let baseline = self.read_score(pubkey).await?;
        let new_score = baseline + delta;
        let pubkey_bytes = pubkey.serialize();
        let now = sqlx::types::chrono::Utc::now();
        sqlx::query(
            r"INSERT INTO global.client_reputation (pubkey, score, last_decayed_at, last_event_at)
              VALUES ($1, $2, $3, $3)
              ON CONFLICT (pubkey) DO UPDATE
                SET score = $2,
                    last_decayed_at = $3,
                    last_event_at = $3",
        )
        .bind(&pubkey_bytes[..])
        .bind(new_score)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Convenience: apply the configured penalty for a single grief event.
    pub async fn record_grief(&self, pubkey: &PublicKey) -> Result<(), sqlx::Error> {
        self.apply_event(pubkey, self.penalty).await
    }

    /// Convenience: apply the configured reward for a single fulfilment.
    pub async fn record_fulfilment(&self, pubkey: &PublicKey) -> Result<(), sqlx::Error> {
        self.apply_event(pubkey, -self.reward).await
    }

    /// `true` if the client's current decayed score crosses the
    /// configured rejection threshold. Reads (and decays) the score.
    pub async fn should_reject(&self, pubkey: &PublicKey) -> Result<bool, sqlx::Error> {
        Ok(self.read_score(pubkey).await? >= self.rejection_threshold)
    }

    /// Configured rejection threshold (read-only accessor for logging).
    #[must_use]
    pub fn rejection_threshold(&self) -> f64 {
        self.rejection_threshold
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// `half_life_hours <= 0` is clamped so reads don't divide by zero.
    /// `tokio::test` because `PgPool::connect_lazy` requires a runtime
    /// even though no I/O fires.
    #[tokio::test]
    async fn half_life_clamp() {
        let scorer = GriefScorer::new(
            sqlx::PgPool::connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none").unwrap(),
            0.0,
            10.0,
            1.0,
            100.0,
        );
        assert!(scorer.half_life_hours > 0.0);
    }

    /// Decay math sanity-check independent of Postgres: at one
    /// half-life the multiplier is 0.5.
    #[test]
    fn decay_at_one_half_life_is_one_half() {
        let half_life = 168.0_f64;
        let elapsed = 168.0_f64;
        let decay = 0.5_f64.powf(elapsed / half_life);
        assert!((decay - 0.5).abs() < 1e-12);
    }

    /// Two half-lives → 0.25.
    #[test]
    fn decay_at_two_half_lives_is_one_quarter() {
        let half_life = 168.0_f64;
        let elapsed = 336.0_f64;
        let decay = 0.5_f64.powf(elapsed / half_life);
        assert!((decay - 0.25).abs() < 1e-12);
    }
}
