//! Wake-path admission control.
//!
//! Gates entry to [`super::manager::NodeManager::wake_loading`] with two
//! mechanisms:
//!
//! 1. **Global concurrency bound** — a [`tokio::sync::Semaphore`] capped at
//!    `memory_budget / per_node_bytes / 2`. Prevents a wake storm from
//!    spawning more actors than will fit under the memory budget.
//!
//! 2. **Per-tenant rate limit** — a simple token bucket (3 tokens, refill
//!    1 token / 20s ≈ 3 wakes/min). Defends against a single malicious
//!    tenant burning wake capacity in a loop. [`WakePriority::Payment`]
//!    bypasses this limit: HTLC arrivals are CLTV-bounded and dropping
//!    them would lose user funds.

use std::sync::Arc;
use std::time::{ Duration, Instant };

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::{ OwnedSemaphorePermit, Semaphore };
use wick_core::TenantId;

/// Priority of a wake request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakePriority {
    /// HTLC-driven: CLTV-bounded, must not sit behind a rate limiter.
    Payment,
    /// User-initiated (`GetBalance`, `GetTransactions`, etc.): rate-limited.
    User,
}

/// Error returned by [`WakeAdmission::acquire`] when a wake is refused.
#[derive(Debug, thiserror::Error)]
pub enum WakeAdmissionError {
    /// The per-tenant token bucket is exhausted.
    #[error("tenant wake rate limit exhausted; retry in ~{retry_after_secs}s")]
    RateLimited {
        /// Seconds until the next token refills.
        retry_after_secs: u64,
    },
    /// The global semaphore has been closed (manager shutting down).
    #[error("admission semaphore closed")]
    SemaphoreClosed,
}

/// Token-bucket state per tenant.
#[derive(Debug)]
struct TokenBucket {
    tokens: u32,
    last_refill: Instant,
}

const BUCKET_CAPACITY: u32 = 3;
const REFILL_INTERVAL: Duration = Duration::from_secs(20);

impl TokenBucket {
    fn new() -> Self {
        Self {
            tokens: BUCKET_CAPACITY,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time and attempt to consume one.
    /// Returns `Ok(())` if a token was consumed, `Err(retry_after_secs)`
    /// if the bucket was empty.
    fn try_consume(&mut self) -> Result<(), u64> {
        let elapsed = self.last_refill.elapsed();
        let refills = (elapsed.as_secs() / REFILL_INTERVAL.as_secs()) as u32;
        if refills > 0 {
            self.tokens = (self.tokens + refills).min(BUCKET_CAPACITY);
            self.last_refill += REFILL_INTERVAL * refills;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            Ok(())
        } else {
            let secs_since_refill = elapsed.as_secs() % REFILL_INTERVAL.as_secs();
            let retry = REFILL_INTERVAL.as_secs().saturating_sub(secs_since_refill);
            Err(retry)
        }
    }
}

/// Admission controller for the wake path.
pub struct WakeAdmission {
    global: Arc<Semaphore>,
    buckets: DashMap<TenantId, Mutex<TokenBucket>>,
}

impl std::fmt::Debug for WakeAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeAdmission")
            .field("global_permits", &self.global.available_permits())
            .field("tracked_buckets", &self.buckets.len())
            .finish()
    }
}

impl WakeAdmission {
    /// Create a new admission controller.
    ///
    /// `global_permits` caps concurrent wakes. Recommended sizing is
    /// `memory_budget_bytes / per_node_bytes / 2` — leaves 50% headroom so
    /// already-active nodes don't get evicted by a wake storm.
    #[must_use]
    pub fn new(global_permits: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global_permits.max(1))),
            buckets: DashMap::new(),
        }
    }

    /// Attempt to admit a wake for `tenant_id` with the given priority.
    ///
    /// On success, returns a [`WakePermit`] that the caller must hold for
    /// the duration of the wake. Dropping it releases the global permit
    /// (and, implicitly, the rate-limit token — there's no release, tokens
    /// refill on a timer).
    ///
    /// `Priority::Payment` skips the per-tenant rate limit (CLTV-bound).
    pub async fn acquire(
        &self,
        tenant_id: TenantId,
        priority: WakePriority
    ) -> Result<WakePermit, WakeAdmissionError> {
        if priority == WakePriority::User {
            let bucket = self.buckets
                .entry(tenant_id)
                .or_insert_with(|| Mutex::new(TokenBucket::new()));
            let mut guard = bucket.lock();
            guard
                .try_consume()
                .map_err(|retry_after_secs| WakeAdmissionError::RateLimited { retry_after_secs })?;
        }

        let global = self.global
            .clone()
            .acquire_owned().await
            .map_err(|_| WakeAdmissionError::SemaphoreClosed)?;
        Ok(WakePermit { _global: global })
    }
}

/// Held across a wake. Drop releases the global semaphore slot.
#[derive(Debug)]
#[must_use = "drop this permit when the wake completes"]
pub struct WakePermit {
    _global: OwnedSemaphorePermit,
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn payment_bypasses_rate_limit() {
        let adm = WakeAdmission::new(10);
        let tid = TenantId::generate();
        // 10 Payment wakes in a row — none rate-limited.
        for _ in 0..10 {
            let _p = adm
                .acquire(tid, WakePriority::Payment).await
                .expect("payment must not be rate-limited");
        }
    }

    #[tokio::test]
    async fn user_respects_rate_limit() {
        let adm = WakeAdmission::new(10);
        let tid = TenantId::generate();
        // 3 back-to-back — should succeed.
        for _ in 0..3 {
            let _p = adm.acquire(tid, WakePriority::User).await.expect("ok");
        }
        // 4th — rate limited.
        let err = adm.acquire(tid, WakePriority::User).await.expect_err("4th must be rate-limited");
        assert!(matches!(err, WakeAdmissionError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn rate_limit_is_per_tenant() {
        let adm = WakeAdmission::new(10);
        let a = TenantId::generate();
        let b = TenantId::generate();
        for _ in 0..3 {
            let _p = adm.acquire(a, WakePriority::User).await.unwrap();
        }
        // Tenant B starts fresh.
        for _ in 0..3 {
            let _p = adm.acquire(b, WakePriority::User).await.unwrap();
        }
    }

    #[tokio::test]
    async fn global_semaphore_bounds_concurrency() {
        let adm = Arc::new(WakeAdmission::new(2));
        let tid = TenantId::generate();
        let _p1 = adm.acquire(tid, WakePriority::Payment).await.unwrap();
        let _p2 = adm.acquire(tid, WakePriority::Payment).await.unwrap();

        // Third acquire would block forever if we awaited — use timeout
        // to verify.
        let adm2 = adm.clone();
        let third = tokio::spawn(async move {
            let _p = adm2.acquire(tid, WakePriority::Payment).await.unwrap();
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), third).await.is_err(),
            "third acquire must block until a permit is returned"
        );
    }
}
