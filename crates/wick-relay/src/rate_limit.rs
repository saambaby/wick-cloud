//! Per-IP sliding-window connect rate limiter.
//!
//! A connect from a given IP is permitted while fewer than `limit`
//! connects have been recorded within the trailing 60-second window.
//! Window resets are lazy: on each check we examine the stored
//! `window_start` and either increment, reset-and-increment, or reject.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Sliding-window length. 60 seconds matches the spec; held internal so
/// the field is not part of the public API.
const WINDOW: Duration = Duration::from_secs(60);

/// In-memory rate limiter keyed by remote IP.
#[derive(Debug)]
pub struct RateLimiter {
    inner: DashMap<IpAddr, (Instant, u32)>,
    limit: u32,
}

impl RateLimiter {
    /// Create a limiter with the given per-IP per-window budget.
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            inner: DashMap::new(),
            limit,
        }
    }

    /// Record a connect attempt from `ip`. Returns `true` if it is
    /// permitted (and the count was incremented), `false` if the budget
    /// was already exhausted for the current window.
    #[must_use]
    pub fn check_and_increment(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut entry = self.inner.entry(ip).or_insert((now, 0));
        let (start, count) = *entry;
        if now.duration_since(start) >= WINDOW {
            *entry = (now, 1);
            true
        } else if count < self.limit {
            *entry = (start, count + 1);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::thread;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    #[test]
    fn enforces_count_within_window() {
        let lim = RateLimiter::new(3);
        assert!(lim.check_and_increment(ip()));
        assert!(lim.check_and_increment(ip()));
        assert!(lim.check_and_increment(ip()));
        assert!(!lim.check_and_increment(ip()));
    }

    #[test]
    fn window_reset_after_60s() {
        let lim = RateLimiter::new(1);
        let addr = ip();
        assert!(lim.check_and_increment(addr));
        assert!(!lim.check_and_increment(addr));
        // Force the stored window-start into the past so the reset path
        // fires without actually sleeping for a minute.
        {
            let mut e = lim.inner.get_mut(&addr).unwrap();
            e.0 = Instant::now()
                .checked_sub(Duration::from_secs(61))
                .expect("test clock supports 61s back-dating");
        }
        assert!(lim.check_and_increment(addr));
    }

    #[test]
    fn concurrent_access_is_consistent() {
        let lim = Arc::new(RateLimiter::new(100));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let lim = Arc::clone(&lim);
            handles.push(thread::spawn(move || {
                let mut accepted = 0u32;
                for _ in 0..20 {
                    if lim.check_and_increment(ip()) {
                        accepted += 1;
                    }
                }
                accepted
            }));
        }
        let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, 100);
    }
}
