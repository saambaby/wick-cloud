//! Single-use registration nonces for the `CreateTenant` signature
//! challenge.
//!
//! Closes the token-rotation hole (vault gotcha #509): without this
//! handshake any caller who knew a tenant's pubkey could rotate its
//! bearer token via `CreateTenant` and adopt the on-chain state. The
//! flow now is:
//!
//! 1. SDK calls `RegisterChallenge(pubkey)`. Server stores a fresh
//!    32-byte random nonce keyed on the pubkey with a 60-second TTL.
//! 2. SDK ECDSA-signs `sha256(b"wick-tenant-register" || nonce)` with
//!    the matching secret key and submits the signature alongside the
//!    nonce in `CreateTenantRequest`.
//! 3. Server looks up the nonce, verifies the signature, **consumes
//!    the nonce** on success, and proceeds with the existing upsert.
//!
//! Storage is a `DashMap<[u8; 33], (Vec<u8>, Instant)>` with lazy
//! sweeping on insert — no background task. Last-writer-wins on
//! duplicate challenges for the same pubkey.

use std::time::{Duration, Instant};

use dashmap::DashMap;
use rand::rngs::OsRng;
use rand::RngCore;

/// 60-second TTL — long enough for a sluggish device to round-trip
/// a sign, short enough to keep replay windows tight.
pub const NONCE_TTL: Duration = Duration::from_secs(60);

/// Domain separation tag prepended to the nonce before hashing. Exactly
/// 20 bytes; concat with the 32-byte nonce → 52-byte input pre-hash.
pub const REGISTER_DOMAIN: &[u8] = b"wick-tenant-register";

/// In-memory map of issued-but-not-yet-consumed registration nonces.
#[derive(Debug, Default)]
pub struct NonceStore {
    inner: DashMap<[u8; 33], (Vec<u8>, Instant)>,
}

impl NonceStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a fresh 32-byte nonce for `pubkey`, sweep any expired
    /// entries opportunistically, and return the new nonce. Last-writer-
    /// wins on duplicate calls for the same pubkey.
    pub fn issue(&self, pubkey: [u8; 33]) -> Vec<u8> {
        self.issue_at(pubkey, Instant::now())
    }

    /// Test seam: same as [`Self::issue`] but with a caller-supplied
    /// "now". Production callers should use [`Self::issue`].
    pub fn issue_at(&self, pubkey: [u8; 33], now: Instant) -> Vec<u8> {
        // Lazy sweep: drop expired entries on every insert. O(n) on the
        // map but n is small (one entry per concurrent registration).
        self.inner
            .retain(|_, (_, issued_at)| now.duration_since(*issued_at) < NONCE_TTL);

        let mut nonce = vec![0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        self.inner.insert(pubkey, (nonce.clone(), now));
        nonce
    }

    /// Validate `presented` against the stored nonce for `pubkey`. On
    /// success the nonce is consumed (deleted) and `Ok(())` is
    /// returned. Returns `Err` on missing / expired / mismatched.
    pub fn consume(&self, pubkey: &[u8; 33], presented: &[u8]) -> Result<(), NonceError> {
        self.consume_at(pubkey, presented, Instant::now())
    }

    /// Test seam mirroring [`Self::consume`].
    pub fn consume_at(
        &self,
        pubkey: &[u8; 33],
        presented: &[u8],
        now: Instant,
    ) -> Result<(), NonceError> {
        // Use `remove_if` so an expired or mismatched entry isn't
        // accidentally consumed — it must remain in the map (or be
        // pruned, in the expired case) so the caller sees the right
        // error and a replay attempt likewise fails.
        let entry = self.inner.get(pubkey).ok_or(NonceError::Unknown)?;
        let (stored_nonce, issued_at) = entry.value();
        if now.duration_since(*issued_at) >= NONCE_TTL {
            // Drop the stale entry while we're here.
            drop(entry);
            self.inner.remove(pubkey);
            return Err(NonceError::Expired);
        }
        if stored_nonce.as_slice() != presented {
            return Err(NonceError::Mismatch);
        }
        drop(entry);
        // Consume — guards against replay.
        self.inner.remove(pubkey);
        Ok(())
    }

    /// Number of currently-tracked nonces. Test helper.
    #[cfg(test)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Reasons [`NonceStore::consume`] can fail.
#[derive(Debug, PartialEq, Eq)]
pub enum NonceError {
    /// No outstanding challenge for this pubkey.
    Unknown,
    /// Challenge issued but TTL elapsed before redemption.
    Expired,
    /// Stored nonce does not match the presented bytes.
    Mismatch,
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => f.write_str("no outstanding registration challenge for this pubkey"),
            Self::Expired => f.write_str("registration challenge expired (>60s old)"),
            Self::Mismatch => f.write_str("nonce does not match the issued challenge"),
        }
    }
}

impl std::error::Error for NonceError {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> [u8; 33] {
        [byte; 33]
    }

    #[test]
    fn issue_returns_32_random_bytes_and_replaces_on_duplicate() {
        let store = NonceStore::new();
        let n1 = store.issue(pk(1));
        let n2 = store.issue(pk(1));
        assert_eq!(n1.len(), 32);
        assert_eq!(n2.len(), 32);
        assert_ne!(n1, n2, "fresh nonce per challenge");
        // Last-writer-wins: only the second nonce is now valid.
        assert_eq!(store.consume(&pk(1), &n1).unwrap_err(), NonceError::Mismatch);
        assert!(store.consume(&pk(1), &n2).is_ok());
    }

    #[test]
    fn consume_unknown_pubkey_errors() {
        let store = NonceStore::new();
        assert_eq!(
            store.consume(&pk(2), b"whatever").unwrap_err(),
            NonceError::Unknown
        );
    }

    #[test]
    fn consume_is_single_use() {
        let store = NonceStore::new();
        let n = store.issue(pk(3));
        store.consume(&pk(3), &n).unwrap();
        // Replay → Unknown (entry was consumed).
        assert_eq!(store.consume(&pk(3), &n).unwrap_err(), NonceError::Unknown);
    }

    #[test]
    fn expired_nonce_is_rejected_and_pruned() {
        let store = NonceStore::new();
        let now = Instant::now();
        let n = store.issue_at(pk(4), now);
        let later = now + NONCE_TTL + Duration::from_millis(1);
        assert_eq!(
            store.consume_at(&pk(4), &n, later).unwrap_err(),
            NonceError::Expired
        );
        assert_eq!(store.len(), 0, "expired entry pruned on consume");
    }

    #[test]
    fn issue_sweeps_expired_entries() {
        let store = NonceStore::new();
        let t0 = Instant::now();
        let _ = store.issue_at(pk(5), t0);
        let _ = store.issue_at(pk(6), t0);
        let later = t0 + NONCE_TTL + Duration::from_millis(1);
        // Inserting a fresh challenge sweeps the expired ones.
        let _ = store.issue_at(pk(7), later);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn mismatched_nonce_does_not_consume() {
        let store = NonceStore::new();
        let n = store.issue(pk(8));
        assert_eq!(
            store.consume(&pk(8), b"not the right nonce").unwrap_err(),
            NonceError::Mismatch
        );
        // Original nonce still works.
        assert!(store.consume(&pk(8), &n).is_ok());
    }
}
