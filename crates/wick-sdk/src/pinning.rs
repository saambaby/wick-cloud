//! Phase-4 server pubkey pinning.
//!
//! Triple-source verification: SDK release pin + transparency log + UI
//! fingerprint. The transparency log is currently a no-op stub — the
//! witness shape is wired so a future log impl can retroactively check
//! every observed pubkey was logged at issue time without needing an
//! SDK release.
//!
//! Pinning is enforced by [`crate::WickClient::register`] after it
//! resolves the server's tenant Lightning node pubkey via `GetNodeInfo`.
//! On `Regtest` no pin is enforced (returns `None`); on signet /
//! mutinynet / bitcoin the SDK release-pinned const is compared in
//! constant time.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use wick_core::WickNetwork;

/// Production server pubkey. Updated only by SDK releases.
///
/// Placeholder until provisioning lands: a deliberately invalid
/// 33-byte sequence (leading byte `0x02` indicates an even-y
/// compressed point but the body is all-zero, which decodes
/// correctly as a point but is not a real key — fine for the
/// constant-time-eq comparator we use here).
pub const PRODUCTION_SERVER_PUBKEY: [u8; 33] = [0x02; 33];

/// Staging / mutinynet server pubkey. Same release coupling.
pub const STAGING_SERVER_PUBKEY: [u8; 33] = [0x03; 33];

/// Where the expected pubkey came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSource {
    /// SDK release pin matched the bound `WickNetwork`.
    ReleasePin,
    /// Operator-supplied via `WickConfig::expected_server_pubkey`.
    ConfigOverride,
}

/// A single observation of the server's pubkey, suitable for handing
/// to a transparency log for retroactive inclusion verification.
#[derive(Debug, Clone)]
pub struct PinWitness {
    /// Where the *expected* pubkey came from (release pin vs override).
    pub source: PinSource,
    /// The actual 33-byte compressed pubkey observed on the wire.
    pub pubkey: [u8; 33],
    /// When the witness was captured.
    pub observed_at: std::time::SystemTime,
}

/// Errors returned by [`TransparencyLog::verify`].
#[derive(Debug, thiserror::Error)]
pub enum TransparencyError {
    /// The log endpoint was unreachable. The caller decides whether to
    /// fail-closed or fail-open.
    #[error("transparency log unavailable")]
    Unavailable,
    /// The log responded but the inclusion proof did not verify.
    #[error("inclusion proof failed for pubkey {pubkey_fp}")]
    InclusionFailed {
        /// Short hex fingerprint of the pubkey that failed inclusion.
        pubkey_fp: String,
    },
}

/// A retroactive inclusion-proof check over observed server pubkeys.
///
/// Default impl is [`NoOpLog`]. A future real impl proves inclusion via
/// a Merkle path, checks the log signature, and rate-limits queries.
#[async_trait::async_trait]
pub trait TransparencyLog: Send + Sync + std::fmt::Debug {
    /// Verify that `witness.pubkey` was logged at issue time.
    async fn verify(&self, witness: &PinWitness) -> std::result::Result<(), TransparencyError>;
}

/// Stub that always returns `Ok(())`. Used until a real log lands.
#[derive(Debug, Default)]
pub struct NoOpLog;

#[async_trait::async_trait]
impl TransparencyLog for NoOpLog {
    async fn verify(&self, _witness: &PinWitness) -> std::result::Result<(), TransparencyError> {
        Ok(())
    }
}

/// Hex SHA-256 prefix for UI display: first 8 bytes → 16 hex chars.
#[must_use]
pub fn fingerprint(pubkey: &[u8; 33]) -> String {
    let h = Sha256::digest(pubkey);
    let mut out = String::with_capacity(16);
    for b in &h[..8] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Constant-time equality over the 33 compressed-pubkey bytes.
///
/// Hand-rolled (XOR accumulator) to avoid pulling `constant_time_eq`
/// into the workspace for one comparator.
#[must_use]
pub(crate) fn ct_eq_pubkey(a: &[u8; 33], b: &[u8; 33]) -> bool {
    let mut acc: u8 = 0;
    for i in 0..33 {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// Resolve the expected server pubkey for a given `WickNetwork` and
/// optional caller override.
///
/// Override wins. Otherwise, the network selects the release-pinned
/// const. `Regtest` returns `None` (no pin enforced — the SDK speaks
/// to whatever local server the developer dialed).
#[must_use]
pub fn expected_pubkey(
    network: WickNetwork,
    override_: Option<[u8; 33]>,
) -> Option<([u8; 33], PinSource)> {
    if let Some(p) = override_ {
        return Some((p, PinSource::ConfigOverride));
    }
    match network {
        WickNetwork::Regtest => None,
        WickNetwork::Signet | WickNetwork::Mutinynet => {
            Some((STAGING_SERVER_PUBKEY, PinSource::ReleasePin))
        }
    }
}

/// Default transparency-log handle returned to `WickClient` when the
/// caller hasn't installed one of their own.
#[must_use]
pub(crate) fn default_log() -> Arc<dyn TransparencyLog> {
    Arc::new(NoOpLog)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regtest_no_override_yields_no_pin() {
        assert!(expected_pubkey(WickNetwork::Regtest, None).is_none());
    }

    #[test]
    fn override_wins_regardless_of_network() {
        let override_ = [0x42_u8; 33];
        for net in [
            WickNetwork::Regtest,
            WickNetwork::Signet,
            WickNetwork::Mutinynet,
        ] {
            let (pk, source) = expected_pubkey(net, Some(override_)).expect("override yields Some");
            assert_eq!(pk, override_);
            assert_eq!(source, PinSource::ConfigOverride);
        }
    }

    #[test]
    fn release_pin_selected_when_no_override() {
        let (pk, source) = expected_pubkey(WickNetwork::Mutinynet, None).unwrap();
        assert_eq!(pk, STAGING_SERVER_PUBKEY);
        assert_eq!(source, PinSource::ReleasePin);

        let (pk, source) = expected_pubkey(WickNetwork::Signet, None).unwrap();
        assert_eq!(pk, STAGING_SERVER_PUBKEY);
        assert_eq!(source, PinSource::ReleasePin);
    }

    #[test]
    fn fingerprint_is_deterministic_and_16_hex() {
        let pk = [0x02_u8; 33];
        let fp1 = fingerprint(&pk);
        let fp2 = fingerprint(&pk);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);
        assert!(fp1.chars().all(|c| c.is_ascii_hexdigit()));

        // Different input → different fingerprint (with overwhelming probability).
        let other = [0x03_u8; 33];
        assert_ne!(fingerprint(&other), fp1);
    }

    #[tokio::test]
    async fn noop_log_always_oks() {
        let log = NoOpLog;
        let witness = PinWitness {
            source: PinSource::ReleasePin,
            pubkey: [0x02; 33],
            observed_at: std::time::SystemTime::now(),
        };
        assert!(log.verify(&witness).await.is_ok());
    }

    #[test]
    fn ct_eq_pubkey_matches_naive_eq() {
        let a = [0x02_u8; 33];
        let mut b = [0x02_u8; 33];
        assert!(ct_eq_pubkey(&a, &b));
        b[17] = 0x03;
        assert!(!ct_eq_pubkey(&a, &b));
    }
}
