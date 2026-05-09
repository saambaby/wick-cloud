//! Macaroon auth primitives.
//!
//! HMAC-SHA256 chain bearer credentials with attenuating first-party caveats.
//! No network, no storage, no integration — those land in later D3 slices.
//!
//! See `architecture §5.4`. Spec lives in the project session note for D3 M1.
#![warn(missing_docs)]

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

// ---------- constants ----------

/// Default lifetime for `Scope::User` macaroons (24h).
pub const USER_DEFAULT_LIFETIME: Duration = Duration::from_secs(24 * 3600);
/// Default lifetime for `Scope::Developer` macaroons (30d).
pub const DEVELOPER_DEFAULT_LIFETIME: Duration = Duration::from_secs(30 * 24 * 3600);
/// Default lifetime for `Scope::Root`/`Scope::Admin` macaroons (365d).
pub const ROOT_DEFAULT_LIFETIME: Duration = Duration::from_secs(365 * 24 * 3600);

// caveat type tags
const TAG_EXPIRY: u8 = 0x01;
const TAG_SCOPE: u8 = 0x02;
const TAG_NONCE: u8 = 0x03;
const TAG_SPEND: u8 = 0x04;

// scope kinds
const SCOPE_USER: u8 = 0;
const SCOPE_DEVELOPER: u8 = 1;
const SCOPE_ADMIN: u8 = 2;
const SCOPE_ROOT: u8 = 3;

// ---------- error ----------

/// Errors produced when issuing or verifying a macaroon.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MacaroonError {
    /// Signature did not match the expected HMAC chain output.
    #[error("invalid signature")]
    InvalidSignature,
    /// One of the expiry caveats has elapsed.
    #[error("macaroon expired")]
    Expired,
    /// The macaroon's nonce is in the revoked set.
    #[error("macaroon revoked")]
    Revoked,
    /// The verified scope did not match the expected scope.
    #[error("scope mismatch")]
    ScopeMismatch,
    /// Failed to decode a serialized macaroon or caveat.
    #[error("decode failed: {0}")]
    DecodeFailed(String),
    /// A caveat's predicate failed during verification.
    #[error("caveat failed: {0}")]
    CaveatFailed(String),
    /// HMAC chain replay produced a different signature — likely tampering.
    #[error("macaroon tampered")]
    Tampered,
}

// ---------- root key ----------

/// Symmetric root key from which a macaroon's HMAC chain is derived.
///
/// Stored zeroized on drop. The 16-byte `identifier` carried in the macaroon
/// is what the verifier uses to look up which `RootKey` to load.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey([u8; 32]);

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RootKey").field(&"<redacted>").finish()
    }
}

impl RootKey {
    /// Generate a fresh 32-byte root key from `OsRng`.
    #[must_use]
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        Self(buf)
    }

    /// Wrap an existing 32-byte secret as a `RootKey`.
    #[must_use]
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ---------- scope ----------

/// Authority bound into a macaroon — controls which RPCs the bearer can call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// End-user tenant scope, keyed by 16-byte tenant id (UUID v4).
    User {
        /// Opaque tenant identifier.
        tenant_id: [u8; 16],
    },
    /// Developer scope, keyed by 16-byte developer id.
    Developer {
        /// Opaque developer identifier.
        developer_id: [u8; 16],
    },
    /// Operator/admin scope — broad privileges, no tenant binding.
    Admin,
    /// Issuance authority — only `Root` may mint above per-scope lifetime caps.
    Root,
}

impl Scope {
    fn payload(&self) -> Vec<u8> {
        match self {
            Scope::User { tenant_id } => {
                let mut v = Vec::with_capacity(17);
                v.push(SCOPE_USER);
                v.extend_from_slice(tenant_id);
                v
            }
            Scope::Developer { developer_id } => {
                let mut v = Vec::with_capacity(17);
                v.push(SCOPE_DEVELOPER);
                v.extend_from_slice(developer_id);
                v
            }
            Scope::Admin => vec![SCOPE_ADMIN],
            Scope::Root => vec![SCOPE_ROOT],
        }
    }

    fn from_payload(p: &[u8]) -> Result<Self, MacaroonError> {
        let kind = *p
            .first()
            .ok_or_else(|| MacaroonError::DecodeFailed("empty scope payload".into()))?;
        match kind {
            SCOPE_USER => {
                if p.len() != 17 {
                    return Err(MacaroonError::DecodeFailed("user scope len".into()));
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(&p[1..17]);
                Ok(Scope::User { tenant_id: id })
            }
            SCOPE_DEVELOPER => {
                if p.len() != 17 {
                    return Err(MacaroonError::DecodeFailed("dev scope len".into()));
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(&p[1..17]);
                Ok(Scope::Developer { developer_id: id })
            }
            SCOPE_ADMIN => Ok(Scope::Admin),
            SCOPE_ROOT => Ok(Scope::Root),
            k => Err(MacaroonError::DecodeFailed(format!("scope kind {k}"))),
        }
    }
}

// ---------- caveat ----------

/// A single first-party caveat, attenuating the macaroon's authority.
///
/// Encoded on the wire as `[u8 type_tag][payload]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caveat {
    tag: u8,
    payload: Vec<u8>,
}

impl Caveat {
    /// Build an `Expiry` caveat — verification fails if `now > unix_ts`.
    #[must_use]
    pub fn expiry(unix_ts: u64) -> Self {
        Self {
            tag: TAG_EXPIRY,
            payload: unix_ts.to_be_bytes().to_vec(),
        }
    }

    /// Build a `Scope` caveat.
    #[must_use]
    pub fn scope(scope: Scope) -> Self {
        Self {
            tag: TAG_SCOPE,
            payload: scope.payload(),
        }
    }

    /// Build a `Nonce` caveat.
    #[must_use]
    pub fn nonce(nonce: [u8; 16]) -> Self {
        Self {
            tag: TAG_NONCE,
            payload: nonce.to_vec(),
        }
    }

    /// Build a `MaxPaymentMsatPerWindow` caveat.
    #[must_use]
    pub fn max_payment(max_msat: u64, window_secs: u32) -> Self {
        let mut p = Vec::with_capacity(12);
        p.extend_from_slice(&max_msat.to_be_bytes());
        p.extend_from_slice(&window_secs.to_be_bytes());
        Self {
            tag: TAG_SPEND,
            payload: p,
        }
    }

    /// Bytes fed into the HMAC chain — the tag and payload, concatenated.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + self.payload.len());
        v.push(self.tag);
        v.extend_from_slice(&self.payload);
        v
    }

    /// Caveat type tag.
    #[must_use]
    pub fn tag(&self) -> u8 {
        self.tag
    }

    /// Caveat payload (excluding tag).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

// ---------- spend window seam ----------

/// Caller-supplied state for the `MaxPaymentMsatPerWindow` check.
///
/// In M1 the macaroon crate does *not* talk to Postgres — the gRPC layer in M2
/// will load the per-nonce running total from the spend-window table and pass
/// it through this struct. M1 only defines the shape and the math.
#[derive(Debug, Clone, Copy)]
pub struct WindowState {
    /// Cumulative msat already spent inside the current sliding window.
    pub spent_msat: u64,
    /// Wall-clock start of the current window — informational, the helper
    /// trusts the caller has already truncated `spent_msat` to that window.
    pub window_started: SystemTime,
}

/// Check that a candidate spend would stay under the macaroon's per-window cap.
///
/// `requested_msat` is the new payment the caller wants to authorize. The
/// helper does *not* mutate `state`; the caller persists the new total after
/// the payment lands.
pub fn check_spend(
    state: &WindowState,
    cap_msat: u64,
    _window_secs: u32,
    requested_msat: u64,
) -> Result<(), MacaroonError> {
    let total = state.spent_msat.saturating_add(requested_msat);
    if total > cap_msat {
        return Err(MacaroonError::CaveatFailed(format!(
            "spend window exceeded: {total} > {cap_msat}"
        )));
    }
    Ok(())
}

// ---------- macaroon ----------

/// An issued macaroon — bearer credential with attenuating caveats.
#[derive(Debug, Clone)]
pub struct Macaroon {
    location: String,
    identifier: [u8; 16],
    caveats: Vec<Caveat>,
    signature: [u8; 32],
}

/// Verifier inputs that vary per request (now, revocation set).
///
/// Borrowed so the gRPC interceptor in M3 can plumb a long-lived revocation
/// set without copying.
#[derive(Debug)]
pub struct VerifyContext<'a> {
    /// Wall-clock for expiry checks. Injected to keep tests hermetic.
    pub now: SystemTime,
    /// Set of revoked nonces — typically loaded once per process and refreshed.
    pub revoked_nonces: &'a HashSet<[u8; 16]>,
    /// Optional expected scope. If `Some`, mismatched scope returns `ScopeMismatch`.
    pub expected_scope: Option<ExpectedScope>,
}

/// What scope a verifier expects to see — coarse-grained match used by RPCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedScope {
    /// Any `Scope::User { .. }`.
    AnyUser,
    /// A specific user tenant.
    User([u8; 16]),
    /// Any `Scope::Developer { .. }`.
    AnyDeveloper,
    /// A specific developer.
    Developer([u8; 16]),
    /// Exactly `Scope::Admin`.
    Admin,
    /// Exactly `Scope::Root`.
    Root,
}

impl ExpectedScope {
    fn matches(self, scope: &Scope) -> bool {
        match (self, scope) {
            (ExpectedScope::AnyUser, Scope::User { .. })
            | (ExpectedScope::AnyDeveloper, Scope::Developer { .. })
            | (ExpectedScope::Admin, Scope::Admin)
            | (ExpectedScope::Root, Scope::Root) => true,
            (ExpectedScope::User(a), Scope::User { tenant_id }) => &a == tenant_id,
            (ExpectedScope::Developer(a), Scope::Developer { developer_id }) => {
                &a == developer_id
            }
            _ => false,
        }
    }
}

/// Result of a successful verification — what the caller acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedScope {
    /// The scope bound to the macaroon.
    pub scope: Scope,
    /// Per-issue nonce — caller records this for spend-window accounting.
    pub nonce: [u8; 16],
    /// `(max_msat, window_secs)` if a spend caveat was present.
    pub spend_caveat: Option<(u64, u32)>,
}

fn hmac_chain_step(prev: &[u8], data: &[u8]) -> [u8; 32] {
    // HMAC accepts any key length — `new_from_slice` is infallible for HMAC-SHA256.
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(prev).expect("HMAC accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut sig = [0u8; 32];
    sig.copy_from_slice(&out);
    sig
}

fn unix_seconds(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn lifetime_cap_for(scope: &Scope) -> Duration {
    match scope {
        Scope::User { .. } => USER_DEFAULT_LIFETIME,
        Scope::Developer { .. } => DEVELOPER_DEFAULT_LIFETIME,
        Scope::Admin | Scope::Root => ROOT_DEFAULT_LIFETIME,
    }
}

impl Macaroon {
    /// Issue a fresh macaroon. Always appends `Scope`, `Expiry`, and `Nonce`.
    ///
    /// `lifetime` is clamped to the per-scope cap; only `Scope::Root` (issuance
    /// authority) may construct macaroons with longer-than-cap lifetimes.
    #[must_use]
    pub fn issue(
        location: &str,
        identifier: [u8; 16],
        root_key: &RootKey,
        scope: Scope,
        lifetime: Duration,
    ) -> Self {
        let cap = lifetime_cap_for(&scope);
        let effective = if matches!(scope, Scope::Root) {
            lifetime
        } else if lifetime > cap {
            cap
        } else {
            lifetime
        };

        let expiry_ts = unix_seconds(SystemTime::now()) + effective.as_secs();

        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);

        let caveats = vec![
            Caveat::scope(scope),
            Caveat::expiry(expiry_ts),
            Caveat::nonce(nonce),
        ];

        let mut sig = hmac_chain_step(root_key.as_bytes(), &identifier);
        for c in &caveats {
            sig = hmac_chain_step(&sig, &c.bytes());
        }

        Self {
            location: location.to_string(),
            identifier,
            caveats,
            signature: sig,
        }
    }

    /// Append an attenuating caveat, advancing the HMAC chain.
    pub fn add_caveat(&mut self, c: Caveat) {
        self.signature = hmac_chain_step(&self.signature, &c.bytes());
        self.caveats.push(c);
    }

    /// Macaroon location string (service identifier).
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    /// Root-key identifier (16 bytes).
    #[must_use]
    pub fn identifier(&self) -> [u8; 16] {
        self.identifier
    }

    /// Caveats in chain order.
    #[must_use]
    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    /// Final HMAC signature.
    #[must_use]
    pub fn signature(&self) -> [u8; 32] {
        self.signature
    }

    /// Length-prefixed binary serialization. Layout:
    ///
    /// ```text
    /// u16 location_len | location_bytes
    /// [16] identifier
    /// u16 num_caveats
    ///   per caveat: u16 caveat_len | u8 tag | payload
    /// [32] signature
    /// ```
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            2 + self.location.len() + 16 + 2 + self.caveats.len() * 8 + 32,
        );
        let loc_bytes = self.location.as_bytes();
        out.extend_from_slice(
            &u16::try_from(loc_bytes.len()).unwrap_or(u16::MAX).to_be_bytes(),
        );
        out.extend_from_slice(loc_bytes);
        out.extend_from_slice(&self.identifier);
        out.extend_from_slice(
            &u16::try_from(self.caveats.len()).unwrap_or(u16::MAX).to_be_bytes(),
        );
        for c in &self.caveats {
            let bytes = c.bytes();
            out.extend_from_slice(
                &u16::try_from(bytes.len()).unwrap_or(u16::MAX).to_be_bytes(),
            );
            out.extend_from_slice(&bytes);
        }
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse a macaroon previously produced by [`Macaroon::serialize`].
    pub fn deserialize(b: &[u8]) -> Result<Self, MacaroonError> {
        let mut cur = Cursor::new(b);
        let loc_len = cur.read_u16()? as usize;
        let loc = cur.read_bytes(loc_len)?;
        let location = String::from_utf8(loc.to_vec())
            .map_err(|e| MacaroonError::DecodeFailed(format!("location utf8: {e}")))?;
        let id_slice = cur.read_bytes(16)?;
        let mut identifier = [0u8; 16];
        identifier.copy_from_slice(id_slice);

        let n_caveats = cur.read_u16()? as usize;
        let mut caveats = Vec::with_capacity(n_caveats);
        for _ in 0..n_caveats {
            let cav_len = cur.read_u16()? as usize;
            if cav_len < 1 {
                return Err(MacaroonError::DecodeFailed("empty caveat".into()));
            }
            let cav_bytes = cur.read_bytes(cav_len)?;
            let tag = cav_bytes[0];
            let payload = cav_bytes[1..].to_vec();
            caveats.push(Caveat { tag, payload });
        }

        let sig_slice = cur.read_bytes(32)?;
        let mut signature = [0u8; 32];
        signature.copy_from_slice(sig_slice);

        if !cur.is_empty() {
            return Err(MacaroonError::DecodeFailed("trailing bytes".into()));
        }

        Ok(Self {
            location,
            identifier,
            caveats,
            signature,
        })
    }

    /// Verify signature, expiry, scope, and revocation. Returns the bound
    /// scope plus the nonce and any spend caveat for the caller to enforce.
    pub fn verify(
        &self,
        root_key: &RootKey,
        ctx: &VerifyContext<'_>,
    ) -> Result<VerifiedScope, MacaroonError> {
        // 1. Replay HMAC chain.
        let mut sig = hmac_chain_step(root_key.as_bytes(), &self.identifier);
        for c in &self.caveats {
            sig = hmac_chain_step(&sig, &c.bytes());
        }
        if sig.ct_eq(&self.signature).unwrap_u8() != 1 {
            return Err(MacaroonError::Tampered);
        }

        // 2. Walk caveats for predicate checks.
        let now_secs = unix_seconds(ctx.now);
        let mut found_scope: Option<Scope> = None;
        let mut found_nonce: Option<[u8; 16]> = None;
        let mut spend: Option<(u64, u32)> = None;

        for c in &self.caveats {
            match c.tag {
                TAG_EXPIRY => {
                    if c.payload.len() != 8 {
                        return Err(MacaroonError::DecodeFailed("expiry len".into()));
                    }
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&c.payload);
                    let ts = u64::from_be_bytes(buf);
                    if now_secs > ts {
                        return Err(MacaroonError::Expired);
                    }
                }
                TAG_SCOPE => {
                    found_scope = Some(Scope::from_payload(&c.payload)?);
                }
                TAG_NONCE => {
                    if c.payload.len() != 16 {
                        return Err(MacaroonError::DecodeFailed("nonce len".into()));
                    }
                    let mut n = [0u8; 16];
                    n.copy_from_slice(&c.payload);
                    if ctx.revoked_nonces.contains(&n) {
                        return Err(MacaroonError::Revoked);
                    }
                    found_nonce = Some(n);
                }
                TAG_SPEND => {
                    if c.payload.len() != 12 {
                        return Err(MacaroonError::DecodeFailed("spend len".into()));
                    }
                    let mut max_b = [0u8; 8];
                    let mut win_b = [0u8; 4];
                    max_b.copy_from_slice(&c.payload[..8]);
                    win_b.copy_from_slice(&c.payload[8..12]);
                    spend = Some((u64::from_be_bytes(max_b), u32::from_be_bytes(win_b)));
                }
                t => {
                    return Err(MacaroonError::CaveatFailed(format!(
                        "unknown caveat tag {t}"
                    )));
                }
            }
        }

        let scope = found_scope.ok_or(MacaroonError::CaveatFailed("missing scope".into()))?;
        let nonce = found_nonce.ok_or(MacaroonError::CaveatFailed("missing nonce".into()))?;

        if let Some(expected) = ctx.expected_scope {
            if !expected.matches(&scope) {
                return Err(MacaroonError::ScopeMismatch);
            }
        }

        Ok(VerifiedScope {
            scope,
            nonce,
            spend_caveat: spend,
        })
    }
}

// ---------- minimal cursor helper ----------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], MacaroonError> {
        if self.pos + n > self.buf.len() {
            return Err(MacaroonError::DecodeFailed("short read".into()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_u16(&mut self) -> Result<u16, MacaroonError> {
        let s = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

// ---------- tests ----------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn ctx_now(now: SystemTime, revoked: &HashSet<[u8; 16]>) -> VerifyContext<'_> {
        VerifyContext {
            now,
            revoked_nonces: revoked,
            expected_scope: None,
        }
    }

    #[test]
    fn roundtrip_issue_serialize_verify() {
        let rk = RootKey::random();
        let id = [7u8; 16];
        let m = Macaroon::issue(
            "wick.cloud",
            id,
            &rk,
            Scope::User { tenant_id: [1u8; 16] },
            Duration::from_secs(3600),
        );
        let bytes = m.serialize();
        let m2 = Macaroon::deserialize(&bytes).unwrap();
        let revoked = HashSet::new();
        let v = m2.verify(&rk, &ctx_now(SystemTime::now(), &revoked)).unwrap();
        assert!(matches!(v.scope, Scope::User { .. }));
        assert_eq!(v.spend_caveat, None);
    }

    #[test]
    fn tampering_byte_breaks_signature() {
        let rk = RootKey::random();
        let m = Macaroon::issue(
            "wick.cloud",
            [0u8; 16],
            &rk,
            Scope::Admin,
            Duration::from_secs(60),
        );
        let mut bytes = m.serialize();
        let loc_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        let id_off = 2 + loc_len;
        bytes[id_off] ^= 0xff;
        let m2 = Macaroon::deserialize(&bytes).unwrap();
        let revoked = HashSet::new();
        let err = m2
            .verify(&rk, &ctx_now(SystemTime::now(), &revoked))
            .unwrap_err();
        assert_eq!(err, MacaroonError::Tampered);
    }

    #[test]
    fn expired_macaroon_rejected() {
        let rk = RootKey::random();
        let m = Macaroon::issue(
            "wick.cloud",
            [0u8; 16],
            &rk,
            Scope::Admin,
            Duration::from_secs(0),
        );
        let future = SystemTime::now() + Duration::from_secs(2);
        let revoked = HashSet::new();
        let err = m.verify(&rk, &ctx_now(future, &revoked)).unwrap_err();
        assert_eq!(err, MacaroonError::Expired);
    }

    #[test]
    fn revoked_nonce_rejected() {
        let rk = RootKey::random();
        let m = Macaroon::issue(
            "wick.cloud",
            [0u8; 16],
            &rk,
            Scope::Admin,
            Duration::from_secs(3600),
        );
        let nonce_cav = m.caveats.iter().find(|c| c.tag == TAG_NONCE).unwrap();
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&nonce_cav.payload);
        let mut revoked = HashSet::new();
        revoked.insert(nonce);
        let err = m
            .verify(&rk, &ctx_now(SystemTime::now(), &revoked))
            .unwrap_err();
        assert_eq!(err, MacaroonError::Revoked);
    }

    #[test]
    fn scope_mismatch_rejected() {
        let rk = RootKey::random();
        let m = Macaroon::issue(
            "wick.cloud",
            [0u8; 16],
            &rk,
            Scope::User { tenant_id: [9u8; 16] },
            Duration::from_secs(3600),
        );
        let revoked = HashSet::new();
        let ctx = VerifyContext {
            now: SystemTime::now(),
            revoked_nonces: &revoked,
            expected_scope: Some(ExpectedScope::Admin),
        };
        let err = m.verify(&rk, &ctx).unwrap_err();
        assert_eq!(err, MacaroonError::ScopeMismatch);
    }

    #[test]
    fn add_caveat_chains_correctly_and_breaks_if_removed() {
        let rk = RootKey::random();
        let mut m = Macaroon::issue(
            "wick.cloud",
            [0u8; 16],
            &rk,
            Scope::Developer { developer_id: [3u8; 16] },
            Duration::from_secs(3600),
        );
        m.add_caveat(Caveat::max_payment(50_000, 60));
        let bytes = m.serialize();
        let m2 = Macaroon::deserialize(&bytes).unwrap();
        let revoked = HashSet::new();
        let v = m2
            .verify(&rk, &ctx_now(SystemTime::now(), &revoked))
            .unwrap();
        assert_eq!(v.spend_caveat, Some((50_000, 60)));

        // Remove the spend caveat: signature corresponds to chain *with* it,
        // so replay must fail.
        let mut tampered = m.clone();
        tampered.caveats.pop();
        let err = tampered
            .verify(&rk, &ctx_now(SystemTime::now(), &revoked))
            .unwrap_err();
        assert_eq!(err, MacaroonError::Tampered);
    }

    #[test]
    fn spend_caveat_propagates_through_verify() {
        let rk = RootKey::random();
        let mut m = Macaroon::issue(
            "wick.cloud",
            [0u8; 16],
            &rk,
            Scope::User { tenant_id: [1u8; 16] },
            Duration::from_secs(3600),
        );
        m.add_caveat(Caveat::max_payment(1_000_000, 3600));
        let revoked = HashSet::new();
        let v = m.verify(&rk, &ctx_now(SystemTime::now(), &revoked)).unwrap();
        assert_eq!(v.spend_caveat, Some((1_000_000, 3600)));
    }

    #[test]
    fn check_spend_under_and_over_cap() {
        let state = WindowState {
            spent_msat: 700_000,
            window_started: SystemTime::now(),
        };
        check_spend(&state, 1_000_000, 3600, 200_000).unwrap();
        let err = check_spend(&state, 1_000_000, 3600, 400_000).unwrap_err();
        assert!(matches!(err, MacaroonError::CaveatFailed(_)));
    }

    #[test]
    fn empty_extra_caveats_edge_case() {
        let rk = RootKey::random();
        let m = Macaroon::issue(
            "wick.cloud",
            [42u8; 16],
            &rk,
            Scope::Root,
            Duration::from_secs(60),
        );
        assert_eq!(m.caveats.len(), 3);
        let bytes = m.serialize();
        let m2 = Macaroon::deserialize(&bytes).unwrap();
        let revoked = HashSet::new();
        let v = m2.verify(&rk, &ctx_now(SystemTime::now(), &revoked)).unwrap();
        assert_eq!(v.scope, Scope::Root);
    }

    #[test]
    fn lifetime_clamped_to_per_scope_cap() {
        let rk = RootKey::random();
        let m = Macaroon::issue(
            "wick.cloud",
            [0u8; 16],
            &rk,
            Scope::User { tenant_id: [0u8; 16] },
            Duration::from_secs(10 * 365 * 24 * 3600),
        );
        let expiry_cav = m.caveats.iter().find(|c| c.tag == TAG_EXPIRY).unwrap();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&expiry_cav.payload);
        let exp = u64::from_be_bytes(buf);
        let now = unix_seconds(SystemTime::now());
        let lifetime = exp - now;
        let cap = USER_DEFAULT_LIFETIME.as_secs();
        assert!(
            lifetime <= cap + 2 && lifetime + 2 >= cap,
            "lifetime {lifetime} not near cap {cap}",
        );
    }

    #[test]
    fn deserialize_rejects_trailing_garbage() {
        let rk = RootKey::random();
        let m = Macaroon::issue(
            "wick.cloud",
            [0u8; 16],
            &rk,
            Scope::Admin,
            Duration::from_secs(60),
        );
        let mut bytes = m.serialize();
        bytes.push(0xaa);
        let err = Macaroon::deserialize(&bytes).unwrap_err();
        assert!(matches!(err, MacaroonError::DecodeFailed(_)));
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config { cases: 64, .. proptest::test_runner::Config::default() })]

        #[test]
        fn proptest_serialize_roundtrip(
            loc in "[a-z]{1,16}",
            id in proptest::array::uniform16(proptest::num::u8::ANY),
            tenant in proptest::array::uniform16(proptest::num::u8::ANY),
            cap in 1u64..u64::MAX,
            window in 1u32..u32::MAX,
        ) {
            let rk = RootKey::random();
            let mut m = Macaroon::issue(
                &loc,
                id,
                &rk,
                Scope::User { tenant_id: tenant },
                Duration::from_secs(60),
            );
            m.add_caveat(Caveat::max_payment(cap, window));
            let b1 = m.serialize();
            let m2 = Macaroon::deserialize(&b1).unwrap();
            let b2 = m2.serialize();
            proptest::prop_assert_eq!(b1, b2);
        }
    }
}
