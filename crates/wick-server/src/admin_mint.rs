//! Admin-macaroon issuance helper.
//!
//! Used by the `wick-server mint-admin-macaroon` subcommand to bootstrap
//! the operator's admin credential. Reads (or mints, on first call) the
//! admin root key from `global.macaroon_root_keys`, issues a fresh
//! macaroon with `Scope::Admin`, serializes, and returns the bytes.
//!
//! This replaces the `WICK_ADMIN_SECRET` env-var shared secret that
//! gated the admin gRPC path through D3 M4. Issued tokens are tied to
//! the root key persisted in Postgres so rotation (drop the row, mint
//! again) works without redeploying the server.
//!
//! ## Encoding
//!
//! The serialized macaroon is binary; the SDK side hex-encodes it for
//! the `x-wick-macaroon` metadata header. The mint subcommand writes
//! raw bytes by default; operators can `hex` the file if their secret
//! store expects ASCII.

use std::time::Duration;

use sqlx::PgPool;
use wick_macaroon::{store::RevocationSet, Macaroon, Scope};

use crate::macaroon_auth::MacaroonAuth;

/// 30-day default lifetime for admin macaroons. Short enough that a
/// compromised token expires before too much damage accrues; long
/// enough that operators don't need to rotate weekly. Operators that
/// need a different cadence can run the subcommand more (or less)
/// frequently — each call mints a fresh token under the same root key.
pub const ADMIN_MACAROON_LIFETIME: Duration = Duration::from_secs(30 * 24 * 3600);

/// Macaroon `location` field baked into every admin token. Matches the
/// user-auth interceptor's location so a single deployment surfaces one
/// consistent identifier.
pub const DEFAULT_LOCATION: &str = "wick.cloud";

/// Result of a mint call — both the on-the-wire macaroon bytes and the
/// root-key identifier they were issued under (for audit logging).
pub struct MintedAdminMacaroon {
    /// Serialized macaroon bytes — write to disk, hand to operator, or
    /// hex-encode for transport. Bytes are opaque to everything except
    /// `Macaroon::deserialize`.
    pub macaroon_bytes: Vec<u8>,
    /// Root-key identifier the macaroon resolves to. Persisted in
    /// `global.macaroon_root_keys.identifier`.
    pub root_key_identifier: [u8; 16],
}

/// Mint a fresh admin-scoped macaroon.
///
/// Idempotent on the *root key*: repeated calls reuse the existing
/// admin row in `global.macaroon_root_keys` (or insert one on first
/// call) and issue a new macaroon with a fresh per-token nonce against
/// that key.
pub async fn mint_admin_macaroon(
    pool: PgPool,
    location: &str,
    lifetime: Duration,
) -> anyhow::Result<MintedAdminMacaroon> {
    // RevocationSet is unused by the mint path — issuance touches the
    // root_keys table only — but `MacaroonAuth::new` takes one. An
    // empty in-process set is fine here; this process exits right
    // after writing the macaroon.
    let auth = MacaroonAuth::new(pool, RevocationSet::new(), location);
    let (identifier, root_key) = auth.ensure_admin_root_key().await?;

    let macaroon = Macaroon::issue(location, identifier, &root_key, Scope::Admin, lifetime);
    let bytes = macaroon.serialize();

    Ok(MintedAdminMacaroon {
        macaroon_bytes: bytes,
        root_key_identifier: identifier,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_constant_is_positive() {
        assert!(ADMIN_MACAROON_LIFETIME.as_secs() > 0);
    }
}
