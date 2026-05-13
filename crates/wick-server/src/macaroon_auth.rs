//! Macaroon verification interceptor for the gRPC service.
//!
//! Replaces the bearer-token check from `auth::Auth` *transitionally*:
//! if the request carries an `x-wick-macaroon` metadata header, we
//! verify it as a macaroon (chain replay against the per-issuance
//! `RootKey`, expiry, revocation, scope). Otherwise we fall back to
//! the legacy bearer check so existing clients keep working until D3
//! M5 retires the bearer path entirely.
//!
//! The macaroon path resolves the tenant from the embedded
//! `Scope::User { tenant_id }` caveat and returns a [`TenantContext`]
//! the handlers can read (no second `Auth::authenticate` round-trip).
//!
//! ## Wire invariants
//!
//! * **Caveat order is canonical.** The macaroon's caveats are encoded
//!   on the wire in the same order they were appended, and
//!   `Macaroon::verify` replays the HMAC chain in array order. The
//!   interceptor MUST NOT sort, dedup, or reorder caveats — the
//!   signature wouldn't match. This is documented at the verify call
//!   site too.
//! * **The metadata header carries hex-encoded bytes.** Tonic metadata
//!   is ASCII-only, so the serialized macaroon (which is arbitrary
//!   bytes) rides as lowercase hex. The SDK side encodes on every
//!   call; here we decode + verify.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use sqlx::PgPool;
use tonic::{Request, Status};
use wick_core::TenantId;
use wick_macaroon::{
    store::RevocationSet, ExpectedScope, Macaroon, MacaroonError, RootKey, Scope, VerifyContext,
};

/// Scope-kind value persisted in `global.macaroon_root_keys.scope_kind`
/// for admin-scoped root keys. Tenant-scoped keys use `0`; this lane is
/// distinct so an admin macaroon and a user macaroon can never collide
/// even if they share an identifier (they can't — identifiers are
/// random 16-byte values — but the scope_kind column makes that an
/// invariant of the data model, not a probabilistic property).
pub const SCOPE_KIND_ADMIN: i16 = 2;

/// gRPC metadata header carrying a base64-encoded serialized macaroon.
/// Distinct from `authorization` so the legacy bearer path is unaffected.
pub const MACAROON_HEADER: &str = "x-wick-macaroon";

/// 30-second grace window applied to the old macaroon when a new one is
/// minted via `RotateCredential`. Lets in-flight RPCs holding the old
/// macaroon finish while replays start failing immediately. Matches
/// the rotation grace described in the D3 M3 research note.
pub const ROTATION_GRACE_TTL: Duration = Duration::from_secs(30);

/// Result of authenticating a request — either via macaroon path or
/// the legacy bearer fallback.
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// Authenticated tenant id. For the macaroon path this comes from
    /// the `Scope::User { tenant_id }` caveat; for the bearer fallback
    /// it comes from the wallets-table lookup.
    pub tenant_id: TenantId,
    /// Macaroon scope, if the request authenticated via the macaroon
    /// path. `None` for legacy bearer requests.
    pub scope: Option<Scope>,
    /// Per-token nonce — the caller uses this for spend-window
    /// accounting. `None` for legacy bearer requests.
    pub nonce: Option<[u8; 16]>,
    /// Optional `(max_msat, window_secs)` spend caveat carried on the
    /// macaroon. `None` when no spend caveat is present.
    pub spend_caveat: Option<(u64, u32)>,
}

/// Interceptor + helper for the macaroon auth path.
#[derive(Clone)]
pub struct MacaroonAuth {
    pool: PgPool,
    revocation: RevocationSet,
    location: String,
}

impl std::fmt::Debug for MacaroonAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacaroonAuth")
            .field("location", &self.location)
            .finish_non_exhaustive()
    }
}

impl MacaroonAuth {
    /// Build the interceptor. `location` is typically the server's
    /// hostname or a stable identifier embedded in every issued
    /// macaroon (`"wick.cloud"` in production).
    #[must_use]
    pub fn new(pool: PgPool, revocation: RevocationSet, location: impl Into<String>) -> Self {
        Self {
            pool,
            revocation,
            location: location.into(),
        }
    }

    /// Borrow the pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Borrow the revocation set — useful for handlers that need to
    /// reach `revoke_with_ttl` (the `RotateCredential` handler).
    #[must_use]
    pub fn revocation(&self) -> &RevocationSet {
        &self.revocation
    }

    /// Server-side location string baked into newly minted macaroons.
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    /// Authenticate a request. Tries the macaroon header first; on
    /// absence, callers may fall back to the legacy bearer check via
    /// `auth::Auth::authenticate`. On *presence* of the header but
    /// failed verification, returns `Status::unauthenticated`.
    ///
    /// Returns `Ok(None)` when no macaroon header is present — the
    /// caller should fall back to the bearer path.
    pub async fn authenticate_optional<T>(
        &self,
        req: &Request<T>,
    ) -> Result<Option<TenantContext>, Status> {
        let Some(bytes) = extract_macaroon_bytes(req)? else {
            return Ok(None);
        };
        let ctx = self.authenticate_macaroon_bytes(&bytes).await?;
        Ok(Some(ctx))
    }

    /// Verify raw serialized macaroon bytes and resolve the tenant.
    /// Used by both the request interceptor (header path) and the
    /// `RotateCredential` handler (request body path).
    pub async fn authenticate_macaroon_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<TenantContext, Status> {
        self.authenticate_macaroon_bytes_with_pk(bytes, None).await
    }

    /// Phase-4 D1 N2 — variant of [`Self::authenticate_macaroon_bytes`]
    /// that threads the Noise tunnel's observed remote static pubkey
    /// into the macaroon verifier. The pk is checked against any
    /// `NoiseStaticPk` caveat embedded in the macaroon; a mismatch (or
    /// a caveat with `None` observed pk) fails closed.
    pub async fn authenticate_macaroon_bytes_with_pk(
        &self,
        bytes: &[u8],
        noise_static_pk_observed: Option<[u8; 32]>,
    ) -> Result<TenantContext, Status> {
        let mac = Macaroon::deserialize(bytes).map_err(|e| {
            tracing::debug!(?e, "macaroon decode failed");
            Status::unauthenticated("invalid macaroon")
        })?;

        // Look up the root key for this identifier. A missing row is
        // unauthenticated — could be a rotated-away key or a forgery.
        let identifier = mac.identifier();
        let root_key = self.load_root_key(&identifier).await.map_err(|e| {
            tracing::warn!(error = %e, "root key lookup failed");
            Status::internal("auth lookup failed")
        })?;
        let root_key = root_key.ok_or_else(|| Status::unauthenticated("unknown macaroon"))?;

        // Build verify context. Snapshot the revocation set so we don't
        // hold a lock across the (CPU-bound) HMAC chain replay.
        let revoked = self.revocation.snapshot();
        let ctx = VerifyContext {
            now: SystemTime::now(),
            revoked_nonces: &revoked,
            // Scope expectation is left to the handler. The interceptor
            // only proves "this macaroon verifies under our root key";
            // per-RPC scope gating belongs to per-RPC code.
            expected_scope: None,
            noise_static_pk_observed,
        };

        // NOTE: `Macaroon::verify` replays caveats in array order — the
        // wire-order invariant documented at the module level lives in
        // the macaroon crate. Do not pre-process `mac.caveats()` here.
        let verified = mac.verify(&root_key, &ctx).map_err(map_macaroon_err)?;

        let tenant_id = match verified.scope {
            Scope::User { tenant_id } => TenantId::from_uuid(uuid::Uuid::from_bytes(tenant_id)),
            // Developer/Admin/Root scopes don't map to a wallet row;
            // the handler that uses them does the right thing with the
            // `scope` field on `TenantContext`. For now we synthesize a
            // tenant id from the scope subject so the existing tenant
            // plumbing keeps working.
            Scope::Developer { developer_id } => {
                TenantId::from_uuid(uuid::Uuid::from_bytes(developer_id))
            }
            Scope::Admin | Scope::Root => {
                return Err(Status::unauthenticated(
                    "admin/root macaroons are not accepted on tenant RPCs",
                ));
            }
        };

        Ok(TenantContext {
            tenant_id,
            scope: Some(verified.scope),
            nonce: Some(verified.nonce),
            spend_caveat: verified.spend_caveat,
        })
    }

    async fn load_root_key(&self, identifier: &[u8; 16]) -> sqlx::Result<Option<RootKey>> {
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT root_key FROM global.macaroon_root_keys WHERE identifier = $1",
        )
        .bind(&identifier[..])
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(bytes,)| {
            if bytes.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Some(RootKey::from_bytes(out))
            } else {
                None
            }
        }))
    }

    /// Look up (or mint) the active user-scope root key for a tenant.
    /// Used by both `CreateTenant` (initial issue) and
    /// `RotateCredential` (mint replacement under the same key).
    ///
    /// Inserts a fresh `RootKey` + random identifier when no active
    /// row exists. Returns `(identifier, root_key)`.
    pub async fn ensure_user_root_key(
        &self,
        tenant_id: TenantId,
    ) -> sqlx::Result<([u8; 16], RootKey)> {
        let subject = tenant_id.as_uuid().as_bytes().to_vec();
        // SCOPE_USER = 0
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT identifier, root_key FROM global.macaroon_root_keys \
             WHERE scope_kind = 0 AND subject = $1 AND rotated_at IS NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&subject)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((id_bytes, rk_bytes)) = row {
            if id_bytes.len() == 16 && rk_bytes.len() == 32 {
                let mut id = [0u8; 16];
                id.copy_from_slice(&id_bytes);
                let mut rk = [0u8; 32];
                rk.copy_from_slice(&rk_bytes);
                return Ok((id, RootKey::from_bytes(rk)));
            }
        }

        // Mint a new row.
        let rk = RootKey::random();
        // Random 16-byte identifier — distinct from tenant_id so issuance
        // history is a separate primary key.
        let id: [u8; 16] = rand::random();
        sqlx::query(
            "INSERT INTO global.macaroon_root_keys (identifier, root_key, scope_kind, subject) \
             VALUES ($1, $2, 0, $3)",
        )
        .bind(&id[..])
        .bind(rk.as_bytes().as_slice())
        .bind(&subject)
        .execute(&self.pool)
        .await?;
        Ok((id, rk))
    }
}

/// Verified admin context — what an admin RPC handler gets back after
/// `MacaroonAuth::authenticate_admin` accepts the request.
#[derive(Debug, Clone)]
pub struct AdminContext {
    /// Resolved scope. Either `Scope::Admin` or `Scope::Root` (root
    /// macaroons retain admin authority — they're a superset).
    pub scope: Scope,
    /// Per-token nonce — useful for audit logging and revocation.
    pub nonce: [u8; 16],
}

impl MacaroonAuth {
    /// Verify an *admin-scoped* macaroon attached to a gRPC request.
    ///
    /// Returns `PermissionDenied` if the macaroon verifies but carries a
    /// non-admin scope (`Scope::User` / `Scope::Developer`).
    /// Returns `Unauthenticated` if no header is present, the header is
    /// malformed, or the macaroon fails signature/expiry/revocation
    /// verification.
    ///
    /// The header (`x-wick-macaroon`) is shared with the user-auth path;
    /// the two paths are distinguished by the embedded scope, not by
    /// metadata key.
    pub async fn authenticate_admin<T>(
        &self,
        req: &Request<T>,
    ) -> Result<AdminContext, Status> {
        let bytes = extract_macaroon_bytes(req)?
            .ok_or_else(|| Status::unauthenticated("admin macaroon required"))?;

        let mac = Macaroon::deserialize(&bytes).map_err(|e| {
            tracing::debug!(?e, "admin macaroon decode failed");
            Status::unauthenticated("invalid macaroon")
        })?;

        let identifier = mac.identifier();
        let root_key = self.load_root_key(&identifier).await.map_err(|e| {
            tracing::warn!(error = %e, "admin root key lookup failed");
            Status::internal("auth lookup failed")
        })?;
        let root_key = root_key.ok_or_else(|| Status::unauthenticated("unknown macaroon"))?;

        let revoked = self.revocation.snapshot();
        let ctx = VerifyContext {
            now: SystemTime::now(),
            revoked_nonces: &revoked,
            // Accept `Scope::Admin` strictly; `Scope::Root` is checked
            // below as an explicit override so the verify error doesn't
            // collapse the two cases.
            expected_scope: Some(ExpectedScope::Admin),
            noise_static_pk_observed: None,
        };

        // Try strict admin first; if that hits ScopeMismatch, retry as
        // root. Anything else (signature failure, expired, revoked) is
        // returned verbatim.
        let verified = match mac.verify(&root_key, &ctx) {
            Ok(v) => v,
            Err(MacaroonError::ScopeMismatch) => {
                let ctx_root = VerifyContext {
                    now: SystemTime::now(),
                    revoked_nonces: &revoked,
                    expected_scope: Some(ExpectedScope::Root),
                    noise_static_pk_observed: None,
                };
                mac.verify(&root_key, &ctx_root).map_err(|e| match e {
                    MacaroonError::ScopeMismatch => {
                        Status::permission_denied("macaroon scope is not admin/root")
                    }
                    other => map_macaroon_err(other),
                })?
            }
            Err(e) => return Err(map_macaroon_err(e)),
        };

        Ok(AdminContext {
            scope: verified.scope,
            nonce: verified.nonce,
        })
    }

    /// Look up (or mint) the active admin-scope root key. Mirrors
    /// [`Self::ensure_user_root_key`] but uses `scope_kind = 2` and a
    /// NULL subject — admin root keys aren't tied to a tenant.
    pub async fn ensure_admin_root_key(&self) -> sqlx::Result<([u8; 16], RootKey)> {
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT identifier, root_key FROM global.macaroon_root_keys \
             WHERE scope_kind = $1 AND subject IS NULL AND rotated_at IS NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(SCOPE_KIND_ADMIN)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((id_bytes, rk_bytes)) = row {
            if id_bytes.len() == 16 && rk_bytes.len() == 32 {
                let mut id = [0u8; 16];
                id.copy_from_slice(&id_bytes);
                let mut rk = [0u8; 32];
                rk.copy_from_slice(&rk_bytes);
                return Ok((id, RootKey::from_bytes(rk)));
            }
        }

        let rk = RootKey::random();
        let id: [u8; 16] = rand::random();
        sqlx::query(
            "INSERT INTO global.macaroon_root_keys (identifier, root_key, scope_kind, subject) \
             VALUES ($1, $2, $3, NULL)",
        )
        .bind(&id[..])
        .bind(rk.as_bytes().as_slice())
        .bind(SCOPE_KIND_ADMIN)
        .execute(&self.pool)
        .await?;
        Ok((id, rk))
    }
}

/// Pull the macaroon bytes off a request's metadata. `Ok(None)` if the
/// header is absent; an error if the value can't be parsed as
/// base64-standard bytes.
fn extract_macaroon_bytes<T>(req: &Request<T>) -> Result<Option<Vec<u8>>, Status> {
    let Some(header) = req.metadata().get(MACAROON_HEADER) else {
        return Ok(None);
    };
    let s = header
        .to_str()
        .map_err(|_| Status::unauthenticated("x-wick-macaroon is not valid ASCII"))?;
    let bytes = hex::decode(s)
        .map_err(|_| Status::unauthenticated("x-wick-macaroon is not valid hex"))?;
    Ok(Some(bytes))
}

/// Encode a serialized macaroon as the metadata header expects. SDK
/// uses the same encoding via [`MACAROON_HEADER`]; exported here for
/// tests.
#[must_use]
pub fn encode_macaroon_header(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn map_macaroon_err(e: MacaroonError) -> Status {
    match e {
        MacaroonError::Expired => Status::unauthenticated("macaroon expired"),
        MacaroonError::Revoked => Status::unauthenticated("macaroon revoked"),
        MacaroonError::ScopeMismatch => Status::permission_denied("macaroon scope mismatch"),
        MacaroonError::Tampered | MacaroonError::InvalidSignature => {
            Status::unauthenticated("macaroon signature invalid")
        }
        MacaroonError::DecodeFailed(_) => Status::unauthenticated("invalid macaroon"),
        MacaroonError::CaveatFailed(msg) => {
            Status::unauthenticated(format!("macaroon caveat failed: {msg}"))
        }
    }
}

// Silence unused warning under no-revocation builds.
#[allow(dead_code)]
fn _assert_sync_send() {
    fn check<T: Send + Sync>() {}
    check::<MacaroonAuth>();
    check::<TenantContext>();
    check::<HashSet<[u8; 16]>>();
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use wick_macaroon::{Caveat, USER_DEFAULT_LIFETIME};

    /// Build a minimal macaroon for header-encode tests — verification
    /// against postgres lives in the postgres-gated tests in the parent
    /// crate's test target.
    fn issue_user_macaroon(tenant: [u8; 16]) -> (Macaroon, RootKey) {
        let rk = RootKey::random();
        let m = Macaroon::issue(
            "wick.cloud",
            [9u8; 16],
            &rk,
            Scope::User { tenant_id: tenant },
            USER_DEFAULT_LIFETIME,
        );
        (m, rk)
    }

    #[test]
    fn header_encode_decode_roundtrip() {
        let (m, _rk) = issue_user_macaroon([1u8; 16]);
        let bytes = m.serialize();
        let encoded = encode_macaroon_header(&bytes);
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(bytes, decoded);
    }

    #[test]
    fn caveat_order_invariant_documented() {
        // Sanity: the macaroon serialization preserves the caveats in
        // append-order. The interceptor relies on this when calling
        // `Macaroon::verify` (chain replay in array order).
        let (mut m, _rk) = issue_user_macaroon([1u8; 16]);
        m.add_caveat(Caveat::max_payment(1_000, 60));
        let bytes = m.serialize();
        let m2 = Macaroon::deserialize(&bytes).unwrap();
        let tags: Vec<u8> = m2.caveats().iter().map(Caveat::tag).collect();
        // scope, expiry, nonce, spend — in that exact order.
        assert_eq!(tags, vec![0x02, 0x01, 0x03, 0x04]);
    }

    #[test]
    fn no_header_returns_none() {
        let req: Request<()> = Request::new(());
        let got = extract_macaroon_bytes(&req).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn garbage_header_returns_unauthenticated() {
        let mut req: Request<()> = Request::new(());
        req.metadata_mut()
            .insert(MACAROON_HEADER, "!!!not-base64!!!".parse().unwrap());
        let err = extract_macaroon_bytes(&req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn map_macaroon_err_expiry_is_unauthenticated() {
        let s = map_macaroon_err(MacaroonError::Expired);
        assert_eq!(s.code(), tonic::Code::Unauthenticated);
        let s = map_macaroon_err(MacaroonError::Revoked);
        assert_eq!(s.code(), tonic::Code::Unauthenticated);
        let s = map_macaroon_err(MacaroonError::ScopeMismatch);
        assert_eq!(s.code(), tonic::Code::PermissionDenied);
        let s = map_macaroon_err(MacaroonError::Tampered);
        assert_eq!(s.code(), tonic::Code::Unauthenticated);
    }
}
