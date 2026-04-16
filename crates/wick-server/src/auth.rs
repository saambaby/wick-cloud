//! Phase-1 bearer-token authentication.
//!
//! Each tenant receives a single opaque API token at registration (`CreateTenant`).
//! The raw token is returned once and never persisted server-side — only its
//! SHA-256 hash is stored in `global.wallets.api_token_hash`. Every
//! data-plane request must include the token as:
//!
//!   Authorization: Bearer <64 lowercase hex chars>
//!
//! Phase 4 replaces this with macaroons (`wick-macaroon`, architecture §5.4).

use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tonic::Status;
use wick_core::TenantId;

/// gRPC metadata key for the bearer token.
pub const AUTH_HEADER: &str = "authorization";

/// Generate a fresh 32-byte random token.
///
/// Returns `(raw_token_hex, sha256_hash_bytes)`:
/// - `raw_token_hex` is sent to the client once and never stored.
/// - `sha256_hash_bytes` is stored in `global.wallets.api_token_hash`.
pub fn generate_token() -> (String, Vec<u8>) {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let hash = Sha256::digest(raw).to_vec();
    (hex::encode(raw), hash)
}

/// Validate the bearer token in `request` metadata and return the owning tenant.
///
/// Hashes the presented token and queries `global.wallets` for a matching,
/// non-suspended row. Returns `Status::unauthenticated` on any failure so
/// callers cannot distinguish "wrong token" from "suspended tenant".
pub async fn authenticate<T>(
    pool: &PgPool,
    request: &tonic::Request<T>,
) -> Result<TenantId, Status> {
    let raw_token = extract_bearer(request)?;

    let raw_bytes = hex::decode(&raw_token)
        .map_err(|_| Status::unauthenticated("token is not valid hex"))?;
    let hash = Sha256::digest(&raw_bytes).to_vec();

    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM global.wallets WHERE api_token_hash = $1 AND suspended = FALSE",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await
    .map_err(|_| Status::internal("authentication lookup failed"))?;

    match row {
        Some((id,)) => {
            let uid = u64::try_from(id)
                .map_err(|_| Status::internal("tenant id out of range"))?;
            Ok(TenantId::new(uid))
        }
        None => Err(Status::unauthenticated("invalid or revoked token")),
    }
}

fn extract_bearer<T>(request: &tonic::Request<T>) -> Result<String, Status> {
    let header = request
        .metadata()
        .get(AUTH_HEADER)
        .ok_or_else(|| Status::unauthenticated("missing Authorization header"))?;

    let value = header
        .to_str()
        .map_err(|_| Status::unauthenticated("Authorization header is not valid UTF-8"))?;

    value
        .strip_prefix("Bearer ")
        .map(str::to_owned)
        .ok_or_else(|| Status::unauthenticated("Authorization header must use Bearer scheme"))
}
