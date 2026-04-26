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

/// Stateless bearer-token auth helper. All operations are associated
/// functions — no instance state to carry.
#[derive(Debug)]
pub struct Auth;

impl Auth {
    /// gRPC metadata key for the bearer token.
    pub const HEADER: &'static str = "authorization";

    /// Generate a fresh 32-byte random token.
    ///
    /// Returns `(raw_token_hex, sha256_hash_bytes)`:
    /// - `raw_token_hex` is sent to the client once and never stored.
    /// - `sha256_hash_bytes` is stored in `global.wallets.api_token_hash`.
    #[must_use]
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
        let raw_token = Self::extract_bearer(request)?;

        let raw_bytes = hex::decode(&raw_token)
            .map_err(|_| Status::unauthenticated("token is not valid hex"))?;
        let hash = Sha256::digest(&raw_bytes).to_vec();

        let row: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id FROM global.wallets WHERE api_token_hash = $1 AND suspended = FALSE",
        )
        .bind(&hash)
        .fetch_optional(pool)
        .await
        .map_err(|_| Status::internal("authentication lookup failed"))?;

        match row {
            Some((id,)) => Ok(TenantId::from_uuid(id)),
            None => Err(Status::unauthenticated("invalid or revoked token")),
        }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn extract_bearer<T>(request: &tonic::Request<T>) -> Result<String, Status> {
        let header = request
            .metadata()
            .get(Self::HEADER)
            .ok_or_else(|| Status::unauthenticated("missing Authorization header"))?;

        let value = header
            .to_str()
            .map_err(|_| Status::unauthenticated("Authorization header is not valid UTF-8"))?;

        value
            .strip_prefix("Bearer ")
            .map(str::to_owned)
            .ok_or_else(|| Status::unauthenticated("Authorization header must use Bearer scheme"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── Header parsing (no DB) ────────────────────────────────────────────────

    #[test]
    fn missing_header_returns_unauthenticated() {
        let req: tonic::Request<()> = tonic::Request::new(());
        assert_eq!(
            Auth::extract_bearer(&req).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }

    #[test]
    fn malformed_scheme_returns_unauthenticated() {
        let mut req: tonic::Request<()> = tonic::Request::new(());
        req.metadata_mut()
            .insert("authorization", "Token abc123".parse().unwrap());
        assert_eq!(
            Auth::extract_bearer(&req).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }

    #[test]
    fn valid_bearer_prefix_extracts_raw_value() {
        let mut req: tonic::Request<()> = tonic::Request::new(());
        req.metadata_mut()
            .insert("authorization", "Bearer deadbeef".parse().unwrap());
        assert_eq!(Auth::extract_bearer(&req).unwrap(), "deadbeef");
    }

    // ── DB-backed ─────────────────────────────────────────────────────────────

    async fn test_pool() -> PgPool {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://wick:wick@localhost:5432/wick".to_owned());
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("postgres connect")
    }

    #[tokio::test]
    #[ignore = "requires postgres (just db-up)"]
    async fn non_hex_token_returns_unauthenticated() {
        let pool = test_pool().await;
        let mut req: tonic::Request<()> = tonic::Request::new(());
        req.metadata_mut()
            .insert("authorization", "Bearer zzz_not_hex!!".parse().unwrap());
        assert_eq!(
            Auth::authenticate(&pool, &req).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }

    #[tokio::test]
    #[ignore = "requires postgres (just db-up)"]
    async fn unknown_token_returns_unauthenticated() {
        let pool = test_pool().await;
        let mut req: tonic::Request<()> = tonic::Request::new(());
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", hex::encode([0xde; 32]))
                .parse()
                .unwrap(),
        );
        assert_eq!(
            Auth::authenticate(&pool, &req).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }

    #[tokio::test]
    #[ignore = "requires postgres (just db-up)"]
    async fn suspended_tenant_returns_unauthenticated() {
        let pool = test_pool().await;
        let (raw_token, token_hash) = Auth::generate_token();
        sqlx::query(
            "INSERT INTO global.wallets (pubkey, plan_tier, api_token_hash, suspended) \
             VALUES ($1, 'free', $2, TRUE)",
        )
        .bind(vec![0xffu8; 33])
        .bind(&token_hash)
        .execute(&pool)
        .await
        .expect("insert suspended wallet");

        let mut req: tonic::Request<()> = tonic::Request::new(());
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {raw_token}").parse().unwrap(),
        );
        assert_eq!(
            Auth::authenticate(&pool, &req).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }
}
