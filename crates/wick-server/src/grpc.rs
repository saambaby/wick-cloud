//! gRPC service implementation.
//!
//! `WickGrpcService` wraps `NodeManager` and exposes the generated
//! `WalletService` trait. Each data-plane handler:
//!
//! 1. Authenticates the request via `Auth::authenticate` — extracts the
//!    `Authorization: Bearer <token>` metadata header, hashes it, and looks
//!    up the owning tenant in `global.wallets`. The caller-supplied
//!    `tenant_id` field in the request body is **ignored**; the authenticated
//!    tenant drives every operation.
//! 2. Creates a `oneshot` channel for the actor response.
//! 3. Dispatches the `NodeCmd` through the manager.
//! 4. Awaits the response and maps it to gRPC types.

use std::sync::Arc;

use tokio::sync::oneshot;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use wick_core::TenantId;
use wick_db::Pool;
use wick_proto::wick::{
    wallet_service_server::WalletService, CreateTenantRequest, CreateTenantResponse,
    GetBalanceRequest, GetBalanceResponse, GetTransactionsRequest, GetTransactionsResponse,
    Payment, ReceivePaymentRequest, ReceivePaymentResponse, SendPaymentRequest,
    SendPaymentResponse,
};

use crate::auth::Auth;
use crate::node::{
    manager::{DispatchError, NodeManager, ProvisionError},
    NodeCmd,
};

/// Translate a typed [`DispatchError`] into the appropriate gRPC
/// `Status`. Preserves the Phase-2 error taxonomy so clients can tell
/// "retry later" (UNAVAILABLE, RESOURCE_EXHAUSTED, DEADLINE_EXCEEDED)
/// apart from "this tenant doesn't exist" (NOT_FOUND) and "something
/// broke" (INTERNAL).
fn dispatch_error_to_status(e: DispatchError) -> Status {
    match e {
        DispatchError::NotFound(_) => Status::not_found(e.to_string()),
        DispatchError::InErrorState(_) | DispatchError::ActorStopped(_) => {
            Status::unavailable(e.to_string())
        }
        DispatchError::WakeTimeout(_) => Status::deadline_exceeded(e.to_string()),
        DispatchError::RateLimited(_) | DispatchError::HeadroomDenied(_) => {
            Status::resource_exhausted(e.to_string())
        }
        DispatchError::Internal(_) => Status::internal(e.to_string()),
    }
}

// ── Plan tier allowlist ───────────────────────────────────────────────────────

const VALID_PLAN_TIERS: &[&str] = &["free", "standard", "premium"];

// ── Service struct ────────────────────────────────────────────────────────────

/// Implements the tonic-generated `WalletService` trait.
#[derive(Debug, Clone)]
pub struct WickGrpcService {
    manager: Arc<NodeManager>,
    pool: Pool,
}

impl WickGrpcService {
    /// Construct the service with a shared manager and pool.
    #[must_use]
    pub fn new(manager: Arc<NodeManager>, pool: Pool) -> Self {
        Self { manager, pool }
    }
}

// ── WalletService impl ────────────────────────────────────────────────────────

#[tonic::async_trait]
impl WalletService for WickGrpcService {
    async fn create_tenant(
        &self,
        request: Request<CreateTenantRequest>,
    ) -> Result<Response<CreateTenantResponse>, Status> {
        let req = request.into_inner();
        let pubkey_hex = req.pubkey_hex.trim().to_lowercase();

        if pubkey_hex.is_empty() {
            return Err(Status::invalid_argument("pubkey_hex is required"));
        }

        // Decode and validate pubkey — must be a valid compressed secp256k1 point.
        let pubkey_bytes = hex::decode(&pubkey_hex)
            .map_err(|_| Status::invalid_argument("pubkey_hex is not valid hex"))?;
        if pubkey_bytes.len() != 33 {
            return Err(Status::invalid_argument(
                "pubkey_hex must be a 33-byte compressed SEC1 pubkey (66 hex chars)",
            ));
        }
        bitcoin::secp256k1::PublicKey::from_slice(&pubkey_bytes)
            .map_err(|_| Status::invalid_argument("pubkey_hex is not a valid secp256k1 public key"))?;

        // Validate plan_tier against the known allowlist.
        let plan_tier = if req.plan_tier.is_empty() {
            "free".to_owned()
        } else if VALID_PLAN_TIERS.contains(&req.plan_tier.as_str()) {
            req.plan_tier.clone()
        } else {
            return Err(Status::invalid_argument(format!(
                "plan_tier must be one of: {}",
                VALID_PLAN_TIERS.join(", ")
            )));
        };

        // Generate a bearer token. Only the hash is persisted; the raw token
        // is returned once and must be stored by the client.
        let (raw_token, token_hash) = Auth::generate_token();

        // Derive a deterministic UUID v5 from the pubkey so the tenant_id is
        // stable across re-registrations with the same key.
        let tenant_id = TenantId::from_pubkey(&pubkey_bytes);

        // Idempotent registration: if a wallet with this pubkey is already
        // registered, rotate its api_token_hash and return the existing
        // tenant_id. The tenant_id is a UUID v5 of the pubkey, so it's
        // stable across re-registrations either way. Rotating the token
        // on re-register lets clients recover access without manual
        // operator intervention; the old token is invalidated by the hash
        // replacement.
        sqlx::query(
            "INSERT INTO global.wallets (id, pubkey, plan_tier, api_token_hash) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (pubkey) DO UPDATE \
             SET api_token_hash = EXCLUDED.api_token_hash, \
                 updated_at = now()",
        )
        .bind(tenant_id.as_uuid())
        .bind(&pubkey_bytes)
        .bind(&plan_tier)
        .bind(&token_hash)
        .execute(self.pool.raw())
        .await
        .map_err(|e| {
            warn!(?e, "create_tenant: DB upsert failed");
            Status::internal("failed to register tenant")
        })?;

        // Provision the Postgres schema and spawn the actor. The schema
        // DDL is `IF NOT EXISTS`, but in-process the manager rejects
        // double-provision (actor already spawned). Swallow that specific
        // error — the tenant is already serviceable and callers shouldn't
        // have to distinguish "fresh register" from "re-register" at the
        // gRPC boundary.
        match self.manager.provision(tenant_id, &self.pool).await {
            Ok(()) => {}
            Err(ProvisionError::AlreadyProvisioned(_)) => {
                info!(%tenant_id, "tenant already provisioned — re-register rotated token only");
            }
            Err(ProvisionError::Other(e)) => {
                warn!(?e, %tenant_id, "create_tenant: provision failed");
                return Err(Status::internal("failed to provision tenant"));
            }
        }

        info!(%tenant_id, plan_tier, "tenant registered");
        Ok(Response::new(CreateTenantResponse {
            tenant_id: tenant_id.to_string(),
            api_token: raw_token,
        }))
    }

    async fn get_balance(
        &self,
        request: Request<GetBalanceRequest>,
    ) -> Result<Response<GetBalanceResponse>, Status> {
        // Authenticate first — the req.tenant_id field is ignored.
        let tenant_id = Auth::authenticate(self.pool.raw(), &request).await?;

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(tenant_id, NodeCmd::GetBalance { resp: tx })
            .await
            .map_err(dispatch_error_to_status)?;

        let balance = rx
            .await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetBalanceResponse {
            lightning_balance_msat: balance.lightning_balance_msat,
            onchain_balance_sats: balance.onchain_balance_sats,
        }))
    }

    async fn send_payment(
        &self,
        request: Request<SendPaymentRequest>,
    ) -> Result<Response<SendPaymentResponse>, Status> {
        // Authenticate first — the req.tenant_id field is ignored.
        let tenant_id = Auth::authenticate(self.pool.raw(), &request).await?;

        let req = request.into_inner();
        if req.bolt11.is_empty() {
            return Err(Status::invalid_argument("bolt11 is required"));
        }

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(
                tenant_id,
                NodeCmd::SendPayment {
                    bolt11: req.bolt11,
                    resp: tx,
                },
            )
            .await
            .map_err(dispatch_error_to_status)?;

        let result = rx
            .await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SendPaymentResponse {
            payment_hash: result.payment_hash,
            fee_paid_msat: result.fee_paid_msat,
            status: result.status,
        }))
    }

    async fn receive_payment(
        &self,
        request: Request<ReceivePaymentRequest>,
    ) -> Result<Response<ReceivePaymentResponse>, Status> {
        // Authenticate first — the req.tenant_id field is ignored.
        let tenant_id = Auth::authenticate(self.pool.raw(), &request).await?;

        let req = request.into_inner();
        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(
                tenant_id,
                NodeCmd::ReceivePayment {
                    amount_msat: req.amount_msat,
                    memo: req.memo,
                    resp: tx,
                },
            )
            .await
            .map_err(dispatch_error_to_status)?;

        let (bolt11, payment_hash) = rx
            .await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ReceivePaymentResponse {
            bolt11,
            payment_hash,
        }))
    }

    async fn get_transactions(
        &self,
        request: Request<GetTransactionsRequest>,
    ) -> Result<Response<GetTransactionsResponse>, Status> {
        // Authenticate first — the req.tenant_id field is ignored.
        let tenant_id = Auth::authenticate(self.pool.raw(), &request).await?;

        let req = request.into_inner();
        let limit = req.limit.clamp(1, 200);

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(tenant_id, NodeCmd::GetTransactions { limit, resp: tx })
            .await
            .map_err(dispatch_error_to_status)?;

        let records = rx
            .await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        let payments = records
            .into_iter()
            .map(|r| Payment {
                payment_hash: r.payment_hash,
                is_outbound: r.is_outbound,
                amount_msat: r.amount_msat,
                fee_msat: r.fee_msat,
                status: r.status,
                timestamp: r.timestamp,
                memo: r.memo,
            })
            .collect();

        Ok(Response::new(GetTransactionsResponse { payments }))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[test]
    fn dispatch_error_maps_to_correct_status_code() {
        let tid = TenantId::generate();

        assert_eq!(
            dispatch_error_to_status(DispatchError::NotFound(tid)).code(),
            Code::NotFound
        );
        assert_eq!(
            dispatch_error_to_status(DispatchError::InErrorState(tid)).code(),
            Code::Unavailable,
            "ERROR state → UNAVAILABLE so clients retry"
        );
        assert_eq!(
            dispatch_error_to_status(DispatchError::ActorStopped(tid)).code(),
            Code::Unavailable
        );
        assert_eq!(
            dispatch_error_to_status(DispatchError::WakeTimeout(tid)).code(),
            Code::DeadlineExceeded,
            "wake over CLTV budget → DEADLINE_EXCEEDED"
        );
        assert_eq!(
            dispatch_error_to_status(DispatchError::RateLimited(tid)).code(),
            Code::ResourceExhausted,
            "per-tenant rate limit → RESOURCE_EXHAUSTED"
        );
        assert_eq!(
            dispatch_error_to_status(DispatchError::HeadroomDenied(tid)).code(),
            Code::ResourceExhausted,
            "memory headroom denial → RESOURCE_EXHAUSTED"
        );
        assert_eq!(
            dispatch_error_to_status(DispatchError::Internal(anyhow::anyhow!("boom"))).code(),
            Code::Internal
        );
    }
}
