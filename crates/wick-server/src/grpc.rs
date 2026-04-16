//! gRPC service implementation.
//!
//! `WickGrpcService` wraps `NodeManager` and exposes the generated
//! `WalletService` trait. Each data-plane handler:
//!
//! 1. Authenticates the request via `auth::authenticate` — extracts the
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

use crate::auth;
use crate::node::{manager::NodeManager, NodeCmd};

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

        // Decode hex pubkey → bytes for the DB.
        let pubkey_bytes = hex::decode(&pubkey_hex)
            .map_err(|_| Status::invalid_argument("pubkey_hex is not valid hex"))?;
        if pubkey_bytes.len() != 33 {
            return Err(Status::invalid_argument(
                "pubkey_hex must be a 33-byte compressed SEC1 pubkey (66 hex chars)",
            ));
        }

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
        let (raw_token, token_hash) = auth::generate_token();

        // Insert into global.wallets, get the auto-assigned tenant_id.
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO global.wallets (pubkey, plan_tier, api_token_hash) \
             VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(&pubkey_bytes)
        .bind(&plan_tier)
        .bind(&token_hash)
        .fetch_one(self.pool.raw())
        .await
        .map_err(|e| {
            warn!(?e, "create_tenant: DB insert failed");
            Status::internal("failed to create tenant")
        })?;

        let raw_id = u64::try_from(row.0).map_err(|_| {
            Status::internal("tenant id overflow: BIGSERIAL returned negative value")
        })?;
        let tenant_id = TenantId::new(raw_id);

        // Provision the Postgres schema and spawn the actor.
        self.manager
            .provision(tenant_id, &self.pool)
            .await
            .map_err(|e| {
                warn!(?e, %tenant_id, "create_tenant: provision failed");
                Status::internal("failed to provision tenant")
            })?;

        info!(%tenant_id, plan_tier, "tenant created");
        Ok(Response::new(CreateTenantResponse {
            tenant_id: tenant_id.as_u64(),
            api_token: raw_token,
        }))
    }

    async fn get_balance(
        &self,
        request: Request<GetBalanceRequest>,
    ) -> Result<Response<GetBalanceResponse>, Status> {
        // Authenticate first — the req.tenant_id field is ignored.
        let tenant_id = auth::authenticate(self.pool.raw(), &request).await?;

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(tenant_id, NodeCmd::GetBalance { resp: tx })
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

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
        let tenant_id = auth::authenticate(self.pool.raw(), &request).await?;

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
            .map_err(|e| Status::not_found(e.to_string()))?;

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
        let tenant_id = auth::authenticate(self.pool.raw(), &request).await?;

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
            .map_err(|e| Status::not_found(e.to_string()))?;

        let bolt11 = rx
            .await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        // Return a stub payment hash matching the invoice length.
        let fake_hash = vec![0u8; 32];
        Ok(Response::new(ReceivePaymentResponse {
            bolt11,
            payment_hash: fake_hash,
        }))
    }

    async fn get_transactions(
        &self,
        request: Request<GetTransactionsRequest>,
    ) -> Result<Response<GetTransactionsResponse>, Status> {
        // Authenticate first — the req.tenant_id field is ignored.
        let tenant_id = auth::authenticate(self.pool.raw(), &request).await?;

        let req = request.into_inner();
        let limit = req.limit.clamp(1, 200);

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(
                tenant_id,
                NodeCmd::GetTransactions { limit, resp: tx },
            )
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

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
