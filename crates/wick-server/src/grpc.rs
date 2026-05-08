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

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use subtle::ConstantTimeEq;

use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use wick_core::TenantId;
use wick_db::Pool;
use wick_lsp::{LspBuilder, LspDaemon};

// `LspBuilder` is used by `WickAdminGrpcService` below.
use wick_proto::wick::{
    admin_service_server::AdminService, wallet_service_server::WalletService,
    ChannelSummary as PbChannelSummary, ConnectPeerRequest, ConnectPeerResponse,
    CreateTenantRequest, CreateTenantResponse, GetBalanceRequest, GetBalanceResponse,
    GetJitInvoiceRequest, GetJitInvoiceResponse, GetLspInfoRequest, GetLspInfoResponse,
    GetNodeInfoRequest, GetNodeInfoResponse, GetTransactionsRequest, GetTransactionsResponse,
    ListChannelsRequest, ListChannelsResponse, LspFinalizeFundingRequest,
    LspFinalizeFundingResponse, LspPendingFunding, LspWatchPendingFundingRequest,
    Lsps2GetInfoRequest, Lsps2GetInfoResponse, OpenChannelFinalizeRequest,
    OpenChannelFinalizeResponse, OpenChannelInitRequest, OpenChannelInitResponse, Payment,
    ReceivePaymentRequest, ReceivePaymentResponse, RegisterChallengeRequest,
    RegisterChallengeResponse, RegisterLspIdentityRequest, RegisterLspIdentityResponse,
    SendPaymentRequest, SendPaymentResponse,
};

use crate::auth::Auth;
use crate::node::{
    manager::{DispatchError, NodeManager, ProvisionError},
    NodeCmd,
};
use crate::nonce_store::{NonceError, NonceStore, REGISTER_DOMAIN};

/// Metadata header carrying the admin shared secret. Compared against
/// `WICK_ADMIN_SECRET` config / env at handler entry. Slice 3.3a auth
/// stop-gap until macaroon scope plumbing arrives in 3.3c.
const ADMIN_SECRET_METADATA: &str = "x-wick-admin-secret";

/// Timeout for `OpenChannelInit` to wait on LDK's `FundingGenerationReady`.
/// The event typically fires within hundreds of milliseconds after
/// `ChannelManager::create_channel`, but regtest + cold-peer handshake
/// can push that out — 15s is generous.
const OPEN_CHANNEL_INIT_TIMEOUT: Duration = Duration::from_secs(15);

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

/// Public-facing identity of the in-process LSP, surfaced to SDK
/// clients via [`WalletService::get_lsp_info`].
#[derive(Debug, Clone)]
pub struct LspInfo {
    /// 33-byte compressed pubkey of the LSP node.
    pub pubkey: bitcoin::secp256k1::PublicKey,
    /// `host:port` string clients use for [`WalletService::connect_peer`].
    pub address: String,
    /// `true` when the LSP is connected to its upstream and has
    /// liquidity available to open JIT channels.
    pub ready: bool,
}

/// Implements the tonic-generated `WalletService` trait.
#[derive(Clone)]
pub struct WickGrpcService {
    manager: Arc<NodeManager>,
    pool: Pool,
    /// Static LSP identity surfaced via `GetLspInfo` (pubkey + listen
    /// address). Sourced from `[lsp].pubkey_hex` config — the operator
    /// publishes their public key at deployment so tenants know which
    /// counterparty to expect LSPS2 messages from.
    lsp_info: Option<LspInfo>,
    /// Slot holding the live LSP daemon once an operator's SDK has
    /// successfully called `RegisterLspIdentity` with a matching seed.
    /// `None` when the slot is empty; `GetLspInfo` reads it to surface
    /// the `ready` flag dynamically.
    lsp_daemon_slot: Option<Arc<RwLock<Option<LspDaemon>>>>,
    /// In-memory store of issued-but-not-yet-redeemed registration
    /// nonces. See [`NonceStore`].
    nonce_store: Arc<NonceStore>,
}

impl std::fmt::Debug for WickGrpcService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WickGrpcService")
            .field("has_lsp", &self.lsp_info.is_some())
            .field("has_daemon_slot", &self.lsp_daemon_slot.is_some())
            .finish_non_exhaustive()
    }
}

impl WickGrpcService {
    /// Construct the service with a shared manager and pool. No LSP
    /// surfaced to clients (`get_lsp_info` returns an empty pubkey).
    #[must_use]
    pub fn new(manager: Arc<NodeManager>, pool: Pool) -> Self {
        Self {
            manager,
            pool,
            lsp_info: None,
            lsp_daemon_slot: None,
            nonce_store: Arc::new(NonceStore::new()),
        }
    }

    /// Construct the service with the LSP identity surfaced to clients.
    /// Used when the operator-mode LSP daemon is enabled.
    #[must_use]
    pub fn with_lsp(
        manager: Arc<NodeManager>,
        pool: Pool,
        lsp_info: LspInfo,
        lsp_daemon_slot: Arc<RwLock<Option<LspDaemon>>>,
    ) -> Self {
        Self {
            manager,
            pool,
            lsp_info: Some(lsp_info),
            lsp_daemon_slot: Some(lsp_daemon_slot),
            nonce_store: Arc::new(NonceStore::new()),
        }
    }

    /// Test seam: borrow the nonce store. Used by integration-style
    /// tests that need to advance time or inject fake challenges.
    #[cfg(test)]
    #[must_use]
    pub fn nonce_store(&self) -> &Arc<NonceStore> {
        &self.nonce_store
    }
}

/// Verify a registration challenge ECDSA signature. Pure function so
/// unit tests don't need a running gRPC server. Returns `Ok(())` iff
/// `signature` is a valid DER-encoded ECDSA signature over
/// `sha256(REGISTER_DOMAIN || nonce)` against `pubkey`.
fn verify_register_signature(
    pubkey: &bitcoin::secp256k1::PublicKey,
    nonce: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use bitcoin::secp256k1::{ecdsa::Signature, Message, Secp256k1};
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(REGISTER_DOMAIN);
    hasher.update(nonce);
    let digest = hasher.finalize();
    let msg = Message::from_digest_slice(digest.as_ref())
        .map_err(|e| format!("digest is not a valid secp message: {e}"))?;
    let sig = Signature::from_der(signature)
        .map_err(|e| format!("signature is not valid DER ECDSA: {e}"))?;
    let secp = Secp256k1::verification_only();
    secp.verify_ecdsa(&msg, &sig, pubkey)
        .map_err(|e| format!("signature verification failed: {e}"))
}

// ── WalletService impl ────────────────────────────────────────────────────────

#[tonic::async_trait]
impl WalletService for WickGrpcService {
    async fn register_challenge(
        &self,
        request: Request<RegisterChallengeRequest>,
    ) -> Result<Response<RegisterChallengeResponse>, Status> {
        let req = request.into_inner();
        if req.pubkey.len() != 33 {
            return Err(Status::invalid_argument(
                "pubkey must be 33 bytes (compressed SEC1)",
            ));
        }
        // Validate as a real curve point so we don't issue nonces for
        // garbage keys that could never produce a valid signature.
        bitcoin::secp256k1::PublicKey::from_slice(&req.pubkey)
            .map_err(|_| Status::invalid_argument("pubkey is not a valid secp256k1 public key"))?;
        let mut pk = [0u8; 33];
        pk.copy_from_slice(&req.pubkey);
        let nonce = self.nonce_store.issue(pk);
        Ok(Response::new(RegisterChallengeResponse { nonce }))
    }

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
        let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&pubkey_bytes).map_err(|_| {
            Status::invalid_argument("pubkey_hex is not a valid secp256k1 public key")
        })?;

        // Signature challenge gate (gotcha #509). Reject before touching
        // the database so a flood of invalid registrations can't burn
        // pool connections.
        if req.nonce.is_empty() || req.signature.is_empty() {
            return Err(Status::invalid_argument(
                "nonce and signature are required (call RegisterChallenge first)",
            ));
        }
        let mut pk_arr = [0u8; 33];
        pk_arr.copy_from_slice(&pubkey_bytes);
        // Verify the signature *before* consuming the nonce — a wrong
        // signature must not burn the challenge.
        verify_register_signature(&pubkey, &req.nonce, &req.signature)
            .map_err(|e| Status::invalid_argument(format!("invalid registration signature: {e}")))?;
        match self.nonce_store.consume(&pk_arr, &req.nonce) {
            Ok(()) => {}
            Err(NonceError::Unknown) | Err(NonceError::Mismatch) => {
                return Err(Status::invalid_argument(
                    "nonce does not match an outstanding challenge for this pubkey",
                ));
            }
            Err(NonceError::Expired) => {
                return Err(Status::invalid_argument(
                    "registration challenge expired; call RegisterChallenge again",
                ));
            }
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
            Err(ProvisionError::CorruptState { tenant, detail }) => {
                // Persisted LDK state is undecodable — the node has
                // quarantined the bytes. The caller retrying will not
                // help; an operator must inspect the `quarantine/*`
                // namespace in the tenant's Postgres schema and either
                // restore from backup or manually clear the row.
                warn!(%tenant, %detail, "create_tenant: tenant has corrupt state");
                return Err(Status::failed_precondition(
                    "tenant has corrupt persisted state — operator intervention required",
                ));
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

    async fn get_node_info(
        &self,
        request: Request<GetNodeInfoRequest>,
    ) -> Result<Response<GetNodeInfoResponse>, Status> {
        let tenant_id = Auth::authenticate(self.pool.raw(), &request).await?;

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(tenant_id, NodeCmd::GetNodeInfo { resp: tx })
            .await
            .map_err(dispatch_error_to_status)?;

        let (pubkey, listen) = rx
            .await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        let (host, port) = match listen {
            Some(addr) => (addr.ip().to_string(), u32::from(addr.port())),
            None => (String::new(), 0),
        };

        Ok(Response::new(GetNodeInfoResponse {
            node_id_hex: hex::encode(pubkey.serialize()),
            listen_host: host,
            listen_port: port,
        }))
    }

    async fn connect_peer(
        &self,
        request: Request<ConnectPeerRequest>,
    ) -> Result<Response<ConnectPeerResponse>, Status> {
        let tenant_id = Auth::authenticate(self.pool.raw(), &request).await?;
        let req = request.into_inner();

        let peer_bytes = hex::decode(&req.peer_pubkey_hex)
            .map_err(|_| Status::invalid_argument("peer_pubkey_hex is not valid hex"))?;
        let peer = bitcoin::secp256k1::PublicKey::from_slice(&peer_bytes).map_err(|_| {
            Status::invalid_argument("peer_pubkey_hex is not a valid secp256k1 key")
        })?;

        if req.host.is_empty() {
            return Err(Status::invalid_argument("host is required"));
        }
        let port = u16::try_from(req.port)
            .map_err(|_| Status::invalid_argument("port must fit in u16"))?;

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(
                tenant_id,
                NodeCmd::ConnectPeer {
                    peer,
                    host: req.host,
                    port,
                    resp: tx,
                },
            )
            .await
            .map_err(dispatch_error_to_status)?;

        rx.await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ConnectPeerResponse {}))
    }

    async fn open_channel_init(
        &self,
        request: Request<OpenChannelInitRequest>,
    ) -> Result<Response<OpenChannelInitResponse>, Status> {
        let tenant_id = Auth::authenticate(self.pool.raw(), &request).await?;
        let req = request.into_inner();

        let peer_bytes = hex::decode(&req.peer_pubkey_hex)
            .map_err(|_| Status::invalid_argument("peer_pubkey_hex is not valid hex"))?;
        let peer = bitcoin::secp256k1::PublicKey::from_slice(&peer_bytes).map_err(|_| {
            Status::invalid_argument("peer_pubkey_hex is not a valid secp256k1 key")
        })?;

        if req.channel_value_sat == 0 {
            return Err(Status::invalid_argument("channel_value_sat must be > 0"));
        }

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(
                tenant_id,
                NodeCmd::OpenChannelInit {
                    peer,
                    value_sat: req.channel_value_sat,
                    push_msat: req.push_msat,
                    timeout: OPEN_CHANNEL_INIT_TIMEOUT,
                    resp: tx,
                },
            )
            .await
            .map_err(dispatch_error_to_status)?;

        let (temp_id, pending) = rx
            .await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(OpenChannelInitResponse {
            temp_channel_id: temp_id.0.to_vec(),
            funding_output_script_hex: hex::encode(pending.output_script.as_bytes()),
            channel_value_sat: pending.value_sat,
        }))
    }

    async fn open_channel_finalize(
        &self,
        request: Request<OpenChannelFinalizeRequest>,
    ) -> Result<Response<OpenChannelFinalizeResponse>, Status> {
        let tenant_id = Auth::authenticate(self.pool.raw(), &request).await?;
        let req = request.into_inner();

        if req.temp_channel_id.len() != 32 {
            return Err(Status::invalid_argument("temp_channel_id must be 32 bytes"));
        }
        let mut tcid = [0u8; 32];
        tcid.copy_from_slice(&req.temp_channel_id);
        let temp_channel_id = lightning::ln::types::ChannelId(tcid);

        let peer_bytes = hex::decode(&req.peer_pubkey_hex)
            .map_err(|_| Status::invalid_argument("peer_pubkey_hex is not valid hex"))?;
        let peer = bitcoin::secp256k1::PublicKey::from_slice(&peer_bytes).map_err(|_| {
            Status::invalid_argument("peer_pubkey_hex is not a valid secp256k1 key")
        })?;

        let tx_bytes = hex::decode(&req.funding_tx_hex)
            .map_err(|_| Status::invalid_argument("funding_tx_hex is not valid hex"))?;
        let funding_tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&tx_bytes).map_err(|e| {
                Status::invalid_argument(format!("funding_tx_hex is not a valid bitcoin tx: {e}"))
            })?;

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(
                tenant_id,
                NodeCmd::OpenChannelFinalize {
                    temp_channel_id,
                    counterparty: peer,
                    funding_tx,
                    resp: tx,
                },
            )
            .await
            .map_err(dispatch_error_to_status)?;

        rx.await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(OpenChannelFinalizeResponse {}))
    }

    async fn list_channels(
        &self,
        request: Request<ListChannelsRequest>,
    ) -> Result<Response<ListChannelsResponse>, Status> {
        let tenant_id = Auth::authenticate(self.pool.raw(), &request).await?;

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(tenant_id, NodeCmd::ListChannels { resp: tx })
            .await
            .map_err(dispatch_error_to_status)?;

        let channels = rx
            .await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        let channels = channels
            .into_iter()
            .map(|c| PbChannelSummary {
                channel_id: c.channel_id,
                counterparty_pubkey_hex: hex::encode(c.counterparty.serialize()),
                capacity_sat: c.capacity_sat,
                outbound_capacity_msat: c.outbound_capacity_msat,
                inbound_capacity_msat: c.inbound_capacity_msat,
                is_usable: c.is_usable,
            })
            .collect();

        Ok(Response::new(ListChannelsResponse { channels }))
    }

    async fn get_lsp_info(
        &self,
        _request: Request<GetLspInfoRequest>,
    ) -> Result<Response<GetLspInfoResponse>, Status> {
        // Public RPC — no auth gate. SDK clients call this before
        // registering so they can connect their tenant Node to the LSP.
        //
        // `ready` is sourced from the live daemon slot when present:
        // the operator's SDK fills the slot via `RegisterLspIdentity`,
        // so `ready=true` exactly when an identity has been registered
        // and the daemon is built.
        let resp = match &self.lsp_info {
            Some(info) => {
                let ready = match &self.lsp_daemon_slot {
                    Some(slot) => slot.read().await.is_some(),
                    None => false,
                };
                GetLspInfoResponse {
                    lsp_pubkey_hex: hex::encode(info.pubkey.serialize()),
                    lsp_address: info.address.clone(),
                    ready,
                }
            }
            None => GetLspInfoResponse::default(),
        };
        Ok(Response::new(resp))
    }

    async fn lsps2_get_info(
        &self,
        request: Request<Lsps2GetInfoRequest>,
    ) -> Result<Response<Lsps2GetInfoResponse>, Status> {
        let tenant_id = Auth::authenticate(self.pool.raw(), &request).await?;
        let req = request.into_inner();

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(
                tenant_id,
                NodeCmd::Lsps2GetInfo {
                    amount_msat: req.amount_msat,
                    resp: tx,
                },
            )
            .await
            .map_err(dispatch_error_to_status)?;

        let quote = rx
            .await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Lsps2GetInfoResponse {
            lsp_pubkey_hex: hex::encode(quote.lsp_pubkey.serialize()),
            min_fee_msat: quote.min_fee_msat,
            proportional_ppm: quote.proportional_ppm,
            min_payment_size_msat: quote.min_payment_size_msat,
            max_payment_size_msat: quote.max_payment_size_msat,
            valid_until_unix: quote.valid_until_unix,
        }))
    }

    async fn get_jit_invoice(
        &self,
        request: Request<GetJitInvoiceRequest>,
    ) -> Result<Response<GetJitInvoiceResponse>, Status> {
        let tenant_id = Auth::authenticate(self.pool.raw(), &request).await?;
        let req = request.into_inner();

        if req.amount_msat == 0 {
            return Err(Status::invalid_argument(
                "amount_msat is required and must be > 0 for JIT invoices",
            ));
        }

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(
                tenant_id,
                NodeCmd::GetJitInvoice {
                    amount_msat: req.amount_msat,
                    memo: req.memo,
                    resp: tx,
                },
            )
            .await
            .map_err(dispatch_error_to_status)?;

        let invoice = rx
            .await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetJitInvoiceResponse {
            bolt11: invoice.bolt11,
            payment_hash: invoice.payment_hash.to_vec(),
            jit_fee_msat_quote: invoice.jit_fee_msat_quote,
            lsp_pubkey_hex: hex::encode(invoice.lsp_pubkey.serialize()),
        }))
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

    // ── Signature-challenge unit tests (D5 / gotcha #509) ───────────────────
    //
    // The full create_tenant path needs a Postgres pool, so we exercise the
    // signature-verification half via the pure helper. Nonce TTL/replay
    // semantics are covered alongside `NonceStore` in `nonce_store::tests`.

    fn signing_keypair() -> (
        bitcoin::secp256k1::SecretKey,
        bitcoin::secp256k1::PublicKey,
    ) {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        // Deterministic for repeatability — non-trivial scalar.
        let sk = SecretKey::from_slice(&[0x42u8; 32]).expect("valid scalar");
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        (sk, pk)
    }

    fn sign_for_test(sk: &bitcoin::secp256k1::SecretKey, nonce: &[u8]) -> Vec<u8> {
        use bitcoin::secp256k1::{Message, Secp256k1};
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(REGISTER_DOMAIN);
        hasher.update(nonce);
        let digest = hasher.finalize();
        let msg = Message::from_digest_slice(digest.as_ref()).unwrap();
        Secp256k1::signing_only()
            .sign_ecdsa(&msg, sk)
            .serialize_der()
            .to_vec()
    }

    #[test]
    fn verify_register_signature_accepts_valid_sig() {
        let (sk, pk) = signing_keypair();
        let nonce = vec![7u8; 32];
        let sig = sign_for_test(&sk, &nonce);
        assert!(verify_register_signature(&pk, &nonce, &sig).is_ok());
    }

    #[test]
    fn verify_register_signature_rejects_wrong_sig_for_pubkey() {
        let (_sk, pk) = signing_keypair();
        // Signature produced by a *different* key over the same nonce.
        let other_sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let nonce = vec![7u8; 32];
        let sig = sign_for_test(&other_sk, &nonce);
        assert!(verify_register_signature(&pk, &nonce, &sig).is_err());
    }

    #[test]
    fn verify_register_signature_rejects_sig_over_different_nonce() {
        let (sk, pk) = signing_keypair();
        let nonce = vec![7u8; 32];
        let other_nonce = vec![8u8; 32];
        let sig = sign_for_test(&sk, &other_nonce);
        assert!(verify_register_signature(&pk, &nonce, &sig).is_err());
    }

    #[test]
    fn verify_register_signature_rejects_garbage_signature_bytes() {
        let (_sk, pk) = signing_keypair();
        let nonce = vec![7u8; 32];
        // Not even valid DER — must be rejected before any curve work.
        assert!(verify_register_signature(&pk, &nonce, &[0u8; 8]).is_err());
        // Empty signature also rejected.
        assert!(verify_register_signature(&pk, &nonce, &[]).is_err());
    }
}

// ── AdminService ──────────────────────────────────────────────────────────────
//
// Operator-scoped RPCs gated behind a shared admin secret. Slice 3.3a
// implementation; macaroon scope plumbing arrives in 3.3c.

/// Implements the operator-side admin gRPC.
///
/// Holds:
/// - The pre-registration `LspBuilder` (constructed at boot from the
///   `[lsp]` config).
/// - The `Arc<RwLock<Option<LspDaemon>>>` slot the registered daemon
///   lands into.
/// - The expected LSP pubkey from `[lsp].pubkey_hex` config (used to
///   validate that the operator's seed matches the published public
///   key) — `None` skips validation.
/// - The shared admin secret used to gate every method.
#[derive(Clone)]
pub struct WickAdminGrpcService {
    pub(crate) lsp_builder: Arc<LspBuilder>,
    pub(crate) lsp_daemon_slot: Arc<RwLock<Option<LspDaemon>>>,
    pub(crate) expected_lsp_pubkey: Option<bitcoin::secp256k1::PublicKey>,
    pub(crate) admin_secret: String,
}

impl std::fmt::Debug for WickAdminGrpcService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WickAdminGrpcService")
            .field("expected_lsp_pubkey", &self.expected_lsp_pubkey)
            .finish_non_exhaustive()
    }
}

impl WickAdminGrpcService {
    /// Construct a new admin service.
    #[must_use]
    pub fn new(
        lsp_builder: Arc<LspBuilder>,
        lsp_daemon_slot: Arc<RwLock<Option<LspDaemon>>>,
        expected_lsp_pubkey: Option<bitcoin::secp256k1::PublicKey>,
        admin_secret: String,
    ) -> Self {
        Self {
            lsp_builder,
            lsp_daemon_slot,
            expected_lsp_pubkey,
            admin_secret,
        }
    }

    /// Reject the request unless the `x-wick-admin-secret` metadata
    /// matches the configured shared secret.
    fn authorize<T>(&self, req: &Request<T>) -> Result<(), Status> {
        let presented = req
            .metadata()
            .get(ADMIN_SECRET_METADATA)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let rhs = self.admin_secret.as_bytes();
        if rhs.is_empty() {
            return Err(Status::unauthenticated("admin secret not configured"));
        }
        if presented.as_bytes().ct_eq(rhs).into() {
            Ok(())
        } else {
            Err(Status::unauthenticated("admin secret missing or invalid"))
        }
    }
}

#[tonic::async_trait]
impl AdminService for WickAdminGrpcService {
    async fn register_lsp_identity(
        &self,
        request: Request<RegisterLspIdentityRequest>,
    ) -> Result<Response<RegisterLspIdentityResponse>, Status> {
        self.authorize(&request)?;
        let req = request.into_inner();

        if req.lightning_seed.len() != 32 {
            return Err(Status::invalid_argument(
                "lightning_seed must be exactly 32 bytes",
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&req.lightning_seed);

        // Idempotency: if a daemon is already registered, return its
        // pubkey. Re-registering with the same seed → the same pubkey,
        // so callers retrying after a network blip get a no-op success.
        // Re-registering with a different seed is rejected — channel
        // state would be stranded.
        {
            let slot = self.lsp_daemon_slot.read().await;
            if let Some(daemon) = slot.as_ref() {
                return Ok(Response::new(RegisterLspIdentityResponse {
                    lsp_pubkey_hex: hex::encode(daemon.pubkey.serialize()),
                    ready: true,
                }));
            }
        }

        let daemon = self
            .lsp_builder
            .build_with_seed(seed)
            .await
            .map_err(|e| Status::internal(format!("build LSP daemon: {e}")))?;

        // Validate pubkey against the operator's published value if
        // configured — protects against accidentally registering the
        // wrong seed against this server.
        if let Some(expected) = self.expected_lsp_pubkey {
            if daemon.pubkey != expected {
                return Err(Status::failed_precondition(format!(
                    "registered seed derived pubkey {} does not match \
                     configured [lsp].pubkey_hex {}",
                    daemon.pubkey, expected
                )));
            }
        }

        let pubkey_hex = hex::encode(daemon.pubkey.serialize());
        let mut slot = self.lsp_daemon_slot.write().await;
        // Re-check under the write lock in case another caller raced.
        if slot.is_some() {
            // Another concurrent register won — drop our build (the
            // daemon's `Drop` aborts the event-pump task). Re-emit the
            // existing daemon's pubkey for idempotency.
            let existing_pubkey = slot
                .as_ref()
                .map(|d| hex::encode(d.pubkey.serialize()))
                .unwrap_or_default();
            // Best-effort shutdown of the duplicate we just built.
            tokio::spawn(async move { daemon.shutdown().await });
            return Ok(Response::new(RegisterLspIdentityResponse {
                lsp_pubkey_hex: existing_pubkey,
                ready: true,
            }));
        }
        *slot = Some(daemon);

        Ok(Response::new(RegisterLspIdentityResponse {
            lsp_pubkey_hex: pubkey_hex,
            ready: true,
        }))
    }

    type LspWatchPendingFundingStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<LspPendingFunding, Status>> + Send>>;

    async fn lsp_watch_pending_funding(
        &self,
        request: Request<LspWatchPendingFundingRequest>,
    ) -> Result<Response<Self::LspWatchPendingFundingStream>, Status> {
        self.authorize(&request)?;

        // Subscribe under the slot read lock so we don't race a fresh
        // `park` between snapshot and subscribe.
        let slot = self.lsp_daemon_slot.read().await;
        let daemon = slot
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("LSP not registered"))?;
        let mut rx = daemon.typed_node.funding_registry_subscribe();
        let snapshot = daemon.typed_node.funding_registry_snapshot();
        drop(slot);

        let (tx, output_rx) = mpsc::channel::<Result<LspPendingFunding, Status>>(64);

        // Bootstrap: replay every currently-parked entry so the operator
        // can drain anything that landed before they connected.
        for (temp_id, pending) in snapshot {
            let msg = LspPendingFunding {
                temp_channel_id: temp_id.0.to_vec(),
                counterparty_pubkey_hex: hex::encode(pending.counterparty.serialize()),
                value_sat: pending.value_sat,
                output_script_hex: hex::encode(pending.output_script.as_bytes()),
            };
            if tx.send(Ok(msg)).await.is_err() {
                // Client disconnected during bootstrap — silently exit.
                return Ok(Response::new(Box::pin(ReceiverStream::new(output_rx))));
            }
        }

        // Live tail: forward broadcast events until the operator
        // disconnects or the LSP daemon shuts down.
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok((temp_id, pending)) => {
                        let msg = LspPendingFunding {
                            temp_channel_id: temp_id.0.to_vec(),
                            counterparty_pubkey_hex: hex::encode(pending.counterparty.serialize()),
                            value_sat: pending.value_sat,
                            output_script_hex: hex::encode(pending.output_script.as_bytes()),
                        };
                        if tx.send(Ok(msg)).await.is_err() {
                            return; // operator disconnected
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // Operator fell behind — surface as a non-fatal
                        // status so the client can re-prime via a fresh
                        // subscribe + snapshot. Continue listening.
                        let _ = tx
                            .send(Err(Status::data_loss(format!(
                                "lsp watch lagged by {n} events; re-subscribe to re-prime"
                            ))))
                            .await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        // Daemon shut down. End the stream cleanly.
                        return;
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(output_rx))))
    }

    async fn lsp_finalize_funding(
        &self,
        request: Request<LspFinalizeFundingRequest>,
    ) -> Result<Response<LspFinalizeFundingResponse>, Status> {
        self.authorize(&request)?;
        let req = request.into_inner();

        if req.temp_channel_id.len() != 32 {
            return Err(Status::invalid_argument("temp_channel_id must be 32 bytes"));
        }
        let mut tcid = [0u8; 32];
        tcid.copy_from_slice(&req.temp_channel_id);
        let temp_channel_id = lightning::ln::types::ChannelId(tcid);

        let counterparty_bytes = hex::decode(&req.counterparty_pubkey_hex)
            .map_err(|_| Status::invalid_argument("counterparty_pubkey_hex is not valid hex"))?;
        let counterparty =
            bitcoin::secp256k1::PublicKey::from_slice(&counterparty_bytes).map_err(|_| {
                Status::invalid_argument("counterparty_pubkey_hex is not a valid secp256k1 key")
            })?;

        let tx_bytes = hex::decode(&req.funding_tx_hex)
            .map_err(|_| Status::invalid_argument("funding_tx_hex is not valid hex"))?;
        let funding_tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&tx_bytes).map_err(|e| {
                Status::invalid_argument(format!("funding_tx_hex is not a valid bitcoin tx: {e}"))
            })?;

        let slot = self.lsp_daemon_slot.read().await;
        let daemon = slot
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("LSP not registered"))?;

        // Drain the parked entry from the registry so it isn't
        // re-yielded to a future watcher. A `None` here means either
        // (a) the operator finalized for an unknown temp_id (client
        // bug), or (b) the entry was already drained by a concurrent
        // finalize. Surface as not_found.
        let _drained = daemon.typed_node.funding_registry_try_take(temp_channel_id);
        if _drained.is_none() {
            return Err(Status::not_found(
                "no parked funding entry for the supplied temp_channel_id",
            ));
        }

        // Hand the signed tx to LDK via the existing wrapped method
        // (also used by tenant `OpenChannelFinalize`).
        daemon
            .node
            .open_channel_finalize(&temp_channel_id, &counterparty, funding_tx)
            .await
            .map_err(|e| Status::internal(format!("funding_transaction_generated: {e}")))?;

        Ok(Response::new(LspFinalizeFundingResponse {}))
    }
}
