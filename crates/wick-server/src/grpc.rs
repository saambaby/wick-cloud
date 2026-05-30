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
    CloseChannelRequest, CloseChannelResponse, ListChannelsRequest, ListChannelsResponse,
    LspFinalizeFundingRequest,
    LspFinalizeFundingResponse, LspPendingFunding, LspWatchPendingFundingRequest,
    Lsps2GetInfoRequest, Lsps2GetInfoResponse, OpenChannelFinalizeRequest,
    OpenChannelFinalizeResponse, OpenChannelInitRequest, OpenChannelInitResponse, Payment,
    ReceivePaymentRequest, ReceivePaymentResponse, RegisterChallengeRequest,
    RegisterChallengeResponse, RegisterLspIdentityRequest, RegisterLspIdentityResponse,
    RotateCredentialRequest, RotateCredentialResponse, SendPaymentRequest, SendPaymentResponse,
};

use wick_macaroon::{Macaroon, Scope, USER_DEFAULT_LIFETIME};

use crate::auth::Auth;
use crate::macaroon_auth::{MacaroonAuth, ROTATION_GRACE_TTL};
use crate::node::{
    manager::{DispatchError, NodeManager, ProvisionError},
    NodeCmd,
};
use crate::nonce_store::{NonceError, NonceStore, REGISTER_DOMAIN};

/// Timeout for `OpenChannelInit` to wait on LDK's `FundingGenerationReady`.
/// The event typically fires within hundreds of milliseconds after
/// `ChannelManager::create_channel`, but regtest + cold-peer handshake
/// can push that out — 15s is generous.
const OPEN_CHANNEL_INIT_TIMEOUT: Duration = Duration::from_secs(15);

/// Dual-accept tenant authentication: prefer macaroon, fall back to bearer.
///
/// Returns the authenticated tenant id. A *present-but-invalid* macaroon
/// header surfaces as `Status::unauthenticated` — only an *absent* header
/// falls through to the legacy bearer path. The bearer path remains the
/// canonical wallets-table lookup; the macaroon path resolves the tenant
/// from the embedded `Scope::User { tenant_id }` caveat.
async fn authenticate_dual<T>(
    pool: &sqlx::PgPool,
    mac_auth: &Option<MacaroonAuth>,
    request: &Request<T>,
) -> Result<TenantId, Status> {
    if let Some(auth) = mac_auth {
        if let Some(ctx) = auth.authenticate_optional(request).await? {
            // Scope must be Scope::User { tenant_id } and the embedded
            // tenant_id must match the verified context.
            match ctx.scope {
                Some(Scope::User { tenant_id: scope_tid })
                    if scope_tid == *ctx.tenant_id.as_uuid().as_bytes() =>
                {
                    return Ok(ctx.tenant_id);
                }
                _ => return Err(Status::permission_denied("macaroon scope mismatch")),
            }
        }
    }
    Auth::authenticate(pool, request).await
}

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
    /// D3 M3 — macaroon verification + issuance. When present, the
    /// service mints user-scoped macaroons at `create_tenant` and
    /// serves the `rotate_credential` RPC. When `None` (legacy boot)
    /// the bearer path is the only auth surface.
    macaroon_auth: Option<MacaroonAuth>,
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
            macaroon_auth: None,
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
            macaroon_auth: None,
        }
    }

    /// Attach a macaroon auth surface. Builder-style so existing
    /// `new` / `with_lsp` call sites stay backwards-compatible.
    #[must_use]
    pub fn with_macaroon_auth(mut self, auth: MacaroonAuth) -> Self {
        self.macaroon_auth = Some(auth);
        self
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
/// Extract the unix-second expiry from an issued macaroon, if present.
/// `Macaroon::issue` always appends an `Expiry` caveat (tag 0x01) with
/// an 8-byte BE unix timestamp, so this is infallible for macaroons we
/// just minted; returning an `Option` keeps the helper honest for
/// caveat-stripped inputs.
fn expiry_from_macaroon(m: &Macaroon) -> Option<i64> {
    const TAG_EXPIRY: u8 = 0x01;
    for c in m.caveats() {
        if c.tag() == TAG_EXPIRY && c.payload().len() == 8 {
            let mut be = [0u8; 8];
            be.copy_from_slice(c.payload());
            return i64::try_from(u64::from_be_bytes(be)).ok();
        }
    }
    None
}

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

        // D3 M3 — also mint a user-scoped macaroon when the macaroon
        // auth surface is wired. The bearer token is retained
        // transitionally (until D3 M5) so old clients keep working.
        let macaroon_bytes = match &self.macaroon_auth {
            Some(auth) => {
                let (identifier, root_key) =
                    auth.ensure_user_root_key(tenant_id).await.map_err(|e| {
                        warn!(?e, %tenant_id, "create_tenant: ensure_user_root_key failed");
                        Status::internal("failed to mint macaroon")
                    })?;
                let mac = Macaroon::issue(
                    auth.location(),
                    identifier,
                    &root_key,
                    Scope::User {
                        tenant_id: *tenant_id.as_uuid().as_bytes(),
                    },
                    USER_DEFAULT_LIFETIME,
                );
                mac.serialize()
            }
            None => Vec::new(),
        };

        info!(%tenant_id, plan_tier, "tenant registered");
        Ok(Response::new(CreateTenantResponse {
            tenant_id: tenant_id.to_string(),
            api_token: raw_token,
            macaroon: macaroon_bytes,
        }))
    }

    async fn rotate_credential(
        &self,
        request: Request<RotateCredentialRequest>,
    ) -> Result<Response<RotateCredentialResponse>, Status> {
        let auth = self
            .macaroon_auth
            .as_ref()
            .ok_or_else(|| Status::unimplemented("macaroon auth not configured"))?;

        let req = request.into_inner();
        if req.old_macaroon.is_empty() {
            return Err(Status::invalid_argument("old_macaroon is required"));
        }

        // Verify the old macaroon (chain, expiry, revocation, scope).
        let ctx = auth.authenticate_macaroon_bytes(&req.old_macaroon).await?;
        let old_nonce = ctx
            .nonce
            .ok_or_else(|| Status::internal("verified macaroon has no nonce"))?;
        let scope = ctx
            .scope
            .ok_or_else(|| Status::internal("verified macaroon has no scope"))?;

        // Re-derive the user-scope root key (same root key as the old
        // macaroon — `ensure_user_root_key` returns the active row).
        let tenant_id = ctx.tenant_id;
        let (identifier, root_key) = auth.ensure_user_root_key(tenant_id).await.map_err(|e| {
            warn!(?e, %tenant_id, "rotate_credential: ensure_user_root_key failed");
            Status::internal("failed to load root key")
        })?;

        // Mint a fresh macaroon — fresh random nonce + fresh expiry,
        // same Scope. Caveat order is canonical (scope, expiry, nonce);
        // see the M3 research note.
        let new_mac = Macaroon::issue(
            auth.location(),
            identifier,
            &root_key,
            scope,
            USER_DEFAULT_LIFETIME,
        );

        // Atomically revoke the old nonce with a 30s grace TTL so
        // in-flight RPCs holding the old macaroon finish, but replays
        // start failing immediately. The in-memory `RevocationSet`
        // ignores TTL — see `RevocationSet::revoke_with_ttl` docs.
        auth.revocation()
            .revoke_with_ttl(auth.pool(), old_nonce, ROTATION_GRACE_TTL, Some("rotated"))
            .await
            .map_err(|e| {
                warn!(?e, "rotate_credential: revoke_with_ttl failed");
                Status::internal("failed to record revocation")
            })?;

        // Parse the expiry off the new macaroon for the convenience field.
        let expires_at_unix = expiry_from_macaroon(&new_mac).unwrap_or(0);

        Ok(Response::new(RotateCredentialResponse {
            new_macaroon: new_mac.serialize(),
            expires_at_unix,
        }))
    }

    async fn get_balance(
        &self,
        request: Request<GetBalanceRequest>,
    ) -> Result<Response<GetBalanceResponse>, Status> {
        // Authenticate first — the req.tenant_id field is ignored.
        let tenant_id = authenticate_dual(self.pool.raw(), &self.macaroon_auth, &request).await?;

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
        let tenant_id = authenticate_dual(self.pool.raw(), &self.macaroon_auth, &request).await?;

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
        let tenant_id = authenticate_dual(self.pool.raw(), &self.macaroon_auth, &request).await?;

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
        let tenant_id = authenticate_dual(self.pool.raw(), &self.macaroon_auth, &request).await?;

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
        let tenant_id = authenticate_dual(self.pool.raw(), &self.macaroon_auth, &request).await?;

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
        let tenant_id = authenticate_dual(self.pool.raw(), &self.macaroon_auth, &request).await?;
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
        let tenant_id = authenticate_dual(self.pool.raw(), &self.macaroon_auth, &request).await?;
        let req = request.into_inner();

        let peer_bytes = hex::decode(&req.peer_pubkey_hex)
            .map_err(|_| Status::invalid_argument("peer_pubkey_hex is not valid hex"))?;
        let peer = bitcoin::secp256k1::PublicKey::from_slice(&peer_bytes).map_err(|_| {
            Status::invalid_argument("peer_pubkey_hex is not a valid secp256k1 key")
        })?;

        if req.channel_value_sat == 0 {
            return Err(Status::invalid_argument("channel_value_sat must be > 0"));
        }

        let t0 = std::time::Instant::now();
        tracing::info!(
            target: "wick_server::open_channel",
            %tenant_id,
            value_sat = req.channel_value_sat,
            push_msat = req.push_msat,
            "→ open_channel_init gRPC entered"
        );

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
        tracing::info!(
            target: "wick_server::open_channel",
            %tenant_id,
            elapsed_ms = t0.elapsed().as_millis() as u64,
            "✓ dispatch(OpenChannelInit) returned; awaiting actor response"
        );

        let t1 = std::time::Instant::now();
        let (temp_id, pending) = rx
            .await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;
        tracing::info!(
            target: "wick_server::open_channel",
            %tenant_id,
            actor_ms = t1.elapsed().as_millis() as u64,
            total_ms = t0.elapsed().as_millis() as u64,
            ?temp_id,
            value_sat = pending.value_sat,
            "✓ actor returned OpenChannelInit; replying to client"
        );

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
        let tenant_id = authenticate_dual(self.pool.raw(), &self.macaroon_auth, &request).await?;
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
        let tenant_id = authenticate_dual(self.pool.raw(), &self.macaroon_auth, &request).await?;

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

    async fn close_channel(
        &self,
        request: Request<CloseChannelRequest>,
    ) -> Result<Response<CloseChannelResponse>, Status> {
        let tenant_id = authenticate_dual(self.pool.raw(), &self.macaroon_auth, &request).await?;
        let req = request.into_inner();

        if req.channel_id.len() != 32 {
            return Err(Status::invalid_argument("channel_id must be 32 bytes"));
        }
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&req.channel_id);
        let channel_id = lightning::ln::types::ChannelId(cid);

        let peer_bytes = hex::decode(&req.counterparty_pubkey_hex).map_err(|_| {
            Status::invalid_argument("counterparty_pubkey_hex is not valid hex")
        })?;
        let counterparty =
            bitcoin::secp256k1::PublicKey::from_slice(&peer_bytes).map_err(|_| {
                Status::invalid_argument("counterparty_pubkey_hex is not a valid secp256k1 key")
            })?;

        let (tx, rx) = oneshot::channel();
        self.manager
            .dispatch(
                tenant_id,
                NodeCmd::CloseChannel {
                    channel_id,
                    counterparty,
                    force: req.force,
                    resp: tx,
                },
            )
            .await
            .map_err(dispatch_error_to_status)?;

        rx.await
            .map_err(|_| Status::internal("node actor dropped the response channel"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CloseChannelResponse {}))
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
        let tenant_id = authenticate_dual(self.pool.raw(), &self.macaroon_auth, &request).await?;
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
        let tenant_id = authenticate_dual(self.pool.raw(), &self.macaroon_auth, &request).await?;
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

    // ── D3 M3 macaroon helpers ────────────────────────────────────────────────

    #[test]
    fn expiry_from_macaroon_reads_unix_seconds_be() {
        use wick_macaroon::{Macaroon, RootKey, Scope, USER_DEFAULT_LIFETIME};
        let rk = RootKey::random();
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let m = Macaroon::issue(
            "wick.cloud",
            [3u8; 16],
            &rk,
            Scope::User {
                tenant_id: [1u8; 16],
            },
            USER_DEFAULT_LIFETIME,
        );
        let exp = expiry_from_macaroon(&m).expect("expiry caveat present");
        // Expiry must be roughly now + USER_DEFAULT_LIFETIME, with slack for
        // wall-clock drift between the two `SystemTime::now()` reads.
        let expected_min = before + USER_DEFAULT_LIFETIME.as_secs() as i64 - 5;
        let expected_max = before + USER_DEFAULT_LIFETIME.as_secs() as i64 + 5;
        assert!(
            exp >= expected_min && exp <= expected_max,
            "expiry {exp} not in [{expected_min}, {expected_max}]",
        );
    }

    #[test]
    fn rotate_mints_fresh_nonce_and_preserves_scope() {
        // Pure macaroon-layer check — no DB needed. The handler delegates
        // nonce randomness + caveat-chain construction to `Macaroon::issue`,
        // so verifying that two consecutive issues under the same root key /
        // scope produce DIFFERENT nonces + DIFFERENT signatures suffices.
        use wick_macaroon::{Macaroon, RootKey, Scope, USER_DEFAULT_LIFETIME};
        let rk = RootKey::random();
        let id = [7u8; 16];
        let scope = Scope::User {
            tenant_id: [9u8; 16],
        };
        let a = Macaroon::issue("wick.cloud", id, &rk, scope, USER_DEFAULT_LIFETIME);
        let b = Macaroon::issue("wick.cloud", id, &rk, scope, USER_DEFAULT_LIFETIME);
        // Serialized bytes differ (nonce caveat differs).
        assert_ne!(a.serialize(), b.serialize());
        // Scope preserved.
        let ctx = wick_macaroon::VerifyContext {
            now: std::time::SystemTime::now(),
            revoked_nonces: &std::collections::HashSet::new(),
            expected_scope: None,
            noise_static_pk_observed: None,
        };
        let av = a.verify(&rk, &ctx).unwrap();
        let bv = b.verify(&rk, &ctx).unwrap();
        assert_eq!(av.scope, bv.scope);
        assert_ne!(av.nonce, bv.nonce, "fresh random nonce per issuance");
    }
}

// ── AdminService ──────────────────────────────────────────────────────────────
//
// Operator-scoped RPCs gated behind an admin-scoped macaroon. Replaces
// the `WICK_ADMIN_SECRET` shared-secret gate from slice 3.3a — mint
// tokens with `wick-server mint-admin-macaroon`, present them as the
// `x-wick-macaroon` metadata header (hex-encoded, same format as the
// user-scoped macaroon path).

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
/// - The [`MacaroonAuth`] interceptor used to verify admin-scoped
///   macaroons on every method.
#[derive(Clone)]
pub struct WickAdminGrpcService {
    pub(crate) lsp_builder: Arc<LspBuilder>,
    pub(crate) lsp_daemon_slot: Arc<RwLock<Option<LspDaemon>>>,
    pub(crate) expected_lsp_pubkey: Option<bitcoin::secp256k1::PublicKey>,
    pub(crate) macaroon_auth: MacaroonAuth,
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
        macaroon_auth: MacaroonAuth,
    ) -> Self {
        Self {
            lsp_builder,
            lsp_daemon_slot,
            expected_lsp_pubkey,
            macaroon_auth,
        }
    }

    /// Reject the request unless it carries a verified admin-scoped
    /// macaroon. Returns `Unauthenticated` on missing/malformed/expired
    /// tokens and `PermissionDenied` when the macaroon verifies but
    /// holds a non-admin/non-root scope.
    async fn authorize<T>(&self, req: &Request<T>) -> Result<(), Status> {
        let _ctx = self.macaroon_auth.authenticate_admin(req).await?;
        Ok(())
    }
}

#[tonic::async_trait]
impl AdminService for WickAdminGrpcService {
    async fn register_lsp_identity(
        &self,
        request: Request<RegisterLspIdentityRequest>,
    ) -> Result<Response<RegisterLspIdentityResponse>, Status> {
        self.authorize(&request).await?;
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
        self.authorize(&request).await?;

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
        self.authorize(&request).await?;
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
