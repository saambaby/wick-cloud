//! gRPC bidi handler for the Phase-4 remote signer.
//!
//! `WickSignerGrpcService::attach` authenticates the SDK against the
//! tenant's bearer token, registers the SDK side of the stream into the
//! shared [`SignerSessionRegistry`] under the tenant's `context_id`, and
//! pumps frames in both directions:
//!
//! - server-originated `OutboundSignerFrame::VlsBinaryCall` → `SignerOutbound`
//! - SDK-originated `SignerInbound { vls_response }` → [`SignerConnection::resolve_response`]
//!
//! Reconnect: most-recent-wins via [`SignerSessionRegistry::register`]; the
//! prior session is closed and its in-flight calls fail with `signer
//! session replaced`. Disconnect: on stream end the session's pending
//! calls fail with `signer session disconnected`.

use std::pin::Pin;
use std::sync::Arc;

use futures::StreamExt;
use prost::Message as _;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use wick_core::TenantId;
use wick_noise::{NoiseFrame, NoisePublicKey, NoiseResponder, NoiseSession, NoiseStaticKeypair};
use wick_proto::wick::{
    signer_inbound, signer_outbound, signer_service_server::SignerService, AttachInner,
    SignerInbound, SignerOutbound,
};
use wick_vls::{OutboundSignerFrame, SignerSessionRegistry};

use crate::auth::Auth;
use crate::macaroon_auth::MacaroonAuth;

/// Resolve an extracted bearer token to its tenant_id. Same lookup logic as
/// [`crate::auth::Auth::authenticate`], but without holding a borrowed
/// non-Sync `Request<Streaming<_>>` across the await.
async fn authenticate_token(pool: &PgPool, raw_token: &str) -> Result<TenantId, Status> {
    let raw_bytes = hex::decode(raw_token)
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

/// Look up the tenant's registered Noise static public key. `Ok(None)`
/// means the tenant pre-dates N2 (or registered before the SDK was
/// updated) and should be served via the legacy bearer attach path.
async fn load_tenant_noise_pk(
    pool: &PgPool,
    tenant_id: TenantId,
) -> Result<Option<[u8; 32]>, Status> {
    let row: Option<(Option<Vec<u8>>,)> =
        sqlx::query_as("SELECT noise_static_pk FROM global.wallets WHERE id = $1")
            .bind(tenant_id.as_uuid())
            .fetch_optional(pool)
            .await
            .map_err(|_| Status::internal("noise pk lookup failed"))?;
    Ok(row.and_then(|(opt,)| opt).and_then(|bytes| {
        if bytes.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Some(out)
        } else {
            None
        }
    }))
}

/// Outbound stream item type alias — the trait demands a fully-named type.
pub type AttachStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<SignerOutbound, Status>> + Send>>;

/// Bidi-stream signer endpoint. Owns nothing tenant-specific — every
/// session is resolved at request time through the shared
/// [`SignerSessionRegistry`].
pub struct WickSignerGrpcService {
    pool: PgPool,
    registry: Arc<SignerSessionRegistry>,
    /// Phase-4 D1 N2 — server's Noise_KK static keypair. When `Some`,
    /// the server consults `global.wallets.noise_static_pk` for each
    /// attaching tenant; tenants with a registered pk ride the
    /// encrypted lane (with macaroon-with-pk verification per frame).
    /// Tenants whose row carries `NULL` log a warning and fall through
    /// to the legacy bearer-only path.
    noise_keypair: Option<NoiseStaticKeypair>,
    /// Macaroon auth surface — required to re-verify the macaroon on
    /// every inner `AttachInner` envelope. `None` matches the legacy
    /// no-macaroon deployment (no Noise either).
    macaroon_auth: Option<MacaroonAuth>,
}

impl std::fmt::Debug for WickSignerGrpcService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WickSignerGrpcService").finish_non_exhaustive()
    }
}

impl WickSignerGrpcService {
    #[must_use]
    pub fn new(pool: PgPool, registry: Arc<SignerSessionRegistry>) -> Self {
        Self {
            pool,
            registry,
            noise_keypair: None,
            macaroon_auth: None,
        }
    }

    /// Enable the Phase-4 D1 N2 Noise_KK tunnel. `noise_keypair` is the
    /// server's static keypair (loaded from operator config — see
    /// `wick_noise::derive_noise_static` if deriving from a seed) and
    /// `macaroon_auth` is required to verify the inner per-frame
    /// macaroon. Tenants without a registered `noise_static_pk` still
    /// flow through the legacy bearer path.
    #[must_use]
    pub fn with_noise(
        mut self,
        noise_keypair: NoiseStaticKeypair,
        macaroon_auth: MacaroonAuth,
    ) -> Self {
        self.noise_keypair = Some(noise_keypair);
        self.macaroon_auth = Some(macaroon_auth);
        self
    }
}

#[tonic::async_trait]
impl SignerService for WickSignerGrpcService {
    type AttachStream = AttachStream;

    async fn attach(
        &self,
        request: Request<Streaming<SignerInbound>>,
    ) -> Result<Response<Self::AttachStream>, Status> {
        // `Streaming<T>` is not `Sync`, so we can't hold `&Request<...>`
        // across an await for `Auth::authenticate`. Extract the bearer
        // synchronously, then run the DB lookup over an owned token.
        let raw_token = Auth::extract_bearer(&request)?;
        let tenant_id = authenticate_token(&self.pool, &raw_token).await?;
        let context_id = tenant_id.to_string();
        let mut inbound = request.into_inner();

        // Phase-4 D1 N2 — decide whether to wrap this stream in the
        // Noise_KK tunnel. The gate is "server has a static keypair AND
        // the tenant registered a Noise pk during CreateTenant". Tenants
        // missing a registered pk drop to the legacy bearer path with a
        // warning — phase-out plan: once every active tenant has a pk
        // (operator dashboard sweep), the warning becomes a hard reject.
        let tenant_noise_pk = if self.noise_keypair.is_some() {
            load_tenant_noise_pk(&self.pool, tenant_id).await?
        } else {
            None
        };
        let mut responder: Option<NoiseResponder> = if let (Some(kp), Some(pk)) =
            (self.noise_keypair.as_ref(), tenant_noise_pk)
        {
            let initiator_pk = NoisePublicKey(pk);
            match NoiseResponder::new(kp.clone(), initiator_pk) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(
                        target: "wick_server::signer",
                        context_id = %context_id,
                        %e,
                        "noise responder construction failed"
                    );
                    return Err(Status::internal("noise setup failed"));
                }
            }
        } else {
            if self.noise_keypair.is_some() && tenant_noise_pk.is_none() {
                tracing::warn!(
                    target: "wick_server::signer",
                    context_id = %context_id,
                    "tenant without noise_static_pk — legacy bearer fallback"
                );
            }
            None
        };

        // mpsc shared between the registry (producer of OutboundSignerFrame
        // via `SignerConnection::dispatch_*_call`) and the gRPC outbound
        // stream (consumer mapping each frame to a `SignerOutbound`).
        let (registry_tx, mut registry_rx) =
            mpsc::channel::<OutboundSignerFrame>(crate::OUTBOUND_FRAME_CAPACITY);

        let conn = self.registry.register(context_id.clone(), registry_tx);
        let session_token = conn.session_token();
        if !conn.activate() {
            return Err(Status::aborted("signer session retired before activation"));
        }

        let (outbound_tx, outbound_rx) =
            mpsc::channel::<Result<SignerOutbound, Status>>(crate::OUTBOUND_FRAME_CAPACITY);

        // If the tunnel is active, drive the KK handshake before either
        // background pump task starts. The SDK sends frame 1 first.
        let observed_static_pk: Option<[u8; 32]>;
        // Shared state between inbound + outbound tasks for the encrypted
        // path: the responder must be the same instance on both sides so
        // ratcheted keys stay in lockstep. We wrap in `Arc<tokio::Mutex>`.
        let noise_state: Option<Arc<tokio::sync::Mutex<NoiseResponder>>>;
        if let Some(ref mut r) = responder {
            // Read first handshake frame from SDK.
            let frame1 = match inbound.next().await {
                Some(Ok(m)) => m,
                Some(Err(e)) => return Err(Status::unauthenticated(format!("handshake stream error: {e}"))),
                None => return Err(Status::unauthenticated("handshake stream ended early")),
            };
            let Some(signer_inbound::Kind::NoiseFrame(bytes)) = frame1.kind else {
                return Err(Status::unauthenticated("first frame must be NoiseFrame"));
            };
            let _ = r
                .read(&bytes)
                .map_err(|e| Status::unauthenticated(format!("noise read(1): {e}")))?;
            // Write responder reply.
            let reply = r
                .write(&[])
                .map_err(|e| Status::unauthenticated(format!("noise write(2): {e}")))?;
            if outbound_tx
                .send(Ok(SignerOutbound {
                    kind: Some(signer_outbound::Kind::NoiseFrame(reply)),
                }))
                .await
                .is_err()
            {
                return Err(Status::aborted("client dropped during handshake"));
            }
            if !r.is_handshake_complete() {
                return Err(Status::unauthenticated("noise handshake did not complete"));
            }
            observed_static_pk = r.remote_static().map(|p| p.0);
            noise_state = Some(Arc::new(tokio::sync::Mutex::new(responder.take().unwrap())));
        } else {
            observed_static_pk = None;
            noise_state = None;
        }

        // Outbound pump: drain registry_rx → SignerOutbound. When the
        // tunnel is active, wrap each VLS call in `AttachInner` and
        // encrypt; otherwise pass through as the legacy `vls_call` lane.
        let noise_state_out = noise_state.clone();
        tokio::spawn(async move {
            let mut tx_seq: u64 = 0;
            while let Some(frame) = registry_rx.recv().await {
                let encoded = match frame {
                    OutboundSignerFrame::VlsBinaryCall { encoded, .. } => encoded,
                    OutboundSignerFrame::StateSync { .. } | OutboundSignerFrame::Ping => continue,
                };
                let msg = if let Some(ns) = noise_state_out.as_ref() {
                    tx_seq = tx_seq.saturating_add(1);
                    let inner = AttachInner {
                        macaroon: Vec::new(),
                        vls_payload: encoded,
                        seq: tx_seq,
                    };
                    let mut buf = Vec::with_capacity(inner.encoded_len());
                    if inner.encode(&mut buf).is_err() {
                        continue;
                    }
                    let ct = {
                        let mut guard = ns.lock().await;
                        match guard.write(&buf) {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::warn!(target: "wick_server::signer", %e, "noise encrypt failed");
                                return;
                            }
                        }
                    };
                    SignerOutbound {
                        kind: Some(signer_outbound::Kind::NoiseFrame(ct)),
                    }
                } else {
                    SignerOutbound {
                        kind: Some(signer_outbound::Kind::VlsCall(encoded)),
                    }
                };
                if outbound_tx.send(Ok(msg)).await.is_err() {
                    return;
                }
            }
        });

        // Inbound pump.
        let registry = Arc::clone(&self.registry);
        let context_for_inbound = context_id.clone();
        let noise_state_in = noise_state.clone();
        let macaroon_auth = self.macaroon_auth.clone();
        tokio::spawn(async move {
            let mut rx_seq: u64 = 0;
            while let Some(item) = inbound.next().await {
                match item {
                    Ok(msg) => {
                        let response_bytes: Option<Vec<u8>> =
                            match (msg.kind, noise_state_in.as_ref()) {
                                (Some(signer_inbound::Kind::NoiseFrame(ct)), Some(ns)) => {
                                    let pt = {
                                        let mut guard = ns.lock().await;
                                        match guard.read(&ct) {
                                            Ok(NoiseFrame::Plaintext(p)) => p,
                                            Ok(_) => {
                                                tracing::warn!(
                                                    target: "wick_server::signer",
                                                    "unexpected noise frame post-handshake"
                                                );
                                                break;
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    target: "wick_server::signer",
                                                    %e,
                                                    "noise decrypt failed"
                                                );
                                                break;
                                            }
                                        }
                                    };
                                    let inner = match AttachInner::decode(pt.as_slice()) {
                                        Ok(i) => i,
                                        Err(e) => {
                                            tracing::warn!(
                                                target: "wick_server::signer",
                                                %e,
                                                "AttachInner decode failed"
                                            );
                                            break;
                                        }
                                    };
                                    rx_seq = rx_seq.saturating_add(1);
                                    if inner.seq != rx_seq {
                                        tracing::warn!(
                                            target: "wick_server::signer",
                                            expected = rx_seq,
                                            got = inner.seq,
                                            "AttachInner seq mismatch"
                                        );
                                        break;
                                    }
                                    // Re-verify the macaroon against the
                                    // tunneled observed pk on every frame.
                                    if let (Some(auth), Some(pk)) =
                                        (macaroon_auth.as_ref(), observed_static_pk)
                                    {
                                        if !inner.macaroon.is_empty() {
                                            if let Err(e) = auth
                                                .authenticate_macaroon_bytes_with_pk(
                                                    &inner.macaroon,
                                                    Some(pk),
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    target: "wick_server::signer",
                                                    %e,
                                                    "AttachInner macaroon verify failed"
                                                );
                                                break;
                                            }
                                        }
                                    }
                                    Some(inner.vls_payload)
                                }
                                (Some(signer_inbound::Kind::VlsResponse(bytes)), None) => {
                                    Some(bytes)
                                }
                                (Some(signer_inbound::Kind::NoiseFrame(_)), None) => {
                                    tracing::warn!(
                                        target: "wick_server::signer",
                                        "received NoiseFrame on legacy attach — dropping"
                                    );
                                    None
                                }
                                (Some(signer_inbound::Kind::VlsResponse(_)), Some(_)) => {
                                    tracing::warn!(
                                        target: "wick_server::signer",
                                        "received plaintext VlsResponse on encrypted attach — dropping"
                                    );
                                    None
                                }
                                (None, _) => {
                                    tracing::warn!(
                                        target: "wick_server::signer",
                                        context_id = %context_for_inbound,
                                        "SignerInbound with empty kind — dropping"
                                    );
                                    None
                                }
                            };
                        if let Some(bytes) = response_bytes {
                            if let Some(c) = registry.get(&context_for_inbound) {
                                if c.session_token() == session_token {
                                    c.resolve_response(bytes);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::info!(
                            target: "wick_server::signer",
                            context_id = %context_for_inbound,
                            session_token,
                            %e,
                            "signer stream errored — closing"
                        );
                        break;
                    }
                }
            }
            registry.unregister(&context_for_inbound, session_token);
            tracing::debug!(
                target: "wick_server::signer",
                context_id = %context_for_inbound,
                session_token,
                "signer session detached"
            );
        });

        Ok(Response::new(
            Box::pin(ReceiverStream::new(outbound_rx)) as AttachStream
        ))
    }
}
