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
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use wick_core::TenantId;
use wick_proto::wick::{
    signer_inbound, signer_outbound, signer_service_server::SignerService, SignerInbound,
    SignerOutbound,
};
use wick_vls::{OutboundSignerFrame, SignerSessionRegistry};

use crate::auth::Auth;

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

/// Outbound stream item type alias — the trait demands a fully-named type.
pub type AttachStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<SignerOutbound, Status>> + Send>>;

/// Bidi-stream signer endpoint. Owns nothing tenant-specific — every
/// session is resolved at request time through the shared
/// [`SignerSessionRegistry`].
pub struct WickSignerGrpcService {
    pool: PgPool,
    registry: Arc<SignerSessionRegistry>,
}

impl std::fmt::Debug for WickSignerGrpcService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WickSignerGrpcService").finish_non_exhaustive()
    }
}

impl WickSignerGrpcService {
    #[must_use]
    pub fn new(pool: PgPool, registry: Arc<SignerSessionRegistry>) -> Self {
        Self { pool, registry }
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

        // mpsc shared between the registry (producer of OutboundSignerFrame
        // via `SignerConnection::dispatch_*_call`) and the gRPC outbound
        // stream (consumer mapping each frame to a `SignerOutbound`).
        let (registry_tx, mut registry_rx) =
            mpsc::channel::<OutboundSignerFrame>(crate::OUTBOUND_FRAME_CAPACITY);

        let conn = self.registry.register(context_id.clone(), registry_tx);
        let session_token = conn.session_token();
        // Activate immediately. wick doesn't run a state-sync handshake yet
        // (channel watermarks land alongside multi-restart channel
        // restoration in a follow-up); the SDK is expected to honour the
        // commitment-number history it persists locally.
        if !conn.activate() {
            // The slot was retired between register() and here (extremely
            // unlikely — would mean a fresh attach took our slot already).
            // Surface as Aborted so the SDK can retry.
            return Err(Status::aborted("signer session retired before activation"));
        }

        // Outbound (server → SDK): drain registry_rx; map to SignerOutbound;
        // forward to client. Closes when the registry drops its sender
        // (which happens on `unregister`/`replace`).
        let (outbound_tx, outbound_rx) =
            mpsc::channel::<Result<SignerOutbound, Status>>(crate::OUTBOUND_FRAME_CAPACITY);
        tokio::spawn(async move {
            while let Some(frame) = registry_rx.recv().await {
                let msg = match frame {
                    OutboundSignerFrame::VlsBinaryCall { encoded, .. } => SignerOutbound {
                        kind: Some(signer_outbound::Kind::VlsCall(encoded)),
                    },
                    // Control frames are not yet wired into the proto envelope.
                    // They are dropped silently — the registry doesn't emit
                    // them today (only `VlsBinaryCall` is sent).
                    OutboundSignerFrame::StateSync { .. } | OutboundSignerFrame::Ping => {
                        continue;
                    }
                };
                if outbound_tx.send(Ok(msg)).await.is_err() {
                    return; // SDK disconnected
                }
            }
        });

        // Inbound (SDK → server): each `vls_response` payload routes to the
        // session's `resolve_response`. On stream end, unregister.
        let registry = Arc::clone(&self.registry);
        let context_for_inbound = context_id.clone();
        tokio::spawn(async move {
            while let Some(item) = inbound.next().await {
                match item {
                    Ok(msg) => match msg.kind {
                        Some(signer_inbound::Kind::VlsResponse(bytes)) => {
                            if let Some(c) = registry.get(&context_for_inbound) {
                                // Stale-stream guard: only resolve if this
                                // session is still the live one. If a fresh
                                // attach replaced us, c.session_token will
                                // differ — drop the response.
                                if c.session_token() == session_token {
                                    c.resolve_response(bytes);
                                }
                            }
                        }
                        None => {
                            tracing::warn!(
                                target: "wick_server::signer",
                                context_id = %context_for_inbound,
                                "SignerInbound with empty kind — dropping"
                            );
                        }
                    },
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
            // End of stream — only unregister if our session is still current.
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
