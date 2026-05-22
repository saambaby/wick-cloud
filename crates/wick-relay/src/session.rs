//! Per-connection handler: parse `?role=…&stream_id=…`, enforce the
//! per-IP rate limit before upgrading, pair with the peer via
//! [`crate::stream::StreamRegistry`], then pump frames opaquely.

use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request, Response,
};
use tokio_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, warn};

use crate::rate_limit::RateLimiter;
use crate::stream::{PendingSocket, StreamRegistry, MAX_FRAME_BYTES};

/// 4001 — protocol error close code, per spec.
const CLOSE_PROTOCOL_ERROR: u16 = 4001;

#[derive(Debug, Clone, Copy)]
enum Role {
    Initiator,
    Responder,
}

#[derive(Debug)]
struct ParsedQuery {
    role: Role,
    stream_id: Option<[u8; 16]>,
}

fn parse_query(uri: &str) -> Option<ParsedQuery> {
    // Extract the query string after `?`.
    let q = uri.split_once('?').map_or("", |(_, q)| q);
    let mut role: Option<Role> = None;
    let mut stream_id: Option<[u8; 16]> = None;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=')?;
        match k {
            "role" => {
                role = match v {
                    "initiator" => Some(Role::Initiator),
                    "responder" => Some(Role::Responder),
                    _ => return None,
                };
            }
            "stream_id" => {
                let bytes = hex::decode(v).ok()?;
                if bytes.len() != 16 {
                    return None;
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(&bytes);
                stream_id = Some(id);
            }
            _ => {}
        }
    }
    Some(ParsedQuery {
        role: role?,
        stream_id,
    })
}

/// Top-level per-connection handler. Steps: (1) rate-limit check by
/// remote IP; over budget → send HTTP 429 on the raw socket and bail.
/// (2) WS handshake with a callback that snags the request URI so we
/// can read the query string. (3) Pair initiator ↔ responder. (4) Pump.
pub async fn handle(
    tcp: TcpStream,
    peer: SocketAddr,
    limiter: Arc<RateLimiter>,
    registry: Arc<StreamRegistry>,
) -> anyhow::Result<()> {
    if !limiter.check_and_increment(peer.ip()) {
        debug!(peer = %peer, "rate-limited; sending 429");
        send_http_429(tcp).await?;
        return Ok(());
    }

    // Capture the query string during the handshake. Mutex is never
    // contended (handshake callback runs once before we read it back),
    // so poisoning is impossible — but we recover defensively anyway.
    let parsed = Arc::new(std::sync::Mutex::new(None::<ParsedQuery>));
    let parsed_cb = Arc::clone(&parsed);
    let callback = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let uri = req.uri().to_string();
        let p = parse_query(&uri);
        if let Ok(mut guard) = parsed_cb.lock() {
            *guard = p;
        }
        Ok(resp)
    };

    let ws = tokio_tungstenite::accept_hdr_async(tcp, callback).await?;
    let parsed = parsed
        .lock()
        .map(|mut g| g.take())
        .unwrap_or_default();
    let Some(parsed) = parsed else {
        return close_with_protocol_error(ws, "missing/invalid role query param").await;
    };

    match (parsed.role, parsed.stream_id) {
        (Role::Initiator, None) => initiator_flow(ws, registry).await,
        (Role::Initiator, Some(_)) => {
            close_with_protocol_error(ws, "initiator must not submit stream_id").await
        }
        (Role::Responder, Some(id)) => responder_flow(ws, registry, id).await,
        (Role::Responder, None) => {
            close_with_protocol_error(ws, "responder requires stream_id").await
        }
    }
}

async fn initiator_flow(
    mut ws: PendingSocket,
    registry: Arc<StreamRegistry>,
) -> anyhow::Result<()> {
    let (id, rx) = registry.register_initiator();
    // First server-sent frame: the minted stream ID as 16 raw bytes (binary).
    if let Err(e) = ws.send(Message::Binary(id.to_vec())).await {
        registry.cancel(&id);
        return Err(e.into());
    }

    // Wait for a responder (or for the registry to drop us — shouldn't
    // happen in current flow, but guard anyway).
    let Ok(responder) = rx.await else {
        registry.cancel(&id);
        return Ok(());
    };
    pump(ws, responder).await
}

async fn responder_flow(
    ws: PendingSocket,
    registry: Arc<StreamRegistry>,
    id: [u8; 16],
) -> anyhow::Result<()> {
    match registry.join_responder(&id, ws) {
        Ok(()) => Ok(()), // initiator_flow takes over both halves
        Err(returned) => {
            close_with_protocol_error(*returned, "unknown stream_id").await
        }
    }
}

/// Bidirectional opaque pump between two WebSocket halves. Binary and
/// text frames flow through unmodified (subject to size cap); Close
/// from either side ends the session; Ping/Pong handled locally by
/// `tungstenite`.
async fn pump(a: PendingSocket, b: PendingSocket) -> anyhow::Result<()> {
    let (mut a_tx, mut a_rx) = a.split();
    let (mut b_tx, mut b_rx) = b.split();

    loop {
        tokio::select! {
            msg = a_rx.next() => {
                match msg {
                    Some(Ok(m)) => {
                        if !forwardable(&m) { continue; }
                        if oversize(&m) {
                            warn!("frame exceeds MAX_FRAME_BYTES; closing");
                            let _ = a_tx.send(Message::Close(Some(CloseFrame {
                                code: CloseCode::Size,
                                reason: "frame too large".into(),
                            }))).await;
                            let _ = b_tx.send(Message::Close(Some(CloseFrame {
                                code: CloseCode::Size,
                                reason: "peer sent oversize frame".into(),
                            }))).await;
                            break;
                        }
                        if matches!(m, Message::Close(_)) {
                            let _ = b_tx.send(m).await;
                            break;
                        }
                        if b_tx.send(m).await.is_err() { break; }
                    }
                    Some(Err(_)) | None => break,
                }
            }
            msg = b_rx.next() => {
                match msg {
                    Some(Ok(m)) => {
                        if !forwardable(&m) { continue; }
                        if oversize(&m) {
                            warn!("frame exceeds MAX_FRAME_BYTES; closing");
                            let _ = b_tx.send(Message::Close(Some(CloseFrame {
                                code: CloseCode::Size,
                                reason: "frame too large".into(),
                            }))).await;
                            let _ = a_tx.send(Message::Close(Some(CloseFrame {
                                code: CloseCode::Size,
                                reason: "peer sent oversize frame".into(),
                            }))).await;
                            break;
                        }
                        if matches!(m, Message::Close(_)) {
                            let _ = a_tx.send(m).await;
                            break;
                        }
                        if a_tx.send(m).await.is_err() { break; }
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }
    }
    Ok(())
}

fn forwardable(m: &Message) -> bool {
    matches!(
        m,
        Message::Binary(_) | Message::Text(_) | Message::Close(_)
    )
}

fn oversize(m: &Message) -> bool {
    match m {
        Message::Binary(b) => b.len() > MAX_FRAME_BYTES,
        Message::Text(t) => t.len() > MAX_FRAME_BYTES,
        _ => false,
    }
}

async fn close_with_protocol_error(
    mut ws: PendingSocket,
    reason: &'static str,
) -> anyhow::Result<()> {
    let _ = ws
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Library(CLOSE_PROTOCOL_ERROR),
            reason: reason.into(),
        })))
        .await;
    Ok(())
}

/// Write a raw HTTP/1.1 429 response before the WS upgrade and drop the
/// socket. We do this on the underlying TCP stream so no WS state is
/// allocated for over-budget peers.
async fn send_http_429(mut tcp: TcpStream) -> anyhow::Result<()> {
    // Drain any pending request bytes opportunistically so the client
    // sees the response before RST.
    let mut scratch = [0u8; 256];
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        tcp.read(&mut scratch),
    )
    .await;
    let body = b"rate limited\n";
    let header = format!(
        "HTTP/1.1 429 Too Many Requests\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    tcp.write_all(header.as_bytes()).await?;
    tcp.write_all(body).await?;
    let _ = tcp.shutdown().await;
    Ok(())
}
