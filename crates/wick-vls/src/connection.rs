//! Per-session VLS connection state.
//!
//! A [`SignerConnection`] is tied to exactly one tenant context and one session
//! generation. The [`crate::SignerSessionRegistry`] swaps these handles on
//! reconnect; callers should always resolve the current handle through the
//! registry rather than caching the [`std::sync::Arc`] across reconnects.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot};

use crate::registry::OutboundSignerFrame;

pub struct SignerConnection {
    context_id: String,
    session_token: u64,
    sender: mpsc::Sender<OutboundSignerFrame>,
    ready: AtomicBool,
    retired: AtomicBool,
    pending_vls: DashMap<u32, oneshot::Sender<anyhow::Result<Vec<u8>>>>,
    req_counter: AtomicU32,
}

impl std::fmt::Debug for SignerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerConnection")
            .field("context_id", &self.context_id)
            .field("session_token", &self.session_token)
            .field("ready", &self.ready.load(Ordering::Acquire))
            .field("retired", &self.retired.load(Ordering::Acquire))
            .field("pending_vls", &self.pending_vls.len())
            .finish()
    }
}

impl SignerConnection {
    pub fn new(
        context_id: String,
        session_token: u64,
        sender: mpsc::Sender<OutboundSignerFrame>,
    ) -> Self {
        Self {
            context_id,
            session_token,
            sender,
            ready: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            pending_vls: DashMap::new(),
            req_counter: AtomicU32::new(1),
        }
    }

    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    pub fn session_token(&self) -> u64 {
        self.session_token
    }

    pub fn is_ready(&self) -> bool {
        !self.retired.load(Ordering::Acquire) && self.ready.load(Ordering::Acquire)
    }

    pub fn activate(&self) -> bool {
        if self.retired.load(Ordering::Acquire) {
            return false;
        }
        self.ready.store(true, Ordering::Release);
        true
    }

    pub fn fail_pending(&self, reason: &str) {
        self.retired.store(true, Ordering::Release);
        self.ready.store(false, Ordering::Release);

        let keys: Vec<u32> = self.pending_vls.iter().map(|entry| *entry.key()).collect();
        for key in keys {
            if let Some((_, tx)) = self.pending_vls.remove(&key) {
                let _ = tx.send(Err(anyhow::anyhow!("{reason}")));
            }
        }
    }

    /// Dispatch a native VLS node-level call and await the binary reply.
    pub async fn dispatch_node_call(
        &self,
        vls_bytes: Vec<u8>,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        let request_id = self.req_counter.fetch_add(1, Ordering::Relaxed);
        let encoded = encode_node_call(request_id, vls_bytes);
        self.dispatch_vls(request_id, encoded, timeout).await
    }

    /// Dispatch a native VLS channel-level call and await the binary reply.
    pub async fn dispatch_channel_call(
        &self,
        dbid: u64,
        peer_id: [u8; 33],
        vls_bytes: Vec<u8>,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        let request_id = self.req_counter.fetch_add(1, Ordering::Relaxed);
        let encoded = encode_channel_call(request_id, dbid, peer_id, vls_bytes);
        self.dispatch_vls(request_id, encoded, timeout).await
    }

    /// Route an inbound binary VLS response frame from the SDK to the waiting caller.
    ///
    /// `frame` = `[4B request_id BE][1B status][body]`
    pub fn resolve_response(&self, frame: Vec<u8>) {
        if frame.len() < 5 {
            tracing::warn!(
                target: "wick_vls",
                context_id = %self.context_id,
                "VLS response frame too short ({} bytes)",
                frame.len()
            );
            return;
        }
        let request_id = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        let status = frame[4];
        let body = frame[5..].to_vec();

        if let Some((_, tx)) = self.pending_vls.remove(&request_id) {
            let result = if status == 0x00 {
                Ok(body)
            } else {
                let msg = String::from_utf8_lossy(&body).into_owned();
                Err(anyhow::anyhow!("VLS signer error: {msg}"))
            };
            let _ = tx.send(result);
        } else {
            tracing::warn!(
                target: "wick_vls",
                context_id = %self.context_id,
                request_id,
                session_token = self.session_token,
                "dropping unmatched VLS response frame"
            );
        }
    }

    async fn dispatch_vls(
        &self,
        request_id: u32,
        encoded: Vec<u8>,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        tracing::info!(
            target: "wick_vls::dispatch",
            context_id = %self.context_id,
            session_token = self.session_token,
            request_id,
            bytes = encoded.len(),
            "→ dispatch_vls"
        );
        if self.retired.load(Ordering::Acquire) {
            anyhow::bail!("signer session replaced for '{}'", self.context_id);
        }
        if !self.is_ready() {
            anyhow::bail!("signer session not ready for '{}'", self.context_id);
        }

        let key = request_id;
        let (tx, rx) = oneshot::channel();
        self.pending_vls.insert(key, tx);

        // Re-check after inserting so a concurrent replacement cannot leave a
        // dangling request behind.
        if self.retired.load(Ordering::Acquire) {
            if let Some((_, tx)) = self.pending_vls.remove(&key) {
                let _ = tx.send(Err(anyhow::anyhow!(
                    "signer session replaced for '{}'",
                    self.context_id
                )));
            }
            anyhow::bail!("signer session replaced for '{}'", self.context_id);
        }

        if self
            .sender
            .send(OutboundSignerFrame::VlsBinaryCall {
                request_id,
                encoded,
            })
            .await
            .is_err()
        {
            self.pending_vls.remove(&key);
            anyhow::bail!("signer session channel closed");
        }

        let result = tokio::time::timeout(timeout, rx)
            .await
            .map_err(|_| {
                self.pending_vls.remove(&key);
                tracing::warn!(
                    target: "wick_vls::dispatch",
                    context_id = %self.context_id,
                    request_id,
                    "✗ dispatch_vls timeout"
                );
                anyhow::anyhow!("VLS call timeout (request_id={request_id})")
            })?
            .map_err(|_| anyhow::anyhow!("VLS response oneshot dropped"))?;
        tracing::info!(
            target: "wick_vls::dispatch",
            context_id = %self.context_id,
            request_id,
            "✓ dispatch_vls reply"
        );
        result
    }
}

#[cfg(test)]
impl Default for SignerConnection {
    fn default() -> Self {
        let (sender, _rx) = mpsc::channel(1);
        Self::new(String::new(), 0, sender)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::mpsc;

    use crate::registry::OutboundSignerFrame;

    use super::SignerConnection;

    /// [INV-CUSTODY-2] VLS policy rejection propagates as an error and is
    /// never silently treated as a valid response body.
    ///
    /// Simulates the path where the on-device VLS policy engine returns
    /// `status != 0x00` (policy violation). The server-side routing layer
    /// must surface this as an `Err` — a compromised or buggy server cannot
    /// manufacture a valid signature by sending a crafted error frame.
    #[tokio::test]
    async fn policy_rejection_propagates_as_error_not_signature() {
        let (sender, mut rx) = mpsc::channel::<OutboundSignerFrame>(1);
        let conn = Arc::new(SignerConnection::new("test-tenant".to_owned(), 42, sender));
        conn.activate();

        let conn_caller = conn.clone();
        let call = tokio::spawn(async move {
            conn_caller
                .dispatch_node_call(vec![0x00, 0x01, 0x02], Duration::from_secs(5))
                .await
        });

        // Drain the outbound frame to get the request_id.
        let request_id = loop {
            match rx.recv().await.expect("outbound frame") {
                OutboundSignerFrame::VlsBinaryCall { request_id, .. } => break request_id,
                // StateSync and Ping are control frames; skip them.
                OutboundSignerFrame::StateSync { .. } | OutboundSignerFrame::Ping => continue,
            }
        };

        // Simulate a policy rejection from the on-device VLS engine.
        // status=0x01 means error; body is a UTF-8 error message, NOT a signature.
        let mut rejection = Vec::new();
        rejection.extend_from_slice(&request_id.to_be_bytes());
        rejection.push(0x01);
        rejection.extend_from_slice(b"policy violation: payment_size exceeds max_payment_sat");
        conn.resolve_response(rejection);

        let result = call.await.expect("task did not panic");
        assert!(
            result.is_err(),
            "policy rejection must propagate as Err, got Ok"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("VLS signer error"),
            "error message should identify the VLS signer as the source: {msg}"
        );
        assert!(
            msg.contains("policy violation"),
            "error message should include the policy rejection reason: {msg}"
        );
    }

    /// A success response (status=0x00) reaches the caller as Ok(body).
    /// Companion to the rejection test — ensures we haven't broken the happy path.
    #[tokio::test]
    async fn success_response_delivered_as_ok_body() {
        let (sender, mut rx) = mpsc::channel::<OutboundSignerFrame>(1);
        let conn = Arc::new(SignerConnection::new("test-tenant".to_owned(), 1, sender));
        conn.activate();

        let conn_caller = conn.clone();
        let call = tokio::spawn(async move {
            conn_caller
                .dispatch_node_call(vec![0xDE, 0xAD], Duration::from_secs(5))
                .await
        });

        let request_id = loop {
            match rx.recv().await.expect("outbound frame") {
                OutboundSignerFrame::VlsBinaryCall { request_id, .. } => break request_id,
                OutboundSignerFrame::StateSync { .. } | OutboundSignerFrame::Ping => continue,
            }
        };

        let sig_body = vec![0xAB, 0xCD, 0xEF];
        let mut response = Vec::new();
        response.extend_from_slice(&request_id.to_be_bytes());
        response.push(0x00); // success
        response.extend_from_slice(&sig_body);
        conn.resolve_response(response);

        let result = call.await.expect("task did not panic");
        assert_eq!(result.expect("success response must be Ok"), sig_body);
    }
}

/// `[4B request_id BE][0x01][3B reserved][vls_bytes]`
fn encode_node_call(request_id: u32, vls_bytes: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + vls_bytes.len());
    out.extend_from_slice(&request_id.to_be_bytes());
    out.push(0x01);
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    out.extend_from_slice(&vls_bytes);
    out
}

/// `[4B request_id BE][0x02][3B reserved][8B dbid BE][33B peer_id][vls_bytes]`
fn encode_channel_call(
    request_id: u32,
    dbid: u64,
    peer_id: [u8; 33],
    vls_bytes: Vec<u8>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 8 + 33 + vls_bytes.len());
    out.extend_from_slice(&request_id.to_be_bytes());
    out.push(0x02);
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    out.extend_from_slice(&dbid.to_be_bytes());
    out.extend_from_slice(&peer_id);
    out.extend_from_slice(&vls_bytes);
    out
}
