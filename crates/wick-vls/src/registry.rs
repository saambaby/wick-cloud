//! In-process routing table for SDK signer sessions.
//!
//! The registry owns lookup and replacement only. Per-session mutable state
//! lives on [`crate::SignerConnection`], which the gRPC handler returns and
//! the per-tenant `Node`'s signer resolves on demand.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::connection::SignerConnection;

/// Outbound frame sent from the server to the SDK over the bidi stream.
///
/// `StateSync` is a control frame sent once after attach to establish baseline
/// channel watermarks (last signed commitment number per channel) so the SDK
/// can refuse to re-sign older commitments after a server restart.
///
/// `VlsBinaryCall` is the native VLS frame, already wrapped with the wire
/// header (`encode_node_call` / `encode_channel_call`) — the gRPC service
/// passes the raw bytes through as `SignerRequest.vls_payload`.
#[derive(Clone, Debug)]
pub enum OutboundSignerFrame {
    StateSync {
        context_id: String,
        channels: Vec<StateSyncChannel>,
    },
    VlsBinaryCall {
        request_id: u32,
        encoded: Vec<u8>,
    },
    Ping,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct StateSyncChannel {
    pub channel_id: String,
    pub last_signed_commitment_num: u64,
}

#[derive(Debug)]
pub struct SignerSessionRegistry {
    sessions: DashMap<String, Arc<SignerConnection>>,
    session_counter: AtomicU64,
}

impl SignerSessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            session_counter: AtomicU64::new(1),
        }
    }

    /// Install a new SDK session under `context_id`. If a prior session exists,
    /// fail all of its in-flight calls and replace it (most-recent-wins).
    pub fn register(
        &self,
        context_id: String,
        sender: mpsc::Sender<OutboundSignerFrame>,
    ) -> Arc<SignerConnection> {
        let session_token = self.session_counter.fetch_add(1, Ordering::Relaxed);
        let conn = Arc::new(SignerConnection::new(
            context_id.clone(),
            session_token,
            sender,
        ));
        if let Some(old) = self.sessions.insert(context_id.clone(), Arc::clone(&conn)) {
            old.fail_pending(&format!("signer session replaced for '{context_id}'"));
        }
        conn
    }

    pub fn get(&self, context_id: &str) -> Option<Arc<SignerConnection>> {
        self.sessions
            .get(context_id)
            .map(|entry| Arc::clone(entry.value()))
    }

    pub fn is_connected(&self, context_id: &str) -> bool {
        self.sessions.contains_key(context_id)
    }

    pub fn is_ready(&self, context_id: &str) -> bool {
        self.get(context_id)
            .map(|conn| conn.is_ready())
            .unwrap_or(false)
    }

    /// Remove the session under `context_id` only if its `session_token` matches.
    /// Stale unregister calls (after a replacement) are no-ops.
    pub fn unregister(&self, context_id: &str, session_token: u64) -> bool {
        let removed = self
            .sessions
            .remove_if(context_id, |_, conn| conn.session_token() == session_token);
        if let Some((_, conn)) = removed {
            conn.fail_pending(&format!("signer session disconnected for '{context_id}'"));
            true
        } else {
            false
        }
    }
}

impl Default for SignerSessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-tenant handle that resolves the *current* [`SignerConnection`] from
/// the [`SignerSessionRegistry`] on every signing call.
///
/// The signer holds this rather than an `Arc<SignerConnection>` directly so
/// that reconnects (which install a fresh connection in the registry) are
/// transparent to the LDK signer trait impls — the next call will simply
/// resolve the new connection.
#[derive(Clone, Debug)]
pub struct ConnLookup {
    context_id: String,
    registry: Arc<SignerSessionRegistry>,
}

impl ConnLookup {
    pub fn new(context_id: String, registry: Arc<SignerSessionRegistry>) -> Self {
        Self {
            context_id,
            registry,
        }
    }

    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    pub fn resolve(&self) -> Option<Arc<SignerConnection>> {
        self.registry.get(&self.context_id)
    }

    pub fn is_ready(&self) -> bool {
        self.registry.is_ready(&self.context_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn stale_unregister_cannot_remove_current_session() {
        let registry = Arc::new(SignerSessionRegistry::new());
        let (tx1, _rx1) = mpsc::channel(8);
        let (tx2, _rx2) = mpsc::channel(8);
        let conn1 = registry.register("ctx".to_string(), tx1);
        let conn2 = registry.register("ctx".to_string(), tx2);

        assert!(!registry.unregister("ctx", conn1.session_token()));
        assert!(registry.is_connected("ctx"));
        assert!(registry.unregister("ctx", conn2.session_token()));
        assert!(!registry.is_connected("ctx"));
    }

    #[tokio::test]
    async fn connection_resolves_own_response_only() {
        let registry = Arc::new(SignerSessionRegistry::new());
        let (tx, mut rx) = mpsc::channel(8);
        let conn = registry.register("ctx".to_string(), tx);
        assert!(conn.activate());

        let registry_for_task = Arc::clone(&registry);
        let task = tokio::spawn(async move {
            let conn = registry_for_task.get("ctx").expect("conn");
            conn.dispatch_node_call(vec![0x01, 0x02], Duration::from_secs(1))
                .await
        });

        let OutboundSignerFrame::VlsBinaryCall { encoded, .. } =
            rx.recv().await.expect("outbound VLS call")
        else {
            panic!("unexpected outbound frame");
        };
        let req_id = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);

        conn.resolve_response({
            let mut frame = Vec::new();
            frame.extend_from_slice(&req_id.to_be_bytes());
            frame.push(0x00);
            frame.extend_from_slice(&[0xBB, 0xCC]);
            frame
        });

        let body = task.await.expect("join").expect("dispatch result");
        assert_eq!(body, vec![0xBB, 0xCC]);
    }

    #[tokio::test]
    async fn replacing_session_fails_inflight_calls() {
        let registry = Arc::new(SignerSessionRegistry::new());
        let (tx1, mut rx1) = mpsc::channel(8);
        let conn1 = registry.register("ctx".to_string(), tx1);
        assert!(conn1.activate());

        let registry_for_task = Arc::clone(&registry);
        let task = tokio::spawn(async move {
            let conn = registry_for_task.get("ctx").expect("conn");
            conn.dispatch_node_call(vec![0x10], Duration::from_secs(2))
                .await
        });

        let _ = rx1.recv().await.expect("initial outbound");

        let (tx2, _rx2) = mpsc::channel(8);
        let _conn2 = registry.register("ctx".to_string(), tx2);

        let err = task
            .await
            .expect("join")
            .expect_err("expected replacement error");
        assert!(err.to_string().contains("replaced"));
    }
}
