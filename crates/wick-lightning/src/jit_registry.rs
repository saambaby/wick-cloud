//! [`PendingJitRegistry`] — parks LSPS2 client responses awaiting a
//! matching `request_id`.
//!
//! Mirrors [`crate::funding_registry::PendingFundingRegistry`]: oneshot-per-key
//! plus a `ready` map for the case where the response arrives before the
//! caller has installed a waiter. Keyed by `LSPSRequestId` so the
//! `request_opening_params` and `select_opening_params` calls can both
//! await independently for their respective `OpeningParametersReady` /
//! `InvoiceParametersReady` events.
//!
//! Unlike [`PendingFundingRegistry`], this registry has **no Postgres
//! backing**. Per the `lightning-liquidity` docs, LSPS2 client events
//! "will not be persisted across restarts" — the protocol assumes a
//! cold start invalidates in-flight requests. If a tenant restart loses
//! a parked request, the SDK simply re-issues `lsps2.get_info`.

use std::fmt;
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use dashmap::DashMap;
use lightning_liquidity::lsps0::ser::LSPSRequestId;
use lightning_liquidity::lsps2::msgs::LSPS2OpeningFeeParams;
use tokio::sync::oneshot;

/// A parked LSPS2 response.
#[derive(Debug, Clone)]
pub enum JitResponse {
    /// Reply to `request_opening_params` (LSPS2 `lsps2.get_info`). Carries
    /// the menu of opening fee params the LSP is offering.
    OpeningParameters {
        /// LSP node id that responded.
        counterparty_node_id: PublicKey,
        /// Menu of fee params; pick one for the follow-up `select_opening_params`.
        opening_fee_params_menu: Vec<LSPS2OpeningFeeParams>,
    },
    /// Reply to `select_opening_params` (LSPS2 `lsps2.buy`). Carries the
    /// intercept SCID and CLTV delta the client must embed in the BOLT11.
    InvoiceParameters {
        /// LSP node id that responded.
        counterparty_node_id: PublicKey,
        /// Intercept SCID assigned by the LSP. Embedded in the route hint.
        intercept_scid: u64,
        /// `cltv_expiry_delta` for the route hint hop.
        cltv_expiry_delta: u32,
        /// Echoed payment size (msat) the client supplied; `None` for any-amount.
        payment_size_msat: Option<u64>,
    },
    /// `lsps2.get_info` failed at the LSP. Returned to the caller as an
    /// error.
    GetInfoFailed {
        /// LSP node id.
        counterparty_node_id: PublicKey,
        /// Stringified LSP error code + message.
        message: String,
    },
    /// `lsps2.buy` failed at the LSP. Returned to the caller as an error.
    BuyFailed {
        /// LSP node id.
        counterparty_node_id: PublicKey,
        /// Stringified LSP error code + message.
        message: String,
    },
}

/// Map of in-flight LSPS2 client requests keyed by `LSPSRequestId`.
#[derive(Default)]
pub struct PendingJitRegistry {
    ready: DashMap<LSPSRequestId, JitResponse>,
    waiters: DashMap<LSPSRequestId, oneshot::Sender<JitResponse>>,
}

impl fmt::Debug for PendingJitRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingJitRegistry")
            .field("ready_count", &self.ready.len())
            .field("waiter_count", &self.waiters.len())
            .finish()
    }
}

impl PendingJitRegistry {
    /// Construct an in-memory registry.
    #[must_use]
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// Park `resp` against `request_id`. If a `take` waiter is already
    /// installed, deliver directly via its oneshot; otherwise stash for
    /// the inevitable `take` call.
    pub fn park(&self, request_id: LSPSRequestId, resp: JitResponse) {
        if let Some((_, tx)) = self.waiters.remove(&request_id) {
            let _ = tx.send(resp);
        } else {
            self.ready.insert(request_id, resp);
        }
    }

    /// Remove and return the parked response for `request_id`. Waits up
    /// to `timeout` for `park` to fire. Returns `None` on timeout.
    pub async fn take(&self, request_id: LSPSRequestId, timeout: Duration) -> Option<JitResponse> {
        // Fast path.
        if let Some((_, resp)) = self.ready.remove(&request_id) {
            return Some(resp);
        }

        let (tx, rx) = oneshot::channel();
        self.waiters.insert(request_id.clone(), tx);
        // Re-check window: park may have fired between the first probe
        // and the waiter insert.
        if let Some((_, resp)) = self.ready.remove(&request_id) {
            self.waiters.remove(&request_id);
            return Some(resp);
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(resp)) => Some(resp),
            Ok(Err(_)) => None,
            Err(_) => {
                self.waiters.remove(&request_id);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use std::time::Duration;

    fn dummy_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn make_request_id(byte: u8) -> LSPSRequestId {
        LSPSRequestId(format!("test-{byte:02x}"))
    }

    #[tokio::test]
    async fn park_then_take_delivers() {
        let reg = PendingJitRegistry::new();
        let req_id = make_request_id(1);
        reg.park(
            req_id.clone(),
            JitResponse::OpeningParameters {
                counterparty_node_id: dummy_pubkey(),
                opening_fee_params_menu: Vec::new(),
            },
        );
        let resp = reg.take(req_id, Duration::from_millis(100)).await;
        assert!(matches!(resp, Some(JitResponse::OpeningParameters { .. })));
    }

    #[tokio::test]
    async fn take_then_park_delivers_via_waiter() {
        let reg = PendingJitRegistry::new();
        let req_id = make_request_id(2);
        let r2 = reg.clone();
        let req_id2 = req_id.clone();
        let handle = tokio::spawn(async move { r2.take(req_id2, Duration::from_secs(1)).await });
        // Yield so the waiter gets installed before we park.
        tokio::time::sleep(Duration::from_millis(10)).await;
        reg.park(
            req_id,
            JitResponse::InvoiceParameters {
                counterparty_node_id: dummy_pubkey(),
                intercept_scid: 0xabcd,
                cltv_expiry_delta: 144,
                payment_size_msat: Some(1000),
            },
        );
        let resp = handle.await.unwrap();
        match resp {
            Some(JitResponse::InvoiceParameters { intercept_scid, .. }) => {
                assert_eq!(intercept_scid, 0xabcd)
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn take_times_out_on_no_park() {
        let reg = PendingJitRegistry::new();
        let req_id = make_request_id(3);
        let resp = reg.take(req_id, Duration::from_millis(50)).await;
        assert!(resp.is_none());
    }
}
