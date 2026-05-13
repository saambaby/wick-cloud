//! D3 M4 — credential storage abstraction + auto-rotation loop.
//!
//! Today the SDK ships a bearer token. After D3 M3 lands, the server will
//! issue a serialised `wick-macaroon` instead. This module wires both code
//! paths behind a [`CredentialStore`] trait + a background [`RotationLoop`]
//! that watches the credential's expiry caveat and asks the server for a
//! fresh one shortly before it would lapse.
//!
//! ## Wire mode toggle
//!
//! [`CredentialKind`] is the runtime discriminant. The rotation loop is a
//! no-op while [`Credential::kind`] is [`CredentialKind::Bearer`] or while
//! [`Credential::expires_at`] is `None`. M3 will retire the bearer branch
//! entirely; until then both work side-by-side.
//!
//! ## Macaroon expiry decoder
//!
//! The macaroon wire layout (mirror of `wick_macaroon::Macaroon::serialize`):
//!
//! ```text
//! u16 location_len | location_bytes
//! [16] identifier
//! u16 num_caveats
//!   per caveat: u16 caveat_len | u8 tag | payload
//! [32] signature
//! ```
//!
//! Caveat tag `0x01` (`Expiry`) carries an 8-byte big-endian unix timestamp.
//! [`try_decode_macaroon_expiry`] skims the byte stream and pulls the first
//! `Expiry` caveat without depending on `wick-macaroon` (which would create
//! a workspace dep cycle: M1 ships primitives the server uses, M3's gRPC
//! interceptor is what the SDK actually talks to, and `wick-sdk` keeps a
//! deliberately tight dep list — see Phase-4 plan).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures::future::BoxFuture;
use parking_lot::RwLock;
use tokio::sync::watch;

use crate::error::{Error, Result};

/// Caveat tag identifying an `Expiry` caveat in the macaroon wire format.
/// Mirror of `wick_macaroon::TAG_EXPIRY`.
const MACAROON_TAG_EXPIRY: u8 = 0x01;

/// How long before [`Credential::expires_at`] the rotation loop fires.
/// Default 5 minutes; tuned so a slow round-trip can't race the expiry.
pub const DEFAULT_ROTATION_LEAD: Duration = Duration::from_secs(5 * 60);

/// Credential the SDK holds for talking to wick-server.
///
/// Today this is a bearer token (legacy, transitional); after D3 M3 lands
/// it's a serialised `wick-macaroon` instead. [`expires_at`] is the parsed
/// `Expiry` caveat for macaroons; bearers return `None` and the rotation
/// loop is a no-op.
///
/// [`expires_at`]: Credential::expires_at
#[derive(Debug, Clone)]
pub struct Credential {
    /// Raw credential bytes — either the bearer's UTF-8 token bytes or a
    /// serialised `wick-macaroon`. The gRPC interceptor stringifies via
    /// `String::from_utf8_lossy` for the `Authorization: Bearer …` header.
    pub bytes: Vec<u8>,
    /// Runtime discriminant. The rotation loop only fires for macaroons.
    pub kind: CredentialKind,
    /// Parsed expiry, if the credential format self-describes one.
    pub expires_at: Option<SystemTime>,
}

/// Runtime mode toggle between the legacy bearer path and the macaroon
/// path that lands in D3 M3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// Legacy opaque bearer string — UUID-ish, bound to the tenant on the
    /// server side, no self-described expiry.
    Bearer,
    /// `wick-macaroon` serialised bytes — carries scope + nonce + expiry.
    Macaroon,
}

/// Pluggable storage backing for [`Credential`].
///
/// The default is [`InMemoryStore`]; production callers can swap in a
/// keychain- or file-backed impl via [`crate::WickClient::with_credential_store`].
#[async_trait]
pub trait CredentialStore: Send + Sync + std::fmt::Debug {
    /// Read the current credential, if any.
    async fn load(&self) -> Option<Credential>;
    /// Persist a credential, replacing any prior value.
    async fn save(&self, c: Credential);
    /// Drop the stored credential (logout / re-register).
    async fn clear(&self);
}

/// In-process default impl. Tests and the unconfigured client share this.
#[derive(Debug, Default, Clone)]
pub struct InMemoryStore {
    inner: Arc<RwLock<Option<Credential>>>,
}

#[async_trait]
impl CredentialStore for InMemoryStore {
    async fn load(&self) -> Option<Credential> {
        self.inner.read().clone()
    }
    async fn save(&self, c: Credential) {
        *self.inner.write() = Some(c);
    }
    async fn clear(&self) {
        *self.inner.write() = None;
    }
}

/// Parse the `Expiry` caveat (tag `0x01`) out of a serialised macaroon.
///
/// Returns `None` when the bytes aren't a valid macaroon, when no `Expiry`
/// caveat is present, or when the expiry would overflow `SystemTime`. Mirror
/// of `wick_macaroon::Caveat::Expiry` wire format — inlined deliberately to
/// keep `wick-sdk`'s dep list tight (see module docs).
#[must_use]
pub fn try_decode_macaroon_expiry(bytes: &[u8]) -> Option<SystemTime> {
    let mut cur = Cursor::new(bytes);
    let loc_len = cur.read_u16()? as usize;
    cur.skip(loc_len)?;
    cur.skip(16)?; // identifier
    let n_caveats = cur.read_u16()? as usize;
    for _ in 0..n_caveats {
        let cav_len = cur.read_u16()? as usize;
        if cav_len < 1 {
            return None;
        }
        let cav = cur.read_bytes(cav_len)?;
        let tag = cav[0];
        let payload = &cav[1..];
        if tag == MACAROON_TAG_EXPIRY && payload.len() == 8 {
            let mut be = [0u8; 8];
            be.copy_from_slice(payload);
            let unix_ts = u64::from_be_bytes(be);
            return UNIX_EPOCH.checked_add(Duration::from_secs(unix_ts));
        }
    }
    None
}

/// Decode the credential kind + expiry hint from the server's response.
///
/// Inspects the bytes for the macaroon wire framing. If the bytes parse as
/// a macaroon with an `Expiry` caveat, returns `(Macaroon, Some(ts))`. If
/// they parse as a macaroon without `Expiry`, returns `(Macaroon, None)`.
/// Otherwise the credential is treated as a legacy bearer.
///
/// M3 will replace this with an explicit proto field; for now we sniff so
/// the wire transition lands without coordinated client/server upgrade.
#[must_use]
pub fn classify(bytes: &[u8]) -> (CredentialKind, Option<SystemTime>) {
    if looks_like_macaroon(bytes) {
        (CredentialKind::Macaroon, try_decode_macaroon_expiry(bytes))
    } else {
        (CredentialKind::Bearer, None)
    }
}

/// Cheap structural check for the macaroon wire layout. Used only to pick
/// the right [`CredentialKind`]; verification still happens server-side.
fn looks_like_macaroon(bytes: &[u8]) -> bool {
    let mut cur = Cursor::new(bytes);
    let Some(loc_len) = cur.read_u16().map(|n| n as usize) else {
        return false;
    };
    if cur.skip(loc_len).is_none() || cur.skip(16).is_none() {
        return false;
    }
    let Some(n_caveats) = cur.read_u16().map(|n| n as usize) else {
        return false;
    };
    for _ in 0..n_caveats {
        let Some(cav_len) = cur.read_u16().map(|n| n as usize) else {
            return false;
        };
        if cav_len < 1 || cur.skip(cav_len).is_none() {
            return false;
        }
    }
    cur.skip(32).is_some() && cur.is_empty()
}

// ── Cursor helper ────────────────────────────────────────────────────────────

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn read_u16(&mut self) -> Option<u16> {
        let bytes = self.read_bytes(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Some(out)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.read_bytes(n).map(|_| ())
    }
    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

// ── Rotation loop ────────────────────────────────────────────────────────────

/// Result of a single rotate-credential call. Returned by the closure
/// [`RotationLoop`] holds; today's placeholder always errors with
/// [`Error::Grpc`] `Unimplemented` because the server-side RPC ships in M3.
pub type RotateResult = Result<Credential>;

/// Closure type for the rotate-credential RPC. Boxed so the loop is
/// generic over the transport (real gRPC client, test fake, …).
pub type RotateFn =
    Arc<dyn Fn() -> BoxFuture<'static, RotateResult> + Send + Sync + 'static>;

/// Configuration knob — primarily for tests, which override the default
/// 5-minute lead so a paused-clock loop fires deterministically.
#[derive(Debug, Clone, Copy)]
pub struct RotationConfig {
    /// How long before `expires_at` we trigger rotation. Defaults to
    /// [`DEFAULT_ROTATION_LEAD`].
    pub lead: Duration,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            lead: DEFAULT_ROTATION_LEAD,
        }
    }
}

/// Handle returned by [`RotationLoop::spawn`]. Holding it keeps the loop
/// alive; dropping it (or calling [`RotationHandle::shutdown`]) signals the
/// loop to exit at its next await point.
#[derive(Debug)]
pub struct RotationHandle {
    shutdown_tx: watch::Sender<bool>,
}

impl RotationHandle {
    /// Signal the loop to exit. Idempotent.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for RotationHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Background task that watches the credential's expiry and rotates it
/// shortly before it lapses. See module docs for the lifecycle rules.
pub struct RotationLoop {
    store: Arc<dyn CredentialStore>,
    rotate_fn: RotateFn,
    config: RotationConfig,
}

impl std::fmt::Debug for RotationLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationLoop")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RotationLoop {
    /// Build a loop. The actual task isn't spawned until [`Self::spawn`].
    #[must_use]
    pub fn new(
        store: Arc<dyn CredentialStore>,
        rotate_fn: RotateFn,
        config: RotationConfig,
    ) -> Self {
        Self {
            store,
            rotate_fn,
            config,
        }
    }

    /// Spawn the loop on the current tokio runtime. Returns a handle whose
    /// drop signals shutdown.
    pub fn spawn(self) -> RotationHandle {
        let (tx, rx) = watch::channel(false);
        tokio::spawn(self.run(rx));
        RotationHandle { shutdown_tx: tx }
    }

    /// Inner task body. Public for parity with [`crate::signer::SignerLoop::run`]
    /// but the normal path is [`Self::spawn`].
    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        // Initial load — if there's nothing or it isn't a macaroon, wait
        // for shutdown only. The credential never gets *upgraded* in-place
        // by a different code path today, so we don't poll the store.
        let Some(cred) = self.store.load().await else {
            wait_for_shutdown(&mut shutdown_rx).await;
            return;
        };
        if cred.kind != CredentialKind::Macaroon || cred.expires_at.is_none() {
            wait_for_shutdown(&mut shutdown_rx).await;
            return;
        }

        let mut current = cred;
        loop {
            let Some(expires_at) = current.expires_at else {
                wait_for_shutdown(&mut shutdown_rx).await;
                return;
            };
            // Compute the rotation deadline. Saturating subtraction: if
            // the credential already expired or is inside the lead window
            // we rotate immediately.
            let now = SystemTime::now();
            let sleep_for = expires_at
                .duration_since(now)
                .unwrap_or(Duration::ZERO)
                .saturating_sub(self.config.lead);

            if sleep_for > Duration::ZERO {
                tokio::select! {
                    biased;
                    res = shutdown_rx.changed() => {
                        if res.is_err() || *shutdown_rx.borrow() {
                            return;
                        }
                    }
                    _ = tokio::time::sleep(sleep_for) => {}
                }
            }

            // Rotate, retrying on transient failure. Reuses the signer
            // backoff schedule (1s → 2s → … → 30s cap).
            let new_cred = match self.rotate_with_retry(&mut shutdown_rx).await {
                Some(c) => c,
                None => return, // shutdown
            };

            self.store.save(new_cred.clone()).await;
            current = new_cred;
        }
    }

    async fn rotate_with_retry(
        &self,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Option<Credential> {
        let mut failures: u32 = 0;
        loop {
            match (self.rotate_fn)().await {
                Ok(c) => return Some(c),
                Err(e) => {
                    failures = failures.saturating_add(1);
                    let delay = crate::signer::next_backoff(failures);
                    tracing::warn!(
                        target: "wick_sdk::credential",
                        failures,
                        backoff_ms = delay.as_millis() as u64,
                        %e,
                        "credential rotation failed; retrying"
                    );
                    tokio::select! {
                        biased;
                        res = shutdown_rx.changed() => {
                            if res.is_err() || *shutdown_rx.borrow() {
                                return None;
                            }
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
            }
        }
    }
}

async fn wait_for_shutdown(rx: &mut watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    let _ = rx.changed().await;
}

/// Placeholder rotate-credential closure for the M3 wire-up.
///
/// Until D3 M3 implements server-side `RotateCredential`, the rotation
/// loop is wired to this stub which always returns
/// [`Error::Grpc`] with `Unimplemented`. The loop retries it on the
/// signer backoff schedule, so when the real RPC lands the SDK starts
/// rotating without any client-side code change.
#[must_use]
pub fn unimplemented_rotate_fn() -> RotateFn {
    Arc::new(|| {
        Box::pin(async {
            Err(Error::Grpc {
                code: tonic::Code::Unimplemented,
                message: "rotate_credential RPC ships in D3 M3".to_owned(),
            })
        })
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // ── Fixture: hand-rolled macaroon byte sequence ─────────────────────────
    //
    // Mirror of `wick_macaroon::Macaroon::serialize` for the smallest valid
    // shape with one `Expiry` caveat. Inlined so the test doesn't depend on
    // `wick-macaroon`.
    fn macaroon_bytes_with_expiry(unix_ts: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let loc = b"wick-server";
        out.extend_from_slice(&(loc.len() as u16).to_be_bytes());
        out.extend_from_slice(loc);
        out.extend_from_slice(&[0u8; 16]); // identifier
        // one caveat: expiry
        out.extend_from_slice(&1u16.to_be_bytes());
        let mut cav = vec![MACAROON_TAG_EXPIRY];
        cav.extend_from_slice(&unix_ts.to_be_bytes());
        out.extend_from_slice(&(cav.len() as u16).to_be_bytes());
        out.extend_from_slice(&cav);
        out.extend_from_slice(&[0u8; 32]); // signature
        out
    }

    #[tokio::test]
    async fn in_memory_store_round_trips() {
        let s = InMemoryStore::default();
        assert!(s.load().await.is_none());
        let c = Credential {
            bytes: b"hello".to_vec(),
            kind: CredentialKind::Bearer,
            expires_at: None,
        };
        s.save(c.clone()).await;
        let got = s.load().await.unwrap();
        assert_eq!(got.bytes, c.bytes);
        assert_eq!(got.kind, c.kind);
        s.clear().await;
        assert!(s.load().await.is_none());
    }

    #[test]
    fn try_decode_macaroon_expiry_extracts_unix_ts() {
        let ts: u64 = 1_700_000_000;
        let bytes = macaroon_bytes_with_expiry(ts);
        let got = try_decode_macaroon_expiry(&bytes).unwrap();
        let secs = got.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, ts);
    }

    #[test]
    fn try_decode_macaroon_expiry_rejects_garbage() {
        assert!(try_decode_macaroon_expiry(&[0u8; 4]).is_none());
        assert!(try_decode_macaroon_expiry(b"not-a-macaroon").is_none());
    }

    #[test]
    fn classify_detects_macaroon_vs_bearer() {
        let bytes = macaroon_bytes_with_expiry(1_700_000_000);
        let (kind, exp) = classify(&bytes);
        assert_eq!(kind, CredentialKind::Macaroon);
        assert!(exp.is_some());

        let (kind, exp) = classify(b"opaque-uuid-bearer-string");
        assert_eq!(kind, CredentialKind::Bearer);
        assert!(exp.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn rotation_loop_no_ops_for_bearer() {
        let store: Arc<dyn CredentialStore> = Arc::new(InMemoryStore::default());
        store
            .save(Credential {
                bytes: b"bearer".to_vec(),
                kind: CredentialKind::Bearer,
                expires_at: None,
            })
            .await;

        let calls = Arc::new(AtomicU32::new(0));
        let calls_cl = Arc::clone(&calls);
        let rotate_fn: RotateFn = Arc::new(move || {
            let c = Arc::clone(&calls_cl);
            Box::pin(async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(Credential {
                    bytes: b"new".to_vec(),
                    kind: CredentialKind::Bearer,
                    expires_at: None,
                })
            })
        });
        let handle = RotationLoop::new(Arc::clone(&store), rotate_fn, RotationConfig::default())
            .spawn();

        // Let the spawned task load + park before advancing.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        // Advance time by an hour — bearer must not trigger rotation.
        tokio::time::advance(Duration::from_secs(3600)).await;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(handle);
    }

    #[tokio::test(start_paused = true)]
    async fn rotation_loop_fires_on_expiry_minus_lead() {
        let store: Arc<dyn CredentialStore> = Arc::new(InMemoryStore::default());
        let lead = Duration::from_secs(60);
        let expires_in = Duration::from_secs(600);
        let expires_at = SystemTime::now() + expires_in;
        store
            .save(Credential {
                bytes: b"mac".to_vec(),
                kind: CredentialKind::Macaroon,
                expires_at: Some(expires_at),
            })
            .await;

        let calls = Arc::new(AtomicU32::new(0));
        let calls_cl = Arc::clone(&calls);
        let rotate_fn: RotateFn = Arc::new(move || {
            let c = Arc::clone(&calls_cl);
            Box::pin(async move {
                c.fetch_add(1, Ordering::SeqCst);
                // Return a credential whose expiry is far in the future
                // so the next loop iteration sleeps until shutdown rather
                // than spinning the test.
                let next = SystemTime::now() + Duration::from_secs(86_400);
                Ok(Credential {
                    bytes: b"rotated".to_vec(),
                    kind: CredentialKind::Macaroon,
                    expires_at: Some(next),
                })
            })
        });

        let handle = RotationLoop::new(
            Arc::clone(&store),
            rotate_fn,
            RotationConfig { lead },
        )
        .spawn();

        // Let the spawned task load + install its sleep before advancing.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        // Advance past expires_at - lead so the sleep fires.
        tokio::time::advance(expires_in - lead + Duration::from_secs(1)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            calls.load(Ordering::SeqCst) >= 1,
            "expected at least one rotate call"
        );
        let stored = store.load().await.unwrap();
        assert_eq!(stored.bytes, b"rotated");
        drop(handle);
    }

    #[tokio::test(start_paused = true)]
    async fn rotation_loop_retries_on_error() {
        let store: Arc<dyn CredentialStore> = Arc::new(InMemoryStore::default());
        let expires_in = Duration::from_secs(600);
        let expires_at = SystemTime::now() + expires_in;
        store
            .save(Credential {
                bytes: b"mac".to_vec(),
                kind: CredentialKind::Macaroon,
                expires_at: Some(expires_at),
            })
            .await;

        let calls = Arc::new(AtomicU32::new(0));
        let calls_cl = Arc::clone(&calls);
        let rotate_fn: RotateFn = Arc::new(move || {
            let c = Arc::clone(&calls_cl);
            Box::pin(async move {
                let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    Err(Error::Grpc {
                        code: tonic::Code::Unavailable,
                        message: "boom".to_owned(),
                    })
                } else {
                    let next = SystemTime::now() + Duration::from_secs(86_400);
                    Ok(Credential {
                        bytes: b"finally".to_vec(),
                        kind: CredentialKind::Macaroon,
                        expires_at: Some(next),
                    })
                }
            })
        });

        let lead = Duration::from_secs(60);
        let handle = RotationLoop::new(
            Arc::clone(&store),
            rotate_fn,
            RotationConfig { lead },
        )
        .spawn();

        // Let the spawned task load + install its sleep before advancing.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        // First fire after expires_in - lead. Then two retries on
        // backoff schedule 1s, 2s before success.
        tokio::time::advance(expires_in - lead + Duration::from_secs(1)).await;
        for _ in 0..32 {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert!(
            calls.load(Ordering::SeqCst) >= 3,
            "expected at least 3 rotate calls, got {}",
            calls.load(Ordering::SeqCst)
        );
        let stored = store.load().await.unwrap();
        assert_eq!(stored.bytes, b"finally");
        drop(handle);
    }

    #[tokio::test]
    async fn unimplemented_rotate_fn_returns_grpc_unimplemented() {
        let f = unimplemented_rotate_fn();
        let err = f().await.unwrap_err();
        match err {
            Error::Grpc { code, .. } => assert_eq!(code, tonic::Code::Unimplemented),
            other => panic!("expected Grpc(Unimplemented), got {other:?}"),
        }
    }
}
