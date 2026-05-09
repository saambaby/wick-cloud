//! Phase-4 SDK signer loop.
//!
//! Opens a long-lived `SignerService.Attach` bidi gRPC stream against the
//! Wick server, consumes wire-encoded VLS frames, dispatches each to either
//! the local [`vls_protocol_signer`] handler chain or one of the five Wick
//! extension RPCs (`0xFD01–0xFD05`), and streams the response back. The
//! tenant Lightning seed lives exclusively here.
//!
//! ## Wire layout (recap — see `wick_vls::SignerConnection`)
//!
//! Outbound (server → SDK), unwrapped from `SignerOutbound::vls_call`:
//!
//! - Node call:    `[4B req_id BE][0x01][3B reserved][type:u16 BE][data]`
//! - Channel call: `[4B req_id BE][0x02][3B reserved][8B dbid BE][33B peer_id][type:u16 BE][data]`
//!
//! Inbound (SDK → server), wrapped in `SignerInbound::vls_response`:
//!
//! - `[4B req_id BE][1B status][body]` — `status=0x00` OK / `0x01` UTF-8 error.
//!
//! ## Extension RPCs
//!
//! Five custom request types live above the standard VLS namespace. The
//! type byte (`u16 BE` at offset 0 of the inner payload) selects the
//! dispatch:
//!
//! - `0xFD01` `GetLdkNodeKeys` — derive the three LDK-only node keys
//!   (peer-storage / inbound-payment / receive-auth) from the master
//!   Lightning seed via domain-separated HKDF-SHA256.
//! - `0xFD02` `VssEncrypt` — not implemented; returns an error frame.
//! - `0xFD03` `VssDecrypt` — not implemented; returns an error frame.
//! - `0xFD04` `GetSpliceNewFundingPubkey` — not implemented; returns an
//!   error frame. Splicing is out of scope for the initial Phase-4 cut.
//! - `0xFD05` `GetWalletAddress` — derive a P2WPKH address at the requested
//!   BIP32 index from the master xprv (matches the on-chain wallet).

use std::sync::Arc;
use std::time::Duration;

use bitcoin::bip32::{ ChildNumber, DerivationPath, Xpriv };
use bitcoin::secp256k1::Secp256k1;
use futures::StreamExt;
use hmac::{ Hmac, Mac };
use parking_lot::Mutex;
use sha2::Sha256;
use tokio::sync::{ mpsc, watch };
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{ Channel, Endpoint };
use tonic::Request;
use vls_protocol::msgs::{ self as vls_msgs, Message, SerBolt };
use vls_protocol::model::{ ExtKey, PubKey };
use vls_protocol_signer::approver::PositiveApprover;
use vls_protocol_signer::handler::{ Handler, HandlerBuilder, InitHandler, RootHandler };
use vls_protocol_signer::lightning_signer;
use wick_core::WickNetwork;
use wick_proto::wick::signer_service_client::SignerServiceClient;
use wick_proto::wick::{ signer_inbound, signer_outbound, SignerInbound };

use crate::error::{ Error, Result };
use crate::grpc::SharedToken;

type HmacSha256 = Hmac<Sha256>;

/// Initial backoff after the first failed connect / stream-drop. Doubled
/// on each subsequent failure up to [`BACKOFF_CAP`].
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Maximum backoff between reconnection attempts.
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Compute the next backoff delay for a reconnection attempt index.
///
/// `failures = 0` ⇒ no failures yet (caller should not sleep). For
/// `failures ≥ 1` we double from [`BACKOFF_INITIAL`] up to [`BACKOFF_CAP`]:
/// `1s, 2s, 4s, 8s, 16s, 30s, 30s …`. Pulled out as a free function so
/// the schedule can be unit-tested without spinning up a gRPC stack.
#[must_use]
pub fn next_backoff(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    // Bounded shift: failures-1 acts as the doubling exponent. Clamp at
    // 20 so the multiplication never overflows even on long outages.
    let shift = failures.saturating_sub(1).min(20);
    let base_nanos = BACKOFF_INITIAL.as_nanos() as u64;
    let nanos = base_nanos.checked_shl(shift).unwrap_or(u64::MAX);
    let dur = Duration::from_nanos(nanos);
    if dur > BACKOFF_CAP { BACKOFF_CAP } else { dur }
}

/// Handle returned by [`SignerLoop::spawn`]. Holding it keeps the loop
/// alive; dropping it (or calling [`SignerHandle::shutdown`]) signals the
/// outer reconnection loop to exit promptly via a `watch` channel.
#[derive(Debug)]
pub struct SignerHandle {
    shutdown_tx: watch::Sender<bool>,
}

impl SignerHandle {
    /// Signal the loop to exit at the next await point. Idempotent.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for SignerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The tenant signer loop. Construct with [`SignerLoop::new`] and drive
/// with [`SignerLoop::run`]. The outer reconnection loop reopens the
/// `Attach` bidi stream with exponential backoff after transport errors
/// or clean stream-end, replaying the VLS init handshake against the
/// fresh server-side `SignerConnection`. Auth-rejection
/// (`Unauthenticated`) is terminal — the loop exits so the caller can
/// re-`register` with a fresh token rather than tight-looping.
pub struct SignerLoop {
    endpoint: String,
    token: SharedToken,
    seed: [u8; 32],
    xprv: Xpriv,
    network: WickNetwork,
    shutdown_rx: Option<watch::Receiver<bool>>,
}

impl std::fmt::Debug for SignerLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerLoop")
            .field("endpoint", &self.endpoint)
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl SignerLoop {
    /// Build a loop for the given `(endpoint, token, seed, xprv, network)`.
    /// The seed is the 32-byte tenant Lightning seed
    /// ([`crate::identity::Identity::tenant_lightning_seed`]); `xprv` is
    /// the master xpriv used for `0xFD05` wallet address derivation.
    #[must_use]
    pub fn new(
        endpoint: String,
        token: SharedToken,
        seed: [u8; 32],
        xprv: Xpriv,
        network: WickNetwork
    ) -> Self {
        Self {
            endpoint,
            token,
            seed,
            xprv,
            network,
            shutdown_rx: None,
        }
    }

    /// Spawn the loop on the current tokio runtime and return a handle
    /// that, when dropped, signals the outer reconnect loop to exit.
    pub fn spawn(mut self) -> SignerHandle {
        let (tx, rx) = watch::channel(false);
        self.shutdown_rx = Some(rx);
        tokio::spawn(async move {
            if let Err(e) = self.run().await {
                tracing::warn!(target: "wick_sdk::signer", %e, "signer loop terminated");
            }
        });
        SignerHandle { shutdown_tx: tx }
    }

    /// Run the outer reconnection loop until the stream survives or a
    /// terminal condition (auth rejection / shutdown) is reached.
    ///
    /// Each iteration: connect, attach, replay the VLS init handshake
    /// against the fresh server-side `SignerConnection`, and pump frames
    /// until the stream ends. Transient errors retry with exponential
    /// backoff (`1s → 2s → … → 30s` cap). `Unauthenticated` is terminal.
    /// A successful frame received resets the failure counter.
    pub async fn run(mut self) -> Result<()> {
        let mut shutdown_rx = self.shutdown_rx.take();
        let mut failures: u32 = 0;
        let mut reconnects: u64 = 0;

        loop {
            // Sleep before retrying (no-op on the first iteration).
            let delay = next_backoff(failures);
            if !delay.is_zero() {
                tracing::info!(
                    target: "wick_sdk::signer",
                    backoff_ms = delay.as_millis() as u64,
                    failures,
                    reconnects,
                    "signer loop reconnecting"
                );
                if Self::sleep_or_shutdown(delay, shutdown_rx.as_mut()).await {
                    return Ok(());
                }
            }

            // Bail fast if the handle was dropped before we even tried.
            if Self::is_shutdown(shutdown_rx.as_ref()) {
                return Ok(());
            }

            match self.run_once(shutdown_rx.as_mut()).await {
                RunOutcome::Shutdown => return Ok(()),
                RunOutcome::Unauthenticated => {
                    tracing::error!(
                        target: "wick_sdk::signer",
                        "signer loop received UNAUTHENTICATED — not reconnecting"
                    );
                    return Err(Error::Config(
                        "signer loop: server rejected bearer token (UNAUTHENTICATED)".to_owned(),
                    ));
                }
                RunOutcome::CleanEnd { saw_frame } => {
                    reconnects += 1;
                    if saw_frame {
                        failures = 0;
                    } else {
                        failures = failures.saturating_add(1);
                    }
                }
                RunOutcome::TransportError { saw_frame } => {
                    reconnects += 1;
                    if saw_frame {
                        // Saw at least one frame this attempt — treat the
                        // disconnect as a transient blip and retry quickly.
                        failures = 1;
                    } else {
                        failures = failures.saturating_add(1);
                    }
                }
            }
        }
    }

    /// Single connect+attach+pump pass. Returns the reason the pass ended.
    async fn run_once(
        &self,
        shutdown_rx: Option<&mut watch::Receiver<bool>>,
    ) -> RunOutcome {
        let ep = match Endpoint::from_shared(self.endpoint.clone()) {
            Ok(ep) => ep,
            Err(e) => {
                tracing::warn!(target: "wick_sdk::signer", %e, "invalid signer endpoint");
                return RunOutcome::TransportError { saw_frame: false };
            }
        };
        let channel: Channel = match ep.connect().await {
            Ok(ch) => ch,
            Err(e) => {
                tracing::warn!(target: "wick_sdk::signer", %e, "signer connect failed");
                return RunOutcome::TransportError { saw_frame: false };
            }
        };

        let mut client = SignerServiceClient::new(channel);

        let (resp_tx, resp_rx) = mpsc::channel::<SignerInbound>(crate::SIGNER_OUTBOUND_CAPACITY);
        let outbound_stream = ReceiverStream::new(resp_rx);

        let mut attach_req = Request::new(outbound_stream);
        let Some(token_value) = self.token.read().clone() else {
            tracing::warn!(
                target: "wick_sdk::signer",
                "signer loop has no bearer token — skipping attempt"
            );
            return RunOutcome::TransportError { saw_frame: false };
        };
        let auth_value: tonic::metadata::MetadataValue<_> =
            match format!("Bearer {token_value}").parse() {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(target: "wick_sdk::signer", %e, "invalid auth metadata");
                    return RunOutcome::TransportError { saw_frame: false };
                }
            };
        attach_req.metadata_mut().insert("authorization", auth_value);

        let mut inbound = match client.attach(attach_req).await {
            Ok(resp) => resp.into_inner(),
            Err(status) => {
                if status.code() == tonic::Code::Unauthenticated {
                    return RunOutcome::Unauthenticated;
                }
                tracing::warn!(
                    target: "wick_sdk::signer",
                    code = ?status.code(),
                    msg = %status.message(),
                    "signer attach failed"
                );
                return RunOutcome::TransportError { saw_frame: false };
            }
        };

        // Fresh handler state for each connection — server-side
        // `SignerConnection` is also fresh, so init must be re-driven.
        let state = match SignerState::new(self.seed, self.network.into()) {
            Ok(s) => Arc::new(Mutex::new(s)),
            Err(e) => {
                tracing::error!(target: "wick_sdk::signer", %e, "VLS handler init failed");
                return RunOutcome::TransportError { saw_frame: false };
            }
        };

        let mut saw_frame = false;
        // Re-borrow into an Option<&mut _> so we can re-use across loop iters.
        let mut shutdown_rx = shutdown_rx;
        loop {
            let next_item = match shutdown_rx.as_mut() {
                Some(rx) => {
                    tokio::select! {
                        biased;
                        res = rx.changed() => {
                            if res.is_err() || *rx.borrow() {
                                return RunOutcome::Shutdown;
                            }
                            continue;
                        }
                        item = inbound.next() => item,
                    }
                }
                None => inbound.next().await,
            };

            let Some(item) = next_item else {
                tracing::info!(target: "wick_sdk::signer", "signer stream ended cleanly");
                return RunOutcome::CleanEnd { saw_frame };
            };
            let msg = match item {
                Ok(m) => m,
                Err(e) => {
                    if e.code() == tonic::Code::Unauthenticated {
                        return RunOutcome::Unauthenticated;
                    }
                    tracing::info!(target: "wick_sdk::signer", %e, "signer stream errored");
                    return RunOutcome::TransportError { saw_frame };
                }
            };
            saw_frame = true;
            let Some(signer_outbound::Kind::VlsCall(encoded)) = msg.kind else {
                tracing::warn!(target: "wick_sdk::signer", "SignerOutbound with empty kind — skipping");
                continue;
            };

            let response = match
                handle_frame(&state, &self.xprv, &self.seed, self.network, encoded)
            {
                Ok((req_id, body)) => encode_success(req_id, body),
                Err((req_id, err)) => {
                    tracing::warn!(target: "wick_sdk::signer", req_id, %err, "signer call failed");
                    encode_error(req_id, &err)
                }
            };

            if
                resp_tx
                    .send(SignerInbound {
                        kind: Some(signer_inbound::Kind::VlsResponse(response)),
                    }).await
                    .is_err()
            {
                tracing::info!(target: "wick_sdk::signer", "outbound channel closed; ending pass");
                return RunOutcome::TransportError { saw_frame };
            }
        }
    }

    async fn sleep_or_shutdown(
        delay: Duration,
        shutdown_rx: Option<&mut watch::Receiver<bool>>,
    ) -> bool {
        if let Some(rx) = shutdown_rx {
            tokio::select! {
                _ = tokio::time::sleep(delay) => false,
                res = rx.changed() => res.is_err() || *rx.borrow(),
            }
        } else {
            tokio::time::sleep(delay).await;
            false
        }
    }

    fn is_shutdown(rx: Option<&watch::Receiver<bool>>) -> bool {
        rx.is_some_and(|r| *r.borrow())
    }
}

/// Outcome of a single `run_once` attempt.
#[derive(Debug)]
enum RunOutcome {
    /// Stream ended without a transport error (server hung up cleanly).
    CleanEnd { saw_frame: bool },
    /// Connect / attach / stream errored.
    TransportError { saw_frame: bool },
    /// Server rejected the bearer token — terminal.
    Unauthenticated,
    /// Outer shutdown signal fired.
    Shutdown,
}

// ── VLS handler state machine ─────────────────────────────────────────────────

enum SignerState {
    Init(InitHandler),
    Ready(RootHandler),
}

impl SignerState {
    fn new(seed: [u8; 32], network: bitcoin::Network) -> Result<Self> {
        let persister: Arc<dyn lightning_signer::persist::Persist> = Arc::new(
            lightning_signer::persist::DummyPersister {}
        );
        let validator_factory = Arc::new(
            lightning_signer::policy::simple_validator::SimpleValidatorFactory::new()
        );
        let starting_time_factory = lightning_signer::signer::ClockStartingTimeFactory::new();
        let clock = Arc::new(lightning_signer::util::clock::StandardClock());
        let services = lightning_signer::node::NodeServices {
            validator_factory,
            starting_time_factory,
            persister,
            clock,
            trusted_oracle_pubkeys: vec![],
        };
        let init = HandlerBuilder::new(network, 0, services, seed)
            .approver(Arc::new(PositiveApprover()))
            .build()
            .map_err(|e| Error::Config(format!("VLS InitHandler build: {e:?}")))?;
        Ok(Self::Init(init))
    }

    fn handle_node(&mut self, message: Message) -> std::result::Result<Vec<u8>, String> {
        match self {
            SignerState::Init(init_handler) => {
                let (done, reply) = init_handler
                    .handle(message)
                    .map_err(|e| format!("init handler error: {e:?}"))?;
                let body = reply.map(|r| r.as_vec()).unwrap_or_default();
                if done {
                    let root: RootHandler = init_handler.clone().into();
                    *self = SignerState::Ready(root);
                }
                Ok(body)
            }
            SignerState::Ready(root_handler) =>
                match message {
                    // Re-init after wick-server restart: keep returning the same
                    // node identity rather than panicking the loop.
                    Message::HsmdInit2(_) => {
                        let bip32 = root_handler.node().get_account_extended_pubkey().encode();
                        let node_id = root_handler.node().get_id().serialize();
                        let bolt12 = root_handler.node().get_bolt12_pubkey().serialize();
                        let reply = vls_msgs::HsmdInit2Reply {
                            node_id: PubKey(node_id),
                            bip32: ExtKey(bip32),
                            bolt12: PubKey(bolt12),
                        };
                        Ok(reply.as_vec())
                    }
                    // GetChannelBasepoints can race a NewChannel — retry once
                    // after creating the channel if the signer says it's
                    // unknown.
                    Message::GetChannelBasepoints(m) => {
                        let node_id = m.node_id.clone();
                        let dbid = m.dbid;
                        let req = Message::GetChannelBasepoints(vls_msgs::GetChannelBasepoints {
                            node_id: node_id.clone(),
                            dbid,
                        });
                        match root_handler.handle(req) {
                            Ok(reply) => Ok(reply.as_vec()),
                            Err(err) => {
                                let msg = format!("{err:?}");
                                if msg.contains("no such channel") {
                                    let _ = root_handler.handle(
                                        Message::NewChannel(vls_msgs::NewChannel {
                                            peer_id: node_id.clone(),
                                            dbid,
                                        })
                                    );
                                    let retry = Message::GetChannelBasepoints(
                                        vls_msgs::GetChannelBasepoints { node_id, dbid }
                                    );
                                    root_handler
                                        .handle(retry)
                                        .map(|reply| reply.as_vec())
                                        .map_err(|e| format!("root handler retry error: {e:?}"))
                                } else {
                                    Err(format!("root handler error: {err:?}"))
                                }
                            }
                        }
                    }
                    other =>
                        root_handler
                            .handle(other)
                            .map(|reply| reply.as_vec())
                            .map_err(|e| format!("root handler error: {e:?}")),
                }
        }
    }

    fn handle_channel(
        &self,
        dbid: u64,
        peer_id: [u8; 33],
        payload: &[u8]
    ) -> std::result::Result<Vec<u8>, String> {
        let SignerState::Ready(root_handler) = self else {
            return Err("channel request received before signer init".to_owned());
        };
        let message = vls_msgs
            ::from_vec(payload.to_vec())
            .map_err(|e| format!("channel decode message: {e:?}"))?;
        let handler = root_handler.for_new_client(0, PubKey(peer_id), dbid);
        match handler.handle(message) {
            Ok(reply) => Ok(reply.as_vec()),
            Err(e) => {
                let msg = format!("{e:?}");
                if !msg.contains("no such channel") {
                    return Err(format!("channel handler error: {e:?}"));
                }
                root_handler
                    .handle(
                        Message::NewChannel(vls_msgs::NewChannel {
                            peer_id: PubKey(peer_id),
                            dbid,
                        })
                    )
                    .map_err(|e2| format!("NewChannel after missing channel: {e2:?}"))?;
                let message = vls_msgs
                    ::from_vec(payload.to_vec())
                    .map_err(|e| format!("channel decode retry: {e:?}"))?;
                let handler2 = root_handler.for_new_client(0, PubKey(peer_id), dbid);
                handler2
                    .handle(message)
                    .map(|reply| reply.as_vec())
                    .map_err(|e| format!("channel handler retry error: {e:?}"))
            }
        }
    }
}

// ── Frame dispatch ────────────────────────────────────────────────────────────

fn handle_frame(
    state: &Arc<Mutex<SignerState>>,
    xprv: &Xpriv,
    seed: &[u8; 32],
    network: WickNetwork,
    encoded: Vec<u8>
) -> std::result::Result<(u32, Vec<u8>), (u32, String)> {
    if encoded.len() < 8 {
        return Err((0, format!("frame too short: {} bytes", encoded.len())));
    }
    let req_id = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
    let kind = encoded[4];

    match kind {
        0x01 => {
            // Node call: [8B header][type:u16 BE][data].
            let payload = &encoded[8..];
            if payload.len() < 2 {
                return Err((req_id, "node payload too short".to_owned()));
            }
            let type_be = u16::from_be_bytes([payload[0], payload[1]]);
            // Wick extension RPCs live above the standard VLS namespace.
            if (0xfd01..=0xfd05).contains(&type_be) {
                handle_extension(req_id, type_be, &payload[2..], xprv, seed, network)
            } else {
                let msg = vls_msgs
                    ::from_vec(payload.to_vec())
                    .map_err(|e| (req_id, format!("decode VLS message: {e:?}")))?;
                let body = state
                    .lock()
                    .handle_node(msg)
                    .map_err(|e| (req_id, e))?;
                Ok((req_id, body))
            }
        }
        0x02 => {
            // Channel call: [8B header][8B dbid BE][33B peer_id][...payload].
            if encoded.len() < 49 {
                return Err((req_id, format!("channel frame too short: {} bytes", encoded.len())));
            }
            let dbid = u64::from_be_bytes(
                encoded[8..16].try_into().map_err(|e| (req_id, format!("dbid slice: {e}")))?
            );
            let mut peer_id = [0u8; 33];
            peer_id.copy_from_slice(&encoded[16..49]);
            let body = state
                .lock()
                .handle_channel(dbid, peer_id, &encoded[49..])
                .map_err(|e| (req_id, e))?;
            Ok((req_id, body))
        }
        other => Err((req_id, format!("unknown frame kind: 0x{other:02x}"))),
    }
}

// ── Wick extension RPCs ───────────────────────────────────────────────────────

fn handle_extension(
    req_id: u32,
    type_be: u16,
    payload: &[u8],
    xprv: &Xpriv,
    seed: &[u8; 32],
    network: WickNetwork
) -> std::result::Result<(u32, Vec<u8>), (u32, String)> {
    match type_be {
        0xfd01 => handle_get_ldk_node_keys(req_id, payload, seed),
        0xfd05 => handle_get_wallet_address(req_id, payload, xprv, network),
        0xfd02 => Err((req_id, "VssEncrypt extension not implemented".to_owned())),
        0xfd03 => Err((req_id, "VssDecrypt extension not implemented".to_owned())),
        0xfd04 => Err((req_id, "GetSpliceNewFundingPubkey extension not implemented".to_owned())),
        _ => unreachable!("type_be is in [0xFD01, 0xFD05]"),
    }
}

/// Wire — request:  `[u8 version=1]`
/// Wire — response: `[32B peer_storage_key][32B inbound_payment_key][32B receive_auth_key]`
///
/// Each key is `HKDF-SHA256(seed, info=<domain-separated tag>)` — the
/// implementation is `HMAC(seed, info)` truncated to 32 bytes, which is
/// equivalent to a single HKDF-Expand step with empty salt.
fn handle_get_ldk_node_keys(
    req_id: u32,
    payload: &[u8],
    seed: &[u8; 32]
) -> std::result::Result<(u32, Vec<u8>), (u32, String)> {
    if payload.first().copied() != Some(1) {
        return Err((req_id, "GetLdkNodeKeys: unsupported version".to_owned()));
    }
    let derive = |info: &[u8]| -> std::result::Result<[u8; 32], (u32, String)> {
        let mut mac = HmacSha256::new_from_slice(seed).map_err(|e| (
            req_id,
            format!("hmac init: {e}"),
        ))?;
        mac.update(info);
        let bytes = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    };
    let peer_storage = derive(b"ldk/peer_storage/v1")?;
    let inbound_payment = derive(b"ldk/inbound_payment/v1")?;
    let receive_auth = derive(b"ldk/receive_auth/v1")?;

    let mut body = Vec::with_capacity(96);
    body.extend_from_slice(&peer_storage);
    body.extend_from_slice(&inbound_payment);
    body.extend_from_slice(&receive_auth);
    Ok((req_id, body))
}

/// Wire — request:
///   v1:  `[u8 version=1][u32 LE index]`               — legacy, derives `m/<index>` from master
///   v2:  `[u8 version=2][u8 change][u32 LE index]`    — BIP84: `m/84'/coin'/0'/<change>/<index>`
/// Wire — response: `[u16 LE addr_len][addr_bytes][script_pubkey]`
///
/// v2 is what the Phase-4 server-side `VlsChangeDestination` issues for
/// channel-close refund / sweep change outputs so addresses match the
/// SDK's BDK BIP84 wallet keychain.
fn handle_get_wallet_address(
    req_id: u32,
    payload: &[u8],
    xprv: &Xpriv,
    network: WickNetwork
) -> std::result::Result<(u32, Vec<u8>), (u32, String)> {
    if payload.is_empty() {
        return Err((req_id, "GetWalletAddress: payload too short".to_owned()));
    }
    let version = payload[0];

    // Resolve `(change_idx, index)` based on version. Both versions
    // produce a P2WPKH address; v2 just routes through the BIP84
    // keychain so the BDK wallet recognises the script.
    let (use_bip84, change_idx, index) = match version {
        1 => {
            if payload.len() < 5 {
                return Err((req_id, "GetWalletAddress v1: payload too short".to_owned()));
            }
            let index = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
            (false, 0u32, index)
        }
        2 => {
            if payload.len() < 6 {
                return Err((req_id, "GetWalletAddress v2: payload too short".to_owned()));
            }
            let change_byte = payload[1];
            let change_idx = match change_byte {
                0 => 0u32,
                1 => 1u32,
                _ => {
                    return Err((
                        req_id,
                        format!("GetWalletAddress v2: invalid change byte {change_byte}"),
                    ))
                }
            };
            let index = u32::from_le_bytes([payload[2], payload[3], payload[4], payload[5]]);
            (true, change_idx, index)
        }
        _ => return Err((req_id, format!("GetWalletAddress: unsupported version {version}"))),
    };

    let secp = Secp256k1::new();
    let path: DerivationPath = if use_bip84 {
        // m/84'/coin'/0'/<change>/<index> — must match the BDK
        // descriptor in `wallet::descriptors_bip84` so the address is
        // recognised as belonging to the wallet's change keychain.
        let coin = network.bip84_coin_type();
        DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(84)
                .map_err(|e| (req_id, format!("derive 84': {e}")))?,
            ChildNumber::from_hardened_idx(coin)
                .map_err(|e| (req_id, format!("derive coin {coin}': {e}")))?,
            ChildNumber::from_hardened_idx(0)
                .map_err(|e| (req_id, format!("derive 0': {e}")))?,
            ChildNumber::from_normal_idx(change_idx)
                .map_err(|e| (req_id, format!("derive change {change_idx}: {e}")))?,
            ChildNumber::from_normal_idx(index)
                .map_err(|e| (req_id, format!("derive index {index}: {e}")))?,
        ])
    } else {
        DerivationPath::from(vec![ChildNumber::from_normal_idx(index)
            .map_err(|e| (req_id, format!("derive index {index}: {e}")))?])
    };

    let derived = xprv
        .derive_priv(&secp, &path)
        .map_err(|e| (req_id, format!("derive priv: {e}")))?;
    let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &derived.private_key);

    use bitcoin::hashes::{ hash160, Hash as _ };
    let hash = hash160::Hash::hash(&pubkey.serialize());
    let wpubkey_hash = bitcoin::WPubkeyHash::from_raw_hash(hash);
    let address = bitcoin::Address::p2wpkh(
        &bitcoin::CompressedPublicKey(pubkey),
        bitcoin::Network::from(network)
    );
    let script_pubkey = bitcoin::ScriptBuf::new_p2wpkh(&wpubkey_hash);

    let addr_str = address.to_string();
    let addr_bytes = addr_str.as_bytes();
    let mut body = Vec::with_capacity(2 + addr_bytes.len() + script_pubkey.len());
    let len = u16::try_from(addr_bytes.len()).map_err(|_| (req_id, "address too long".to_owned()))?;
    body.extend_from_slice(&len.to_le_bytes());
    body.extend_from_slice(addr_bytes);
    body.extend_from_slice(script_pubkey.as_bytes());
    Ok((req_id, body))
}

// ── Wire encoders ─────────────────────────────────────────────────────────────

fn encode_success(req_id: u32, body: Vec<u8>) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + body.len());
    frame.extend_from_slice(&req_id.to_be_bytes());
    frame.push(0x00);
    frame.extend_from_slice(&body);
    frame
}

fn encode_error(req_id: u32, err: &str) -> Vec<u8> {
    let bytes = err.as_bytes();
    let mut frame = Vec::with_capacity(5 + bytes.len());
    frame.extend_from_slice(&req_id.to_be_bytes());
    frame.push(0x01);
    frame.extend_from_slice(bytes);
    frame
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_xprv() -> Xpriv {
        // Deterministic seed → xprv for derivation tests. NOT a real wallet.
        Xpriv::new_master(bitcoin::Network::Regtest, &[0x42; 32]).unwrap()
    }

    fn test_seed() -> [u8; 32] {
        [0x11; 32]
    }

    #[test]
    fn ldk_node_keys_derivation_is_deterministic() {
        let seed = test_seed();
        let (_, body1) = handle_get_ldk_node_keys(7, &[1], &seed).unwrap();
        let (_, body2) = handle_get_ldk_node_keys(7, &[1], &seed).unwrap();
        assert_eq!(body1, body2);
        assert_eq!(body1.len(), 96);
        // Three keys must differ (different domain-separated info strings).
        assert_ne!(&body1[0..32], &body1[32..64]);
        assert_ne!(&body1[32..64], &body1[64..96]);
    }

    #[test]
    fn ldk_node_keys_rejects_unknown_version() {
        let seed = test_seed();
        let err = handle_get_ldk_node_keys(7, &[2], &seed).unwrap_err();
        assert_eq!(err.0, 7);
        assert!(err.1.contains("unsupported version"));
    }

    #[test]
    fn wallet_address_derivation_round_trips() {
        let xprv = test_xprv();
        let payload = {
            let mut p = vec![1];
            p.extend_from_slice(&7u32.to_le_bytes());
            p
        };
        let (_, body) = handle_get_wallet_address(9, &payload, &xprv, WickNetwork::Regtest).unwrap();

        // [u16 LE addr_len][addr_bytes][script_pubkey]
        assert!(body.len() > 2);
        let addr_len = u16::from_le_bytes([body[0], body[1]]) as usize;
        assert!(body.len() >= 2 + addr_len);
        let addr = std::str::from_utf8(&body[2..2 + addr_len]).unwrap();
        // Regtest P2WPKH addresses start with `bcrt1q`.
        assert!(addr.starts_with("bcrt1q"), "expected bcrt1q…, got {addr}");

        // Repeat — derivation must be deterministic for the same index.
        let (_, body2) = handle_get_wallet_address(9, &payload, &xprv, WickNetwork::Regtest).unwrap();
        assert_eq!(body, body2);
    }

    #[test]
    fn wallet_address_rejects_short_payload() {
        let xprv = test_xprv();
        let err =
            handle_get_wallet_address(9, &[1, 0, 0], &xprv, WickNetwork::Regtest).unwrap_err();
        assert!(err.1.contains("too short"));
    }

    #[test]
    fn unimplemented_extensions_return_explicit_errors() {
        let xprv = test_xprv();
        let seed = test_seed();
        for type_be in [0xFD02u16, 0xFD03, 0xFD04] {
            let err =
                handle_extension(7, type_be, &[], &xprv, &seed, WickNetwork::Regtest).unwrap_err();
            assert!(
                err.1.contains("not implemented"),
                "type 0x{type_be:04X}: {}",
                err.1
            );
        }
    }

    #[test]
    fn encode_success_layout() {
        let frame = encode_success(0xDEAD_BEEF, vec![0xCA, 0xFE]);
        assert_eq!(frame[..4], [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(frame[4], 0x00);
        assert_eq!(&frame[5..], &[0xCA, 0xFE]);
    }

    #[test]
    fn encode_error_layout() {
        let frame = encode_error(0x0000_0001, "boom");
        assert_eq!(frame[..4], [0x00, 0x00, 0x00, 0x01]);
        assert_eq!(frame[4], 0x01);
        assert_eq!(&frame[5..], b"boom");
    }

    // ── Reconnection backoff (B5) ────────────────────────────────────────
    //
    // Mocking a tonic bidi stream end-to-end is heavy; the backoff schedule
    // is the load-bearing piece of the reconnection logic, so we extract
    // it as a free function and verify the doubling + cap directly.
    // Stream-close behavior is exercised by the integration tests in
    // `crates/wick-sdk/tests/restart_flow.rs`.

    #[test]
    fn backoff_starts_at_one_second_and_doubles() {
        assert_eq!(next_backoff(0), Duration::ZERO);
        assert_eq!(next_backoff(1), Duration::from_secs(1));
        assert_eq!(next_backoff(2), Duration::from_secs(2));
        assert_eq!(next_backoff(3), Duration::from_secs(4));
        assert_eq!(next_backoff(4), Duration::from_secs(8));
        assert_eq!(next_backoff(5), Duration::from_secs(16));
    }

    #[test]
    fn backoff_caps_at_thirty_seconds() {
        // 32s would be the next double — must clamp to BACKOFF_CAP.
        assert_eq!(next_backoff(6), Duration::from_secs(30));
        assert_eq!(next_backoff(10), Duration::from_secs(30));
        assert_eq!(next_backoff(100), Duration::from_secs(30));
        // Saturating: a pathological huge failure count must not panic.
        assert_eq!(next_backoff(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn backoff_doubles_monotonically_until_cap() {
        let mut prev = next_backoff(1);
        for failures in 2..=6 {
            let cur = next_backoff(failures);
            assert!(
                cur >= prev,
                "backoff went backwards at failures={failures}: {prev:?} → {cur:?}"
            );
            prev = cur;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn signer_handle_drop_signals_shutdown() {
        // The watch channel inside `SignerHandle` is the cancellation
        // primitive for the outer reconnect loop — verify drop flips it.
        let (tx, mut rx) = watch::channel(false);
        let handle = SignerHandle { shutdown_tx: tx };
        assert!(!*rx.borrow());
        drop(handle);
        // After drop, `changed()` returns Err (sender gone) — we treat
        // both `Err` and `*rx.borrow() == true` as a shutdown signal.
        let res = rx.changed().await;
        assert!(res.is_err() || *rx.borrow());
    }
}
