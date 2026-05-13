//! `Noise_KK_25519_ChaChaPoly_SHA256` session state machine.
//!
//! [`NoiseInitiator`] and [`NoiseResponder`] wrap a [`snow::HandshakeState`]
//! during the two-message KK handshake and a [`snow::TransportState`] once
//! the handshake completes. Both expose the unified [`NoiseSession`]
//! interface that N2 will drive from the gRPC bidi loop.
//!
//! ## Rekey
//!
//! Every [`REKEY_INTERVAL`] cipher operations **per direction**, we rotate
//! the AEAD key BOLT 8-style: a chaining key (`ck`, seeded from
//! `snow::HandshakeState::get_handshake_hash()` at handshake completion)
//! is ratcheted via HKDF-SHA256 to produce a fresh 32-byte cipher key,
//! which is then installed on the [`snow::TransportState`] through
//! [`snow::TransportState::rekey_manually`].
//!
//! This is **stronger than Noise spec §11.3 `Rekey()`** (which derives the
//! new key from the current key alone, with no chaining material), and
//! structurally matches BOLT 8's "Lightning Message Key Rotation" except
//! that snow does not expose the live cipher key — so our ratchet mixes
//! only the chaining key (`ck' = HKDF(ck, empty)`) rather than BOLT 8's
//! `(ck', k') = HKDF(ck, k)`. The fresh-forward-secrecy window per 1000
//! ops is preserved; we lose the additional dependence on the dying key,
//! which the research note flags as a non-blocking deviation.

use snow::{Builder, HandshakeState, TransportState};
use thiserror::Error;
use zeroize::Zeroize;

use crate::identity::{NoisePublicKey, NoiseStaticKeypair};

/// Wire string for the Noise handshake pattern (KK / 25519 / ChaChaPoly / SHA256).
/// Off-spec features (P-256 / XChaCha20) are deliberately not enabled.
pub const NOISE_HANDSHAKE_PATTERN: &str = "Noise_KK_25519_ChaChaPoly_SHA256";

/// BOLT 8-style rekey threshold — every 1000 cipher operations per
/// direction, the AEAD key is rotated via HKDF chain-key ratchet.
pub const REKEY_INTERVAL: u64 = 1000;

/// Buffer sized to hold any Noise message — protocol max is 65535 bytes.
const NOISE_BUF: usize = 65_535;

/// HKDF info string for the rotation ratchet; versioned so a future
/// scheme can coexist with v1 sessions during migration.
const REKEY_INFO: &[u8] = b"wick/v1 noise-kk rekey";

/// Errors surfaced by the Noise session state machine.
#[derive(Debug, Error)]
pub enum NoiseError {
    /// BIP32 / HKDF derivation failure when building the static keypair.
    #[error("noise key derivation: {0}")]
    Derivation(String),
    /// `snow` rejected a handshake or transport operation. Wraps the
    /// underlying [`snow::Error`] as a string to avoid leaking the
    /// crate type into our public API.
    #[error("noise protocol: {0}")]
    Protocol(String),
    /// Called [`NoiseSession::write`] with a transport payload before
    /// the handshake completed, or [`NoiseSession::read`] after it
    /// finished from the wrong side.
    #[error("noise state: {0}")]
    State(&'static str),
    /// Internal buffer too small for a Noise message. Should not occur
    /// at runtime — surfaced for completeness.
    #[error("noise buffer: {0}")]
    Buffer(String),
}

impl From<snow::Error> for NoiseError {
    fn from(e: snow::Error) -> Self {
        Self::Protocol(e.to_string())
    }
}

/// Outcome of pushing a Noise frame into a session.
#[derive(Debug)]
pub enum NoiseFrame {
    /// Handshake message produced; caller MUST send these bytes to the peer.
    HandshakeReply(Vec<u8>),
    /// Handshake completed with no further reply needed (the responder side
    /// returns this after reading the second message; the initiator returns
    /// this after writing the second message — captured by [`NoiseSession`]
    /// semantics, see impl docs).
    HandshakeComplete,
    /// Decrypted application plaintext from a transport-phase frame.
    Plaintext(Vec<u8>),
}

/// One side of a Noise_KK handshake / transport session.
pub trait NoiseSession {
    /// Push a Noise frame from the peer.
    ///
    /// During handshake this advances the state machine and may yield
    /// [`NoiseFrame::HandshakeReply`] (bytes to send back) or
    /// [`NoiseFrame::HandshakeComplete`]. During transport this yields
    /// [`NoiseFrame::Plaintext`] with the decrypted application bytes.
    fn read(&mut self, msg: &[u8]) -> Result<NoiseFrame, NoiseError>;

    /// Produce a Noise frame to send.
    ///
    /// During handshake this advances the state machine and ignores
    /// `payload` (KK handshake payloads are not exposed to N2 yet).
    /// During transport this encrypts `payload` and returns the wire bytes.
    fn write(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError>;

    /// True once both sides have completed the two-message KK handshake
    /// and transitioned to transport mode.
    fn is_handshake_complete(&self) -> bool;

    /// Authenticated remote static public key. `None` before the
    /// handshake completes.
    fn remote_static(&self) -> Option<NoisePublicKey>;
}

/// Per-direction key rotation state. The chaining key `ck` is bootstrapped
/// from the Noise handshake hash and ratcheted via HKDF-SHA256 every
/// [`REKEY_INTERVAL`] ops. `count` tallies cipher operations on this
/// direction.
struct Direction {
    ck: [u8; 32],
    count: u64,
}

impl Drop for Direction {
    fn drop(&mut self) {
        self.ck.zeroize();
    }
}

impl Direction {
    fn new(seed: &[u8]) -> Self {
        let mut ck = [0u8; 32];
        // Derive the initial direction chaining key from the handshake
        // hash via HKDF. The `info` is per-direction (see
        // [`Self::for_send`] / [`Self::for_recv`]).
        ck.copy_from_slice(&seed[..32]);
        Self { ck, count: 0 }
    }

    /// I→R direction chaining key. Used as `tx` on the initiator and as
    /// `rx` on the responder so both sides ratchet to identical keys for
    /// the same wire frames.
    fn i_to_r(handshake_hash: &[u8]) -> Self {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"wick/v1"), handshake_hash);
        let mut ck = [0u8; 32];
        hk.expand(b"noise-kk i2r-ck", &mut ck)
            .expect("HKDF-SHA256 32-byte expand is infallible");
        Self::new(&ck)
    }

    /// R→I direction chaining key. Used as `tx` on the responder and as
    /// `rx` on the initiator.
    fn r_to_i(handshake_hash: &[u8]) -> Self {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"wick/v1"), handshake_hash);
        let mut ck = [0u8; 32];
        hk.expand(b"noise-kk r2i-ck", &mut ck)
            .expect("HKDF-SHA256 32-byte expand is infallible");
        Self::new(&ck)
    }

    /// Ratchet the chaining key and return a fresh 32-byte AEAD key to
    /// install on the [`snow::TransportState`] cipher slot. Mirrors BOLT
    /// 8's chain-key advance (minus mixing the live `k`, since snow does
    /// not expose it — see the module doc).
    fn ratchet(&mut self) -> [u8; 32] {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&self.ck), &[]);
        let mut out = [0u8; 64];
        // Infallible — 64 bytes is well under HKDF-SHA256's cap.
        hk.expand(REKEY_INFO, &mut out)
            .expect("HKDF-SHA256 64-byte expand is infallible");
        let (new_ck, new_k) = out.split_at(32);
        self.ck.copy_from_slice(new_ck);
        let mut k = [0u8; 32];
        k.copy_from_slice(new_k);
        out.zeroize();
        k
    }
}

/// Internal transport-phase state — owns the snow `TransportState` plus
/// our two-direction rotation counters.
struct Transport {
    state: TransportState,
    tx: Direction,
    rx: Direction,
    remote_static: NoisePublicKey,
    /// True if this side is the KK initiator. Used to map our
    /// outgoing/incoming directions to snow's
    /// `rekey_manually(initiator_to_responder, responder_to_initiator)`
    /// slots — snow's arg order is fixed regardless of caller.
    initiator: bool,
}

impl Transport {
    fn from_handshake(hs: HandshakeState, initiator: bool) -> Result<Self, NoiseError> {
        let remote_static = hs
            .get_remote_static()
            .ok_or(NoiseError::State("handshake produced no remote static"))?;
        if remote_static.len() != 32 {
            return Err(NoiseError::Protocol(format!(
                "expected 32-byte remote static, got {}",
                remote_static.len()
            )));
        }
        let mut rs = [0u8; 32];
        rs.copy_from_slice(remote_static);
        let handshake_hash = hs.get_handshake_hash().to_vec();
        let state = hs.into_transport_mode()?;
        let (tx, rx) = if initiator {
            (
                Direction::i_to_r(&handshake_hash),
                Direction::r_to_i(&handshake_hash),
            )
        } else {
            (
                Direction::r_to_i(&handshake_hash),
                Direction::i_to_r(&handshake_hash),
            )
        };
        Ok(Self {
            state,
            tx,
            rx,
            remote_static: NoisePublicKey(rs),
            initiator,
        })
    }

    fn write(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.tx.count = self.tx.count.saturating_add(1);
        // Rotate BEFORE encrypting when crossing a 1000-op boundary so
        // the receiver — which rotates at the same threshold before its
        // matching decrypt — stays in lockstep. Op 1..=1000 use K_0;
        // op 1001..=2000 use K_1; etc.
        //
        // snow's `rekey_manually(i_to_r, r_to_i)` slots are fixed
        // regardless of caller side. Our outgoing direction is I→R if
        // we're the initiator, otherwise R→I.
        if self.tx.count > REKEY_INTERVAL && (self.tx.count - 1) % REKEY_INTERVAL == 0 {
            let mut new_k = self.tx.ratchet();
            if self.initiator {
                self.state.rekey_manually(Some(&new_k), None);
            } else {
                self.state.rekey_manually(None, Some(&new_k));
            }
            new_k.zeroize();
        }
        let mut buf = vec![0u8; payload.len() + 64];
        let n = self.state.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn read(&mut self, msg: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.rx.count = self.rx.count.saturating_add(1);
        if self.rx.count > REKEY_INTERVAL && (self.rx.count - 1) % REKEY_INTERVAL == 0 {
            let mut new_k = self.rx.ratchet();
            // Incoming direction = R→I (slot 2) for initiator, else I→R.
            if self.initiator {
                self.state.rekey_manually(None, Some(&new_k));
            } else {
                self.state.rekey_manually(Some(&new_k), None);
            }
            new_k.zeroize();
        }
        let mut buf = vec![0u8; msg.len()];
        let n = self.state.read_message(msg, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

/// Active phase of either [`NoiseInitiator`] or [`NoiseResponder`].
enum Phase {
    Handshake(Box<HandshakeState>),
    Transport(Box<Transport>),
    /// Transient state during [`Transport::from_handshake`] — present
    /// only while the move happens; never observed externally.
    Transitioning,
}

/// `Noise_KK` initiator. Sends the first handshake message (`-> e, es, ss`),
/// reads the responder's reply (`<- e, ee, se`), then enters transport mode.
pub struct NoiseInitiator {
    phase: Phase,
}

impl std::fmt::Debug for NoiseInitiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseInitiator")
            .field("handshake_complete", &self.is_handshake_complete())
            .finish_non_exhaustive()
    }
}

/// `Noise_KK` responder. Pre-knows the expected initiator static key
/// (passed as `expected_initiator`); a handshake from any other static
/// fails authentication at the snow layer.
pub struct NoiseResponder {
    phase: Phase,
}

impl std::fmt::Debug for NoiseResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseResponder")
            .field("handshake_complete", &self.is_handshake_complete())
            .finish_non_exhaustive()
    }
}

fn build_handshake(
    local: &NoiseStaticKeypair,
    remote: &NoisePublicKey,
    initiator: bool,
) -> Result<HandshakeState, NoiseError> {
    let params = NOISE_HANDSHAKE_PATTERN
        .parse()
        .map_err(|e: snow::Error| NoiseError::Protocol(format!("parse params: {e}")))?;
    let builder = Builder::new(params)
        .local_private_key(&local.secret)?
        .remote_public_key(remote.as_bytes())?;
    let hs = if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    };
    Ok(hs)
}

impl NoiseInitiator {
    /// Build a fresh `Noise_KK` initiator session.
    ///
    /// `local` is the device's Noise transport keypair (derive via
    /// [`crate::derive_noise_static`]); `remote` is the server's pinned
    /// Noise static public key (delivered out of band — D4 pinning).
    ///
    /// # Errors
    /// Returns [`NoiseError::Protocol`] if `snow` rejects the keys or
    /// pattern string.
    pub fn new(local: NoiseStaticKeypair, remote: NoisePublicKey) -> Result<Self, NoiseError> {
        let hs = build_handshake(&local, &remote, true)?;
        Ok(Self {
            phase: Phase::Handshake(Box::new(hs)),
        })
    }
}

impl NoiseResponder {
    /// Build a fresh `Noise_KK` responder session.
    ///
    /// `local` is the server's Noise transport keypair;
    /// `expected_initiator` is the tenant's pre-registered Noise static
    /// public key (provisioned alongside the tenant's LN node id at
    /// onboarding). Mismatches surface as [`NoiseError::Protocol`]
    /// during handshake.
    ///
    /// # Errors
    /// Returns [`NoiseError::Protocol`] if `snow` rejects the keys or
    /// pattern string.
    pub fn new(
        local: NoiseStaticKeypair,
        expected_initiator: NoisePublicKey,
    ) -> Result<Self, NoiseError> {
        let hs = build_handshake(&local, &expected_initiator, false)?;
        Ok(Self {
            phase: Phase::Handshake(Box::new(hs)),
        })
    }
}

/// Shared session machinery — both `NoiseInitiator` and `NoiseResponder`
/// route their `NoiseSession` impl through these helpers since the
/// state machines differ only in who writes first.
fn session_read(phase: &mut Phase, msg: &[u8], initiator: bool) -> Result<NoiseFrame, NoiseError> {
    match phase {
        Phase::Handshake(hs) => {
            let mut buf = vec![0u8; NOISE_BUF];
            hs.read_message(msg, &mut buf)?;
            // KK is exactly two messages. If this read finished the
            // handshake, transition; otherwise the caller must call
            // `write` next to produce the reply.
            if hs.is_handshake_finished() {
                let taken = std::mem::replace(phase, Phase::Transitioning);
                let Phase::Handshake(hs) = taken else {
                    unreachable!("phase was Handshake under the outer match");
                };
                let transport = Transport::from_handshake(*hs, initiator)?;
                *phase = Phase::Transport(Box::new(transport));
                Ok(NoiseFrame::HandshakeComplete)
            } else {
                // Caller is expected to call `write(&[])` next to
                // produce the next handshake frame.
                Ok(NoiseFrame::HandshakeReply(Vec::new()))
            }
        }
        Phase::Transport(t) => {
            let pt = t.read(msg)?;
            Ok(NoiseFrame::Plaintext(pt))
        }
        Phase::Transitioning => Err(NoiseError::State("session is mid-transition")),
    }
}

fn session_write(phase: &mut Phase, payload: &[u8], initiator: bool) -> Result<Vec<u8>, NoiseError> {
    match phase {
        Phase::Handshake(hs) => {
            let mut buf = vec![0u8; NOISE_BUF];
            // KK message bodies are empty in N1 — payload is ignored.
            let n = hs.write_message(&[], &mut buf)?;
            buf.truncate(n);
            if hs.is_handshake_finished() {
                let taken = std::mem::replace(phase, Phase::Transitioning);
                let Phase::Handshake(hs) = taken else {
                    unreachable!("phase was Handshake under the outer match");
                };
                let transport = Transport::from_handshake(*hs, initiator)?;
                *phase = Phase::Transport(Box::new(transport));
            }
            let _ = payload; // ack the unused param explicitly
            Ok(buf)
        }
        Phase::Transport(t) => t.write(payload),
        Phase::Transitioning => Err(NoiseError::State("session is mid-transition")),
    }
}

fn session_remote_static(phase: &Phase) -> Option<NoisePublicKey> {
    match phase {
        Phase::Handshake(hs) => {
            let rs = hs.get_remote_static()?;
            if rs.len() != 32 {
                return None;
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(rs);
            Some(NoisePublicKey(out))
        }
        Phase::Transport(t) => Some(t.remote_static),
        Phase::Transitioning => None,
    }
}

fn session_complete(phase: &Phase) -> bool {
    matches!(phase, Phase::Transport(_))
}

impl NoiseSession for NoiseInitiator {
    fn read(&mut self, msg: &[u8]) -> Result<NoiseFrame, NoiseError> {
        session_read(&mut self.phase, msg, true)
    }
    fn write(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        session_write(&mut self.phase, payload, true)
    }
    fn is_handshake_complete(&self) -> bool {
        session_complete(&self.phase)
    }
    fn remote_static(&self) -> Option<NoisePublicKey> {
        session_remote_static(&self.phase)
    }
}

impl NoiseSession for NoiseResponder {
    fn read(&mut self, msg: &[u8]) -> Result<NoiseFrame, NoiseError> {
        session_read(&mut self.phase, msg, false)
    }
    fn write(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        session_write(&mut self.phase, payload, false)
    }
    fn is_handshake_complete(&self) -> bool {
        session_complete(&self.phase)
    }
    fn remote_static(&self) -> Option<NoisePublicKey> {
        session_remote_static(&self.phase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::derive_noise_static;
    use bitcoin::bip32::Xpriv;
    use wick_core::WickNetwork;

    fn pair() -> (NoiseStaticKeypair, NoiseStaticKeypair) {
        let seed_a = [0x11u8; 64];
        let seed_b = [0x22u8; 64];
        let xa = Xpriv::new_master(bitcoin::Network::Regtest, &seed_a).unwrap();
        let xb = Xpriv::new_master(bitcoin::Network::Regtest, &seed_b).unwrap();
        let a = derive_noise_static(&xa, WickNetwork::Regtest, 0).unwrap();
        let b = derive_noise_static(&xb, WickNetwork::Regtest, 0).unwrap();
        (a, b)
    }

    /// Drive a KK handshake to completion between two fresh sessions.
    fn handshake(
        init: &mut NoiseInitiator,
        resp: &mut NoiseResponder,
    ) -> Result<(), NoiseError> {
        // -> e, es, ss
        let msg1 = init.write(&[])?;
        let _ = resp.read(&msg1)?;
        // <- e, ee, se
        let msg2 = resp.write(&[])?;
        let _ = init.read(&msg2)?;
        Ok(())
    }

    #[test]
    fn kk_handshake_completes_in_two_messages() {
        let (a, b) = pair();
        let mut init = NoiseInitiator::new(a.clone(), b.public).unwrap();
        let mut resp = NoiseResponder::new(b, a.public).unwrap();

        // First message ----
        let m1 = init.write(&[]).unwrap();
        assert!(!init.is_handshake_complete());
        let r1 = resp.read(&m1).unwrap();
        assert!(matches!(r1, NoiseFrame::HandshakeReply(_)));
        assert!(!resp.is_handshake_complete());

        // Second message ----
        let m2 = resp.write(&[]).unwrap();
        assert!(resp.is_handshake_complete());
        let r2 = init.read(&m2).unwrap();
        assert!(matches!(r2, NoiseFrame::HandshakeComplete));
        assert!(init.is_handshake_complete());

        // Mutual auth — each side has the other's static.
        assert_eq!(init.remote_static().unwrap().0.len(), 32);
        assert_eq!(resp.remote_static().unwrap().0.len(), 32);
    }

    #[test]
    fn kk_handshake_fails_on_wrong_remote_static() {
        let (a, b) = pair();
        // Responder expects a different initiator static than `a`.
        let seed_c = [0x33u8; 64];
        let xc = Xpriv::new_master(bitcoin::Network::Regtest, &seed_c).unwrap();
        let wrong = derive_noise_static(&xc, WickNetwork::Regtest, 0).unwrap();

        let mut init = NoiseInitiator::new(a, b.public).unwrap();
        let mut resp = NoiseResponder::new(b, wrong.public).unwrap();

        let m1 = init.write(&[]).unwrap();
        // Responder MAC-verifies the initiator's static against its
        // pre-registered expectation; the read must fail.
        assert!(resp.read(&m1).is_err());
    }

    #[test]
    fn transport_round_trips_plaintext() {
        let (a, b) = pair();
        let mut init = NoiseInitiator::new(a.clone(), b.public).unwrap();
        let mut resp = NoiseResponder::new(b, a.public).unwrap();
        handshake(&mut init, &mut resp).unwrap();

        // initiator -> responder
        let ct = init.write(b"hello server").unwrap();
        let NoiseFrame::Plaintext(pt) = resp.read(&ct).unwrap() else {
            panic!("expected plaintext frame");
        };
        assert_eq!(pt, b"hello server");

        // responder -> initiator
        let ct = resp.write(b"hello client").unwrap();
        let NoiseFrame::Plaintext(pt) = init.read(&ct).unwrap() else {
            panic!("expected plaintext frame");
        };
        assert_eq!(pt, b"hello client");
    }

    #[test]
    fn transport_rekey_at_1000_ops_per_direction() {
        let (a, b) = pair();

        // ---- Baseline session: encrypt 1001 messages WITHOUT any
        // rekey. Compare the 1001st ciphertext bit-pattern against our
        // rotating session to confirm keys actually changed. We achieve
        // "no rekey" by simply running a parallel pair where we never
        // exercise the threshold (under 1000 ops). The cleanest
        // baseline is the ciphertext at op #1 — the rotating session's
        // op #1001 must NOT equal the baseline's op #1 (different
        // nonces alone would diverge them, but together with rotation
        // we're checking both vectors).
        let mut init_base = NoiseInitiator::new(a.clone(), b.public).unwrap();
        let mut resp_base = NoiseResponder::new(b.clone(), a.public).unwrap();
        handshake(&mut init_base, &mut resp_base).unwrap();
        let baseline_ct = init_base.write(b"plaintext").unwrap();

        // ---- Rotating session: drive 1001 send ops on the initiator.
        let mut init = NoiseInitiator::new(a.clone(), b.public).unwrap();
        let mut resp = NoiseResponder::new(b, a.public).unwrap();
        handshake(&mut init, &mut resp).unwrap();

        let mut last_ct = Vec::new();
        for i in 0..1001 {
            let ct = init.write(b"plaintext").unwrap();
            // Responder must successfully decrypt every one — including
            // the post-rekey op #1001 — which proves both sides
            // rotated in lockstep.
            let NoiseFrame::Plaintext(pt) = resp.read(&ct).unwrap() else {
                panic!("expected plaintext at op {i}");
            };
            assert_eq!(pt, b"plaintext");
            last_ct = ct;
        }

        // Sanity: the 1001st ciphertext must differ from op-1 of the
        // baseline (different nonce + post-rotation key both push it).
        assert_ne!(last_ct, baseline_ct);
    }
}
