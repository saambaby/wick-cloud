//! Phase-4 D1: `Noise_KK` mutual-auth transport for `SignerService.Attach`.
//!
//! Wraps a [`snow::HandshakeState`] / [`snow::TransportState`] with
//! wick-specific key derivation, BOLT 8-style chain-key rekey at 1000 cipher
//! ops per direction, and a typed envelope around handshake + transport
//! messages.
//!
//! This crate is library-only. The N2 slice plugs it into the
//! `SignerService.Attach` gRPC bidi stream (Noise frames travel inside the
//! existing `vls_payload: bytes` field — no proto churn).
//!
//! Design references:
//! - Noise spec rev 34, §7.5 (KK pattern) and §5.3 (`Split()`).
//! - BOLT 8, "Lightning Message Key Rotation" (HKDF chain-key rotation
//!   at 1000 ops, used here in place of Noise's bare `Rekey()`).
//! - Internal research note: `research/concepts/noise-kk-for-wick.md`.
#![warn(missing_docs)]

pub mod identity;
pub mod session;

pub use identity::{derive_noise_static, NoisePublicKey, NoiseStaticKeypair};
pub use session::{
    NoiseError, NoiseFrame, NoiseInitiator, NoiseResponder, NoiseSession, NOISE_HANDSHAKE_PATTERN,
    REKEY_INTERVAL,
};
