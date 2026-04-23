//! Canonical Rust SDK for Wick Cloud.
//!
//! `wick-sdk` is the device-side slice of a self-custodial Bitcoin Lightning
//! wallet. It owns:
//!
//! - **Identity** — BIP39 mnemonic → deterministic seed → identity pubkey.
//! - **On-chain wallet** — BDK 1.x with BIP84 (P2WPKH) and BIP86 (P2TR)
//!   descriptors, synced against a user-configured Esplora endpoint.
//! - **Chain data** — an `esplora-client` against public Esplora by default
//!   (bypasses `wick-server`'s internal pool — portfolio queries must not
//!   round-trip through the server).
//! - **Lightning ops** — a tonic gRPC client talking to `wick-server`'s
//!   `WalletService` with a bearer-token interceptor.
//!
//! See [`WickClient`] for the single top-level handle.
//!
//! ## Non-goals (for now)
//!
//! - VLS / Noise tunnel / macaroons (Phase 4 — the bearer-token plumbing here
//!   is a pre-VLS stand-in).
//! - FFI / WASM bindings (sibling crates).
//! - LDK on device (Phase 4 — signing is still server-side custodial).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod chain;
mod client;
mod config;
mod error;
mod grpc;
mod identity;
mod types;
mod wallet;

#[cfg(feature = "regtest")]
pub mod regtest;

pub use client::WickClient;
pub use config::WickConfig;
pub use error::{Error, Result};
pub use types::{
    Balance, ChannelSummary, CreateTenantOutcome, NodeInfo, PaymentRecord, PaymentResult,
    PaymentStatus, ReceiveInvoice,
};
