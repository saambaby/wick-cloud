//! `wick-server` library crate.
//!
//! Exposes the per-tenant Lightning-node actor model and gRPC service for use
//! by integration tests and the binary entry point. All application logic
//! lives here; `main.rs` is a thin boot shim.

pub mod auth;
pub mod factory;
pub mod grpc;
pub mod lsp_bridge;
pub mod macaroon_auth;
pub mod node;
pub mod nonce_store;
pub mod signer_meta_store;
pub mod signer_service;

/// Bound on the in-flight outbound frame mpsc between
/// [`wick_vls::SignerConnection`] and [`signer_service::WickSignerGrpcService`].
/// Sized to absorb a burst from the hottest path (signing every HTLC on a
/// commitment update) without back-pressuring the LDK signer thread.
pub const OUTBOUND_FRAME_CAPACITY: usize = 256;
