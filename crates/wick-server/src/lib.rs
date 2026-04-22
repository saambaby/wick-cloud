//! `wick-server` library crate.
//!
//! Exposes the per-tenant Lightning-node actor model and gRPC service for use
//! by integration tests and the binary entry point. All application logic
//! lives here; `main.rs` is a thin boot shim.

pub mod auth;
pub mod factory;
pub mod grpc;
pub mod node;
