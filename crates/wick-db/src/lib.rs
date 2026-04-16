//! Postgres access layer for Wick Cloud.
//!
//! The central invariant here — and the reason this crate exists instead of
//! each caller using `sqlx` directly — is **tenant isolation**. See
//! `docs/wick_architecture.md` §4.1. Every tenant-scoped query must run
//! inside a [`tenant_tx`] block so the `SET LOCAL` discipline and runtime
//! guard are applied uniformly.

#![warn(missing_docs)]

pub mod pool;
pub mod tenant_tx;

pub use pool::Pool;
pub use tenant_tx::tenant_tx;
