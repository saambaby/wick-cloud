//! Shared primitives for Wick Cloud.
//!
//! This crate is the dependency floor of the workspace: every other crate
//! depends on it, and it depends on nothing internal. Keep it small — only
//! types and helpers that are genuinely cross-cutting belong here.

#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod metrics;
pub mod tenant;
pub mod tracing_init;

pub use error::{Result, WickError};
pub use tenant::TenantId;
