//! Loom concurrency models for wick-server's park/wake state machine.
//!
//! This crate exists solely to provide an isolated compilation unit for
//! loom model tests. It has no async runtime dependency so the global
//! `--cfg loom` flag does not conflict with tokio's internals.
//!
//! Run via `just loom`.

pub mod park_wake;
