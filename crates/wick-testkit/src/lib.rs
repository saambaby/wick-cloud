//! Shared test fixtures for the workspace.
//!
//! The regtest harness, mock LSP, chaos injectors, and red-team fixtures
//! live here. Phase 0 ships the regtest module as a stub; real harness
//! implementation lands alongside the Phase 0 LDK wiring.

#![warn(missing_docs)]

pub mod deps;
pub mod regtest;
pub mod signer;
pub mod wallet;

pub use deps::{stub, stub_deps, StubDepsConfig};
pub use regtest::{parse_address, BitcoindConfig, Regtest};
pub use signer::{deterministic_seed, node_id_from_seed, random_seed, signer_for_tenant};
pub use wallet::TestWallet;
