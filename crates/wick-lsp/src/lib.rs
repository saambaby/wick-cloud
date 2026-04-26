//! Wick Cloud LSP daemon (Phase 3 operator role).
//!
//! `wick-lsp` runs alongside `wick-server` in the same process, hosting
//! a dedicated [`wick_lightning::Node`] in **service mode** and exposing
//! the LSPS2 JIT channel flow to tenants. Tenants connect to the LSP
//! over LDK's normal P2P transport and consume LSPS2 client-side
//! through their own [`wick_lightning::PendingJitRegistry`] (slice 3.1).
//!
//! ## Components
//!
//! - [`peer_registry::PeerRegistry`] — `DashMap<scid, (TenantId, Epoch)>`
//!   plus a strict-ordering `lsps2.buy` allocator. Phase-3 dispatch by
//!   SCID, never by counterparty pubkey.
//! - [`fee_params::FeeParamCache`] — HMAC-rotated `promise` generator
//!   for `lsps2.get_info` / `lsps2.buy` flows. 5-min key rotation.
//! - [`daemon::LspDaemon`] — top-level orchestrator: builds the LSP
//!   Node via [`wick_lightning::NodeBuilder::with_liquidity_service`]
//!   and runs the LSPS2 service-event pump.
//!
//! ## Crate boundaries
//!
//! `wick-lsp` depends on `wick-lightning` (it reuses `Node`,
//! `NodeBuilder`, and `PgKvStore`). It does NOT depend on `wick-server`
//! directly — the integration point is a small dispatcher trait the
//! server implements so the LSP can drive `LSPS2ServiceEvent::OpenChannel`
//! into the right tenant `NodeActor` over its mpsc channel.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod daemon;
pub mod dispatcher;
pub mod fee_params;
pub mod grief;
pub mod handler;
pub mod peer_registry;
pub mod reorg;
pub mod unknown_scid_queue;

pub use daemon::{LspBuilder, LspDaemon, LspDaemonConfig, LspPartialConfig};
pub use dispatcher::{LspDispatcher, OpenChannelRequest};
pub use fee_params::{FeeParamCache, OpeningParamsView};
pub use handler::OperatorServiceHandler;
pub use grief::GriefScorer;
pub use peer_registry::{Epoch, JitRequestState, PeerRegistry, RegisteredJit};
pub use reorg::{projected_capacity_sat, ReorgGuard, ReserveExceeded};
pub use unknown_scid_queue::{HtlcParkRequest, UnknownScidQueue};
