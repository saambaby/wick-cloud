//! Phase-4 dumb-pipe WebSocket relay.
//!
//! The relay is **stateless** at the cryptographic layer: SDK ↔ ldk-server
//! Noise sessions terminate at the endpoints, never at the relay. Our jobs:
//!
//! 1. Mint 128-bit server-issued stream IDs (`OsRng`); never trust a
//!    client-submitted ID that does not match an outstanding pending stream.
//! 2. Pair an `initiator` connection with a `responder` connection by
//!    stream ID and shuffle frames between them opaquely.
//! 3. Per-IP connect rate limit (default 30/min sliding window).
//! 4. Enforce a max frame size (Noise wire max = 65535 bytes).
//!
//! Architecture reference: §3.10.
#![warn(missing_docs)]

pub mod rate_limit;
pub mod session;
pub mod stream;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{info, warn};

pub use rate_limit::RateLimiter;
pub use stream::{StreamRegistry, MAX_FRAME_BYTES};

/// Runtime configuration for the relay.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Address the TCP listener binds to.
    pub bind: SocketAddr,
    /// Per-IP connection budget per 60-second sliding window.
    pub rate_per_min: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], 9999)),
            rate_per_min: 30,
        }
    }
}

/// Start the relay listener. Returns the bound [`SocketAddr`] and a
/// `JoinHandle` running the accept loop. The caller is responsible for
/// aborting the handle on shutdown.
///
/// Binding happens synchronously so integration tests can capture the
/// ephemeral port before spawning clients.
pub async fn run(cfg: RelayConfig) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(cfg.bind).await?;
    let local_addr = listener.local_addr()?;
    let limiter = Arc::new(RateLimiter::new(cfg.rate_per_min));
    let registry = Arc::new(StreamRegistry::new());

    info!(addr = %local_addr, rate_per_min = cfg.rate_per_min, "wick-relay listening");

    let handle = tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    continue;
                }
            };
            let limiter = Arc::clone(&limiter);
            let registry = Arc::clone(&registry);
            tokio::spawn(async move {
                if let Err(e) = session::handle(tcp, peer, limiter, registry).await {
                    warn!(peer = %peer, error = %e, "relay session ended with error");
                }
            });
        }
    });
    Ok((local_addr, handle))
}
