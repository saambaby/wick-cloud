//! Relay binary entrypoint. See lib.rs / architecture §3.10.

use std::net::SocketAddr;

use anyhow::Result;
use clap::Parser;
use wick_core::tracing_init;
use wick_relay::{run, RelayConfig};

#[derive(Debug, Parser)]
#[command(
    name = "wick-relay",
    about = "Dumb-pipe WebSocket relay between VLS signer and ldk-server"
)]
struct Args {
    /// Address to bind. Default: 0.0.0.0:9999.
    #[arg(long, default_value = "0.0.0.0:9999")]
    bind: SocketAddr,

    /// Per-IP connect budget per 60-second sliding window.
    #[arg(long, default_value_t = 30)]
    rate_per_min: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_init::install();
    let args = Args::parse();
    let (_addr, handle) = run(RelayConfig {
        bind: args.bind,
        rate_per_min: args.rate_per_min,
    })
    .await?;
    handle.await?;
    Ok(())
}
