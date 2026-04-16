//! Relay binary. Scope lands in Phase 4 (see plan + architecture §3.10).

use anyhow::Result;
use tracing::info;
use wick_core::tracing_init;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_init::install();
    info!("wick-relay scaffolded — implementation arrives in Phase 4");
    Ok(())
}
