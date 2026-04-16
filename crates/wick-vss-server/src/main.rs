//! VSS server binary. Scope lands in Phase 4 (architecture §3.9).

use anyhow::Result;
use tracing::info;
use wick_core::tracing_init;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_init::install();
    info!("wick-vss-server scaffolded — implementation arrives in Phase 4");
    Ok(())
}
