//! Prometheus metrics bootstrap.
//!
//! Every binary calls [`install`] once at startup. Individual crates then
//! use the `metrics` crate macros (`counter!`, `gauge!`, `histogram!`).
//!
//! Metric names are documented alongside the fix they back-stop in
//! `docs/wick_architecture.md` §7.3.

use std::net::SocketAddr;

use metrics_exporter_prometheus::PrometheusBuilder;

use crate::error::{Result, WickError};

/// Install the Prometheus exporter, listening on `addr`.
pub fn install(addr: SocketAddr) -> Result<()> {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| WickError::Internal(format!("metrics install failed: {e}")))
}
