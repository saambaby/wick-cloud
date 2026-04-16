//! Bridge LDK's logger to the `tracing` ecosystem.
//!
//! Every LDK log record is emitted under the `ldk` target (and `ldk::gossip`
//! for the noisy gossip level). Filter via `RUST_LOG=ldk=info` etc.

use lightning::util::logger::{Level, Logger, Record};

/// LDK → `tracing` adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingLogger;

impl Logger for TracingLogger {
    fn log(&self, record: Record<'_>) {
        let msg = record.args.to_string();
        match record.level {
            Level::Error => tracing::error!(target: "ldk", "{msg}"),
            Level::Warn => tracing::warn!(target: "ldk", "{msg}"),
            Level::Info => tracing::info!(target: "ldk", "{msg}"),
            Level::Debug => tracing::debug!(target: "ldk", "{msg}"),
            Level::Trace => tracing::trace!(target: "ldk", "{msg}"),
            Level::Gossip => tracing::trace!(target: "ldk::gossip", "{msg}"),
        }
    }
}
