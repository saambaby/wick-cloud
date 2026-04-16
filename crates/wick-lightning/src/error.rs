//! Error types for `wick-lightning`.

use thiserror::Error;

/// Unified error type for node construction, persistence, and payments.
///
/// Wraps lower-level errors so callers can `?`-propagate without pulling in
/// LDK/sqlx/bitcoin types.
#[derive(Debug, Error)]
pub enum WickLightningError {
    /// The Esplora HTTP client rejected a request or returned a network error.
    #[error("esplora: {0}")]
    Esplora(String),

    /// A Postgres query or transaction failed.
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),

    /// Persisted LDK bytes failed to deserialise — store corruption or a
    /// version mismatch.
    #[error("persistence decode failed ({what}): {err}")]
    PersistenceDecode {
        /// What was being decoded (`channel_manager`, `monitor`, …).
        what: &'static str,
        /// Underlying error message.
        err: String,
    },

    /// A BOLT11 invoice could not be parsed or signed.
    #[error("invoice: {0}")]
    Invoice(String),

    /// LDK signalled a payment failure.
    #[error("payment: {0}")]
    Payment(String),

    /// An LDK API call returned an error that isn't covered above.
    #[error("ldk: {0}")]
    Ldk(String),

    /// Invalid configuration passed to [`crate::NodeBuilder`].
    #[error("config: {0}")]
    Config(String),

    /// Catch-all wrapping for callers that still use `anyhow::Error`.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Shorthand for results scoped to this crate.
pub type Result<T, E = WickLightningError> = std::result::Result<T, E>;
