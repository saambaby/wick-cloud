//! Workspace-wide error type.
//!
//! Library crates should define their own `thiserror` enums and convert into
//! [`WickError`] at the boundary where a generic error is acceptable
//! (typically the gRPC/HTTP handler layer).

use thiserror::Error;

/// Convenience alias used throughout the workspace.
pub type Result<T, E = WickError> = std::result::Result<T, E>;

/// Top-level error variant. Concrete crates widen this as they're added.
#[derive(Debug, Error)]
pub enum WickError {
    /// Configuration could not be loaded or validated.
    #[error("config error: {0}")]
    Config(String),

    /// A tenant-id failed validation at the SDK boundary.
    #[error("invalid tenant id: {0}")]
    InvalidTenantId(String),

    /// The tenant guard detected a mismatch between the query's expected
    /// tenant and the session's `app.current_tenant_id`.
    #[error("tenant guard mismatch: expected {expected}, session had {actual}")]
    TenantGuardMismatch {
        /// Tenant the caller expected.
        expected: String,
        /// Tenant the session actually had.
        actual: String,
    },

    /// A downstream dependency (Postgres, Esplora, etc.) returned an error.
    #[error("dependency error: {0}")]
    Dependency(String),

    /// BIP39 mnemonic parse failure or BIP32/BIP84 key derivation failure.
    #[error("key derivation error: {0}")]
    KeyDerivation(String),

    /// Catch-all for errors we haven't categorised yet. Avoid using this in
    /// new code — add a proper variant instead.
    #[error("internal error: {0}")]
    Internal(String),
}
