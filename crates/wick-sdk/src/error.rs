//! SDK error surface.
//!
//! Every fallible entry point on [`crate::WickClient`] returns [`Result<T>`].
//! We deliberately do **not** leak `tonic::Status`, `bdk_wallet::Error`, or
//! `esplora_client::Error` through the public API — each is wrapped as a
//! `String` variant so the public surface stays stable across upstream
//! version bumps.

use thiserror::Error;

/// Convenience alias used throughout the SDK.
pub type Result<T> = std::result::Result<T, Error>;

/// The SDK error type.
#[derive(Error, Debug)]
pub enum Error {
    /// gRPC transport failure: could not connect / broken channel / invalid URI.
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    /// The server rejected the request with `UNAUTHENTICATED`.
    ///
    /// Specialised so callers can match-and-re-register cleanly without
    /// string-matching on a generic gRPC error.
    #[error("authentication failed: {0}")]
    Unauthenticated(String),

    /// The server returned a non-OK, non-`UNAUTHENTICATED` status.
    #[error("gRPC error ({code:?}): {message}")]
    Grpc {
        /// The tonic status code the server returned.
        code: tonic::Code,
        /// The status message the server returned.
        message: String,
    },

    /// The server returned a response that could not be parsed (e.g. a
    /// payment hash of the wrong length, or a timestamp we can't decode).
    #[error("invalid response from server: {0}")]
    InvalidResponse(String),

    /// Caller-supplied input failed validation before we made an RPC.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// BIP39 mnemonic parse failure or BIP32 key derivation failure.
    #[error("identity / key derivation: {0}")]
    Identity(String),

    /// BDK wallet error (create / sync / sign / build transaction).
    #[error("wallet error: {0}")]
    Wallet(String),

    /// Esplora chain error (broadcast, fee estimate, tx lookup).
    #[error("chain error: {0}")]
    Chain(String),

    /// [`crate::WickConfig`] validation failure.
    #[error("config error: {0}")]
    Config(String),
}

impl From<tonic::Status> for Error {
    fn from(s: tonic::Status) -> Self {
        match s.code() {
            tonic::Code::Unauthenticated => Self::Unauthenticated(s.message().to_owned()),
            code => Self::Grpc {
                code,
                message: s.message().to_owned(),
            },
        }
    }
}
