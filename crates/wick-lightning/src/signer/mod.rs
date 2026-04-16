//! Signer abstraction for the Lightning node.
//!
//! [`WickSigner`] is a capability boundary combining LDK's three signer
//! traits. Phase 3 ships [`keys_manager::LocalKeysManager`] — a thin newtype
//! around LDK's [`KeysManager`] so the node runs in regtest / dev loops. The
//! Phase 4 swap wires a `RemoteVlsSigner` (in the separate `wick-vls` crate)
//! that forwards calls over `Noise_KK` to an on-device policy engine; [`Node`]
//! itself does not change.
//!
//! Rationale: by the time this bound is satisfied, we know the signer can
//! hand out every piece LDK needs without the node touching key material
//! directly. The Phase 4 swap is purely "bind a different `S` to
//! `NodeBuilder::with_signer`".
//!
//! [`Node`]: crate::Node
//! [`KeysManager`]: lightning::sign::KeysManager

pub mod keys_manager;

pub use keys_manager::{from_seed, LocalKeysManager};

use lightning::sign::{EntropySource, NodeSigner, OutputSpender, SignerProvider};

/// Unified capability boundary required by [`crate::Node`].
///
/// Any type that implements the four LDK signer traits automatically
/// satisfies this bound — it is deliberately marker-shaped so that swapping
/// the backing implementation (local key manager → remote VLS) requires no
/// changes to the trait hierarchy.
///
/// [`OutputSpender`] is included so the background [`OutputSweeper`] type
/// used by `process_events_async` can parameterise cleanly on `Arc<S>`.
/// LDK's [`KeysManager`] already implements it; VLS must too.
///
/// [`OutputSpender`]: lightning::sign::OutputSpender
/// [`OutputSweeper`]: lightning::util::sweep::OutputSweeper
/// [`KeysManager`]: lightning::sign::KeysManager
pub trait WickSigner:
    EntropySource + NodeSigner + SignerProvider + OutputSpender + Send + Sync + 'static
{
}

impl<T> WickSigner for T where
    T: EntropySource + NodeSigner + SignerProvider + OutputSpender + Send + Sync + 'static
{
}
