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

use lightning::sign::{EntropySource, KeysManager, NodeSigner, OutputSpender, SignerProvider};

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
    /// Stage a `push_msat` value for an outbound channel open under
    /// `user_channel_id`.
    ///
    /// Called by [`crate::Node`]'s open-channel paths immediately before
    /// `ChannelManager::create_channel`. VLS-backed signers
    /// ([`wick_vls::SignerSession`]) drain the staging at
    /// `generate_channel_keys_id` time and forward the value through
    /// `SetupChannel.push_value` so the validator's initial-commitment
    /// check sees the right `to_remote`. The default no-op is correct
    /// for [`KeysManager`]-backed signers, which have no validator
    /// state to feed.
    ///
    /// [`KeysManager`]: lightning::sign::KeysManager
    fn register_outbound_channel_open(&self, _user_channel_id: u128, _push_msat: u64) {}

    /// Discard a previously-staged push value (e.g. on `create_channel`
    /// error or a `OpenChannelInit` timeout) so the staging map doesn't
    /// leak. No-op for non-VLS signers.
    fn clear_outbound_channel_open(&self, _user_channel_id: u128) {}

    /// Install a callback the signer invokes whenever an internal state
    /// transition (e.g. delivery of `SetupChannel` on a VLS-backed signer)
    /// has unblocked previously-pending `ChannelSigner` calls. The builder
    /// wires this to `ChannelManager::signer_unblocked(None)` so LDK's
    /// async-signer-pending protocol retries the parked channel.
    ///
    /// Called at most once per session by the builder, after the
    /// `ChannelManager` is built. Default is a no-op — local
    /// `KeysManager`-backed signers never park work and so don't need
    /// the unblock pump.
    fn set_signer_unblock_callback(&self, _cb: Box<dyn Fn() + Send + Sync>) {}
}

// Explicit impl for LDK's KeysManager (used by tests + the dev signer).
// We deliberately do NOT keep the prior blanket `impl<T> WickSigner for T`
// because the new methods need a concrete dispatch site (the blanket impl
// can't be specialised).
impl WickSigner for KeysManager {}
