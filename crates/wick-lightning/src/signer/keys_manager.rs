//! Phase 3 signer type alias + seed-to-signer construction.
//!
//! [`LocalKeysManager`] is a re-export of LDK's built-in [`KeysManager`].
//! [`from_seed`] is the seed-agnostic plumbing that turns 32 bytes + the
//! current clock into a usable signer. The *seed bytes* originate outside
//! this crate (server binary config for regtest/dev, a VLS-derived handle
//! for Phase 4 prod); `wick-lightning` never persists or stores a seed, but
//! the helper to construct a signer from one lives here because it has no
//! wallet-specific state of its own.
//!
//! Phase 4 replaces this with a remote VLS signer in `wick-vls` — the node
//! type parameter flips from `LocalKeysManager` to `RemoteVlsSigner` and
//! nothing else changes.
//!
//! [`KeysManager`]: lightning::sign::KeysManager

use std::time::{SystemTime, UNIX_EPOCH};

use lightning::sign::KeysManager;

/// Phase 3 local signer — type alias over LDK's [`KeysManager`].
pub type LocalKeysManager = KeysManager;

/// Enable v2 remote-key-derivation — required for new LDK 0.2 nodes, and a
/// one-way door per the 0.2 release notes.
const V2_REMOTE_KEY_DERIVATION: bool = true;

/// Build a [`LocalKeysManager`] from a 32-byte seed.
///
/// The `(starting_time_secs, starting_time_nanos)` pair is a ephemeral-key
/// entropy salt pulled from the current clock.
#[must_use]
pub fn from_seed(seed: [u8; 32]) -> LocalKeysManager {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    KeysManager::new(
        &seed,
        now.as_secs(),
        now.subsec_nanos(),
        V2_REMOTE_KEY_DERIVATION,
    )
}
