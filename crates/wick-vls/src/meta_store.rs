//! Pluggable persistence for [`crate::SignerSession`]'s per-channel state.
//!
//! `SignerSession` keys per-channel state on `channel_keys_id` — the random
//! 32-byte identifier LDK assigns at `generate_channel_keys_id`. Each entry
//! records the VLS-protocol `dbid`, the counterparty `peer_id`, the cached
//! 5-basepoint set returned by `GetChannelBasepoints`, and the funding
//! outpoint that promoted the channel via `SetupChannel`.
//!
//! Without persistence this state is in-memory only: a wick-server restart
//! starts the session with an empty map, LDK then calls
//! `derive_channel_signer` for every persisted channel, and we'd allocate a
//! fresh `dbid` — VLS rejects every subsequent signing call with "channel
//! not found" because the SDK's per-channel state is keyed on the original
//! `dbid`.
//!
//! [`ChannelMetaStore`] is the trait the session calls to write-through and
//! to rehydrate at boot. The crate is transport-agnostic — the concrete
//! Postgres implementation lives in `wick-server` (so wick-vls keeps its
//! "no SQL deps" constraint).

use std::sync::Arc;

use async_trait::async_trait;

/// Snapshot of one channel's signer-side state, ready to round-trip
/// through Postgres / disk / any other durable backing.
///
/// `pubkeys` is `None` until the SDK answers `GetChannelBasepoints` — for
/// the offline-derivation case (signer not attached at
/// `derive_channel_signer` time) we still want to persist the
/// `(channel_keys_id, dbid)` binding so a subsequent successful derive can
/// fill in the basepoints. `setup_funding` is `None` until
/// `SetupChannel` lands.
#[derive(Debug, Clone)]
pub struct StoredChannelMeta {
    pub channel_keys_id: [u8; 32],
    pub dbid: u64,
    pub peer_id: [u8; 33],
    pub setup_funding: Option<(bitcoin::Txid, u16)>,
    pub push_value_msat: u64,
    /// 5×33-byte concatenation of (funding, revocation, payment,
    /// delayed_payment, htlc) basepoints in that order. `None` when the
    /// channel was inserted before `GetChannelBasepoints` ever succeeded.
    pub pubkeys: Option<[u8; 165]>,
}

/// Async persistence backend used by [`crate::SignerSession`].
///
/// Implementations must be cheap to `Arc::clone` (the session tracks the
/// store as `Option<Arc<dyn ChannelMetaStore>>`).
#[async_trait]
pub trait ChannelMetaStore: Send + Sync + std::fmt::Debug {
    /// Load every stored row for the bound tenant. Called once during
    /// [`crate::SignerSession::rehydrate`] before LDK touches the signer.
    /// Implementations should log + skip malformed rows rather than fail
    /// the whole boot.
    async fn load_all(&self) -> anyhow::Result<Vec<StoredChannelMeta>>;

    /// Insert or update a row. Idempotent on `channel_keys_id`. Called
    /// from a `tokio::spawn`'d write-through path on the hot LDK signer
    /// thread, so it must not panic on transient errors — return them.
    async fn upsert(&self, meta: StoredChannelMeta) -> anyhow::Result<()>;
}

/// Convenience boxed handle the session stores. `Arc<dyn ..>` instead of
/// `Box<dyn ..>` so the session can clone-and-spawn for write-through.
pub type ChannelMetaStoreRef = Arc<dyn ChannelMetaStore>;
