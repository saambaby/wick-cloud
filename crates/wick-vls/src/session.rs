//! LDK 0.2 signer trait impls backed by a remote VLS-protocol signer.
//!
//! [`SignerSession`] satisfies `wick_lightning::WickSigner` (and therefore
//! the four LDK super-traits `EntropySource + NodeSigner + SignerProvider +
//! OutputSpender`) by routing every call through the per-tenant
//! [`crate::ConnLookup`] to the SDK device that holds the seed.
//!
//! Per-channel signers are vended as [`VlsRemoteChannelSigner`] which
//! implements `ChannelSigner + EcdsaChannelSigner`.
//!
//! ## Lifecycle
//!
//! 1. Construct via [`SignerSession::new(lookup)`] — non-blocking, holds no
//!    secret material.
//! 2. After the SDK opens its bidi stream and the registry sees `is_ready`,
//!    call [`SignerSession::init(network)`] once — it negotiates `HsmdInit2`
//!    + `GetLdkNodeKeys`, caches the node pubkey + LDK-only keys
//!    (peer-storage, inbound-payment, receive-auth) for the session.
//! 3. Hand the `Arc<SignerSession>` to `NodeBuilder::with_signer` and run.
//!
//! All LDK-side calls are synchronous (the trait is sync) but the underlying
//! signer RPC is async over the gRPC stream. The [`block_vls!`] macro uses
//! `tokio::task::block_in_place` + `Handle::block_on` to bridge — safe under
//! a multi-thread Tokio runtime, which is always how LDK runs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

/// Process-wide dbid allocator. VLS keys per-channel state on `dbid`; two
/// tenants in the same `wick-server` process previously seeded their
/// per-session counters from `unix_ts * 100_000` and could collide when
/// constructed inside the same second. A single atomic eliminates the
/// collision and is cheaper than the per-session field. Starts at 1
/// because VLS reserves 0 for the node-level dbid.
static DBID_COUNTER: AtomicU64 = AtomicU64::new(1);

use bitcoin::hashes::Hash as _;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::{schnorr, PublicKey, Scalar, Secp256k1, SecretKey};
use dashmap::DashMap;
use lightning::ln::chan_utils::{
    get_htlc_redeemscript, get_keyed_anchor_redeemscript, get_revokeable_redeemscript,
    make_funding_redeemscript, ChannelPublicKeys, ChannelTransactionParameters,
    ClosingTransaction, CommitmentTransaction, HTLCOutputInCommitment,
    HolderCommitmentTransaction, TxCreationKeys,
};
use lightning::ln::channel_keys::{
    DelayedPaymentBasepoint, DelayedPaymentKey, HtlcBasepoint, RevocationBasepoint, RevocationKey,
};
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::ln::msgs::{UnsignedChannelAnnouncement, UnsignedGossipMessage};
use lightning::ln::script::ShutdownScript;
use lightning::offers::invoice::UnsignedBolt12Invoice;
use lightning::sign::ecdsa::EcdsaChannelSigner;
use lightning::sign::{
    ChannelSigner, EntropySource, HTLCDescriptor, NodeSigner, OutputSpender, PeerStorageKey,
    ReceiveAuthKey, Recipient, SignerProvider, SpendableOutputDescriptor,
};
use lightning::types::payment::PaymentPreimage;
use lightning::util::ser::Writeable as _;
use lightning_invoice::RawBolt11Invoice;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::connection::SignerConnection;
use crate::meta_store::{ChannelMetaStoreRef, StoredChannelMeta};
use crate::registry::ConnLookup;
use crate::rpc;

// ── Constants ─────────────────────────────────────────────────────────────────

const ANCHOR_OUTPUT_VALUE_SATOSHI: u64 = 330;
const DUST_LIMIT_SAT: u64 = 546;

/// Compressed encoding of secp256k1 generator G. Used as a placeholder peer
/// pubkey on channel-scoped VLS calls before `SetupChannel` promotes the
/// channel with the real counterparty pubkey, and as a sentinel pubkey when
/// the signer is unreachable at `derive_channel_signer` time (LDK does not
/// tolerate errors there — we hand back a "failed" signer that returns
/// errors on every actual signing call instead).
const SENTINEL_PUBKEY: [u8; 33] = [
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98,
];

#[allow(clippy::expect_used)] // SENTINEL_PUBKEY is a compile-time constant, infallible.
fn sentinel_pubkey() -> PublicKey {
    PublicKey::from_slice(&SENTINEL_PUBKEY).expect("SENTINEL_PUBKEY is always valid")
}

#[allow(clippy::expect_used)] // sentinel DER bytes are constant + valid.
fn sentinel_signature() -> Signature {
    Signature::from_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
        .expect("sentinel DER is always valid")
}

/// Derive the P2WPKH shutdown script from a node pubkey. Matches the
/// SDK-side derivation used at `local_wallet_path_hint = [1]` for
/// cooperative-close `SignWithdrawal` calls.
fn shutdown_script_from_pubkey(pubkey: PublicKey) -> ShutdownScript {
    use bitcoin::hashes::{hash160, Hash as _};
    let hash = hash160::Hash::hash(&pubkey.serialize());
    let wpubkey_hash = bitcoin::WPubkeyHash::from_raw_hash(hash);
    ShutdownScript::new_p2wpkh(&wpubkey_hash)
}

/// Run an async future synchronously from an LDK signer callback.
///
/// LDK calls signer methods synchronously. We drive the future to completion
/// via `block_in_place` (releases the current async worker thread) +
/// `block_on`. Requires a multi-thread Tokio runtime — always true in wick
/// where the runtime is constructed by `wick-server` with `flavor = multi`.
macro_rules! block_vls {
    ($fut:expr) => {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on($fut))
    };
}

// ── Per-channel cached state ──────────────────────────────────────────────────

#[derive(Clone)]
struct CachedChannelKeys {
    pubkeys: ChannelPublicKeys,
    destination_script: bitcoin::ScriptBuf,
}

/// VLS identifies channels by `(dbid, peer_id)`. LDK identifies them by
/// `channel_keys_id`. This struct is the bridge.
///
/// `peer_id` is initially [`SENTINEL_PUBKEY`]; once the funding outpoint and
/// counterparty keys are known, [`VlsRemoteChannelSigner::maybe_setup_channel`]
/// calls `SetupChannel` to promote the VLS-side channel to its real
/// counterparty, but the routing `peer_id` we use for channel-scoped frames
/// continues to be the sentinel — the real counterparty pubkey is delivered
/// inside the `SetupChannel` payload, not on the wire header.
struct ChannelMeta {
    dbid: u64,
    peer_id: [u8; 33],
    setup_funding: Option<(bitcoin::Txid, u16)>,
    push_value_msat: u64,
    /// Signer `session_token` for which `SetupChannel` has actually been
    /// delivered to the **device** in this process. Distinct from
    /// `setup_funding` (which persists to Postgres and survives restarts):
    /// the device signer holds no durable channel state (`DummyPersister`)
    /// and is rebuilt fresh on every `Attach`, so a persisted `setup_funding`
    /// from a prior process/attach does NOT mean the freshly-attached device
    /// knows the channel. `maybe_setup_channel` re-issues `SetupChannel`
    /// whenever this does not match the current connection's session token.
    /// Not persisted — always `None` after rehydrate.
    setup_done_for_session: Option<u64>,
}

// ── SignerSession ─────────────────────────────────────────────────────────────

/// Remote-signer-backed implementation of `wick_lightning::WickSigner`.
pub struct SignerSession {
    lookup: ConnLookup,

    // Populated by `init()` via `rpc_hsmd_init2` + `rpc_get_ldk_node_keys`.
    node_pubkey: OnceLock<PublicKey>,
    peer_storage_key: OnceLock<[u8; 32]>,
    inbound_payment_key: OnceLock<[u8; 32]>,
    receive_auth_key: OnceLock<[u8; 32]>,

    /// LDK-side channel pubkeys + destination script keyed by `channel_keys_id`.
    channel_keys: DashMap<[u8; 32], CachedChannelKeys>,

    /// VLS dbid + peer_id keyed by `channel_keys_id`. Shared with each
    /// `VlsRemoteChannelSigner` so future `SetupChannel` promotions are
    /// visible without rebuilding the signer.
    channel_meta: Arc<DashMap<[u8; 32], ChannelMeta>>,

    /// `user_channel_id → push_msat` set when wick-server initiates an
    /// outbound `OpenChannelInit`. Drained into
    /// `pending_outbound_push_by_channel_keys_id` by the next
    /// `generate_channel_keys_id(inbound=false, ..)` call.
    pending_outbound_push_by_user_channel_id: DashMap<u128, u64>,

    /// `channel_keys_id → push_msat` — the staged value `derive_channel_signer`
    /// will move into the new `ChannelMeta::push_value_msat`.
    pending_outbound_push_by_channel_keys_id: DashMap<[u8; 32], u64>,

    /// Callback fired when a `SetupChannel` lands and unblocks any
    /// previously-parked `ChannelSigner` calls. The builder wires this to
    /// `ChannelManager::signer_unblocked(None)` so LDK retries the parked
    /// channel instead of waiting on a 1s timer. Shared with each
    /// [`VlsRemoteChannelSigner`] vended out of this session so the
    /// callback can fire from inside `maybe_setup_channel`.
    signer_unblock: Arc<OnceLock<Box<dyn Fn() + Send + Sync>>>,

    /// Optional durable backing for [`Self::channel_meta`] +
    /// [`Self::channel_keys`]. When `Some`, every mutation to either map
    /// is mirrored to the store via a fire-and-forget `tokio::spawn`, and
    /// [`Self::rehydrate`] re-populates both maps + the global
    /// `DBID_COUNTER` floor on boot. When `None` the session behaves
    /// exactly as before (in-memory only — fine for unit tests, never
    /// for production).
    meta_store: Option<ChannelMetaStoreRef>,
}

impl std::fmt::Debug for SignerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerSession")
            .field("context_id", &self.lookup.context_id())
            .field("node_pubkey", &self.node_pubkey.get())
            .field("channels", &self.channel_meta.len())
            .finish_non_exhaustive()
    }
}

impl SignerSession {
    /// Construct a fresh session bound to a tenant context. Holds no secret
    /// material; the SDK-side stream attaches via the registry separately.
    #[must_use]
    pub fn new(lookup: ConnLookup) -> Self {
        Self {
            lookup,
            node_pubkey: OnceLock::new(),
            peer_storage_key: OnceLock::new(),
            inbound_payment_key: OnceLock::new(),
            receive_auth_key: OnceLock::new(),
            channel_keys: DashMap::new(),
            channel_meta: Arc::new(DashMap::new()),
            pending_outbound_push_by_user_channel_id: DashMap::new(),
            pending_outbound_push_by_channel_keys_id: DashMap::new(),
            signer_unblock: Arc::new(OnceLock::new()),
            meta_store: None,
        }
    }

    /// Bind a durable [`ChannelMetaStore`] for write-through + restart
    /// rehydration. Pass [`Self::rehydrate`] before
    /// [`crate::SignerSession::init`] so LDK's first call into
    /// `derive_channel_signer` sees the persisted `(channel_keys_id →
    /// dbid, peer_id, pubkeys)` map.
    #[must_use]
    pub fn with_meta_store(mut self, store: ChannelMetaStoreRef) -> Self {
        self.meta_store = Some(store);
        self
    }

    /// Re-load every persisted [`ChannelMeta`] into the in-memory map and
    /// raise the process-global `DBID_COUNTER` floor above the highest
    /// persisted `dbid` so newly-allocated channels never collide with a
    /// pre-restart channel. Idempotent.
    ///
    /// Call exactly once, after [`Self::with_meta_store`] and before
    /// `NodeBuilder::build` invokes
    /// `ChannelManager::read` (which is what calls
    /// `derive_channel_signer` for every persisted channel).
    pub async fn rehydrate(&self) -> anyhow::Result<()> {
        let Some(store) = self.meta_store.as_ref() else {
            return Ok(());
        };
        let rows = store.load_all().await?;
        let mut max_dbid: u64 = 0;
        for row in rows {
            max_dbid = max_dbid.max(row.dbid);
            // Reconstruct the in-memory `ChannelMeta`.
            self.channel_meta.insert(
                row.channel_keys_id,
                ChannelMeta {
                    dbid: row.dbid,
                    peer_id: row.peer_id,
                    setup_funding: row.setup_funding,
                    push_value_msat: row.push_value_msat,
                    // Restored from a prior process — the freshly-attached
                    // device has not been sent SetupChannel yet.
                    setup_done_for_session: None,
                },
            );
            // If we have the cached basepoints, re-hydrate `channel_keys`
            // too — `derive_channel_signer` will then short-circuit on
            // the cache hit instead of hitting the SDK.
            if let Some(blob) = row.pubkeys {
                if let Some(keys) = decode_pubkeys_blob(&blob) {
                    let destination_script = match self.node_pubkey.get() {
                        Some(pk) => shutdown_script_from_pubkey(*pk).into_inner(),
                        None => bitcoin::ScriptBuf::new(),
                    };
                    self.channel_keys.insert(
                        row.channel_keys_id,
                        CachedChannelKeys {
                            pubkeys: keys,
                            destination_script,
                        },
                    );
                }
            }
        }
        // Lift the global counter to max+1 so a fresh `alloc_dbid` post-
        // restart never overlaps a persisted channel. `fetch_max` is
        // monotonic — concurrent restarts are still safe.
        if max_dbid > 0 {
            DBID_COUNTER.fetch_max(max_dbid.saturating_add(1), Ordering::Relaxed);
        }
        Ok(())
    }

    /// Snapshot the in-memory state for `channel_keys_id` and fire-and-
    /// forget write it to the store on a tokio task. No-op when no store
    /// is bound. Failures are logged but never propagated — Postgres is
    /// the journal, the in-memory map is authoritative for live calls.
    fn persist_meta(&self, channel_keys_id: [u8; 32]) {
        let Some(store) = self.meta_store.as_ref().cloned() else {
            return;
        };
        let Some(meta_ref) = self.channel_meta.get(&channel_keys_id) else {
            return;
        };
        let pubkeys_blob = self
            .channel_keys
            .get(&channel_keys_id)
            .map(|c| encode_pubkeys_blob(&c.pubkeys));
        let snapshot = StoredChannelMeta {
            channel_keys_id,
            dbid: meta_ref.dbid,
            peer_id: meta_ref.peer_id,
            setup_funding: meta_ref.setup_funding,
            push_value_msat: meta_ref.push_value_msat,
            pubkeys: pubkeys_blob,
        };
        drop(meta_ref);
        let ctx = self.lookup.context_id().to_string();
        tokio::spawn(async move {
            if let Err(e) = store.upsert(snapshot).await {
                tracing::warn!(
                    target: "wick_vls",
                    ctx = %ctx,
                    error = %e,
                    "ChannelMetaStore::upsert failed (write-through; in-memory state still authoritative)"
                );
            }
        });
    }

    /// Negotiate VLS `HsmdInit2` + fetch LDK-only node keys. Must run after
    /// the SDK signer stream is attached and ready, and before the signer
    /// is wired into a `Node`.
    pub async fn init(&self, network: bitcoin::Network) -> anyhow::Result<()> {
        let conn = self.active_conn()?;
        if !conn.is_ready() {
            anyhow::bail!(
                "signer session not ready for '{}'",
                self.lookup.context_id()
            );
        }
        let (node_id_bytes, _bip32) = rpc::rpc_hsmd_init2(&conn, network).await?;
        let node_pubkey = PublicKey::from_slice(&node_id_bytes)
            .map_err(|e| anyhow::anyhow!("invalid node pubkey from HsmdInit2: {e}"))?;
        let keys = rpc::rpc_get_ldk_node_keys(&conn).await?;

        let _ = self.node_pubkey.set(node_pubkey);
        let _ = self.peer_storage_key.set(keys.peer_storage_key);
        let _ = self.inbound_payment_key.set(keys.inbound_payment_key);
        let _ = self.receive_auth_key.set(keys.receive_auth_key);
        Ok(())
    }

    /// 33-byte compressed node pubkey. Panics if called before [`Self::init`].
    #[must_use]
    pub fn node_pubkey(&self) -> PublicKey {
        *self.node_pubkey.get().unwrap_or_else(|| {
            panic!(
                "SignerSession::node_pubkey() called before init() for '{}'",
                self.lookup.context_id()
            )
        })
    }

    /// `true` when the SDK's signer bidi stream is currently attached and
    /// ready to serve calls. Use this for the `SignerOffline` precheck on
    /// `wake_loading` / `dispatch_*` to refuse work cleanly without
    /// burning a wake slot.
    #[must_use]
    pub fn is_signer_active(&self) -> bool {
        self.lookup.is_ready()
    }

    /// Install a callback fired by [`VlsRemoteChannelSigner::maybe_setup_channel`]
    /// once `SetupChannel` lands and unblocks previously-parked
    /// `ChannelSigner` calls. The builder wires this to
    /// `ChannelManager::signer_unblocked(None)` so LDK retries the parked
    /// channel via the async-signer-pending protocol.
    pub fn set_signer_unblock(&self, cb: Box<dyn Fn() + Send + Sync>) {
        let _ = self.signer_unblock.set(cb);
    }

    /// Stage a push-msat for an outbound channel open. Called by
    /// `wick-server` from `OpenChannelInit` before LDK creates the channel
    /// keys. The value is drained into the new `channel_keys_id` slot the
    /// next time LDK calls `generate_channel_keys_id(inbound=false, ..)`
    /// for `user_channel_id`.
    pub fn register_outbound_channel_open(&self, user_channel_id: u128, push_msat: u64) {
        self.pending_outbound_push_by_user_channel_id
            .insert(user_channel_id, push_msat);
    }

    /// Drop a previously-staged push-msat (e.g. when an `OpenChannelInit`
    /// is cancelled before `OpenChannelFinalize`).
    pub fn clear_outbound_channel_open(&self, user_channel_id: u128) {
        self.pending_outbound_push_by_user_channel_id
            .remove(&user_channel_id);
    }

    /// Ask the SDK signer to derive a wallet address at the given BIP32
    /// index. Used by wick-server when an operator wants the LSP node's
    /// shutdown / sweep address without holding the seed.
    pub async fn get_deposit_address(
        &self,
        index: u32,
    ) -> anyhow::Result<(bitcoin::Address, bitcoin::ScriptBuf)> {
        let conn = self.active_conn()?;
        let (addr_str, spk_bytes) = rpc::rpc_get_wallet_address(&conn, index).await?;
        let unchecked = addr_str
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|e| {
                anyhow::anyhow!("get_deposit_address: invalid address '{addr_str}': {e}")
            })?;
        Ok((unchecked.assume_checked(), bitcoin::ScriptBuf::from_bytes(spk_bytes)))
    }

    /// Encrypt a VSS plaintext through the signer (signer derives the VSS
    /// key from its master seed via domain-separated HKDF).
    pub async fn vss_encrypt(&self, store_key: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let conn = self.active_conn()?;
        rpc::rpc_vss_encrypt(&conn, store_key, plaintext).await
    }

    /// Decrypt a VSS ciphertext through the signer.
    pub async fn vss_decrypt(&self, store_key: &str, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let conn = self.active_conn()?;
        rpc::rpc_vss_decrypt(&conn, store_key, ciphertext).await
    }

    fn active_conn(&self) -> anyhow::Result<Arc<SignerConnection>> {
        self.lookup.resolve().ok_or_else(|| {
            anyhow::anyhow!(
                "signer session not connected for '{}'",
                self.lookup.context_id()
            )
        })
    }

    fn active_conn_if_ready(&self) -> Result<Arc<SignerConnection>, ()> {
        self.lookup.resolve().filter(|conn| conn.is_ready()).ok_or(())
    }

    fn peer_storage_key_bytes(&self) -> [u8; 32] {
        *self.peer_storage_key.get().unwrap_or_else(|| {
            panic!(
                "SignerSession::peer_storage_key called before init() for '{}'",
                self.lookup.context_id()
            )
        })
    }

    fn inbound_payment_key_bytes(&self) -> [u8; 32] {
        *self.inbound_payment_key.get().unwrap_or_else(|| {
            panic!(
                "SignerSession::inbound_payment_key called before init() for '{}'",
                self.lookup.context_id()
            )
        })
    }

    fn receive_auth_key_bytes(&self) -> [u8; 32] {
        *self.receive_auth_key.get().unwrap_or_else(|| {
            panic!(
                "SignerSession::receive_auth_key called before init() for '{}'",
                self.lookup.context_id()
            )
        })
    }

    fn alloc_dbid(&self) -> u64 {
        DBID_COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    fn make_failed_channel_signer(
        &self,
        channel_keys_id: [u8; 32],
        dbid: u64,
    ) -> VlsRemoteChannelSigner {
        let sentinel = sentinel_pubkey();
        VlsRemoteChannelSigner {
            lookup: self.lookup.clone(),
            channel_keys_id,
            dbid,
            peer_id: SENTINEL_PUBKEY,
            pubkeys: ChannelPublicKeys {
                funding_pubkey: sentinel,
                revocation_basepoint: RevocationBasepoint::from(sentinel),
                payment_point: sentinel,
                delayed_payment_basepoint: DelayedPaymentBasepoint::from(sentinel),
                htlc_basepoint: HtlcBasepoint::from(sentinel),
            },
            channel_meta: Arc::clone(&self.channel_meta),
            signer_unblock: Arc::clone(&self.signer_unblock),
            meta_store: self.meta_store.clone(),
            failed: true,
        }
    }

    fn drain_pending_push(&self, channel_keys_id: &[u8; 32]) -> u64 {
        self.pending_outbound_push_by_channel_keys_id
            .remove(channel_keys_id)
            .map(|(_, v)| v)
            .unwrap_or(0)
    }
}

// ── WickSigner ────────────────────────────────────────────────────────────────

// Explicit `WickSigner` impl wires the trait's outbound-channel staging
// methods to `SignerSession`'s existing inherent helpers. Required because
// the prior blanket `impl<T> WickSigner for T` was dropped when the trait
// gained methods (defaults can't be specialised).
impl wick_lightning::WickSigner for SignerSession {
    fn register_outbound_channel_open(&self, user_channel_id: u128, push_msat: u64) {
        SignerSession::register_outbound_channel_open(self, user_channel_id, push_msat);
    }

    fn clear_outbound_channel_open(&self, user_channel_id: u128) {
        SignerSession::clear_outbound_channel_open(self, user_channel_id);
    }

    fn set_signer_unblock_callback(&self, cb: Box<dyn Fn() + Send + Sync>) {
        SignerSession::set_signer_unblock(self, cb);
    }

    fn preapprove_invoice(&self, bolt11: &str) -> anyhow::Result<()> {
        let conn = self.active_conn()?;
        let approved = block_vls!(rpc::rpc_preapprove_invoice(&conn, bolt11.to_owned()))?;
        if !approved {
            anyhow::bail!("device VLS signer declined to preapprove invoice");
        }
        Ok(())
    }

    fn change_destination_source(
        &self,
    ) -> Option<Arc<dyn lightning::sign::ChangeDestinationSourceSync + Send + Sync>> {
        Some(Arc::new(crate::change_destination::VlsChangeDestination::new(
            self.lookup.clone(),
        )))
    }
}

// ── EntropySource ─────────────────────────────────────────────────────────────

impl EntropySource for SignerSession {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        OsRng.fill_bytes(&mut out);
        out
    }
}

// ── NodeSigner ────────────────────────────────────────────────────────────────

impl NodeSigner for SignerSession {
    fn get_expanded_key(&self) -> ExpandedKey {
        ExpandedKey::new(self.inbound_payment_key_bytes())
    }

    fn get_peer_storage_key(&self) -> PeerStorageKey {
        PeerStorageKey {
            inner: self.peer_storage_key_bytes(),
        }
    }

    fn get_receive_auth_key(&self) -> ReceiveAuthKey {
        ReceiveAuthKey(self.receive_auth_key_bytes())
    }

    fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
        match recipient {
            Recipient::Node => self.node_pubkey.get().copied().ok_or(()),
            Recipient::PhantomNode => Err(()),
        }
    }

    fn ecdh(
        &self,
        recipient: Recipient,
        other_key: &PublicKey,
        _tweak: Option<&Scalar>,
    ) -> Result<SharedSecret, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => return Err(()),
        }
        let conn = self.active_conn_if_ready()?;
        tracing::info!(
            target: "wick_vls::dispatch",
            context_id = %self.lookup.context_id(),
            peer = %hex::encode(other_key.serialize()),
            "→ ecdh"
        );
        let secret = block_vls!(rpc::rpc_ecdh(&conn, other_key.serialize())).map_err(|_| ())?;
        tracing::info!(
            target: "wick_vls::dispatch",
            context_id = %self.lookup.context_id(),
            peer = %hex::encode(other_key.serialize()),
            "✓ ecdh"
        );
        Ok(SharedSecret::from_bytes(secret))
    }

    fn sign_invoice(
        &self,
        invoice: &RawBolt11Invoice,
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => return Err(()),
        }
        let hrp_bytes = invoice.hrp.to_string().into_bytes();
        let invoice_data = invoice
            .to_raw()
            .1
            .into_iter()
            .map(|v| v.to_u8())
            .collect::<Vec<u8>>();

        let conn = self.active_conn_if_ready()?;
        let sig65 = block_vls!(rpc::rpc_sign_invoice(&conn, invoice_data, hrp_bytes))
            .map_err(|_| ())?;
        let recovery_id = bitcoin::secp256k1::ecdsa::RecoveryId::from_i32(i32::from(sig65[64]))
            .map_err(|_| ())?;
        RecoverableSignature::from_compact(&sig65[..64], recovery_id).map_err(|_| ())
    }

    fn sign_bolt12_invoice(
        &self,
        invoice: &UnsignedBolt12Invoice,
    ) -> Result<schnorr::Signature, ()> {
        let merkle_root = invoice.tagged_hash().merkle_root().to_byte_array();
        let conn = self.active_conn_if_ready()?;
        let sig64 =
            block_vls!(rpc::rpc_sign_bolt12_invoice(&conn, merkle_root)).map_err(|e| {
                tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, "sign_bolt12_invoice failed");
            })?;
        schnorr::Signature::from_slice(&sig64).map_err(|_| ())
    }

    fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
        let mut bytes = Vec::new();
        msg.write(&mut bytes).map_err(|_| ())?;
        let conn = self.active_conn_if_ready()?;
        let sig64 =
            block_vls!(rpc::rpc_sign_gossip_message(&conn, bytes)).map_err(|_| ())?;
        Signature::from_compact(&sig64).map_err(|_| ())
    }

    fn sign_message(&self, _msg: &[u8]) -> Result<String, ()> {
        // Not required by the VLS protocol for LDK Lightning operation —
        // VLS doesn't expose `lnd-style` signMessage. wick doesn't surface
        // it either; if a tenant needs it, signing happens on the SDK
        // side directly using the on-device identity key.
        Err(())
    }
}

// ── SignerProvider ────────────────────────────────────────────────────────────

impl SignerProvider for SignerSession {
    type EcdsaSigner = VlsRemoteChannelSigner;

    fn generate_channel_keys_id(&self, inbound: bool, user_channel_id: u128) -> [u8; 32] {
        let mut id = [0u8; 32];
        OsRng.fill_bytes(&mut id);
        // Encode direction in the high bit of byte 0 for debug visibility.
        id[0] = (id[0] & 0x7F) | (if inbound { 0x80 } else { 0x00 });

        if !inbound {
            let push_msat = self
                .pending_outbound_push_by_user_channel_id
                .remove(&user_channel_id)
                .map(|(_, v)| v)
                .unwrap_or(0);
            self.pending_outbound_push_by_channel_keys_id
                .insert(id, push_msat);
        }
        id
    }

    fn derive_channel_signer(&self, channel_keys_id: [u8; 32]) -> VlsRemoteChannelSigner {
        // Cache hit: hand back a signer bound to the same dbid + cached pubkeys.
        if let (Some(meta), Some(keys)) = (
            self.channel_meta.get(&channel_keys_id),
            self.channel_keys.get(&channel_keys_id),
        ) {
            return VlsRemoteChannelSigner {
                lookup: self.lookup.clone(),
                channel_keys_id,
                dbid: meta.dbid,
                peer_id: meta.peer_id,
                pubkeys: keys.pubkeys.clone(),
                channel_meta: Arc::clone(&self.channel_meta),
                signer_unblock: Arc::clone(&self.signer_unblock),
                meta_store: self.meta_store.clone(),
                failed: false,
            };
        }

        let dbid = self.alloc_dbid();
        let conn = match self.active_conn_if_ready() {
            Ok(conn) => conn,
            Err(()) => {
                // SDK offline at construction time. LDK does not tolerate
                // an Err return here, so we record the channel and hand
                // back a "failed" signer that errors on every actual
                // signing call.
                self.channel_meta.insert(
                    channel_keys_id,
                    ChannelMeta {
                        dbid,
                        peer_id: SENTINEL_PUBKEY,
                        setup_funding: None,
                        push_value_msat: self.drain_pending_push(&channel_keys_id),
                        setup_done_for_session: None,
                    },
                );
                self.persist_meta(channel_keys_id);
                return self.make_failed_channel_signer(channel_keys_id, dbid);
            }
        };

        let result = block_vls!(rpc::rpc_get_channel_basepoints(
            &conn,
            SENTINEL_PUBKEY,
            dbid
        ));

        // Record the channel identity regardless of RPC outcome — keeps
        // dbid allocation consistent across retries.
        self.channel_meta.insert(
            channel_keys_id,
            ChannelMeta {
                dbid,
                peer_id: SENTINEL_PUBKEY,
                setup_funding: None,
                push_value_msat: self.drain_pending_push(&channel_keys_id),
                setup_done_for_session: None,
            },
        );

        match result {
            Ok(bp) => {
                let parse_pk = |b: &[u8; 33]| {
                    PublicKey::from_slice(b)
                        .unwrap_or_else(|_| panic!("signer returned invalid pubkey"))
                };
                let pubkeys = ChannelPublicKeys {
                    funding_pubkey: parse_pk(&bp.funding),
                    revocation_basepoint: RevocationBasepoint::from(parse_pk(&bp.revocation)),
                    payment_point: parse_pk(&bp.payment),
                    delayed_payment_basepoint: DelayedPaymentBasepoint::from(parse_pk(
                        &bp.delayed_payment,
                    )),
                    htlc_basepoint: HtlcBasepoint::from(parse_pk(&bp.htlc)),
                };
                let destination_script =
                    shutdown_script_from_pubkey(self.node_pubkey()).into_inner();
                self.channel_keys.insert(
                    channel_keys_id,
                    CachedChannelKeys {
                        pubkeys: pubkeys.clone(),
                        destination_script,
                    },
                );
                self.persist_meta(channel_keys_id);
                VlsRemoteChannelSigner {
                    lookup: self.lookup.clone(),
                    channel_keys_id,
                    dbid,
                    peer_id: SENTINEL_PUBKEY,
                    pubkeys,
                    channel_meta: Arc::clone(&self.channel_meta),
                    signer_unblock: Arc::clone(&self.signer_unblock),
                    meta_store: self.meta_store.clone(),
                    failed: false,
                }
            }
            Err(e) => {
                tracing::error!(
                    target: "wick_vls",
                    ctx = %self.lookup.context_id(),
                    ?channel_keys_id,
                    dbid,
                    %e,
                    "GetChannelBasepoints RPC failed — returning failed signer"
                );
                self.make_failed_channel_signer(channel_keys_id, dbid)
            }
        }
    }

    fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<bitcoin::ScriptBuf, ()> {
        self.channel_keys
            .get(&channel_keys_id)
            .map(|c| c.destination_script.clone())
            .ok_or(())
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
        Ok(shutdown_script_from_pubkey(self.node_pubkey()))
    }
}

// ── OutputSpender ─────────────────────────────────────────────────────────────

/// Per-input bundle built from a list of [`SpendableOutputDescriptor`]s.
/// Pulled out of [`SignerSession::spend_spendable_outputs`] so the
/// tx-construction logic is unit-testable without a live signer.
struct DescriptorInputs {
    tx_ins: Vec<bitcoin::TxIn>,
    psbt_inputs: Vec<bitcoin::psbt::Input>,
    withdrawal_utxos: Vec<rpc::WithdrawalUtxo>,
    total_in_sat: u64,
}

impl SignerSession {
    /// Convert a slice of [`SpendableOutputDescriptor`]s into the per-input
    /// vectors that drive `rpc_sign_withdrawal`. Returns `Err(())` if any
    /// channel-key descriptor references a `channel_keys_id` that this
    /// session has never persisted (i.e. the channel was never opened on
    /// this signer instance).
    fn build_descriptor_inputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
    ) -> Result<DescriptorInputs, ()> {
        let mut tx_ins = Vec::new();
        let mut psbt_inputs = Vec::new();
        let mut withdrawal_utxos = Vec::new();
        let mut total_in_sat: u64 = 0;

        for desc in descriptors {
            match desc {
                SpendableOutputDescriptor::StaticOutput {
                    outpoint, output, ..
                } => {
                    total_in_sat = total_in_sat.saturating_add(output.value.to_sat());
                    tx_ins.push(bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint {
                            txid: outpoint.txid,
                            vout: u32::from(outpoint.index),
                        },
                        script_sig: bitcoin::ScriptBuf::new(),
                        sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: bitcoin::Witness::new(),
                    });
                    psbt_inputs.push(bitcoin::psbt::Input {
                        witness_utxo: Some(output.clone()),
                        ..Default::default()
                    });
                    withdrawal_utxos.push(rpc::WithdrawalUtxo {
                        txid: outpoint.txid,
                        outnum: u32::from(outpoint.index),
                        amount_sat: output.value.to_sat(),
                        keyindex: 1,
                        is_p2sh: false,
                        script_pubkey: output.script_pubkey.to_bytes(),
                        is_in_coinbase: false,
                        close_info: None,
                    });
                }
                SpendableOutputDescriptor::DelayedPaymentOutput(d) => {
                    // `to_local` recovery from a channel close. We must look up
                    // the VLS-side channel binding (dbid + peer_id); without it
                    // the signer can't unilaterally re-derive the per-channel
                    // delayed-payment key.
                    let Some(meta_ref) = self.channel_meta.get(&d.channel_keys_id) else {
                        tracing::warn!(
                            target: "wick_vls",
                            ctx = %self.lookup.context_id(),
                            channel_keys_id = ?d.channel_keys_id,
                            "spend_spendable_outputs: unknown channel_keys_id for DelayedPaymentOutput",
                        );
                        return Err(());
                    };
                    let dbid = meta_ref.dbid;
                    let peer_id = meta_ref.peer_id;
                    drop(meta_ref);

                    let is_anchors = d
                        .channel_transaction_parameters
                        .as_ref()
                        .map(|p| p.channel_type_features.supports_anchors_zero_fee_htlc_tx())
                        .unwrap_or(false);

                    total_in_sat = total_in_sat.saturating_add(d.output.value.to_sat());
                    tx_ins.push(bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint {
                            txid: d.outpoint.txid,
                            vout: u32::from(d.outpoint.index),
                        },
                        script_sig: bitcoin::ScriptBuf::new(),
                        // BIP68 relative time-lock — required for the OP_CSV
                        // check inside the to_local revocable redeemscript.
                        sequence: bitcoin::Sequence(u32::from(d.to_self_delay)),
                        witness: bitcoin::Witness::new(),
                    });
                    psbt_inputs.push(bitcoin::psbt::Input {
                        witness_utxo: Some(d.output.clone()),
                        ..Default::default()
                    });
                    withdrawal_utxos.push(rpc::WithdrawalUtxo {
                        txid: d.outpoint.txid,
                        outnum: u32::from(d.outpoint.index),
                        amount_sat: d.output.value.to_sat(),
                        keyindex: 0,
                        is_p2sh: false,
                        script_pubkey: d.output.script_pubkey.to_bytes(),
                        is_in_coinbase: false,
                        close_info: Some(rpc::WithdrawalCloseInfo {
                            channel_id: dbid,
                            peer_id,
                            commitment_point: Some(d.per_commitment_point.serialize()),
                            is_anchors,
                            csv: u32::from(d.to_self_delay),
                        }),
                    });
                }
                SpendableOutputDescriptor::StaticPaymentOutput(s) => {
                    // `to_remote` from a channel close paid to our static
                    // payment key. On anchor-outputs channels, the output is a
                    // P2WSH wrapping a `1 OP_CSV` script and requires
                    // `nSequence >= 1`; on legacy channels it's plain P2WPKH.
                    let Some(meta_ref) = self.channel_meta.get(&s.channel_keys_id) else {
                        tracing::warn!(
                            target: "wick_vls",
                            ctx = %self.lookup.context_id(),
                            channel_keys_id = ?s.channel_keys_id,
                            "spend_spendable_outputs: unknown channel_keys_id for StaticPaymentOutput",
                        );
                        return Err(());
                    };
                    let dbid = meta_ref.dbid;
                    let peer_id = meta_ref.peer_id;
                    drop(meta_ref);

                    let is_anchors = s
                        .channel_transaction_parameters
                        .as_ref()
                        .map(|p| p.channel_type_features.supports_anchors_zero_fee_htlc_tx())
                        .unwrap_or(false);
                    let csv: u32 = if is_anchors { 1 } else { 0 };
                    let sequence = if is_anchors {
                        bitcoin::Sequence(1)
                    } else {
                        bitcoin::Sequence::ZERO
                    };

                    total_in_sat = total_in_sat.saturating_add(s.output.value.to_sat());
                    tx_ins.push(bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint {
                            txid: s.outpoint.txid,
                            vout: u32::from(s.outpoint.index),
                        },
                        script_sig: bitcoin::ScriptBuf::new(),
                        sequence,
                        witness: bitcoin::Witness::new(),
                    });
                    psbt_inputs.push(bitcoin::psbt::Input {
                        witness_utxo: Some(s.output.clone()),
                        witness_script: s.witness_script(),
                        ..Default::default()
                    });
                    withdrawal_utxos.push(rpc::WithdrawalUtxo {
                        txid: s.outpoint.txid,
                        outnum: u32::from(s.outpoint.index),
                        amount_sat: s.output.value.to_sat(),
                        keyindex: 0,
                        is_p2sh: false,
                        script_pubkey: s.output.script_pubkey.to_bytes(),
                        is_in_coinbase: false,
                        close_info: Some(rpc::WithdrawalCloseInfo {
                            channel_id: dbid,
                            peer_id,
                            // No per-commitment point: VLS uses the static
                            // payment basepoint directly.
                            commitment_point: None,
                            is_anchors,
                            csv,
                        }),
                    });
                }
            }
        }

        Ok(DescriptorInputs {
            tx_ins,
            psbt_inputs,
            withdrawal_utxos,
            total_in_sat,
        })
    }
}

impl OutputSpender for SignerSession {
    fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<bitcoin::TxOut>,
        change_destination_script: bitcoin::ScriptBuf,
        feerate_sat_per_1000_weight: u32,
        locktime: Option<bitcoin::absolute::LockTime>,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<bitcoin::Transaction, ()> {
        let lock_time = locktime.unwrap_or(bitcoin::absolute::LockTime::ZERO);

        let DescriptorInputs {
            tx_ins,
            psbt_inputs,
            withdrawal_utxos,
            total_in_sat,
        } = self.build_descriptor_inputs(descriptors)?;

        let mut tx_outs = outputs;
        let total_out_sat: u64 = tx_outs.iter().map(|o| o.value.to_sat()).sum();

        // Fee estimate: assume one extra change output. Matches gateway-lightning's
        // estimate so the signer's withdrawal validator accepts the tx.
        let vbytes = estimate_p2wpkh_tx_vbytes(tx_ins.len(), tx_outs.len() + 1);
        let weight = vbytes.saturating_mul(4);
        let fee_sat = u64::from(feerate_sat_per_1000_weight)
            .saturating_mul(weight)
            .saturating_div(1000);

        if total_in_sat < total_out_sat.saturating_add(fee_sat) {
            return Err(());
        }
        let change_sat = total_in_sat - total_out_sat - fee_sat;
        if change_sat >= DUST_LIMIT_SAT {
            tx_outs.push(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(change_sat),
                script_pubkey: change_destination_script,
            });
        }

        let unsigned_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time,
            input: tx_ins,
            output: tx_outs,
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).map_err(|_| ())?;
        psbt.inputs = psbt_inputs;

        let conn = self.active_conn_if_ready()?;
        let signed_psbt_bytes = block_vls!(rpc::rpc_sign_withdrawal(
            &conn,
            psbt.serialize(),
            withdrawal_utxos
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, "rpc_sign_withdrawal failed");
        })?;

        let signed = Psbt::deserialize(&signed_psbt_bytes).map_err(|_| ())?;
        signed.extract_tx().map_err(|_| ())
    }
}

/// Concatenate the 5 channel basepoints into a flat 165-byte blob for
/// persistence. Order is fixed: funding, revocation, payment,
/// delayed_payment, htlc — matches the layout of
/// `vls_protocol::msgs::GetChannelBasepointsReply` so reads are stable
/// across restarts.
fn encode_pubkeys_blob(pubkeys: &ChannelPublicKeys) -> [u8; 165] {
    let mut out = [0u8; 165];
    out[0..33].copy_from_slice(&pubkeys.funding_pubkey.serialize());
    out[33..66].copy_from_slice(&pubkeys.revocation_basepoint.0.serialize());
    out[66..99].copy_from_slice(&pubkeys.payment_point.serialize());
    out[99..132].copy_from_slice(&pubkeys.delayed_payment_basepoint.0.serialize());
    out[132..165].copy_from_slice(&pubkeys.htlc_basepoint.0.serialize());
    out
}

/// Inverse of [`encode_pubkeys_blob`]. Returns `None` if any of the five
/// 33-byte slots fail to parse — the row is then logged + skipped by
/// `rehydrate`.
fn decode_pubkeys_blob(blob: &[u8; 165]) -> Option<ChannelPublicKeys> {
    let parse = |off: usize| PublicKey::from_slice(&blob[off..off + 33]).ok();
    Some(ChannelPublicKeys {
        funding_pubkey: parse(0)?,
        revocation_basepoint: RevocationBasepoint::from(parse(33)?),
        payment_point: parse(66)?,
        delayed_payment_basepoint: DelayedPaymentBasepoint::from(parse(99)?),
        htlc_basepoint: HtlcBasepoint::from(parse(132)?),
    })
}

fn estimate_p2wpkh_tx_vbytes(num_inputs: usize, num_outputs: usize) -> u64 {
    // P2WPKH approximation: base 10, ~68 vB/input, ~31 vB/output.
    10 + (num_inputs as u64) * 68 + (num_outputs as u64) * 31
}

// ── VlsRemoteChannelSigner ────────────────────────────────────────────────────

/// Per-channel remote signer. Vended by [`SignerSession::derive_channel_signer`]
/// and bound to a stable `(channel_keys_id, dbid)` pair. Every signing call
/// round-trips to the SDK; cached state is `pubkeys` + `channel_keys_id` only.
#[derive(Clone)]
pub struct VlsRemoteChannelSigner {
    lookup: ConnLookup,
    channel_keys_id: [u8; 32],

    /// VLS channel identifier — stable within this `SignerSession` instance.
    /// Seeded from `unix_ts` at construction so distinct restarts allocate
    /// non-overlapping ranges.
    dbid: u64,

    /// Counterparty pubkey routing field on channel-scoped VLS frames.
    /// Currently always [`SENTINEL_PUBKEY`]; the real counterparty pubkey
    /// is delivered inside `SetupChannel` when `maybe_setup_channel` fires.
    #[allow(dead_code)]
    peer_id: [u8; 33],

    pubkeys: ChannelPublicKeys,

    /// Shared with the parent [`SignerSession`] so future `peer_id`
    /// promotions land here without rebuilding the signer.
    channel_meta: Arc<DashMap<[u8; 32], ChannelMeta>>,

    /// Shared signer-unblock callback (installed by the builder on the
    /// parent `SignerSession`). Fired from `maybe_setup_channel` once
    /// `SetupChannel` lands so LDK retries the parked channel via
    /// `ChannelManager::signer_unblocked`.
    signer_unblock: Arc<OnceLock<Box<dyn Fn() + Send + Sync>>>,

    /// `true` if `GetChannelBasepoints` failed at construction — every
    /// signing call returns `Err(())` immediately so LDK force-closes the
    /// channel cleanly rather than producing invalid signatures.
    failed: bool,

    /// Optional durable backing — fired from
    /// [`Self::maybe_setup_channel`] once `setup_funding` is promoted so
    /// a restart sees the SetupChannel-completed state.
    meta_store: Option<ChannelMetaStoreRef>,
}

impl std::fmt::Debug for VlsRemoteChannelSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlsRemoteChannelSigner")
            .field("channel_keys_id", &hex::encode(self.channel_keys_id))
            .field("dbid", &self.dbid)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl VlsRemoteChannelSigner {
    fn active_conn(&self) -> Result<Arc<SignerConnection>, ()> {
        self.lookup.resolve().filter(|conn| conn.is_ready()).ok_or(())
    }

    fn current_peer_id(&self) -> [u8; 33] {
        self.channel_meta
            .get(&self.channel_keys_id)
            .map(|m| m.peer_id)
            .unwrap_or(SENTINEL_PUBKEY)
    }

    /// `true` once `SetupChannel` has been delivered to VLS.
    fn channel_is_set_up(&self) -> bool {
        self.channel_meta
            .get(&self.channel_keys_id)
            .map(|m| m.setup_funding.is_some())
            .unwrap_or(false)
    }

    /// Probe whether `SetupChannel` has landed before serving a
    /// `ChannelSigner` method that has no `ChannelTransactionParameters`
    /// argument (and therefore can't call `maybe_setup_channel` itself).
    ///
    /// Non-blocking: returns `Err(())` immediately when setup hasn't
    /// landed yet. LDK 0.2's async-signer-pending protocol will retry
    /// once `maybe_setup_channel` (running concurrently from a sibling
    /// `EcdsaChannelSigner` call that *does* receive
    /// `ChannelTransactionParameters`) flips `setup_funding` and fires
    /// the signer-unblock callback wired by the builder.
    fn await_setup(&self) -> Result<(), ()> {
        if self.channel_is_set_up() {
            Ok(())
        } else {
            Err(())
        }
    }

    fn fire_signer_unblock(&self) {
        if let Some(cb) = self.signer_unblock.get() {
            cb();
        }
    }

    /// Snapshot the post-`SetupChannel` `ChannelMeta` and write it to the
    /// store on a tokio task. No-op when no store is bound. Failures are
    /// logged-and-swallowed; the in-memory map is authoritative for live
    /// calls (Postgres is the journal).
    fn persist_meta_after_setup(&self) {
        let Some(store) = self.meta_store.as_ref().cloned() else {
            return;
        };
        let Some(meta_ref) = self.channel_meta.get(&self.channel_keys_id) else {
            return;
        };
        let snapshot = StoredChannelMeta {
            channel_keys_id: self.channel_keys_id,
            dbid: meta_ref.dbid,
            peer_id: meta_ref.peer_id,
            setup_funding: meta_ref.setup_funding,
            push_value_msat: meta_ref.push_value_msat,
            // The basepoints blob doesn't change at SetupChannel time;
            // the prior `derive_channel_signer` row already persisted
            // them. Leave it `None` to keep the upsert column count
            // small — the store is expected to preserve `pubkeys` if
            // already set (see `PgChannelMetaStore::upsert`).
            pubkeys: Some(encode_pubkeys_blob(&self.pubkeys)),
        };
        drop(meta_ref);
        let ctx = self.lookup.context_id().to_string();
        tokio::spawn(async move {
            if let Err(e) = store.upsert(snapshot).await {
                tracing::warn!(
                    target: "wick_vls",
                    ctx = %ctx,
                    error = %e,
                    "ChannelMetaStore::upsert (setup) failed"
                );
            }
        });
    }

    /// Ensure the VLS-side channel is promoted to its real counterparty
    /// keys + funding outpoint. Idempotent — short-circuits when the
    /// `SetupChannel` has already been delivered for the same funding
    /// outpoint.
    fn maybe_setup_channel(
        &self,
        channel_parameters: &ChannelTransactionParameters,
    ) -> Result<(), ()> {
        if !channel_parameters.is_populated() {
            return Ok(());
        }

        let funding_outpoint = channel_parameters.funding_outpoint.as_ref().ok_or(())?;
        let counterparty = channel_parameters
            .counterparty_parameters
            .as_ref()
            .ok_or(())?;
        let target_funding = (funding_outpoint.txid, funding_outpoint.index);

        // Resolve the live signer connection up front — we need its
        // `session_token` to decide whether the *device* has been sent
        // SetupChannel in THIS attach. The device keeps no durable channel
        // state (`DummyPersister`) and is rebuilt on every Attach, so a
        // `setup_funding` rehydrated from a prior process is NOT proof the
        // freshly-attached device knows the channel. Short-circuit only when
        // setup landed for the current session; otherwise re-issue it (the
        // VLS `SetupChannel` promotion is idempotent on the device).
        let conn = self.active_conn()?;
        let session = conn.session_token();

        if self
            .channel_meta
            .get(&self.channel_keys_id)
            .map(|m| {
                m.setup_funding == Some(target_funding)
                    && m.setup_done_for_session == Some(session)
            })
            .unwrap_or(false)
        {
            return Ok(());
        }

        let mut channel_type = Vec::new();
        channel_parameters
            .channel_type_features
            .write(&mut channel_type)
            .map_err(|_| ())?;

        let peer_id = self.current_peer_id();
        let push_msat = self
            .channel_meta
            .get(&self.channel_keys_id)
            .map(|m| m.push_value_msat)
            .unwrap_or(0);
        block_vls!(rpc::rpc_setup_channel_from_primitives(
            &conn,
            self.dbid,
            peer_id,
            channel_parameters.is_outbound_from_holder,
            channel_parameters.channel_value_satoshis,
            push_msat,
            funding_outpoint.txid,
            funding_outpoint.index,
            channel_parameters.holder_selected_contest_delay,
            vec![],
            None,
            counterparty.pubkeys.revocation_basepoint.0.serialize(),
            counterparty.pubkeys.payment_point.serialize(),
            counterparty.pubkeys.htlc_basepoint.0.serialize(),
            counterparty.pubkeys.delayed_payment_basepoint.0.serialize(),
            counterparty.pubkeys.funding_pubkey.serialize(),
            counterparty.selected_contest_delay,
            vec![],
            channel_type,
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, "setup_channel failed");
        })?;

        if let Some(mut meta) = self.channel_meta.get_mut(&self.channel_keys_id) {
            meta.setup_funding = Some(target_funding);
            // Record that the device for THIS attach now knows the channel,
            // so subsequent signing calls in the same session short-circuit.
            meta.setup_done_for_session = Some(session);
        }
        self.persist_meta_after_setup();

        // Setup just landed — wake any `ChannelSigner` calls that returned
        // `Err(())` (via `await_setup`) while `setup_funding` was still
        // `None`. LDK 0.2's async-signer-pending protocol retries them on
        // `ChannelManager::signer_unblocked`, which the builder wires to
        // this callback.
        self.fire_signer_unblock();

        Ok(())
    }
}

// ── ChannelSigner ─────────────────────────────────────────────────────────────

impl ChannelSigner for VlsRemoteChannelSigner {
    fn get_per_commitment_point(
        &self,
        idx: u64,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<PublicKey, ()> {
        if self.failed {
            return Err(());
        }
        // VLS in stub state (NewChannel, no SetupChannel yet) only allows
        // points 0 and 1 — the per-commitment points used in OpenChannel
        // / AcceptChannel. For commit ≥ 2 the channel must be `setup_channel`
        // promoted; await that briefly rather than returning Err (which LDK
        // would treat as a fatal signer error and disable the channel).
        let vls_commit_number = (1u64 << 48).saturating_sub(1).saturating_sub(idx);
        if vls_commit_number > 1 {
            self.await_setup()?;
        }
        let conn = self.active_conn()?;
        let peer_id = self.current_peer_id();
        let bytes = block_vls!(rpc::rpc_get_per_commitment_point(
            &conn, self.dbid, peer_id, idx
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, idx, "get_per_commitment_point failed");
        })?;
        PublicKey::from_slice(&bytes).map_err(|_| ())
    }

    fn release_commitment_secret(&self, idx: u64) -> Result<[u8; 32], ()> {
        if self.failed {
            return Err(());
        }
        // Same stub-state gate as `get_per_commitment_point`.
        self.await_setup()?;
        let conn = self.active_conn()?;
        let peer_id = self.current_peer_id();
        let r = block_vls!(rpc::rpc_release_commitment_secret(
            &conn, self.dbid, peer_id, idx
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, idx, "release_commitment_secret failed");
        });
        if r.is_ok() {
            // `RevokeCommitmentTx` just advanced the device's
            // `next_holder_commit_num`. LDK fetches the next per-commitment
            // point *before* this revoke (the device's ceiling is
            // `commitment_number <= next_holder_commit_num + 1`), so a
            // `get_per_commitment_point` for the commitment beyond the old
            // ceiling was rejected and parked as signer-pending. Now that the
            // counter has advanced, nudge LDK to retry that parked call —
            // otherwise the channel stalls waiting for a point the device is
            // now ready to give. Without this, JIT HTLC settlement hangs with
            // "get_per_commitment_point: commitment_number N invalid when
            // next_holder_commit_num is N-2".
            self.fire_signer_unblock();
        }
        r
    }

    fn validate_holder_commitment(
        &self,
        holder_tx: &HolderCommitmentTransaction,
        _outbound_htlc_preimages: Vec<PaymentPreimage>,
    ) -> Result<(), ()> {
        if self.failed {
            return Err(());
        }
        // LDK 0.2's two-phase funding calls `validate_holder_commitment` as a
        // pre-funding self-check for the INITIAL commitment (LDK number
        // `(1<<48)-1` = VLS commit 0), before any `EcdsaChannelSigner` method
        // has run `maybe_setup_channel`/`SetupChannel`. For that one call there
        // is no concurrent racing call to deliver `SetupChannel`, so awaiting
        // setup would deadlock — skip the VLS round-trip and let
        // `sign_holder_commitment` validate downstream.
        //
        // For EVERY subsequent (post-funding) commitment this call MUST be
        // forwarded. At VLS protocol v5+ (which we now negotiate so
        // `RevokeCommitmentTx` is available), `ValidateCommitmentTx2` is the
        // *only* message that stages `next_holder_commit_info` — the
        // prerequisite for `release_commitment_secret` (`RevokeCommitmentTx`)
        // to advance the device's `next_holder_commit_num`. Dropping it strands
        // the device counter at 1 while LDK marches its commitments forward,
        // producing `get_per_commitment_point: commitment_number N invalid when
        // next_holder_commit_num is 1` at the next HTLC. So PARK (await_setup),
        // never stub, for post-funding commitments.
        let commitment_number = holder_tx.commitment_number();
        let is_initial = commitment_number == (1u64 << 48) - 1;
        if is_initial && !self.channel_is_set_up() {
            tracing::debug!(
                target: "wick_vls",
                ctx = %self.lookup.context_id(),
                dbid = self.dbid,
                "validate_holder_commitment: initial pre-funding self-check — deferring to sign_holder_commitment"
            );
            return Ok(());
        }
        self.await_setup()?;

        let conn = self.active_conn()?;
        let feerate = holder_tx.negotiated_feerate_per_kw();
        let to_local_value_sat = holder_tx.to_broadcaster_value_sat();
        let to_remote_value_sat = holder_tx.to_countersignatory_value_sat();
        let htlcs: Vec<rpc::HtlcEntry> = holder_tx
            .nondust_htlcs()
            .iter()
            .map(|htlc| {
                let side: u8 = if htlc.offered { 0 } else { 1 };
                (
                    side,
                    htlc.amount_msat,
                    htlc.payment_hash.0,
                    htlc.cltv_expiry,
                )
            })
            .collect();
        let commitment_sig = holder_tx.counterparty_sig.serialize_compact();
        let htlc_sigs = holder_tx
            .counterparty_htlc_sigs
            .iter()
            .map(|s| s.serialize_compact())
            .collect();

        let peer_id = self.current_peer_id();
        block_vls!(rpc::rpc_validate_holder_commitment(
            &conn,
            self.dbid,
            peer_id,
            commitment_number,
            feerate,
            to_local_value_sat,
            to_remote_value_sat,
            htlcs,
            commitment_sig,
            htlc_sigs,
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, commitment_number, "validate_holder_commitment failed");
        })?;
        Ok(())
    }

    fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()> {
        if self.failed {
            return Err(());
        }
        let conn = self.active_conn()?;
        let peer_id = self.current_peer_id();
        block_vls!(rpc::rpc_validate_counterparty_revocation(
            &conn,
            self.dbid,
            peer_id,
            idx,
            secret.secret_bytes(),
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, idx, "validate_counterparty_revocation failed");
        })
    }

    fn pubkeys(&self, _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> ChannelPublicKeys {
        self.pubkeys.clone()
    }

    fn new_funding_pubkey(
        &self,
        splice_parent_funding_txid: bitcoin::Txid,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> PublicKey {
        let conn = match self.active_conn() {
            Ok(conn) => conn,
            Err(()) => return self.pubkeys.funding_pubkey,
        };
        match block_vls!(rpc::rpc_get_splice_new_funding_pubkey(
            &conn,
            splice_parent_funding_txid
        )) {
            Ok(pk) => PublicKey::from_slice(&pk).unwrap_or(self.pubkeys.funding_pubkey),
            Err(e) => {
                tracing::warn!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, "new_funding_pubkey extension unavailable; using cached funding key");
                self.pubkeys.funding_pubkey
            }
        }
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        self.channel_keys_id
    }
}

// ── EcdsaChannelSigner ────────────────────────────────────────────────────────

impl EcdsaChannelSigner for VlsRemoteChannelSigner {
    fn sign_counterparty_commitment(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        commitment_tx: &CommitmentTransaction,
        _inbound_htlc_preimages: Vec<PaymentPreimage>,
        _outbound_htlc_preimages: Vec<PaymentPreimage>,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        if self.failed {
            return Err(());
        }
        self.maybe_setup_channel(channel_parameters)?;

        let commitment_number = commitment_tx.commitment_number();
        let feerate = commitment_tx.negotiated_feerate_per_kw();
        // VLS terminology in `SignRemoteCommitmentTx2` is from the LOCAL
        // signer's perspective:
        //   - `to_local_value_sat`  = OUR (local) value
        //   - `to_remote_value_sat` = COUNTERPARTY's value
        // In LDK's counterparty commitment, the counterparty is the
        // broadcaster and we are the countersignatory, so map the names
        // accordingly.
        let to_local_value_sat = commitment_tx.to_countersignatory_value_sat();
        let to_remote_value_sat = commitment_tx.to_broadcaster_value_sat();

        let trusted = commitment_tx.trust();
        let per_commitment_point = trusted.keys().per_commitment_point.serialize();

        // Counterparty commitment: `htlc.offered = true` means *they* are
        // offering the HTLC → inbound for us → VLS side = 1.
        let htlcs: Vec<rpc::HtlcEntry> = commitment_tx
            .nondust_htlcs()
            .iter()
            .map(|htlc| {
                let side: u8 = if htlc.offered { 1 } else { 0 };
                (
                    side,
                    htlc.amount_msat,
                    htlc.payment_hash.0,
                    htlc.cltv_expiry,
                )
            })
            .collect();

        let peer_id = self.current_peer_id();
        let conn = self.active_conn()?;
        let (commitment_sig_bytes, htlc_sig_bytes) = block_vls!(rpc::rpc_sign_remote_commitment(
            &conn,
            self.dbid,
            peer_id,
            per_commitment_point,
            commitment_number,
            feerate,
            to_local_value_sat,
            to_remote_value_sat,
            htlcs,
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, commitment_number, "sign_counterparty_commitment failed");
        })?;

        let commitment_sig = Signature::from_compact(&commitment_sig_bytes).map_err(|_| ())?;
        let htlc_sigs = htlc_sig_bytes
            .iter()
            .map(|b| Signature::from_compact(b))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ())?;
        Ok((commitment_sig, htlc_sigs))
    }

    fn sign_holder_commitment(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        commitment_tx: &HolderCommitmentTransaction,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        if self.failed {
            return Err(());
        }
        self.maybe_setup_channel(channel_parameters)?;
        let commitment_number = commitment_tx.commitment_number();
        let peer_id = self.current_peer_id();
        let conn = self.active_conn()?;
        let sig_bytes = block_vls!(rpc::rpc_sign_holder_commitment(
            &conn,
            self.dbid,
            peer_id,
            commitment_number
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, commitment_number, "sign_holder_commitment failed");
        })?;
        Signature::from_compact(&sig_bytes).map_err(|_| ())
    }

    fn sign_justice_revoked_output(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        justice_tx: &bitcoin::Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        if self.failed {
            return Err(());
        }
        self.maybe_setup_channel(channel_parameters)?;

        let per_commitment_point = PublicKey::from_secret_key(secp_ctx, per_commitment_key);
        let revocation_key = RevocationKey::from_basepoint(
            secp_ctx,
            &channel_parameters.holder_pubkeys.revocation_basepoint,
            &per_commitment_point,
        );
        let delayed_payment_key = DelayedPaymentKey::from_basepoint(
            secp_ctx,
            &channel_parameters
                .counterparty_parameters
                .as_ref()
                .ok_or(())?
                .pubkeys
                .delayed_payment_basepoint,
            &per_commitment_point,
        );
        let wscript = get_revokeable_redeemscript(
            &revocation_key,
            channel_parameters.holder_selected_contest_delay,
            &delayed_payment_key,
        );

        let mut psbt = Psbt::from_unsigned_tx(justice_tx.clone()).map_err(|_| ())?;
        if input >= psbt.inputs.len() {
            return Err(());
        }
        psbt.inputs[input].witness_utxo = Some(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(amount),
            script_pubkey: wscript.to_p2wsh(),
        });

        let peer_id = self.current_peer_id();
        let conn = self.active_conn()?;
        let sig_bytes = block_vls!(rpc::rpc_sign_penalty_to_us(
            &conn,
            self.dbid,
            peer_id,
            per_commitment_key.secret_bytes(),
            justice_tx.clone(),
            psbt.serialize(),
            wscript.to_bytes(),
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, input, "sign_justice_revoked_output failed");
        })?;
        Signature::from_compact(&sig_bytes).map_err(|_| ())
    }

    fn sign_justice_revoked_htlc(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        justice_tx: &bitcoin::Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        if self.failed {
            return Err(());
        }
        self.maybe_setup_channel(channel_parameters)?;

        let per_commitment_point = PublicKey::from_secret_key(secp_ctx, per_commitment_key);
        let counterparty = channel_parameters
            .counterparty_parameters
            .as_ref()
            .ok_or(())?
            .pubkeys
            .clone();
        let keys = TxCreationKeys::from_channel_static_keys(
            &per_commitment_point,
            &counterparty,
            &channel_parameters.holder_pubkeys,
            secp_ctx,
        );
        let wscript =
            get_htlc_redeemscript(htlc, &channel_parameters.channel_type_features, &keys);

        let mut psbt = Psbt::from_unsigned_tx(justice_tx.clone()).map_err(|_| ())?;
        if input >= psbt.inputs.len() {
            return Err(());
        }
        psbt.inputs[input].witness_utxo = Some(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(amount),
            script_pubkey: wscript.to_p2wsh(),
        });

        let peer_id = self.current_peer_id();
        let conn = self.active_conn()?;
        let sig_bytes = block_vls!(rpc::rpc_sign_penalty_to_us(
            &conn,
            self.dbid,
            peer_id,
            per_commitment_key.secret_bytes(),
            justice_tx.clone(),
            psbt.serialize(),
            wscript.to_bytes(),
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, input, "sign_justice_revoked_htlc failed");
        })?;
        Signature::from_compact(&sig_bytes).map_err(|_| ())
    }

    fn sign_holder_htlc_transaction(
        &self,
        htlc_tx: &bitcoin::Transaction,
        input: usize,
        htlc_descriptor: &HTLCDescriptor,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        if self.failed {
            return Err(());
        }
        let peer_id = self.current_peer_id();
        let conn = self.active_conn()?;
        let sig_bytes = block_vls!(rpc::rpc_sign_local_htlc_tx2(
            &conn,
            self.dbid,
            peer_id,
            htlc_tx.clone(),
            input as u32,
            htlc_descriptor.per_commitment_number,
            htlc_descriptor.htlc.offered,
            htlc_descriptor.htlc.cltv_expiry,
            htlc_descriptor.htlc.amount_msat,
            htlc_descriptor.htlc.payment_hash.0,
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, input, "sign_holder_htlc_transaction failed");
        })?;
        Signature::from_compact(&sig_bytes).map_err(|_| ())
    }

    fn sign_counterparty_htlc_transaction(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        htlc_tx: &bitcoin::Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &PublicKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        if self.failed {
            return Err(());
        }
        self.maybe_setup_channel(channel_parameters)?;

        let counterparty = channel_parameters
            .counterparty_parameters
            .as_ref()
            .ok_or(())?
            .pubkeys
            .clone();
        let keys = TxCreationKeys::from_channel_static_keys(
            per_commitment_point,
            &counterparty,
            &channel_parameters.holder_pubkeys,
            secp_ctx,
        );
        let wscript =
            get_htlc_redeemscript(htlc, &channel_parameters.channel_type_features, &keys);

        let mut psbt = Psbt::from_unsigned_tx(htlc_tx.clone()).map_err(|_| ())?;
        if input >= psbt.inputs.len() {
            return Err(());
        }
        psbt.inputs[input].witness_utxo = Some(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(amount),
            script_pubkey: wscript.to_p2wsh(),
        });

        let peer_id = self.current_peer_id();
        let conn = self.active_conn()?;
        let sig_bytes = block_vls!(rpc::rpc_sign_remote_htlc_tx(
            &conn,
            self.dbid,
            peer_id,
            htlc_tx.clone(),
            psbt.serialize(),
            wscript.to_bytes(),
            per_commitment_point.serialize(),
            channel_parameters
                .channel_type_features
                .supports_anchors_zero_fee_htlc_tx(),
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, input, "sign_counterparty_htlc_transaction failed");
        })?;
        Signature::from_compact(&sig_bytes).map_err(|_| ())
    }

    fn sign_closing_transaction(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        closing_tx: &ClosingTransaction,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        if self.failed {
            return Err(());
        }
        self.maybe_setup_channel(channel_parameters)?;
        let peer_id = self.current_peer_id();
        let conn = self.active_conn()?;
        let sig_bytes = block_vls!(rpc::rpc_sign_closing_tx(
            &conn,
            self.dbid,
            peer_id,
            closing_tx.to_holder_value_sat(),
            closing_tx.to_counterparty_value_sat(),
            closing_tx.to_holder_script().to_bytes(),
            closing_tx.to_counterparty_script().to_bytes(),
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, "sign_closing_transaction failed");
        })?;
        Signature::from_compact(&sig_bytes).map_err(|_| ())
    }

    fn sign_holder_keyed_anchor_input(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        anchor_tx: &bitcoin::Transaction,
        input: usize,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        if self.failed {
            return Err(());
        }
        self.maybe_setup_channel(channel_parameters)?;

        let anchor_wscript =
            get_keyed_anchor_redeemscript(&channel_parameters.holder_pubkeys.funding_pubkey);
        let mut psbt = Psbt::from_unsigned_tx(anchor_tx.clone()).map_err(|_| ())?;
        if input >= psbt.inputs.len() {
            return Err(());
        }
        psbt.inputs[input].witness_utxo = Some(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(ANCHOR_OUTPUT_VALUE_SATOSHI),
            script_pubkey: anchor_wscript.to_p2wsh(),
        });

        let peer_id = self.current_peer_id();
        let utxo = rpc::AnchorUtxo {
            txid: psbt.unsigned_tx.input[input].previous_output.txid,
            outnum: psbt.unsigned_tx.input[input].previous_output.vout,
            amount_sat: ANCHOR_OUTPUT_VALUE_SATOSHI,
            keyindex: 0,
            is_p2sh: false,
            script_pubkey: anchor_wscript.to_bytes(),
            is_in_coinbase: false,
        };

        let conn = self.active_conn()?;
        let signed_psbt_bytes = block_vls!(rpc::rpc_sign_anchorspend(
            &conn,
            peer_id,
            self.dbid,
            psbt.serialize(),
            vec![utxo],
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, input, "sign_holder_keyed_anchor_input failed");
        })?;

        let signed_psbt = Psbt::deserialize(&signed_psbt_bytes).map_err(|_| ())?;
        let in_psbt = signed_psbt.inputs.get(input).ok_or(())?;
        let pk = bitcoin::PublicKey::new(channel_parameters.holder_pubkeys.funding_pubkey);
        let part = in_psbt.partial_sigs.get(&pk).ok_or(())?;
        Ok(part.signature)
    }

    fn sign_channel_announcement_with_funding_key(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        msg: &UnsignedChannelAnnouncement,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        if self.failed {
            return Err(());
        }
        self.maybe_setup_channel(channel_parameters)?;
        let mut bytes = Vec::new();
        msg.write(&mut bytes).map_err(|_| ())?;
        let peer_id = self.current_peer_id();
        let conn = self.active_conn()?;
        let sig_bytes = block_vls!(rpc::rpc_sign_channel_announcement(
            &conn,
            self.dbid,
            peer_id,
            bytes,
        ))
        .map_err(|e| {
            tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, "sign_channel_announcement failed");
        })?;
        Signature::from_compact(&sig_bytes).map_err(|_| ())
    }

    fn sign_splice_shared_input(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        tx: &bitcoin::Transaction,
        input_index: usize,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Signature {
        // Note: this method's signature returns `Signature` rather than
        // `Result<Signature, ()>`. We hand back a sentinel signature on
        // every failure path so LDK doesn't panic; the resulting splice
        // tx will simply fail validation against the funding output.
        if self.failed {
            return sentinel_signature();
        }
        if self.maybe_setup_channel(channel_parameters).is_err() {
            return sentinel_signature();
        }
        if input_index >= tx.input.len() {
            return sentinel_signature();
        }

        let Some(counterparty) = channel_parameters.counterparty_pubkeys() else {
            return sentinel_signature();
        };
        let Some(funding_outpoint) = channel_parameters.funding_outpoint.as_ref() else {
            return sentinel_signature();
        };
        let prev_out = tx.input[input_index].previous_output;
        if prev_out.txid != funding_outpoint.txid
            || prev_out.vout != u32::from(funding_outpoint.index)
        {
            return sentinel_signature();
        }

        let redeem_script =
            make_funding_redeemscript(&self.pubkeys.funding_pubkey, &counterparty.funding_pubkey);
        let Ok(mut psbt) = Psbt::from_unsigned_tx(tx.clone()) else {
            return sentinel_signature();
        };
        psbt.inputs[input_index].witness_utxo = Some(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(channel_parameters.channel_value_satoshis),
            script_pubkey: redeem_script.to_p2wsh(),
        });

        let peer_id = self.current_peer_id();
        let Ok(conn) = self.active_conn() else {
            return sentinel_signature();
        };
        let sig64 = match block_vls!(rpc::rpc_sign_splice_tx(
            &conn,
            self.dbid,
            peer_id,
            tx.clone(),
            psbt.serialize(),
            counterparty.funding_pubkey.serialize(),
            input_index as u32,
        )) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!(target: "wick_vls", ctx = %self.lookup.context_id(), %e, dbid = self.dbid, input_index, "sign_splice_shared_input failed");
                return sentinel_signature();
            }
        };
        Signature::from_compact(&sig64).unwrap_or_else(|_| sentinel_signature())
    }
}

#[cfg(test)]
mod restart_tests {
    //! Restart-load coverage for the persisted-meta path.
    //!
    //! These are pure unit tests — no Postgres, no SDK. They exercise
    //! the in-memory state machine of `SignerSession` against a faked
    //! [`crate::ChannelMetaStore`] and verify that:
    //!
    //! 1. `derive_channel_signer` writes through to the store on every
    //!    insert / update.
    //! 2. A fresh session pointed at the same store rehydrates the
    //!    `(channel_keys_id → dbid, peer_id, pubkeys, setup_funding)`
    //!    map and a subsequent `derive_channel_signer` returns a
    //!    Ready signer (not a `failed` placeholder) without re-issuing
    //!    `GetChannelBasepoints` to a (possibly absent) signer
    //!    connection.
    //! 3. The global `DBID_COUNTER` is lifted past the highest
    //!    persisted dbid.
    use std::sync::Mutex;

    use async_trait::async_trait;
    use lightning::sign::SignerProvider as _;

    use super::*;
    use crate::meta_store::{ChannelMetaStore, StoredChannelMeta};
    use crate::registry::SignerSessionRegistry;

    /// Minimal in-memory [`ChannelMetaStore`] that mirrors the Postgres
    /// upsert semantics (last-write-wins on `channel_keys_id`, with
    /// `pubkeys` preserved if a later upsert passes `None`).
    #[derive(Debug, Default)]
    struct FakeStore {
        rows: Mutex<Vec<StoredChannelMeta>>,
    }

    impl FakeStore {
        fn snapshot(&self) -> Vec<StoredChannelMeta> {
            self.rows.lock().expect("fake store mutex").clone()
        }
    }

    #[async_trait]
    impl ChannelMetaStore for FakeStore {
        async fn load_all(&self) -> anyhow::Result<Vec<StoredChannelMeta>> {
            Ok(self.snapshot())
        }
        async fn upsert(&self, meta: StoredChannelMeta) -> anyhow::Result<()> {
            let mut rows = self.rows.lock().expect("fake store mutex");
            if let Some(existing) =
                rows.iter_mut().find(|r| r.channel_keys_id == meta.channel_keys_id)
            {
                let preserved_pubkeys = meta.pubkeys.or(existing.pubkeys);
                *existing = StoredChannelMeta {
                    pubkeys: preserved_pubkeys,
                    ..meta
                };
            } else {
                rows.push(meta);
            }
            Ok(())
        }
    }

    fn fresh_session_with_store(store: Arc<FakeStore>) -> Arc<SignerSession> {
        let registry = Arc::new(SignerSessionRegistry::new());
        let lookup = ConnLookup::new(format!("ctx-{}", rand::random::<u64>()), registry);
        Arc::new(SignerSession::new(lookup).with_meta_store(store))
    }

    /// Persisting a row offline (signer not attached) lets a fresh
    /// session reattach to the same `(channel_keys_id, dbid)` after
    /// rehydrate. The new `derive_channel_signer` short-circuits on
    /// the cache hit (we wrote pubkeys synthetically) and does NOT
    /// allocate a fresh dbid.
    #[tokio::test(flavor = "multi_thread")]
    async fn rehydrate_restores_dbid_and_pubkeys() {
        let store = Arc::new(FakeStore::default());
        let channel_keys_id = [0xAAu8; 32];

        // Hand-craft a row that mimics what the live path persists
        // after `GetChannelBasepoints` returns. We use the sentinel
        // pubkey for all 5 basepoints — this test only cares about
        // the round-trip, not the cryptographic validity.
        let pubkey = SENTINEL_PUBKEY;
        let mut blob = [0u8; 165];
        for chunk in blob.chunks_mut(33) {
            chunk.copy_from_slice(&pubkey);
        }
        store
            .upsert(StoredChannelMeta {
                channel_keys_id,
                dbid: 4242,
                peer_id: SENTINEL_PUBKEY,
                setup_funding: None,
                push_value_msat: 100_000,
                pubkeys: Some(blob),
            })
            .await
            .expect("seed");

        let session = fresh_session_with_store(Arc::clone(&store));
        session.rehydrate().await.expect("rehydrate");

        // dbid floor lifted past the persisted value.
        assert!(DBID_COUNTER.load(Ordering::Relaxed) >= 4243);

        // Cache hit on derive_channel_signer — no SDK call, returns a
        // non-failed signer bound to the persisted dbid.
        let signer = session.derive_channel_signer(channel_keys_id);
        assert_eq!(signer.dbid, 4242);
        assert!(!signer.failed, "expected Ready signer after rehydrate");

        // Pubkeys faithfully reconstructed.
        assert_eq!(
            signer.pubkeys.funding_pubkey.serialize(),
            SENTINEL_PUBKEY,
            "funding_pubkey should round-trip via blob"
        );
    }

    /// `derive_channel_signer` writes through on the offline-derive
    /// path so an immediate restart sees the row even if the SDK was
    /// never reachable for `GetChannelBasepoints`.
    #[tokio::test(flavor = "multi_thread")]
    async fn offline_derive_persists_dbid_binding() {
        let store = Arc::new(FakeStore::default());
        let session = fresh_session_with_store(Arc::clone(&store));

        // No SDK attached → `active_conn_if_ready` returns Err →
        // session takes the offline branch.
        let channel_keys_id = [0x55u8; 32];
        let signer = session.derive_channel_signer(channel_keys_id);
        assert!(signer.failed, "expected failed signer in offline branch");

        // Yield so the spawned upsert future runs.
        tokio::task::yield_now().await;
        // Sometimes the runtime needs a small nudge for the spawned
        // task to flush; spin with `yield_now` up to 50 times.
        for _ in 0..50 {
            if !store.snapshot().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }

        let rows = store.snapshot();
        assert_eq!(rows.len(), 1, "exactly one row persisted");
        assert_eq!(rows[0].channel_keys_id, channel_keys_id);
        assert_eq!(rows[0].dbid, signer.dbid);
        assert!(
            rows[0].pubkeys.is_none(),
            "offline derive has no basepoints to persist yet"
        );
    }
}
