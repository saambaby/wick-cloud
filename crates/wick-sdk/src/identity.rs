//! BIP39 mnemonic → device identity + master xprv.
//!
//! The identity pubkey is the 33-byte compressed secp256k1 public key the
//! SDK sends to `wick-server` as `CreateTenantRequest.pubkey_hex`. The
//! server derives a stable tenant id (UUID-v5) from it.
//!
//! The derivation path is `m/84'/{coin}'/0'/0/0` — BIP84's first external
//! receive child. This matches [`wick_core::WickIdentity`] so the SDK's
//! `node_id` agrees with every server-side derivation of the same mnemonic
//! (fixtures, regtest harness, `wick-server`'s per-tenant seed factory).
//! Changing this path would break tenant-id agreement and must be done in
//! lockstep with [`wick_core::WickIdentity::from_mnemonic`].
//!
//! Today this is purely an identity handle — signing keys are still on the
//! server (custodial pre-Phase-4).

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use wick_core::WickNetwork;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// BIP84 first external receive path parameterised by `coin_type`.
/// See the module doc — must stay in lockstep with `wick-core`.
fn identity_path(network: WickNetwork) -> String {
    format!("m/84'/{}'/0'/0/0", network.bip84_coin_type())
}

/// Device identity derived from a BIP39 mnemonic.
///
/// Holds the BIP39 seed and master xprv. `Drop` zeroizes the seed; the xprv
/// carries its own secrecy via `bitcoin::bip32::Xpriv` (the inner
/// `SecretKey` is not zeroized by the `bitcoin` crate, but dropping the
/// `Identity` releases it and it is not retained elsewhere).
pub(crate) struct Identity {
    seed: [u8; 64],
    xprv: Xpriv,
    node_id: PublicKey,
    fingerprint: [u8; 4],
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("node_id", &self.node_id)
            .field("fingerprint", &hex::encode(self.fingerprint))
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Derive an [`Identity`] from a BIP39 mnemonic + optional passphrase.
    ///
    /// Does not touch the network. Deterministic: the same
    /// `(mnemonic, passphrase, network)` tuple always produces the same
    /// identity.
    pub(crate) fn from_mnemonic(
        mnemonic: &str,
        passphrase: Option<&str>,
        network: WickNetwork,
    ) -> Result<Self> {
        let parsed = bip39::Mnemonic::parse(mnemonic)
            .map_err(|e| Error::Identity(format!("bip39 parse: {e}")))?;
        let seed = parsed.to_seed(passphrase.unwrap_or(""));
        let xprv = Xpriv::new_master(bitcoin::Network::from(network), &seed)
            .map_err(|e| Error::Identity(format!("xpriv master: {e}")))?;

        let secp = Secp256k1::new();
        let path: DerivationPath = identity_path(network)
            .parse()
            .map_err(|e| Error::Identity(format!("derivation path: {e}")))?;
        let identity_xprv = xprv
            .derive_priv(&secp, &path)
            .map_err(|e| Error::Identity(format!("derive identity: {e}")))?;
        let node_id = PublicKey::from_secret_key(&secp, &identity_xprv.private_key);
        let fingerprint = xprv.fingerprint(&secp).to_bytes();

        Ok(Self {
            seed,
            xprv,
            node_id,
            fingerprint,
        })
    }

    /// 33-byte compressed secp256k1 identity pubkey.
    pub(crate) fn node_id(&self) -> PublicKey {
        self.node_id
    }

    /// 4-byte BIP32 master fingerprint.
    pub(crate) fn fingerprint(&self) -> [u8; 4] {
        self.fingerprint
    }

    /// Master xprv. Used by [`crate::wallet::OnchainWallet`] to build BDK
    /// descriptors without re-deriving from the seed.
    pub(crate) fn master_xprv(&self) -> &Xpriv {
        &self.xprv
    }

    /// Hex-encoded identity pubkey — the value sent as
    /// `CreateTenantRequest.pubkey_hex`.
    pub(crate) fn node_id_hex(&self) -> String {
        hex::encode(self.node_id.serialize())
    }

    /// Derive the 32-byte LSP Lightning seed used by the operator's
    /// `RegisterLspIdentity` admin RPC.
    ///
    /// Uses a domain-separated BIP32 path (`m/13037'/{coin}'/0'`) so
    /// this seed is independent of the operator's on-chain BIP84
    /// receive addresses and of the on-device tenant identity. The
    /// resulting 32 bytes are the `private_key` of the derived xpriv —
    /// same shape `wick_lightning::from_seed` consumes today.
    ///
    /// Phase 4 swaps this for a remote-signer handle on the device;
    /// the seed never crosses the wire then.
    /// Derive the 32-byte tenant Lightning seed used by the Phase-4 SDK
    /// signer loop ([`crate::signer::SignerLoop`]).
    ///
    /// Domain-separated from both the BIP84 on-chain identity path
    /// (`m/84'/{coin}'/0'/0/0`) and the operator's LSP Lightning seed
    /// (`m/13037'/{coin}'/0'`) by a fresh hardened path
    /// (`m/13038'/{coin}'/0'`), so the tenant's Lightning identity is
    /// independent of every other key the SDK derives. The 32 bytes are
    /// the `private_key` of the derived xpriv — the same shape
    /// `vls_protocol_signer::handler::HandlerBuilder::new(_, _, _, seed)`
    /// consumes.
    pub(crate) fn tenant_lightning_seed(&self, network: WickNetwork) -> Result<[u8; 32]> {
        let secp = Secp256k1::new();
        let coin = network.bip84_coin_type();
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(13038)
                .map_err(|e| Error::Identity(format!("tenant path 13038': {e}")))?,
            ChildNumber::from_hardened_idx(coin)
                .map_err(|e| Error::Identity(format!("tenant path coin': {e}")))?,
            ChildNumber::from_hardened_idx(0)
                .map_err(|e| Error::Identity(format!("tenant path 0': {e}")))?,
        ]);
        let derived = self
            .xprv
            .derive_priv(&secp, &path)
            .map_err(|e| Error::Identity(format!("derive tenant seed: {e}")))?;
        Ok(derived.private_key.secret_bytes())
    }

    pub(crate) fn lsp_lightning_seed(&self, network: WickNetwork) -> Result<[u8; 32]> {
        let secp = Secp256k1::new();
        let coin = network.bip84_coin_type();
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(13037)
                .map_err(|e| Error::Identity(format!("lsp path 13037': {e}")))?,
            ChildNumber::from_hardened_idx(coin)
                .map_err(|e| Error::Identity(format!("lsp path coin': {e}")))?,
            ChildNumber::from_hardened_idx(0)
                .map_err(|e| Error::Identity(format!("lsp path 0': {e}")))?,
        ]);
        let derived = self
            .xprv
            .derive_priv(&secp, &path)
            .map_err(|e| Error::Identity(format!("derive lsp seed: {e}")))?;
        Ok(derived.private_key.secret_bytes())
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}
