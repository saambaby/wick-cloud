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

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Network;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// BIP84 first external receive path parameterised by `coin_type`.
/// See the module doc — must stay in lockstep with `wick-core`.
fn identity_path(network: Network) -> String {
    let coin = match network {
        Network::Bitcoin => 0,
        _ => 1,
    };
    format!("m/84'/{coin}'/0'/0/0")
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
        network: Network,
    ) -> Result<Self> {
        let parsed = bip39::Mnemonic::parse(mnemonic)
            .map_err(|e| Error::Identity(format!("bip39 parse: {e}")))?;
        let seed = parsed.to_seed(passphrase.unwrap_or(""));
        let xprv = Xpriv::new_master(network, &seed)
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

}

impl Drop for Identity {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}
