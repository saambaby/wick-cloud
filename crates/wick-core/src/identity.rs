//! [`WickIdentity`] — single BIP39/BIP84 source of truth for a participant.
//!
//! A `WickIdentity` derives everything needed for a Wick participant from one
//! BIP39 mnemonic:
//!
//! - `seed` — first 32 bytes of the BIP39 64-byte seed, passed directly into
//!   `LocalKeysManager` / `from_seed` (LDK's `KeysManager` API requires
//!   exactly 32 bytes).
//!
//! - `master_xprv` — BIP32 master private key derived from the full
//!   BIP39 64-byte seed. Shared between the SDK's on-chain wallet
//!   (`wick_sdk::OnchainWallet`) so both derive identical BIP84 / BIP86
//!   keychains for a given mnemonic.
//!
//! - `identity_pubkey` — the compressed secp256k1 public key at the BIP84
//!   first-external-receive path `m/84'/{coin}'/0'/0/0`. This is the key the
//!   client supplies in `CreateTenantRequest.pubkey_hex`.
//!
//! - `tenant_id` — `TenantId::from_pubkey(&identity_pubkey.serialize())`:
//!   UUID v5 derived from the identity pubkey. Stable across re-registrations
//!   with the same mnemonic.
//!
//! `coin` follows SLIP-44: `0'` on mainnet, `1'` on all test networks
//! (regtest / signet / mutinynet).

use bitcoin::bip32::{ DerivationPath, Xpriv, Xpub };
use bitcoin::secp256k1::{ PublicKey, Secp256k1 };
use bip39::Mnemonic;

use crate::network::WickNetwork;
use crate::tenant::TenantId;
use crate::{ Result, WickError };

/// Derived participant identity — one mnemonic owns the Lightning seed,
/// the on-chain BDK wallet descriptor, and the tenant registration pubkey.
#[derive(Debug, Clone)]
pub struct WickIdentity {
    /// The source BIP39 mnemonic.
    pub mnemonic: Mnemonic,
    /// Network this identity was derived for.
    pub network: WickNetwork,
    /// First 32 bytes of `mnemonic.to_seed("")` — the 32-byte seed passed to
    /// `LocalKeysManager` / `from_seed`. Required by LDK's `KeysManager` API
    /// which takes exactly 32 bytes.
    pub seed: [u8; 32],
    /// BIP32 master xprv derived from the full 64-byte BIP39 seed.
    ///
    /// Shared with `wick_sdk::OnchainWallet` — both derive identical BIP84 /
    /// BIP86 keychains for a given mnemonic.
    pub master_xprv: Xpriv,
    /// Compressed secp256k1 public key at `m/84'/{coin}'/0'/0/0`.
    /// Supplied as `pubkey_hex` in `CreateTenantRequest`.
    pub identity_pubkey: PublicKey,
    /// Stable UUID v5 derived from `identity_pubkey`.
    pub tenant_id: TenantId,
}

impl WickIdentity {
    /// Derive a [`WickIdentity`] from an existing [`Mnemonic`] on `network`.
    ///
    /// # Errors
    /// Returns [`WickError::KeyDerivation`] if the BIP32 derivation fails
    /// (e.g. the mnemonic produces a master key at a hardened path that hits
    /// a point at infinity — astronomically unlikely with a real mnemonic).
    pub fn from_mnemonic(mnemonic: Mnemonic, network: WickNetwork) -> Result<Self> {
        let seed_64 = mnemonic.to_seed("");
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_64[..32]);

        let btc_network: bitcoin::Network = network.into();
        let secp = Secp256k1::new();

        let master = Xpriv::new_master(btc_network, &seed_64).map_err(|e|
            WickError::KeyDerivation(format!("new_master: {e}"))
        )?;

        let coin = network.bip84_coin_type();
        let path: DerivationPath = format!("m/84'/{coin}'/0'/0/0")
            .parse()
            .map_err(|e| WickError::KeyDerivation(format!("parse path: {e}")))?;

        let child = master
            .derive_priv(&secp, &path)
            .map_err(|e| WickError::KeyDerivation(format!("derive_priv: {e}")))?;

        let identity_pubkey: PublicKey = Xpub::from_priv(&secp, &child).public_key;
        let tenant_id = TenantId::from_pubkey(&identity_pubkey.serialize());

        Ok(Self {
            mnemonic,
            network,
            seed,
            master_xprv: master,
            identity_pubkey,
            tenant_id,
        })
    }

    /// Parse `phrase` as a BIP39 mnemonic, then derive a [`WickIdentity`].
    ///
    /// # Errors
    /// Returns [`WickError::KeyDerivation`] if the phrase is invalid BIP39
    /// or if key derivation fails (see [`from_mnemonic`](Self::from_mnemonic)).
    pub fn from_phrase(phrase: &str, network: WickNetwork) -> Result<Self> {
        let mnemonic = Mnemonic::parse(phrase).map_err(|e|
            WickError::KeyDerivation(format!("mnemonic parse: {e}"))
        )?;
        Self::from_mnemonic(mnemonic, network)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const ALICE_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn from_phrase_is_deterministic() {
        let a = WickIdentity::from_phrase(ALICE_MNEMONIC, WickNetwork::Regtest).unwrap();
        let b = WickIdentity::from_phrase(ALICE_MNEMONIC, WickNetwork::Regtest).unwrap();
        assert_eq!(a.seed, b.seed);
        assert_eq!(a.identity_pubkey, b.identity_pubkey);
        assert_eq!(a.tenant_id, b.tenant_id);
    }

    #[test]
    fn tenant_id_matches_from_pubkey() {
        let id = WickIdentity::from_phrase(ALICE_MNEMONIC, WickNetwork::Regtest).unwrap();
        let expected = TenantId::from_pubkey(&id.identity_pubkey.serialize());
        assert_eq!(id.tenant_id, expected);
    }

    #[test]
    fn different_networks_produce_different_keys() {
        let regtest = WickIdentity::from_phrase(ALICE_MNEMONIC, WickNetwork::Regtest).unwrap();
        let mutinynet = WickIdentity::from_phrase(ALICE_MNEMONIC, WickNetwork::Mutinynet).unwrap();
        // Both use coin_type=1 (test networks), so same derivation — same keys.
        assert_eq!(regtest.identity_pubkey, mutinynet.identity_pubkey);
    }

    #[test]
    fn seed_is_first_32_bytes_of_bip39() {
        let id = WickIdentity::from_phrase(ALICE_MNEMONIC, WickNetwork::Regtest).unwrap();
        let mnemonic = Mnemonic::parse(ALICE_MNEMONIC).unwrap();
        let seed_64 = mnemonic.to_seed("");
        let expected: [u8; 32] = seed_64[..32].try_into().unwrap();
        assert_eq!(id.seed, expected);
    }
}
