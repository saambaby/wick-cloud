//! Per-tenant Noise transport keypair derivation.
//!
//! The Noise transport identity is **independent** of the tenant's
//! Lightning node id. The LN node id is a secp256k1 key derived at
//! `m/13038'/<coin>'/0'` (see `wick_sdk::identity::tenant_lightning_seed`);
//! we cannot reuse it here because no audited Rust crate plugs secp256k1
//! into `snow`. Instead we HKDF-derive a Curve25519 keypair from a fresh
//! BIP32 child at the dedicated path
//!
//! ```text
//! m/13039'/<coin>'/<tenant_index>'
//! ```
//!
//! where `<coin>` matches BIP-44 conventions through
//! [`WickNetwork::bip84_coin_type`] (0 for mainnet, 1 for every test
//! network — Regtest / Signet / Mutinynet). `<tenant_index>` is the
//! SDK's local rotation counter (start at 0; increments on rotation).
//!
//! Rotating the Noise transport key never touches LN channel state.

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use hkdf::Hkdf;
use sha2::Sha256;
use wick_core::WickNetwork;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::session::NoiseError;

/// BIP32 "purpose" child used for Noise transport keys. Sits parallel
/// to `13037'` (LSP Lightning) and `13038'` (tenant Lightning) — see
/// the module doc for the full path shape.
pub const NOISE_BIP32_PURPOSE: u32 = 13_039;

/// HKDF-SHA256 salt for clamping the BIP32 child into a Curve25519 scalar.
/// Versioned so we can roll the derivation without colliding with v1
/// material if we ever need to.
const HKDF_SALT: &[u8] = b"wick/v1";

/// HKDF-SHA256 info for the Noise transport key derivation.
const HKDF_INFO: &[u8] = b"noise-kk-curve25519-transport";

/// 32-byte Curve25519 static public key used as a Noise `s` token.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NoisePublicKey(pub [u8; 32]);

impl NoisePublicKey {
    /// Borrow as a byte slice — handy for `snow::Builder::remote_public_key`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 32-byte Curve25519 static keypair. The `secret` is RFC-7748-clamped
/// X25519 scalar bytes — feed directly to `snow::Builder::local_private_key`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NoiseStaticKeypair {
    /// Clamped Curve25519 scalar.
    pub secret: [u8; 32],
    /// Curve25519 public key.
    #[zeroize(skip)]
    pub public: NoisePublicKey,
}

impl std::fmt::Debug for NoiseStaticKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseStaticKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Derive the per-tenant Noise transport keypair from the device master
/// xprv at `m/13039'/<coin>'/<tenant_index>'`.
///
/// Deterministic: same `(xprv, network, tenant_index)` always produces
/// the same keypair. See the module doc for path conventions.
///
/// # Errors
/// Returns [`NoiseError::Derivation`] if any BIP32 step fails (only
/// possible for malformed child indices, which we control).
pub fn derive_noise_static(
    xprv: &Xpriv,
    network: WickNetwork,
    tenant_index: u32,
) -> Result<NoiseStaticKeypair, NoiseError> {
    let secp = Secp256k1::new();
    let coin = network.bip84_coin_type();
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(NOISE_BIP32_PURPOSE)
            .map_err(|e| NoiseError::Derivation(format!("purpose 13039': {e}")))?,
        ChildNumber::from_hardened_idx(coin)
            .map_err(|e| NoiseError::Derivation(format!("coin {coin}': {e}")))?,
        ChildNumber::from_hardened_idx(tenant_index)
            .map_err(|e| NoiseError::Derivation(format!("tenant {tenant_index}': {e}")))?,
    ]);
    let child = xprv
        .derive_priv(&secp, &path)
        .map_err(|e| NoiseError::Derivation(format!("derive {path}: {e}")))?;

    // HKDF-SHA256 the secp256k1 scalar bytes into a fresh 32-byte IKM
    // we'll clamp into Curve25519. Domain-separated via salt+info.
    let ikm = child.private_key.secret_bytes();
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    // Bind the network into the HKDF `info` so signet/mutinynet/regtest
    // (which all share BIP-44 coin type 1) yield distinct Noise keys.
    // Without this the BIP32 path collapses and the master xprv only
    // differs in version bytes, which HKDF does not see.
    let network_tag: &[u8] = match network {
        WickNetwork::Regtest => b"regtest",
        WickNetwork::Signet => b"signet",
        WickNetwork::Mutinynet => b"mutinynet",
    };
    let mut info = Vec::with_capacity(HKDF_INFO.len() + 1 + network_tag.len());
    info.extend_from_slice(HKDF_INFO);
    info.push(b'/');
    info.extend_from_slice(network_tag);
    let mut scalar = [0u8; 32];
    hk.expand(&info, &mut scalar)
        .map_err(|e| NoiseError::Derivation(format!("hkdf expand: {e}")))?;

    // RFC 7748 clamping. `x25519-dalek`'s `StaticSecret::from([u8;32])`
    // also clamps internally, but we clamp explicitly so the bytes we
    // store and the bytes we hand to snow are unambiguous.
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    let secret = X25519StaticSecret::from(scalar);
    let public = X25519PublicKey::from(&secret);

    let keypair = NoiseStaticKeypair {
        secret: scalar,
        public: NoisePublicKey(public.to_bytes()),
    };

    // Zeroize the intermediate `ikm` — `scalar` is moved into the
    // keypair (which zeroizes on drop).
    let mut ikm_owned = ikm;
    ikm_owned.zeroize();
    drop(secret);

    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::Xpriv;

    fn xprv(network: WickNetwork) -> Xpriv {
        // Deterministic 64-byte seed for tests.
        let seed = [0x42u8; 64];
        Xpriv::new_master(bitcoin::Network::from(network), &seed).expect("xpriv master")
    }

    #[test]
    fn derivation_is_deterministic() {
        let x = xprv(WickNetwork::Regtest);
        let a = derive_noise_static(&x, WickNetwork::Regtest, 0).unwrap();
        let b = derive_noise_static(&x, WickNetwork::Regtest, 0).unwrap();
        assert_eq!(a.public, b.public);
        assert_eq!(a.secret, b.secret);
    }

    #[test]
    fn derivation_differs_across_indices() {
        let x = xprv(WickNetwork::Regtest);
        let a = derive_noise_static(&x, WickNetwork::Regtest, 0).unwrap();
        let b = derive_noise_static(&x, WickNetwork::Regtest, 1).unwrap();
        assert_ne!(a.public, b.public);
    }

    #[test]
    fn derivation_differs_across_networks() {
        // All wick networks (Regtest / Signet / Mutinynet) share BIP-44
        // `coin_type = 1`, but the master xprv tags itself with the
        // underlying `bitcoin::Network` version bytes (`Regtest` vs
        // `Signet`), so child material differs. Verify keys don't
        // collide across the two distinct underlying bitcoin networks.
        let x_reg = xprv(WickNetwork::Regtest);
        let x_sig = xprv(WickNetwork::Signet);
        let reg = derive_noise_static(&x_reg, WickNetwork::Regtest, 0).unwrap();
        let sig = derive_noise_static(&x_sig, WickNetwork::Signet, 0).unwrap();
        assert_ne!(reg.public, sig.public);
    }

    #[test]
    fn public_key_is_clamped_scalar_basepoint() {
        // Sanity: the public key must equal X25519(clamped_scalar, basepoint).
        let x = xprv(WickNetwork::Regtest);
        let kp = derive_noise_static(&x, WickNetwork::Regtest, 7).unwrap();
        let recomputed =
            X25519PublicKey::from(&X25519StaticSecret::from(kp.secret));
        assert_eq!(kp.public.0, recomputed.to_bytes());
    }
}
