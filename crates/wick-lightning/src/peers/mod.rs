//! Seed-peer bootstrap for Wick Lightning nodes.
//!
//! On first boot, if the `PeerStore` is empty, we write the well-known
//! seed peers for the current network so the reconnect loop dials them
//! immediately. For regtest the seed list is empty, so this is a no-op.

use std::net::SocketAddr;

use bitcoin::secp256k1::PublicKey;
use wick_core::WickNetwork;

use crate::peer_store::{PeerInfo, PeerStore};

/// Write `WickNetwork::seed_peers()` into `peer_store` if and only if the
/// store currently has no entries.
///
/// Idempotent: a second call (or a call after the user has persisted their
/// own peers) is a silent no-op.
pub async fn seed_peers_if_empty(peer_store: &PeerStore, network: WickNetwork) {
    let seeds = network.seed_peers();
    if seeds.is_empty() {
        return;
    }

    let existing = match peer_store.list().await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                target: "wick_lightning",
                error = %e,
                "seed_peers_if_empty: peer_store.list failed; skipping seed"
            );
            return;
        }
    };
    if !existing.is_empty() {
        return;
    }

    for (pubkey_hex, addr_str) in seeds {
        let pubkey_bytes = match hex::decode(pubkey_hex) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    target: "wick_lightning",
                    pubkey_hex,
                    error = %e,
                    "seed_peers_if_empty: invalid pubkey hex; skipping"
                );
                continue;
            }
        };
        let node_id = match PublicKey::from_slice(&pubkey_bytes) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(
                    target: "wick_lightning",
                    pubkey_hex,
                    error = %e,
                    "seed_peers_if_empty: invalid pubkey; skipping"
                );
                continue;
            }
        };
        let address: SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(
                    target: "wick_lightning",
                    addr_str,
                    error = %e,
                    "seed_peers_if_empty: invalid address; skipping"
                );
                continue;
            }
        };
        if let Err(e) = peer_store.upsert(&PeerInfo { node_id, address }).await {
            tracing::warn!(
                target: "wick_lightning",
                pubkey = %node_id,
                error = %e,
                "seed_peers_if_empty: peer_store.upsert failed"
            );
        } else {
            tracing::info!(
                target: "wick_lightning",
                pubkey = %node_id,
                address = %address,
                network = %network,
                "seeded peer"
            );
        }
    }
}
