//! Phase-1 `NodeFactory` — `LocalKeysManager` backed by HMAC-derived per-tenant seeds.
//!
//! The server holds a single 32-byte master seed (resolved from
//! `server_mnemonic` in [`crate::main`]) and derives a per-tenant seed via
//! `HMAC-SHA256(master, tenant_id)`. This is explicitly temporary: Phase 4
//! replaces the master seed entirely with a remote VLS signer.
//!
//! The server is **not** custodial of channel-funding UTXOs. Channel opens
//! use the two-phase `OpenChannelInit` / `OpenChannelFinalize` gRPC flow:
//! the client builds + signs the funding tx on its own BDK wallet and
//! hands it to the server, which passes it straight to LDK's
//! `ChannelManager::funding_transaction_generated`. The node never holds
//! on-chain keys beyond the LDK signing keys (`LocalKeysManager`) that
//! Phase 4 VLS will move on-device.

use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use wick_core::TenantId;
use wick_lightning::{from_seed, LocalKeysManager, NodeApi, NodeBuilder, NodeDeps};

use crate::node::manager::NodeFactory;

/// Derive a per-tenant 32-byte seed from the server master seed.
///
/// Same inputs always produce the same seed — required so `NodeBuilder`'s
/// restart path can reattach to previously-persisted channel state.
#[allow(clippy::expect_used)] // [u8; 32] is never zero-length; new_from_slice cannot fail
fn derive_tenant_seed(master: &[u8; 32], tenant_id: TenantId) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(master).expect("HMAC accepts any key length");
    mac.update(tenant_id.to_string().as_bytes());
    mac.finalize().into_bytes().into()
}

/// Build a `NodeFactory` that derives per-tenant seeds from the server's
/// BIP39-derived `master_seed` and captures the shared [`NodeDeps`] via
/// closure.
///
/// Phase 4 replaces this entire factory with a VLS-backed closure — the
/// server no longer holds seed material at that point. Callers pass the
/// returned value directly to `NodeManager::new` — the closure shape is
/// unchanged across the swap.
#[must_use]
pub fn node_factory(master_seed: [u8; 32], deps: NodeDeps) -> NodeFactory {
    Arc::new(move |tenant_id| {
        let seed = derive_tenant_seed(&master_seed, tenant_id);
        let deps = deps.clone();
        Box::pin(async move {
            let signer = Arc::new(from_seed(seed));
            let node = NodeBuilder::<LocalKeysManager>::new(tenant_id, deps)
                .with_signer(signer)
                .build()
                .await?;
            Ok(node as Arc<dyn NodeApi>)
        })
    })
}
