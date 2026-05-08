//! Phase-4 `NodeFactory` — `wick_vls::SignerSession` backed by a per-tenant
//! gRPC bidi stream the SDK opens via [`SignerService.Attach`].
//!
//! The server holds **no** seed material. For each tenant the closure:
//!
//! 1. Builds a [`ConnLookup`] over the shared
//!    [`SignerSessionRegistry`] keyed on the tenant's `context_id`.
//! 2. Refuses early with `signer offline` if the SDK side of the bidi
//!    stream is not currently attached — `wake_loading` surfaces this as
//!    `WakeError::SignerOffline` so the gRPC layer can map it to
//!    `Status::failed_precondition` without burning a wake slot.
//! 3. Calls [`SignerSession::init`] to negotiate VLS `HsmdInit2` + fetch
//!    the three LDK-only node keys (peer-storage, inbound-payment,
//!    receive-auth) over the live stream.
//! 4. Hands the `Arc<SignerSession>` to `NodeBuilder::with_signer`.
//!
//! Channel funding remains self-custodial via the existing two-phase
//! `OpenChannelInit` / `OpenChannelFinalize` flow; this factory does not
//! touch on-chain key material.

use std::sync::Arc;

use anyhow::Context as _;
use bitcoin::secp256k1::PublicKey;
use wick_core::TenantId;
use wick_lightning::{NodeApi, NodeBuilder, NodeDeps};
use wick_vls::{ChannelMetaStoreRef, ConnLookup, SignerSession, SignerSessionRegistry};

use crate::node::manager::NodeFactory;
use crate::signer_meta_store::PgChannelMetaStore;

/// Build a remote-signer-backed `NodeFactory` capturing the shared
/// [`NodeDeps`] + [`SignerSessionRegistry`] via closure.
#[must_use]
pub fn node_factory(deps: NodeDeps, registry: Arc<SignerSessionRegistry>) -> NodeFactory {
    node_factory_with_lsp(deps, registry, None)
}

/// Variant that wires every tenant `Node` as an LSPS2 client of `lsp_peer`
/// (when `Some`). Identical to [`node_factory`] otherwise.
#[must_use]
pub fn node_factory_with_lsp(
    deps: NodeDeps,
    registry: Arc<SignerSessionRegistry>,
    lsp_peer: Option<PublicKey>,
) -> NodeFactory {
    Arc::new(move |tenant_id: TenantId| {
        let deps = deps.clone();
        let registry = Arc::clone(&registry);
        Box::pin(async move {
            let context_id = tenant_id.to_string();
            let lookup = ConnLookup::new(context_id.clone(), registry);

            // SignerOffline precheck: refuse cleanly before paying any
            // wake cost. The gRPC layer maps this to
            // `Status::failed_precondition("signer offline")` so the
            // SDK can surface a clear "reconnect your signer" message.
            if !lookup.is_ready() {
                anyhow::bail!(
                    "signer offline for tenant {tenant_id} — SDK must be attached to receive payments"
                );
            }

            // Bind a Postgres-backed `ChannelMetaStore` so the
            // session's per-channel `(dbid, peer_id, pubkeys,
            // setup_funding)` map survives a wick-server restart. LDK
            // calls `derive_channel_signer` for every persisted channel
            // during `ChannelManager::read`, and that path needs the
            // ORIGINAL `dbid` — otherwise VLS rejects every signing
            // call after restart with "channel not found".
            let meta_store: ChannelMetaStoreRef = Arc::new(PgChannelMetaStore::new(
                tenant_id,
                deps.pg_pool.clone(),
            ));
            let signer =
                Arc::new(SignerSession::new(lookup).with_meta_store(Arc::clone(&meta_store)));

            // Rehydrate BEFORE init() / NodeBuilder::build so LDK's
            // first `derive_channel_signer` call hits the cache that
            // `rehydrate` populates rather than allocating a fresh dbid.
            signer
                .rehydrate()
                .await
                .with_context(|| format!("signer rehydrate failed for tenant {tenant_id}"))?;

            signer
                .init(deps.network.into())
                .await
                .with_context(|| format!("signer init failed for tenant {tenant_id}"))?;

            let mut builder =
                NodeBuilder::<SignerSession>::new(tenant_id, deps).with_signer(Arc::clone(&signer));
            if let Some(peer) = lsp_peer {
                builder = builder.with_liquidity_client(peer);
            }
            let node = builder.build().await?;
            Ok(node as Arc<dyn NodeApi>)
        })
    })
}
