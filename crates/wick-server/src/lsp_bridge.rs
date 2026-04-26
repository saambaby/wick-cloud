//! Bridges `wick-lsp`'s [`LspDispatcher`] trait to the local
//! [`NodeManager`].
//!
//! When the LSP fires a JIT channel-open request via
//! [`wick_lsp::OpenChannelRequest`], this bridge:
//!
//! 1. Resolves the tenant pubkey to a [`TenantId`] via the manager's
//!    pubkey reverse index.
//! 2. Wakes the tenant if parked (transparent — `NodeManager::wake`
//!    is a no-op when the tenant is already `ACTIVE`).
//!
//! Once the tenant is `ACTIVE`, its `PeerManager` is alive and ready to
//! receive the BOLT8 channel-open messages the LSP is about to send via
//! `ChannelManager::create_channel`. The actual `create_channel` call
//! happens on the LSP node side immediately after this dispatch
//! returns; LDK then negotiates the open over the wire and the
//! tenant's `Event::OpenChannelRequest` handler accepts the 0-conf
//! channel from the trusted LSP peer (see
//! `crate::wick_lightning::EventHandler::lsp_peer`).

use std::sync::Arc;

use async_trait::async_trait;
use wick_lsp::{LspDispatcher, OpenChannelRequest};

use crate::node::manager::NodeManager;

/// Implements [`LspDispatcher`] over a shared [`NodeManager`].
#[derive(Debug, Clone)]
pub struct ManagerLspBridge {
    manager: Arc<NodeManager>,
}

impl ManagerLspBridge {
    /// Construct a bridge over `manager`.
    #[must_use]
    pub fn new(manager: Arc<NodeManager>) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl LspDispatcher for ManagerLspBridge {
    async fn dispatch_open_channel(&self, req: OpenChannelRequest) -> anyhow::Result<()> {
        // 1. Resolve pubkey → TenantId. Failure here means the LSPS2
        //    counterparty doesn't match any provisioned tenant — either
        //    a forged pubkey or a tenant that hasn't been activated
        //    since process start (the index is populated on first
        //    wake). Either way, refuse the open.
        let tenant_id = self
            .manager
            .tenant_id_by_pubkey(&req.tenant_pubkey)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "lsp bridge: no tenant for counterparty pubkey {}",
                    req.tenant_pubkey
                )
            })?;

        // 2. Wake. `NodeManager::wake` returns Ok immediately if the
        //    tenant is already ACTIVE; otherwise drives PARKED → LOADING
        //    → ACTIVE under the manager's wake_deadline (default 2s).
        //    We use Payment priority so the wake bypasses the per-tenant
        //    user-rate limit — JIT opens are CLTV-bound and shouldn't
        //    queue behind interactive User wakes.
        self.manager
            .wake_with_priority(tenant_id, crate::node::admission::WakePriority::Payment)
            .await
            .map_err(|e| anyhow::anyhow!("lsp bridge: wake tenant {tenant_id}: {e}"))?;

        tracing::info!(
            target: "wick_server",
            tenant = %tenant_id,
            tenant_pubkey = %req.tenant_pubkey,
            amt_to_forward_msat = req.amt_to_forward_msat,
            opening_fee_msat = req.opening_fee_msat,
            intercept_scid = req.intercept_scid,
            "lsp bridge: tenant awake; LSP may proceed with channel open"
        );

        Ok(())
    }
}
