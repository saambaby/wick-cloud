//! [`ChangeDestinationSourceSync`] implementation that routes channel-close
//! refund / sweep change outputs to an SDK-side BDK wallet via the
//! `0xFD05` `GetWalletAddress` Wick extension RPC.
//!
//! Phase-4 promise: with VLS holding the LDK signing keys on-device, the
//! background [`OutputSweeperSync`](lightning::util::sweep::OutputSweeperSync)
//! must no longer route refund residuals to a server-side script. Instead
//! every sweep cycle asks the SDK for a fresh **change** address on the
//! BIP84 keychain (`m/84'/coin'/0'/1/<n>`) so the on-device BDK wallet
//! sees the refund directly.
//!
//! Address-index allocation is a process-local monotonic counter
//! ([`AtomicU32`]). After a server restart it resets to 0; the SDK's BDK
//! wallet still tracks used indices, so the only practical impact is a
//! handful of address-reuse hits on the first few sweeps after a restart
//! — acceptable for a privacy-soft path. A durable per-tenant counter is
//! a Path-B follow-up if reuse becomes load-bearing.
//!
//! On any failure (SDK offline, RPC timeout, malformed reply) the trait
//! method returns `Err(())` — LDK retries the sweep on its next cadence.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use lightning::sign::ChangeDestinationSourceSync;

use crate::registry::ConnLookup;
use crate::rpc;

/// Resolves a fresh BIP84 change address for the background sweeper by
/// round-tripping through the SDK over the Wick `0xFD05` extension RPC.
///
/// Holds no key material — just the [`ConnLookup`] needed to find the
/// SDK signer connection plus the monotonic change-index allocator.
pub struct VlsChangeDestination {
    lookup: ConnLookup,
    /// Process-local monotonic change-index. `fetch_add` returns the
    /// pre-increment value, which we feed into the RPC; the SDK derives
    /// `m/84'/coin'/0'/1/<index>`.
    next_change_index: AtomicU32,
}

impl std::fmt::Debug for VlsChangeDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlsChangeDestination")
            .field("context_id", &self.lookup.context_id())
            .field(
                "next_change_index",
                &self.next_change_index.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl VlsChangeDestination {
    #[must_use]
    pub fn new(lookup: ConnLookup) -> Self {
        Self {
            lookup,
            next_change_index: AtomicU32::new(0),
        }
    }
}

impl ChangeDestinationSourceSync for VlsChangeDestination {
    fn get_change_destination_script(&self) -> Result<bitcoin::ScriptBuf, ()> {
        let conn = self.lookup.resolve().filter(|c| c.is_ready()).ok_or(())?;
        let index = self.next_change_index.fetch_add(1, Ordering::Relaxed);

        // LDK calls this synchronously from the background sweeper; bridge
        // to the async RPC the same way `SignerSession` does (multi-thread
        // runtime invariant — guaranteed by `wick-server`).
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(rpc::rpc_get_wallet_address_v2(&conn, index, /*change=*/ true))
        });

        match result {
            Ok((_addr, script_pubkey)) => Ok(bitcoin::ScriptBuf::from_bytes(script_pubkey)),
            Err(e) => {
                tracing::warn!(
                    target: "wick_vls",
                    ctx = %self.lookup.context_id(),
                    index,
                    %e,
                    "rpc_get_wallet_address_v2 failed; sweeper will retry"
                );
                Err(())
            }
        }
    }
}

/// Convenience constructor used by the `WickSigner::change_destination_source`
/// hook on `SignerSession`. Boxed-as-trait-object so the builder can keep
/// a single concrete `OutputSweeperSync` type alias regardless of which
/// signer path is in use.
pub fn arc_dyn(lookup: ConnLookup) -> Arc<dyn ChangeDestinationSourceSync + Send + Sync> {
    Arc::new(VlsChangeDestination::new(lookup))
}
