//! Esplora-backed transaction broadcaster.
//!
//! [`EsploraBroadcaster`] implements LDK's [`BroadcasterInterface`] directly.
//! Broadcast calls are dispatched from a spawned task so the LDK event
//! processor never blocks on network I/O.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::Transaction;
use lightning::chain::chaininterface::BroadcasterInterface;

/// Timeout for a single tx broadcast attempt.
const TX_BROADCAST_TIMEOUT_SECS: u64 = 30;

/// Immediate broadcaster backed by Esplora.
///
/// Packages are sent from a spawned task so the LDK event processor does not
/// block on network I/O.
#[derive(Debug)]
pub struct EsploraBroadcaster {
    esplora: Arc<esplora_client::AsyncClient>,
}

impl EsploraBroadcaster {
    /// Construct a broadcaster around a shared Esplora client.
    #[must_use]
    pub fn new(esplora: Arc<esplora_client::AsyncClient>) -> Self {
        Self { esplora }
    }
}

impl BroadcasterInterface for EsploraBroadcaster {
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        let package: Vec<Transaction> = txs.iter().map(|t| (*t).clone()).collect();
        let esplora = self.esplora.clone();

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    for tx in package {
                        let txid = tx.compute_txid();
                        match tokio::time::timeout(
                            Duration::from_secs(TX_BROADCAST_TIMEOUT_SECS),
                            esplora.broadcast(&tx),
                        )
                        .await
                        {
                            Ok(Ok(())) => {
                                tracing::info!(target: "ldk", %txid, "broadcasted transaction");
                            }
                            Ok(Err(e)) => {
                                let msg = e.to_string();
                                // Treat "already in mempool" responses as success-ish.
                                if msg.contains("400") || msg.contains("already") {
                                    tracing::debug!(
                                        target: "ldk",
                                        %txid,
                                        error = %msg,
                                        "transaction already accepted by mempool"
                                    );
                                } else {
                                    tracing::error!(
                                        target: "ldk",
                                        %txid,
                                        error = %msg,
                                        "failed to broadcast transaction"
                                    );
                                }
                            }
                            Err(_) => {
                                tracing::error!(
                                    target: "ldk",
                                    %txid,
                                    timeout_secs = TX_BROADCAST_TIMEOUT_SECS,
                                    "broadcast timed out"
                                );
                            }
                        }
                    }
                });
            }
            Err(e) => {
                tracing::error!(
                    target: "ldk",
                    error = %e,
                    "broadcast_transactions called without an active Tokio runtime"
                );
            }
        }
    }
}
