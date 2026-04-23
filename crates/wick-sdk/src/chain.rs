//! Public-Esplora chain client.
//!
//! Portfolio queries, fee estimates, and transaction broadcasts must
//! bypass `wick-server`'s internal Esplora pool — architecture gotcha:
//! "Portfolio queries bypass wick.cloud Esplora". [`EsploraChain`] talks
//! directly to whatever URL [`crate::WickConfig::esplora_url`] holds
//! (e.g. `https://mempool.space/api`).

use std::collections::HashMap;

use bdk_esplora::esplora_client;
use bitcoin::{Transaction, Txid};

use crate::error::{Error, Result};

/// Thin wrapper around [`bdk_esplora::esplora_client::AsyncClient`].
pub(crate) struct EsploraChain {
    inner: esplora_client::AsyncClient,
    url: String,
}

impl std::fmt::Debug for EsploraChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EsploraChain")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl EsploraChain {
    pub(crate) fn new(url: &str) -> Result<Self> {
        let inner = esplora_client::Builder::new(url)
            .build_async()
            .map_err(|e| Error::Chain(format!("esplora build_async: {e}")))?;
        Ok(Self {
            inner,
            url: url.to_owned(),
        })
    }

    pub(crate) async fn broadcast(&self, tx: &Transaction) -> Result<()> {
        self.inner
            .broadcast(tx)
            .await
            .map_err(|e| Error::Chain(format!("broadcast: {e}")))
    }

    /// Fee estimates as a map of `block_target → sat/vB`.
    pub(crate) async fn fee_estimates(&self) -> Result<HashMap<u16, f64>> {
        self.inner
            .get_fee_estimates()
            .await
            .map_err(|e| Error::Chain(format!("fee_estimates: {e}")))
    }

    pub(crate) async fn get_tx(&self, txid: Txid) -> Result<Option<Transaction>> {
        self.inner
            .get_tx(&txid)
            .await
            .map_err(|e| Error::Chain(format!("get_tx: {e}")))
    }
}
