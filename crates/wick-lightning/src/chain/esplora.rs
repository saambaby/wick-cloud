//! Esplora chain client.
//!
//! [`EsploraChainClient`] is the single chain-source type passed to LDK as a
//! [`BlockSource`]. It also provides UTXO queries and raw fee-estimate fetches
//! consumed by the fee-polling task owned by the server (one task per process,
//! shared across tenants).
//!
//! Broadcasting and fee estimation are intentionally separated into
//! [`super::EsploraBroadcaster`] and [`super::FeeEstimator`] so each type
//! carries a single LDK trait responsibility.

use std::collections::HashMap;
use std::sync::Arc;

use esplora_client::Utxo;
use lightning_block_sync::{ BlockData, BlockHeaderData, BlockSource, BlockSourceError };
use wick_core::WickNetwork;

/// Esplora-backed chain source.
///
/// Implements [`BlockSource`] for the SPV chain-sync loop. Also exposes
/// helpers for UTXO queries and raw fee-estimate fetches used by the
/// background fee-polling task.
#[derive(Debug)]
pub struct EsploraChainClient {
    esplora: Arc<esplora_client::AsyncClient>,
    wick_network: WickNetwork,
}

impl EsploraChainClient {
    /// Construct an Esplora-backed chain client.
    ///
    /// # Errors
    /// Returns an error if the Esplora client builder rejects the URL.
    pub fn new(esplora_url: &str, wick_network: WickNetwork) -> anyhow::Result<Self> {
        let esplora = Arc::new(
            esplora_client::Builder
                ::new(esplora_url)
                .build_async()
                .map_err(|e| anyhow::anyhow!("esplora client: {e:?}"))?
        );
        Ok(Self { esplora, wick_network })
    }

    /// Wick-layer network enum (includes mutinynet distinction from signet).
    #[must_use]
    pub fn wick_network(&self) -> WickNetwork {
        self.wick_network
    }

    /// `bitcoin` crate `Network` value for LDK and chain-sync APIs.
    ///
    /// Both `Signet` and `Mutinynet` return `bitcoin::Network::Signet`.
    #[must_use]
    pub fn network(&self) -> ::bitcoin::Network {
        self.wick_network.into()
    }

    /// Shared Esplora async client — used by [`super::EsploraBroadcaster`] and
    /// the fee-polling task.
    #[must_use]
    pub fn esplora(&self) -> Arc<esplora_client::AsyncClient> {
        self.esplora.clone()
    }

    /// Fetch all known UTXOs for the given address via Esplora.
    ///
    /// # Errors
    /// Propagates the underlying `esplora-client` error.
    pub async fn get_address_utxos(
        &self,
        address: &::bitcoin::Address
    ) -> anyhow::Result<Vec<Utxo>> {
        self.esplora
            .get_address_utxos(address).await
            .map_err(|e| anyhow::anyhow!("esplora get_address_utxos: {e}"))
    }

    /// Fetch raw fee estimates from Esplora (`block_count → sat/vB`).
    ///
    /// Called by the background polling task which converts the result and
    /// pushes it into [`super::FeeEstimator`] via `update()`.
    ///
    /// # Errors
    /// Propagates the underlying `esplora-client` error.
    pub async fn fetch_fee_estimates(&self) -> anyhow::Result<HashMap<u16, f64>> {
        self.esplora
            .get_fee_estimates().await
            .map_err(|e| anyhow::anyhow!("esplora get_fee_estimates: {e}"))
    }
}

// ── BlockSource ───────────────────────────────────────────────────────────────

impl BlockSource for EsploraChainClient {
    fn get_header<'a>(
        &'a self,
        header_hash: &'a ::bitcoin::BlockHash,
        _height_hint: Option<u32>
    ) -> lightning_block_sync::AsyncBlockSourceResult<'a, BlockHeaderData> {
        let esplora = self.esplora.clone();
        let hash = *header_hash;
        Box::pin(async move {
            let header = esplora
                .get_header_by_hash(&hash).await
                .map_err(|e| BlockSourceError::transient(e.to_string()))?;
            let info = esplora
                .get_block_info(&hash).await
                .map_err(|e| BlockSourceError::transient(e.to_string()))?;
            if header.block_hash() != hash {
                return Err(BlockSourceError::transient("header hash mismatch"));
            }

            // Compute cumulative chainwork as (height + 1) × per-block work.
            //
            // `lightning-block-sync` validates chainwork monotonicity; returning
            // per-block work for every block makes them all look equally heavy
            // and prevents the SPV tip from advancing. On regtest /
            // constant-difficulty chains the per-block work fits in the low
            // u128, so this is exact there; on mainnet this is an
            // approximation that preserves monotonicity.
            let per_block = header.target().to_work();
            let per_block_bytes = per_block.to_be_bytes();
            let per_block_lo = u128::from_be_bytes(
                per_block_bytes[16..32]
                    .try_into()
                    .map_err(|_| BlockSourceError::transient("unexpected work byte length"))?
            );
            let count = u128::from(info.height) + 1;
            let total_lo = per_block_lo.saturating_mul(count);
            let mut total_bytes = [0u8; 32];
            total_bytes[16..32].copy_from_slice(&total_lo.to_be_bytes());
            let chainwork = ::bitcoin::pow::Work::from_be_bytes(total_bytes);

            Ok(BlockHeaderData {
                header,
                height: info.height,
                chainwork,
            })
        })
    }

    fn get_block<'a>(
        &'a self,
        header_hash: &'a ::bitcoin::BlockHash
    ) -> lightning_block_sync::AsyncBlockSourceResult<'a, BlockData> {
        let esplora = self.esplora.clone();
        let hash = *header_hash;
        Box::pin(async move {
            let block = esplora
                .get_block_by_hash(&hash).await
                .map_err(|e| BlockSourceError::transient(e.to_string()))?
                .ok_or_else(|| BlockSourceError::transient("block not found"))?;
            if block.block_hash() != hash {
                return Err(BlockSourceError::transient("block hash mismatch"));
            }
            Ok(BlockData::FullBlock(block))
        })
    }

    fn get_best_block(
        &self
    ) -> lightning_block_sync::AsyncBlockSourceResult<'_, (::bitcoin::BlockHash, Option<u32>)> {
        let esplora = self.esplora.clone();
        Box::pin(async move {
            // Fetch tip hash, then look up *that block's* height — never
            // call `get_height()` separately. A naive `(get_tip_hash,
            // get_height)` pair races against electrs's indexer: a new
            // block can land between the two calls, returning a hash from
            // height N and a height of N+1. SPV then walks the wrong chain
            // and trips the channel-manager `chain-order` assert.
            let hash = esplora
                .get_tip_hash().await
                .map_err(|e| BlockSourceError::transient(e.to_string()))?;
            let info = esplora
                .get_block_info(&hash).await
                .map_err(|e| BlockSourceError::transient(e.to_string()))?;
            Ok((hash, Some(info.height)))
        })
    }
}
