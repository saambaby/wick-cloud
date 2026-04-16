//! [`TestWallet`] — BDK 1.x on-chain wallet for regtest integration tests.
//!
//! Responsibilities:
//! - Derive addresses deterministically from a seed (BIP84 wpkh descriptor).
//! - Sync UTXOs via the Electrum protocol against Electrs (`tcp://localhost:50001`
//!   in the docker-compose stack, port 50001).
//! - Produce signed funding transactions for LDK's `FundingGenerationReady`
//!   event so the Lightning node can open channels in tests.
//!
//! Not persisted — the whole wallet is rebuilt on every `TestWallet::new`.
//! Fine for tests; would be wrong in production.
//!
//! ## Sync strategy
//!
//! The first call to [`TestWallet::sync`] runs a BDK `full_scan` — it queries
//! Electrs for the full transaction history of every script pubkey in the
//! wallet's keychain up to [`STOP_GAP`] consecutive unused addresses.
//! Subsequent calls run `sync_with_revealed_spks`, an incremental update that
//! only checks already-revealed SPKs. This matches the standard BDK wallet
//! lifecycle:
//!
//! - **`full_scan`**: required on first boot or wallet restore; discovers all
//!   previously-used addresses.
//! - **`sync_with_revealed_spks`**: used for routine updates; much faster.
//!
//! ## BDK + Electrum version note
//!
//! `bdk_electrum 0.20` is the version that shares `bdk_core 0.4.x` with
//! `bdk_wallet 1.2`. Using a newer `bdk_electrum` introduces a duplicate
//! `bdk_core` and the `FullScanRequest`/`SyncRequest` types become
//! incompatible (different `bdk_core` instances). Pin to `"0.20"` until the
//! workspace upgrades to `bdk_wallet 1.3+`.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

use anyhow::{Context, Result};
use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, ScriptBuf, Transaction};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use wick_lightning::FundingSource;

/// BIP84 (native segwit) derivation path for regtest (`coin_type = 1`).
const ACCOUNT_PATH: &str = "84'/1'/0'";

/// Stop-gap for the initial full scan: stop scanning a keychain after this
/// many consecutive unused script pubkeys. BIP44 recommendation is 20.
const STOP_GAP: usize = 20;

/// Number of SPKs fetched per Electrum batch request.
const BATCH_SIZE: usize = 5;

/// Regtest BDK wallet backed by an Electrs Electrum server.
///
/// Wrapped in a `Mutex` so test code can hold `Arc<TestWallet>` and call
/// `sync` / `next_address` / `build_and_sign_funding` without needing `&mut`.
pub struct TestWallet {
    inner: Mutex<Wallet>,
    network: Network,
    /// Flips to `true` after the first `sync()` call. Controls whether we do
    /// a full SPK-range scan (first call) or an incremental update (subsequent).
    full_scan_done: AtomicBool,
}

impl std::fmt::Debug for TestWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestWallet")
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl TestWallet {
    /// Build a fresh BDK wallet from a 32-byte seed on the given network.
    ///
    /// Descriptors are derived from an Xpriv anchored at the seed. Both
    /// external and internal (change) descriptors are generated.
    ///
    /// # Errors
    /// Returns an error if descriptor construction or wallet creation fails.
    pub fn new(seed: [u8; 32], network: Network) -> Result<Self> {
        let xpriv = Xpriv::new_master(network, &seed).context("Xpriv::new_master")?;

        let external = format!("wpkh({xpriv}/{ACCOUNT_PATH}/0/*)");
        let internal = format!("wpkh({xpriv}/{ACCOUNT_PATH}/1/*)");

        let wallet = Wallet::create(external, internal)
            .network(network)
            .create_wallet_no_persist()
            .context("bdk_wallet::Wallet::create")?;

        Ok(Self {
            inner: Mutex::new(wallet),
            network,
            full_scan_done: AtomicBool::new(false),
        })
    }

    /// Return the next unused external address.
    ///
    /// BDK advances the external keychain internally so concurrent calls get
    /// distinct addresses.
    pub fn next_address(&self) -> Result<Address> {
        let mut w = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("wallet mutex poisoned"))?;
        Ok(w.next_unused_address(KeychainKind::External).address)
    }

    /// Sum of confirmed + trusted-pending balance in satoshis.
    ///
    /// Returns 0 until [`TestWallet::sync`] has been called at least once
    /// *after* mining the funding outputs to the wallet's address.
    pub fn spendable_sat(&self) -> Result<u64> {
        let w = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("wallet mutex poisoned"))?;
        let b = w.balance();
        Ok(b.confirmed.to_sat() + b.trusted_pending.to_sat())
    }

    /// Sync the wallet's UTXO set against Electrs at `electrum_url`.
    ///
    /// `electrum_url` must be a `tcp://host:port` (or `ssl://`) address. In
    /// the docker-compose stack, Electrs binds the Electrum protocol on port
    /// 50001: `tcp://localhost:50001`.
    ///
    /// **Sync lifecycle:**
    /// - **First call**: runs a `full_scan` — discovers all funded addresses
    ///   by scanning every keychain SPK up to [`STOP_GAP`] consecutive unused
    ///   addresses.
    /// - **Subsequent calls**: runs `sync_with_revealed_spks` — only rescans
    ///   previously-revealed script pubkeys. Suitable for polling.
    ///
    /// # Errors
    /// Returns an error on Electrum connection failure, RPC error, or if the
    /// update cannot be applied to the local chain (tip diverged).
    pub fn sync(&self, electrum_url: &str) -> Result<()> {
        let electrum = electrum_client::Client::new(electrum_url)
            .map_err(|e| anyhow::anyhow!("electrum connect {electrum_url}: {e}"))?;
        let client = BdkElectrumClient::new(electrum);

        let mut w = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("wallet mutex poisoned"))?;

        if self.full_scan_done.load(Ordering::Acquire) {
            // Incremental update: only check already-revealed SPKs.
            let request = w.start_sync_with_revealed_spks().build();
            let response = client
                .sync(request, BATCH_SIZE, false)
                .map_err(|e| anyhow::anyhow!("electrum sync: {e}"))?;
            w.apply_update(response)
                .map_err(|e| anyhow::anyhow!("apply_update: {e}"))?;
        } else {
            // Full scan: discover every used SPK in the keychain.
            let request = w.start_full_scan().build();
            let response = client
                .full_scan(request, STOP_GAP, BATCH_SIZE, false)
                .map_err(|e| anyhow::anyhow!("electrum full_scan: {e}"))?;
            w.apply_update(response)
                .map_err(|e| anyhow::anyhow!("apply_update: {e}"))?;
            self.full_scan_done.store(true, Ordering::Release);
        }

        Ok(())
    }

    /// Build, sign, and return a funding transaction paying `amount_sat` to
    /// `output_script`.
    ///
    /// Uses a fixed 4 sat/vB fee rate — regtest has no congestion.
    /// The transaction is not broadcast here; LDK's configured
    /// `BroadcasterInterface` handles that after
    /// `ChannelManager::funding_transaction_generated` is called.
    ///
    /// # Errors
    /// Returns an error on insufficient funds, coin-selection failure, or
    /// PSBT signing / finalisation failure.
    pub fn build_and_sign_funding(
        &self,
        output_script: ScriptBuf,
        amount_sat: u64,
    ) -> Result<Transaction> {
        const FEE_RATE_SAT_PER_VB: u64 = 4;

        let mut w = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("wallet mutex poisoned"))?;

        let mut tx_builder = w.build_tx();
        tx_builder.add_recipient(output_script, Amount::from_sat(amount_sat));
        tx_builder.fee_rate(FeeRate::from_sat_per_vb_unchecked(FEE_RATE_SAT_PER_VB));

        let mut psbt = tx_builder.finish().context("TxBuilder::finish")?;
        let finalized = w
            .sign(&mut psbt, SignOptions::default())
            .context("wallet.sign")?;
        if !finalized {
            anyhow::bail!("funding psbt not finalised after signing");
        }
        psbt.extract_tx().context("psbt.extract_tx")
    }

    /// Network this wallet was built for.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }
}

// ── FundingSource bridge ──────────────────────────────────────────────────────

impl FundingSource for TestWallet {
    fn fund_channel(
        &self,
        output_script: ScriptBuf,
        channel_value_sats: u64,
    ) -> anyhow::Result<Transaction> {
        self.build_and_sign_funding(output_script, channel_value_sats)
    }
}
