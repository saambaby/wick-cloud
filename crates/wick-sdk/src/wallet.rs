//! BDK 1.x on-chain wallets — one BIP84 (P2WPKH) and one BIP86 (P2TR).
//!
//! Two separate [`bdk_wallet::Wallet`] instances (one per address type)
//! rather than a single wallet with two keychains: BDK 1.0 keychains are
//! descriptor-typed, and the two descriptors use different script types
//! (`wpkh` vs `tr`).
//!
//! First `sync_onchain` call runs `full_scan`; subsequent calls use
//! `sync_with_revealed_spks`. The cutover is tracked by
//! [`OnchainWallet::full_scan_done`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use bdk_esplora::{esplora_client, EsploraAsyncExt};
use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, ScriptBuf, Transaction};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};

use crate::config::WickConfig;
use crate::error::{Error, Result};

/// Default sat/vB for funding transactions when no fee-estimator is wired.
/// Low enough for regtest / dev, safely high enough for testnet.
const DEFAULT_FUNDING_FEE_RATE_SAT_PER_VB: u64 = 2;

/// Two-descriptor BDK wallet pair: P2WPKH + P2TR.
pub(crate) struct OnchainWallet {
    p2wpkh: Mutex<Wallet>,
    p2tr: Mutex<Wallet>,
    full_scan_done: AtomicBool,
    network: Network,
}

impl std::fmt::Debug for OnchainWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnchainWallet")
            .field("network", &self.network)
            .field("full_scan_done", &self.full_scan_done.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl OnchainWallet {
    /// Build from a master [`Xpriv`] and SDK [`WickConfig`].
    pub(crate) fn from_xprv(master: &Xpriv, config: &WickConfig) -> Result<Self> {
        let coin = config.coin_type();
        let (wpkh_ext, wpkh_int) = descriptors_bip84(master, coin);
        let (tr_ext, tr_int) = descriptors_bip86(master, coin);

        let p2wpkh = Wallet::create(wpkh_ext, wpkh_int)
            .network(config.network)
            .create_wallet_no_persist()
            .map_err(|e| Error::Wallet(format!("create BIP84 wallet: {e}")))?;
        let p2tr = Wallet::create(tr_ext, tr_int)
            .network(config.network)
            .create_wallet_no_persist()
            .map_err(|e| Error::Wallet(format!("create BIP86 wallet: {e}")))?;

        Ok(Self {
            p2wpkh: Mutex::new(p2wpkh),
            p2tr: Mutex::new(p2tr),
            full_scan_done: AtomicBool::new(false),
            network: config.network,
        })
    }

    pub(crate) fn next_address_p2wpkh(&self) -> Result<Address> {
        let mut w = self
            .p2wpkh
            .lock()
            .map_err(|_| Error::Wallet("p2wpkh wallet mutex poisoned".to_owned()))?;
        Ok(w.next_unused_address(KeychainKind::External).address)
    }

    pub(crate) fn next_address_p2tr(&self) -> Result<Address> {
        let mut w = self
            .p2tr
            .lock()
            .map_err(|_| Error::Wallet("p2tr wallet mutex poisoned".to_owned()))?;
        Ok(w.next_unused_address(KeychainKind::External).address)
    }

    /// Build and sign a channel-funding transaction on the BIP84 wallet.
    ///
    /// Spends P2WPKH UTXOs to produce a Bitcoin transaction paying
    /// exactly `amount_sat` to `output_script` (LDK's 2-of-2 multisig),
    /// with BDK-managed change back to the same wallet. The returned tx
    /// is fully signed and ready for LDK to broadcast via
    /// `ChannelManager::funding_transaction_generated`.
    ///
    /// The caller must have [synced][Self::sync] the wallet first so
    /// freshly-received UTXOs are visible.
    pub(crate) fn build_and_sign_funding(
        &self,
        output_script: ScriptBuf,
        amount_sat: u64,
    ) -> Result<Transaction> {
        let mut guard = self
            .p2wpkh
            .lock()
            .map_err(|_| Error::Wallet("p2wpkh wallet mutex poisoned".to_owned()))?;
        let spendable_before = guard.balance().confirmed.to_sat();

        let mut tx_builder = guard.build_tx();
        tx_builder.add_recipient(output_script, Amount::from_sat(amount_sat));
        tx_builder.fee_rate(FeeRate::from_sat_per_vb_unchecked(
            DEFAULT_FUNDING_FEE_RATE_SAT_PER_VB,
        ));
        // Lightning funding txs must be final (nLockTime == 0). BDK
        // defaults to the current tip height to prevent fee-sniping;
        // that makes the tx non-final and triggers a force-close from
        // the counterparty.
        tx_builder.nlocktime(LockTime::ZERO);

        let mut psbt = tx_builder.finish().map_err(|e| {
            Error::Wallet(format!(
                "TxBuilder::finish failed (wanted {amount_sat} sats + fee, \
                 wallet confirmed = {spendable_before} sats): {e}"
            ))
        })?;
        let finalized = guard
            .sign(&mut psbt, SignOptions::default())
            .map_err(|e| Error::Wallet(format!("wallet.sign: {e}")))?;
        if !finalized {
            return Err(Error::Wallet(
                "funding psbt not finalised after signing".to_owned(),
            ));
        }
        psbt.extract_tx()
            .map_err(|e| Error::Wallet(format!("psbt.extract_tx: {e}")))
    }

    /// Confirmed + trusted-pending balance across both descriptors.
    pub(crate) fn spendable_sat(&self) -> Result<u64> {
        let wpkh = self
            .p2wpkh
            .lock()
            .map_err(|_| Error::Wallet("p2wpkh wallet mutex poisoned".to_owned()))?;
        let tr = self
            .p2tr
            .lock()
            .map_err(|_| Error::Wallet("p2tr wallet mutex poisoned".to_owned()))?;
        let a = wpkh.balance();
        let b = tr.balance();
        Ok(a.confirmed.to_sat()
            + a.trusted_pending.to_sat()
            + b.confirmed.to_sat()
            + b.trusted_pending.to_sat())
    }

    /// Sync both descriptors against `esplora_url`.
    ///
    /// First call: `full_scan` (stops after `gap_limit` consecutive empty
    /// SPKs per keychain). Subsequent calls: `sync_with_revealed_spks`.
    pub(crate) async fn sync(&self, esplora_url: &str, config: &WickConfig) -> Result<()> {
        let client = esplora_client::Builder::new(esplora_url)
            .build_async()
            .map_err(|e| Error::Chain(format!("esplora build_async: {e}")))?;

        let first = !self.full_scan_done.load(Ordering::Acquire);
        self.sync_one(&self.p2wpkh, &client, config, first).await?;
        self.sync_one(&self.p2tr, &client, config, first).await?;
        if first {
            self.full_scan_done.store(true, Ordering::Release);
        }
        Ok(())
    }

    async fn sync_one(
        &self,
        wallet: &Mutex<Wallet>,
        client: &esplora_client::AsyncClient,
        config: &WickConfig,
        first: bool,
    ) -> Result<()> {
        if first {
            let request = {
                let guard = wallet
                    .lock()
                    .map_err(|_| Error::Wallet("wallet mutex poisoned".to_owned()))?;
                guard.start_full_scan().build()
            };
            let response = client
                .full_scan(request, config.gap_limit, config.parallel_esplora_requests)
                .await
                .map_err(|e| Error::Chain(format!("esplora full_scan: {e}")))?;
            let mut guard = wallet
                .lock()
                .map_err(|_| Error::Wallet("wallet mutex poisoned".to_owned()))?;
            guard
                .apply_update(response)
                .map_err(|e| Error::Wallet(format!("apply_update: {e}")))?;
        } else {
            let request = {
                let guard = wallet
                    .lock()
                    .map_err(|_| Error::Wallet("wallet mutex poisoned".to_owned()))?;
                guard.start_sync_with_revealed_spks().build()
            };
            let response = client
                .sync(request, config.parallel_esplora_requests)
                .await
                .map_err(|e| Error::Chain(format!("esplora sync: {e}")))?;
            let mut guard = wallet
                .lock()
                .map_err(|_| Error::Wallet("wallet mutex poisoned".to_owned()))?;
            guard
                .apply_update(response)
                .map_err(|e| Error::Wallet(format!("apply_update: {e}")))?;
        }
        Ok(())
    }
}

fn descriptors_bip84(master: &Xpriv, coin_type: u32) -> (String, String) {
    let path = format!("84'/{coin_type}'/0'");
    (
        format!("wpkh({master}/{path}/0/*)"),
        format!("wpkh({master}/{path}/1/*)"),
    )
}

fn descriptors_bip86(master: &Xpriv, coin_type: u32) -> (String, String) {
    let path = format!("86'/{coin_type}'/0'");
    (
        format!("tr({master}/{path}/0/*)"),
        format!("tr({master}/{path}/1/*)"),
    )
}
