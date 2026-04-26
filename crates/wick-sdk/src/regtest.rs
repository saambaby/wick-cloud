//! Regtest helpers for local development and integration tests.
//!
//! This module is compiled only when the `regtest` feature is enabled:
//!
//! ```toml
//! wick-sdk = { version = "…", features = ["regtest"] }
//! ```
//!
//! It exposes:
//!
//! - [`RegtestRpc`] — a thin wrapper around `bitcoincore_rpc::Client` with
//!   the handful of calls integration tests and dev tooling need (mine,
//!   send to address, wait for mempool size, tip height).
//! - [`wait_until_async`] — a generic async polling utility with a
//!   200 ms tick and a user-supplied timeout.
//!
//! None of this is part of the production SDK — the feature flag keeps
//! `bitcoincore-rpc` out of the default dependency graph.

use std::future::Future;
use std::time::{Duration, Instant};

use bitcoin::{Address, BlockHash, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use crate::error::{Error, Result};

/// `bitcoind` JSON-RPC client.
///
/// Construct via [`RegtestRpc::connect`]. All methods map onto
/// `bitcoincore_rpc` calls and translate errors into [`Error::Chain`].
pub struct RegtestRpc {
    client: Client,
    wallet_name: String,
}

impl std::fmt::Debug for RegtestRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegtestRpc")
            .field("wallet_name", &self.wallet_name)
            .finish_non_exhaustive()
    }
}

impl RegtestRpc {
    /// Connect to `url` with HTTP Basic auth (`user` / `pass`), ensuring a
    /// named default wallet exists so subsequent `mine` / `send_to_address`
    /// calls have somewhere to live.
    ///
    /// The default wallet is named `"wick-regtest"`. On a fresh `bitcoind`
    /// data directory the method creates it; on a reused data directory it
    /// loads the existing one.
    pub fn connect(url: &str, user: &str, pass: &str) -> Result<Self> {
        let base = Client::new(url, Auth::UserPass(user.to_owned(), pass.to_owned()))
            .map_err(|e| Error::Chain(format!("bitcoincore-rpc connect: {e}")))?;

        let wallet_name = "wick-regtest".to_owned();

        // Idempotent bring-up: try to load the wallet; if missing, create
        // it. Either branch leaves the named wallet active on the daemon.
        // Errors are ignored because a double-load / double-create is
        // the expected no-op path on re-runs.
        let _ = base.load_wallet(&wallet_name);
        let _ = base.create_wallet(&wallet_name, None, None, None, None);

        // Switch to the wallet-scoped endpoint so subsequent calls
        // (`send_to_address`, `get_new_address`) target it explicitly.
        let wallet_url = format!("{}/wallet/{}", url.trim_end_matches('/'), wallet_name);
        let client = Client::new(
            &wallet_url,
            Auth::UserPass(user.to_owned(), pass.to_owned()),
        )
        .map_err(|e| Error::Chain(format!("bitcoincore-rpc wallet connect: {e}")))?;

        Ok(Self {
            client,
            wallet_name,
        })
    }

    /// Current chain tip height.
    pub fn tip_height(&self) -> Result<u32> {
        let n = self
            .client
            .get_block_count()
            .map_err(|e| Error::Chain(format!("get_block_count: {e}")))?;
        u32::try_from(n).map_err(|_| Error::Chain(format!("block count {n} overflows u32")))
    }

    /// Get a fresh receive address from the bitcoind wallet. Useful for
    /// mining to a disposable address without leaking the wallet's state.
    pub fn new_address(&self) -> Result<Address> {
        let addr = self
            .client
            .get_new_address(None, None)
            .map_err(|e| Error::Chain(format!("get_new_address: {e}")))?;
        addr.require_network(bitcoin::Network::Regtest)
            .map_err(|e| Error::Chain(format!("address not regtest: {e}")))
    }

    /// Mine `n` blocks to a disposable bitcoind-wallet address.
    pub fn mine(&self, n: u64) -> Result<Vec<BlockHash>> {
        let addr = self.new_address()?;
        self.mine_to(n, &addr)
    }

    /// Mine `n` blocks to a specific address. Use this to pre-fund a
    /// target wallet on regtest.
    pub fn mine_to(&self, n: u64, address: &Address) -> Result<Vec<BlockHash>> {
        self.client
            .generate_to_address(n, address)
            .map_err(|e| Error::Chain(format!("generate_to_address: {e}")))
    }

    /// Send `amount_sat` to `address` from the bitcoind wallet. Returns the
    /// broadcast tx's txid.
    pub fn send_to_address(&self, address: &Address, amount_sat: u64) -> Result<Txid> {
        let amount = bitcoin::Amount::from_sat(amount_sat);
        self.client
            .send_to_address(address, amount, None, None, None, None, None, None)
            .map_err(|e| Error::Chain(format!("send_to_address: {e}")))
    }

    /// Poll until bitcoind's mempool contains at least `n` transactions,
    /// or `timeout` elapses.
    pub async fn wait_for_mempool_size(&self, n: usize, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let entries = self
                .client
                .get_raw_mempool()
                .map_err(|e| Error::Chain(format!("get_raw_mempool: {e}")))?;
            if entries.len() >= n {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::Chain(format!(
                    "timed out waiting for mempool size >= {n}, saw {}",
                    entries.len()
                )));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

/// Poll `predicate` every 200 ms until it returns `true` or `timeout`
/// elapses. Panics with a useful message on timeout.
///
/// This is a generic async polling utility used by regtest-style
/// integration tests where a condition (channel becomes usable, payment
/// status flips to Succeeded, mempool fills, etc.) needs to be observed
/// without a deterministic event stream.
pub async fn wait_until_async<F, Fut>(label: &str, timeout: Duration, mut predicate: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if predicate().await {
            return;
        }
        if Instant::now() >= deadline {
            panic!("wait_until_async: timed out waiting for '{label}' after {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
