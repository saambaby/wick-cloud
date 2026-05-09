//! Top-level [`WickClient`] — composes identity, on-chain wallet, chain
//! client, and Lightning gRPC client.
//!
//! Construction is one call: [`WickClient::new`] takes a BIP39 mnemonic
//! plus a [`crate::WickConfig`] and does every derivation + dial in one
//! go. [`WickClient::register`] then provisions a tenant on the server
//! and stores the returned bearer token internally; subsequent RPC calls
//! authenticate automatically via a tonic interceptor that reads the
//! shared token cell on every request.
//!
//! `WickClient` is `Clone` — internals live behind `Arc`s. Clones share
//! the same token cell, so a rotation via [`WickClient::with_token`] on
//! any clone is visible to all.

use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Transaction, Txid};
use parking_lot::RwLock;

use crate::chain::EsploraChain;
use crate::config::WickConfig;
use crate::error::{Error, Result};
use crate::grpc::{empty_token, LightningClient, SharedToken};
use crate::identity::Identity;
use crate::pinning::{self, PinWitness, TransparencyLog};
use crate::types::{
    Balance, ChannelSummary, CreateTenantOutcome, JitInvoice, JitQuote, LspInfo, NodeInfo,
    PaymentRecord, PaymentResult, ReceiveInvoice,
};
use crate::signer::{ SignerHandle, SignerLoop };
use crate::wallet::OnchainWallet;

/// Canonical Wick Cloud client.
#[derive(Debug, Clone)]
pub struct WickClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    identity: Identity,
    wallet: OnchainWallet,
    chain: EsploraChain,
    ln: LightningClient,
    config: WickConfig,
    token: SharedToken,
    tenant_id: RwLock<Option<String>>,
    /// Background reconnecting signer loop. `Some` after `register()`.
    /// Dropped when the last `WickClient` clone is released, which fires
    /// the watch-channel shutdown signal inside `SignerHandle::drop`.
    signer: RwLock<Option<SignerHandle>>,
    /// Phase-4 transparency-log handle. Default is `NoOpLog`; tests can
    /// install a stub via `with_transparency_log`.
    transparency_log: Arc<dyn TransparencyLog>,
}

impl WickClient {
    /// Build a client from a BIP39 mnemonic.
    ///
    /// Hits the network once — to open the gRPC channel to
    /// `config.server_endpoint`. Key derivation, wallet construction, and
    /// Esplora client setup are offline.
    pub async fn new(mnemonic: &str, passphrase: Option<&str>, config: WickConfig) -> Result<Self> {
        config.validate()?;

        let identity = Identity::from_mnemonic(mnemonic, passphrase, config.network)?;
        let wallet = OnchainWallet::from_xprv(identity.master_xprv(), &config)?;
        let chain = EsploraChain::new(&config.esplora_url)?;

        let token = empty_token();
        let ln = LightningClient::connect(&config.server_endpoint, Arc::clone(&token)).await?;

        Ok(Self {
            inner: Arc::new(Inner {
                identity,
                wallet,
                chain,
                ln,
                config,
                token,
                tenant_id: RwLock::new(None),
                signer: RwLock::new(None),
                transparency_log: pinning::default_log(),
            }),
        })
    }


    // ── Identity ─────────────────────────────────────────────────────────────

    /// 33-byte compressed secp256k1 identity pubkey.
    #[must_use]
    pub fn node_id(&self) -> PublicKey {
        self.inner.identity.node_id()
    }

    /// 4-byte BIP32 master fingerprint.
    #[must_use]
    pub fn xpub_fingerprint(&self) -> [u8; 4] {
        self.inner.identity.fingerprint()
    }

    /// Hex-encoded identity pubkey (as sent in `CreateTenantRequest`).
    #[must_use]
    pub fn node_id_hex(&self) -> String {
        self.inner.identity.node_id_hex()
    }

    /// The tenant id returned by the server at [`Self::register`] time,
    /// or `None` if the client has not yet registered.
    #[must_use]
    pub fn tenant_id(&self) -> Option<String> {
        self.inner.tenant_id.read().clone()
    }

    // ── Server registration + Lightning RPCs ─────────────────────────────────

    /// Provision a tenant on the server and attach the returned bearer token.
    ///
    /// Idempotent — the server rotates the token on re-register with the
    /// same pubkey (upsert semantics). The SDK stores the new token and
    /// overwrites any previous one.
    pub async fn register(&self, plan_tier: impl Into<String>) -> Result<CreateTenantOutcome> {
        let pubkey_hex = self.inner.identity.node_id_hex();
        // D5 (gotcha #509): two-step signature challenge. Step 1 fetches
        // a fresh nonce keyed on our pubkey; step 2 submits the
        // ECDSA-signed nonce alongside the create-tenant request. The
        // public `register()` API stays unchanged — internal RPC count
        // is now 2.
        let pubkey_bytes = self.inner.identity.node_id().serialize().to_vec();
        let nonce = self.inner.ln.register_challenge(&pubkey_bytes).await?;
        let signature = self.inner.identity.sign_register_challenge(&nonce);
        let outcome = self
            .inner
            .ln
            .create_tenant(&pubkey_hex, &plan_tier.into(), nonce, signature)
            .await?;
        *self.inner.token.write() = Some(outcome.api_token.clone());
        *self.inner.tenant_id.write() = Some(outcome.tenant_id.clone());

        // Phase-4 server pubkey pinning. Skipped on `Regtest` (no pin)
        // and when the operator hasn't supplied an override on a
        // network that has no release const yet. On signet / mutinynet
        // / bitcoin we constant-time-compare the server's tenant LN
        // pubkey against the expected pin and hand a witness to the
        // installed transparency log. The default `NoOpLog` always Oks.
        let node_info = self.inner.ln.get_node_info().await?;
        let actual_pubkey = node_info.pubkey.serialize();
        if let Some((expected, source)) =
            pinning::expected_pubkey(self.inner.config.network, self.inner.config.expected_server_pubkey)
        {
            if !pinning::ct_eq_pubkey(&actual_pubkey, &expected) {
                return Err(Error::ServerPubkeyMismatch {
                    expected: pinning::fingerprint(&expected),
                    actual: pinning::fingerprint(&actual_pubkey),
                    pin_source: source,
                });
            }
            let witness = PinWitness {
                source,
                pubkey: actual_pubkey,
                observed_at: std::time::SystemTime::now(),
            };
            self.inner
                .transparency_log
                .verify(&witness)
                .await
                .map_err(|e| Error::TransparencyVerify(e.to_string()))?;
        }

        // Phase-4: spawn the on-device signer loop on a background task as
        // soon as we have a bearer token. The server's per-tenant
        // `wick_vls::SignerSession` resolves the live SDK side of this
        // bidi stream on every LDK signer-trait call. Without this, the
        // tenant's `Node` cannot sign anything (parked).
        let seed = self
            .inner
            .identity
            .tenant_lightning_seed(self.inner.config.network)?;
        let xprv = *self.inner.identity.master_xprv();
        let endpoint = self.inner.config.server_endpoint.clone();
        let token = Arc::clone(&self.inner.token);
        let network = self.inner.config.network;
        // Spawn the reconnecting signer loop. The returned handle owns a
        // watch-channel sender; storing it on `Inner` ties the loop's
        // lifetime to the last `WickClient` clone (B5).
        let handle = SignerLoop::new(endpoint, token, seed, xprv, network).spawn();
        *self.inner.signer.write() = Some(handle);

        Ok(outcome)
    }

    /// Current Lightning + server-side on-chain balance.
    pub async fn lightning_balance(&self) -> Result<Balance> {
        self.inner.ln.get_balance().await
    }

    /// Pay a BOLT11 invoice.
    pub async fn send_payment(&self, bolt11: &str) -> Result<PaymentResult> {
        self.inner.ln.send_payment(bolt11).await
    }

    /// Issue a BOLT11 invoice. `amount_msat = None` produces an
    /// any-amount invoice.
    pub async fn receive_payment(
        &self,
        amount_msat: Option<u64>,
        memo: impl Into<String>,
    ) -> Result<ReceiveInvoice> {
        self.inner
            .ln
            .receive_payment(amount_msat, &memo.into())
            .await
    }

    /// Paginated payment history, newest first.
    pub async fn transactions(
        &self,
        limit: u32,
        before_timestamp: Option<i64>,
    ) -> Result<Vec<PaymentRecord>> {
        self.inner
            .ln
            .get_transactions(limit, before_timestamp)
            .await
    }

    /// Server-side Lightning node info — pubkey + P2P listen address.
    /// Required so other clients can [`Self::connect_peer`] to this tenant.
    pub async fn node_info(&self) -> Result<NodeInfo> {
        self.inner.ln.get_node_info().await
    }

    /// Short hex SHA-256 fingerprint of the server's tenant LN pubkey
    /// (first 16 hex chars). Suitable for the user-facing settings UI
    /// — pair it with the expected pin's [`pinning::fingerprint`] so a
    /// user can eyeball-verify a self-hosted endpoint.
    pub async fn server_fingerprint(&self) -> Result<String> {
        let info = self.node_info().await?;
        Ok(pinning::fingerprint(&info.pubkey.serialize()))
    }

    /// Connect to a Lightning peer over P2P and persist it for reconnection.
    pub async fn connect_peer(&self, peer: PublicKey, host: &str, port: u16) -> Result<()> {
        self.inner.ln.connect_peer(peer, host, port).await
    }

    /// Open an outbound channel to an already-connected peer, building and
    /// signing the funding transaction on the **client's** BDK wallet.
    ///
    /// Two-phase self-custodial open:
    /// 1. Ask the server to start the channel. Server returns the 2-of-2
    ///    multisig `output_script` + exact `value` LDK wants.
    /// 2. Build + sign a BDK transaction paying `value` to that script
    ///    using the SDK's own on-chain wallet. The SDK's BDK wallet must
    ///    have sufficient confirmed UTXOs — call
    ///    [`Self::sync_onchain`] after funding to pick them up.
    /// 3. Send the signed tx to the server, which hands it to LDK's
    ///    `ChannelManager::funding_transaction_generated`.
    ///
    /// The server never touches on-chain funds. Phase 4 VLS moves the
    /// LDK signing keys on-device too.
    pub async fn open_channel(
        &self,
        peer: PublicKey,
        channel_value_sat: u64,
        push_msat: u64,
    ) -> Result<[u8; 32]> {
        let (temp_channel_id, output_script, value_sat) = self
            .inner
            .ln
            .open_channel_init(peer, channel_value_sat, push_msat)
            .await?;

        let funding_tx = self
            .inner
            .wallet
            .build_and_sign_funding(output_script, value_sat)?;

        self.inner
            .ln
            .open_channel_finalize(temp_channel_id, peer, &funding_tx)
            .await?;

        Ok(temp_channel_id)
    }

    /// Snapshot of the tenant's current channels.
    pub async fn list_channels(&self) -> Result<Vec<ChannelSummary>> {
        self.inner.ln.list_channels().await
    }

    /// Cooperatively close a channel by `channel_id`. Phase-4: the
    /// closing transaction is signed via the on-device VLS signer over
    /// `SignerService::Attach`. The on-chain refund lands on the
    /// server-side change destination configured at node-build time;
    /// it is not (yet) wired through to the client-side BDK wallet,
    /// so the spendable refund manifests as
    /// [`Self::lightning_balance`]'s `onchain_sats`.
    pub async fn close_channel(
        &self,
        channel_id: [u8; 32],
        counterparty: PublicKey,
    ) -> Result<()> {
        self.inner.ln.close_channel(channel_id, counterparty).await
    }

    // ── LSP / LSPS2 (Phase 3) ────────────────────────────────────────────────

    /// Server-side LSP identity. Returns `LspInfo { pubkey: None, ... }`
    /// when the server has no operator-mode LSP enabled — JIT calls
    /// will fail in that configuration.
    ///
    /// Public RPC: does not require [`Self::register`] to have been
    /// called first. Use it on first launch to decide whether to surface
    /// a "JIT receive" UI option.
    pub async fn lsp_info(&self) -> Result<LspInfo> {
        self.inner.ln.get_lsp_info().await
    }

    /// Negotiate `lsps2.get_info` with the server's LSP and return a
    /// fee quote. Use to display a fee preview before committing to a
    /// JIT invoice via [`Self::receive_payment_jit`].
    pub async fn lsps2_get_info(&self, amount_msat: Option<u64>) -> Result<JitQuote> {
        self.inner.ln.lsps2_get_info(amount_msat).await
    }

    /// Issue a JIT-enabled BOLT11 invoice. End-to-end LSPS2 negotiation:
    /// `get_info` + `buy` against the configured LSP, then a BOLT11 with
    /// the LSP's intercept SCID embedded as a private route hint.
    ///
    /// `amount_msat` is required (LSPS2 buy quotes against a payment
    /// size). Pays of this exact size — minus the quoted opening fee —
    /// will route through the LSP, which opens a 0-conf channel to the
    /// tenant before forwarding.
    pub async fn receive_payment_jit(
        &self,
        amount_msat: u64,
        memo: impl Into<String>,
    ) -> Result<JitInvoice> {
        self.inner
            .ln
            .get_jit_invoice(amount_msat, &memo.into())
            .await
    }

    // ── On-chain (BDK + Esplora, bypasses the server) ────────────────────────

    /// Sync both BIP84 and BIP86 descriptors against the configured
    /// Esplora URL. `full_scan` on first call, incremental afterwards.
    pub async fn sync_onchain(&self) -> Result<()> {
        self.inner
            .wallet
            .sync(&self.inner.config.esplora_url, &self.inner.config)
            .await
    }

    /// Next unused P2WPKH (BIP84) external address.
    pub fn next_address_p2wpkh(&self) -> Result<Address> {
        self.inner.wallet.next_address_p2wpkh()
    }

    /// Next unused P2TR (BIP86) external address.
    pub fn next_address_p2tr(&self) -> Result<Address> {
        self.inner.wallet.next_address_p2tr()
    }

    /// Device-side confirmed + trusted-pending balance, summed across
    /// both descriptors. Call [`Self::sync_onchain`] first for fresh data.
    pub fn onchain_spendable_sat(&self) -> Result<u64> {
        self.inner.wallet.spendable_sat()
    }

    /// Broadcast a signed transaction via the public Esplora endpoint.
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<()> {
        self.inner.chain.broadcast(tx).await
    }

    /// Fetch a transaction by id via the public Esplora endpoint.
    pub async fn get_transaction(&self, txid: Txid) -> Result<Option<Transaction>> {
        self.inner.chain.get_tx(txid).await
    }

    /// Fee-rate estimates from the public Esplora endpoint, keyed by
    /// block target (sat/vB).
    pub async fn fee_estimates(&self) -> Result<std::collections::HashMap<u16, f64>> {
        self.inner.chain.fee_estimates().await
    }

    // ── Escape hatches ───────────────────────────────────────────────────────

    /// Manually attach a bearer token. Rotates in place on the shared
    /// cell — all clones of this client see the new token on their next
    /// RPC.
    #[must_use]
    pub fn with_token(self, token: impl Into<String>) -> Self {
        *self.inner.token.write() = Some(token.into());
        self
    }

    /// Clear the bearer token. The next RPC will be anonymous (and the
    /// server will reject it with `UNAUTHENTICATED`).
    pub fn clear_token(&self) {
        *self.inner.token.write() = None;
    }
}
