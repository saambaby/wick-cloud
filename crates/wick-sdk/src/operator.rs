//! Operator-side SDK client for self-custodial LSP funding.
//!
//! `OperatorClient` is the device-side counterpart to `wick-server`'s
//! [`AdminService`]. The operator runs this on a trusted machine and
//! drives:
//!
//! 1. **Identity registration** — installs the LSP's Lightning seed on
//!    the server in-memory only via [`OperatorClient::register_lsp`].
//!    The seed is never stored on the server; Phase 4 replaces it with
//!    a remote-signer handle inside the same RPC.
//! 2. **Self-custodial funding** — subscribes to the server's
//!    `LspWatchPendingFunding` stream, signs each parked
//!    `FundingGenerationReady` from a local BDK wallet, and replies via
//!    `LspFinalizeFunding`. Reuses
//!    [`crate::wallet::OnchainWallet::build_and_sign_funding`]
//!    byte-for-byte — the same path tenants already use for two-phase
//!    `OpenChannelFinalize`.
//!
//! Auth is gated by an `x-wick-admin-secret` metadata header
//! (configured via `WICK_ADMIN_SECRET` on the server side). Macaroon
//! scope plumbing arrives in slice 3.3c.

use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::{Address, Network, ScriptBuf, Transaction};
use tokio_stream::StreamExt as _;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};
use wick_core::WickNetwork;
use wick_proto::wick::admin_service_client::AdminServiceClient;
use wick_proto::wick::{
    LspFinalizeFundingRequest, LspWatchPendingFundingRequest, RegisterLspIdentityRequest,
};

use crate::config::WickConfig;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::wallet::OnchainWallet;

/// Metadata header carrying the admin shared secret. Must match the
/// server-side `WICK_ADMIN_SECRET` (slice 3.3a auth gate).
const ADMIN_SECRET_HEADER: &str = "x-wick-admin-secret";

/// Tonic interceptor that injects the admin secret on every outbound
/// request. Cloned cheaply per call alongside the underlying `Channel`.
#[derive(Clone)]
struct AdminInterceptor {
    secret: MetadataValue<Ascii>,
}

impl Interceptor for AdminInterceptor {
    fn call(&mut self, mut req: Request<()>) -> std::result::Result<Request<()>, Status> {
        req.metadata_mut()
            .insert(ADMIN_SECRET_HEADER, self.secret.clone());
        Ok(req)
    }
}

/// One parked funding entry from the LSP's watch stream.
///
/// Operator's signing loop turns each event into a signed
/// [`bitcoin::Transaction`] via the local BDK wallet and replies with
/// [`OperatorClient::finalize_funding`].
#[derive(Debug, Clone)]
pub struct PendingFundingEvent {
    /// LDK temporary channel id — opaque 32-byte correlation handle
    /// echoed back verbatim on `finalize_funding`. Treated as bytes
    /// inside the SDK to avoid pulling LDK in as a dep.
    pub temp_channel_id: [u8; 32],
    /// Counterparty pubkey (the JIT-receiver tenant's Lightning node).
    pub counterparty: PublicKey,
    /// Channel capacity in satoshis. Funding tx must pay this exact
    /// amount to `output_script`.
    pub value_sat: u64,
    /// 2-of-2 multisig SegWit `scriptPubKey` LDK wants funded.
    pub output_script: ScriptBuf,
}

/// Operator-side handle. Composes the admin gRPC stub with a local BDK
/// wallet derived from the operator's mnemonic — both the Lightning
/// identity seed and the on-chain UTXO set live in this struct.
///
/// `Clone` is intentionally **not** derived: the underlying gRPC stub
/// is `Clone` but the wallet wraps a `Mutex`, and a single owner per
/// process is the right shape for the funding loop.
pub struct OperatorClient {
    grpc: AdminServiceClient<
        tonic::service::interceptor::InterceptedService<Channel, AdminInterceptor>,
    >,
    wallet: OnchainWallet,
    lightning_seed: [u8; 32],
    /// LSP node pubkey derived offline from the operator's mnemonic.
    /// Identical to whatever the server reports back from
    /// `RegisterLspIdentity`; pre-computed here so the operator can
    /// publish it into deployment config (`[lsp].pubkey_hex`) before
    /// the server is even started.
    lsp_pubkey: PublicKey,
    config: WickConfig,
    /// Operator-held reorg reserve. Sats earmarked here are subtracted
    /// from `effective_spendable_sat`; `sign_and_finalize` refuses
    /// requests that would dip below it. Operators set this to the
    /// same number the server's `LspConfig::reorg_safety_threshold_sats`
    /// uses so the on-chain side has matching cover for the worst-case
    /// 0-conf reorg refund. `0` (default) disables.
    reserve_sats: AtomicU64,
}

impl std::fmt::Debug for OperatorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorClient")
            .field("lsp_pubkey", &self.lsp_pubkey)
            .finish_non_exhaustive()
    }
}

impl OperatorClient {
    /// Build an operator client from a BIP39 mnemonic.
    ///
    /// Deterministic: same `(mnemonic, passphrase, network)` always
    /// produces the same Lightning seed and the same on-chain wallet.
    /// The Lightning seed comes from
    /// [`Identity::lsp_lightning_seed`] — domain-separated from the
    /// BIP84 receive addresses, so the LSP identity is independent of
    /// the on-chain UTXO set even though both come from the same
    /// master xprv.
    ///
    /// Hits the network once — to dial `config.server_endpoint`. Key
    /// derivation, wallet construction, and Esplora setup are offline.
    pub async fn new(
        mnemonic: &str,
        passphrase: Option<&str>,
        admin_secret: impl Into<String>,
        config: WickConfig,
    ) -> Result<Self> {
        config.validate()?;
        let identity = Identity::from_mnemonic(mnemonic, passphrase, config.network)?;
        let wallet = OnchainWallet::from_xprv(identity.master_xprv(), &config)?;
        let lightning_seed = identity.lsp_lightning_seed(config.network)?;
        let lsp_pubkey = derive_node_id_from_lightning_seed(lightning_seed)?;

        let secret = admin_secret.into();
        if secret.is_empty() {
            return Err(Error::InvalidInput(
                "admin_secret must not be empty (must match server's WICK_ADMIN_SECRET)".to_owned(),
            ));
        }
        let secret_md = MetadataValue::try_from(secret.as_str())
            .map_err(|_| Error::InvalidInput("admin_secret contains non-ASCII bytes".to_owned()))?;
        let endpoint = Endpoint::from_shared(config.server_endpoint.clone())
            .map_err(|e| Error::Config(format!("invalid server_endpoint: {e}")))?;
        let channel = endpoint.connect().await?;
        let interceptor = AdminInterceptor { secret: secret_md };
        let grpc = AdminServiceClient::with_interceptor(channel, interceptor);

        Ok(Self {
            grpc,
            wallet,
            lightning_seed,
            lsp_pubkey,
            config,
            reserve_sats: AtomicU64::new(0),
        })
    }

    /// Pin `sats` as the operator's on-chain reorg reserve. Subsequent
    /// `sign_and_finalize` calls refuse if `spendable - reserved < amount`.
    /// Idempotent — last call wins.
    pub fn set_reorg_reserve_sats(&self, sats: u64) {
        self.reserve_sats.store(sats, Ordering::SeqCst);
    }

    /// Currently-reserved sats. `effective_spendable_sat` returns
    /// `spendable_sat - reserve_sats` (saturating).
    #[must_use]
    pub fn reserve_sats(&self) -> u64 {
        self.reserve_sats.load(Ordering::SeqCst)
    }

    /// Wallet spendable balance minus the operator-pinned reserve.
    /// Returns 0 if the reserve exceeds spendable balance (i.e. the
    /// operator hasn't topped up enough to honour the reserve).
    pub fn effective_spendable_sat(&self) -> Result<u64> {
        Ok(self
            .balance_sat()?
            .saturating_sub(self.reserve_sats.load(Ordering::SeqCst)))
    }

    /// LSP node pubkey derived offline from the operator's mnemonic.
    /// Always available — does not require a network round-trip.
    #[must_use]
    pub fn lsp_pubkey(&self) -> PublicKey {
        self.lsp_pubkey
    }

    /// Hex-encoded LSP pubkey. Suitable for putting into deployment
    /// config as `[lsp].pubkey_hex`.
    #[must_use]
    pub fn lsp_pubkey_hex(&self) -> String {
        hex::encode(self.lsp_pubkey.serialize())
    }

    /// Sync the operator's on-chain wallet against Esplora. Must be
    /// called at least once after on-chain top-ups so freshly-received
    /// UTXOs become visible to [`Self::sign_and_finalize`].
    pub async fn sync_wallet(&self) -> Result<()> {
        self.wallet
            .sync(&self.config.esplora_url, &self.config)
            .await
    }

    /// Next unused BIP84 (P2WPKH) receive address. The operator pays
    /// this address from an external faucet / miner to top up funding
    /// liquidity.
    pub fn next_funding_address(&self) -> Result<Address> {
        self.wallet.next_address_p2wpkh()
    }

    /// Confirmed + trusted-pending balance across the operator wallet.
    pub fn balance_sat(&self) -> Result<u64> {
        self.wallet.spendable_sat()
    }

    /// Install the LSP's Lightning identity on the server.
    ///
    /// Idempotent: re-registering with the same seed returns the same
    /// pubkey without rebuilding the daemon. Verifies that the server
    /// agrees on the derived pubkey — a mismatch is a bug somewhere
    /// (LDK key derivation drift, bad mnemonic, or wrong server) and
    /// surfaces as [`Error::InvalidResponse`].
    pub async fn register_lsp(&mut self) -> Result<PublicKey> {
        let resp = self
            .grpc
            .register_lsp_identity(RegisterLspIdentityRequest {
                lightning_seed: self.lightning_seed.to_vec(),
            })
            .await?
            .into_inner();
        let bytes = hex::decode(&resp.lsp_pubkey_hex).map_err(|e| {
            Error::InvalidResponse(format!("RegisterLspIdentity returned invalid hex: {e}"))
        })?;
        let server_pubkey = PublicKey::from_slice(&bytes).map_err(|e| {
            Error::InvalidResponse(format!("RegisterLspIdentity returned invalid pubkey: {e}"))
        })?;
        if server_pubkey != self.lsp_pubkey {
            return Err(Error::InvalidResponse(format!(
                "server-registered pubkey {server_pubkey} does not match operator-derived pubkey \
                 {} — LDK key derivation drift?",
                self.lsp_pubkey
            )));
        }
        Ok(server_pubkey)
    }

    /// Subscribe to the LSP's parked-funding watch stream.
    ///
    /// Yields one [`PendingFundingEvent`] per JIT channel the LSP
    /// opens. The stream first replays any currently-parked entries
    /// (so an operator that crashes mid-flight catches up on restart),
    /// then yields newly-parked entries as they arrive. Lossy on
    /// subscriber lag: a `Lagged` server error surfaces as
    /// [`Error::Grpc`] with `data_loss`; recover by re-subscribing.
    pub async fn watch_pending_funding(
        &mut self,
    ) -> Result<impl tokio_stream::Stream<Item = Result<PendingFundingEvent>> + Send + 'static>
    {
        let stream = self
            .grpc
            .lsp_watch_pending_funding(LspWatchPendingFundingRequest {})
            .await?
            .into_inner();
        Ok(stream.map(|item| match item {
            Ok(msg) => PendingFundingEvent::try_from(msg),
            Err(s) => Err(Error::from(s)),
        }))
    }

    /// Sign `event.output_script` paying `event.value_sat` from the
    /// operator's BDK wallet, then call `LspFinalizeFunding`.
    ///
    /// Reuses [`OnchainWallet::build_and_sign_funding`] byte-for-byte
    /// — the same builder the SDK uses for tenant-initiated
    /// `OpenChannelFinalize`. Calls [`Self::sync_wallet`] before the
    /// build so freshly-confirmed UTXOs from operator top-ups are
    /// visible.
    pub async fn sign_and_finalize(&mut self, event: PendingFundingEvent) -> Result<()> {
        self.sync_wallet().await?;

        // Operator-side reorg reserve gate: refuse to consume reserve
        // sats for a JIT funding tx. The server-side reorg-reserve
        // guard (`LspConfig::reorg_safety_threshold_sats`) caps total
        // unconfirmed JIT exposure; this enforces the matching
        // on-chain invariant on the operator's wallet so a chain reorg
        // that drops a 0-conf JIT funding tx still leaves the operator
        // with sats to refund the tenant.
        let reserve = self.reserve_sats.load(Ordering::SeqCst);
        if reserve > 0 {
            let spendable = self.balance_sat()?;
            if spendable.saturating_sub(reserve) < event.value_sat {
                return Err(Error::Wallet(format!(
                    "operator reorg reserve gate: requested {value_sat} sat but \
                     spendable {spendable} sat - reserve {reserve} sat = \
                     {effective} sat",
                    value_sat = event.value_sat,
                    effective = spendable.saturating_sub(reserve),
                )));
            }
        }

        let signed = self
            .wallet
            .build_and_sign_funding(event.output_script.clone(), event.value_sat)?;
        self.finalize_funding(&event, signed).await
    }

    /// Hand a fully-signed funding tx back to the server.
    ///
    /// Use [`Self::sign_and_finalize`] for the common path; this
    /// raw method exists so callers can plug in a custom signer (e.g.
    /// a test that pre-signs with a mock wallet).
    pub async fn finalize_funding(
        &mut self,
        event: &PendingFundingEvent,
        funding_tx: Transaction,
    ) -> Result<()> {
        let tx_hex = hex::encode(bitcoin::consensus::serialize(&funding_tx));
        self.grpc
            .lsp_finalize_funding(LspFinalizeFundingRequest {
                temp_channel_id: event.temp_channel_id.to_vec(),
                counterparty_pubkey_hex: hex::encode(event.counterparty.serialize()),
                funding_tx_hex: tx_hex,
            })
            .await?;
        Ok(())
    }
}

/// Run the funding loop until the watch stream ends. For each parked
/// event, sync the wallet, sign from BDK, and finalize. Stops on the
/// first error or when the stream completes.
///
/// Convenience wrapper around the public methods — operators that need
/// custom retry policies should drive the loop themselves using
/// [`OperatorClient::watch_pending_funding`] and
/// [`OperatorClient::sign_and_finalize`].
pub async fn run_funding_loop(client: &mut OperatorClient) -> Result<()> {
    let mut stream = Box::pin(client.watch_pending_funding().await?);
    while let Some(item) = stream.next().await {
        let event = item?;
        client.sign_and_finalize(event).await?;
    }
    Ok(())
}

/// Compute the LSP node pubkey from a BIP39 mnemonic without dialing
/// the server. Same derivation [`OperatorClient::new`] performs
/// internally — exposed as a free function so deployment scripts can
/// fill `[lsp].pubkey_hex` in their server config before the server
/// is even started, then bring up `wick-server` and finally have the
/// operator's `OperatorClient::register_lsp()` install the matching
/// signing seed.
///
/// Phase 4: this becomes a thin wrapper that asks the remote signer
/// for its pubkey rather than computing locally.
pub fn compute_operator_lsp_pubkey(
    mnemonic: &str,
    passphrase: Option<&str>,
    network: WickNetwork,
) -> Result<PublicKey> {
    let identity = Identity::from_mnemonic(mnemonic, passphrase, network)?;
    let lightning_seed = identity.lsp_lightning_seed(network)?;
    derive_node_id_from_lightning_seed(lightning_seed)
}

/// Replicate the `node_id` derivation `wick_lightning::from_seed`
/// performs server-side via LDK's `KeysManager::new`.
///
/// LDK 0.2's `KeysManager::new` (lightning-0.2.2 src/sign/mod.rs:2018-2026)
/// builds the node id like:
///
/// ```ignore
/// let master = Xpriv::new_master(Network::Testnet, seed)?;
/// let node_secret = master.derive_priv(&secp, &ChildNumber::Hardened{index:0})?.private_key;
/// let node_id = PublicKey::from_secret_key(&secp, &node_secret);
/// ```
///
/// `Network::Testnet` is hard-coded inside LDK — the comment notes
/// "when we aren't serializing the key, network doesn't matter".
/// Replicated faithfully here so the SDK and server agree without
/// pulling LDK into wick-sdk.
fn derive_node_id_from_lightning_seed(seed: [u8; 32]) -> Result<PublicKey> {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Testnet, &seed)
        .map_err(|e| Error::Identity(format!("derive lsp master xpriv: {e}")))?;
    let node_secret = master
        .derive_priv(&secp, &ChildNumber::Hardened { index: 0 })
        .map_err(|e| Error::Identity(format!("derive lsp node_secret: {e}")))?
        .private_key;
    Ok(PublicKey::from_secret_key(&secp, &node_secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock in that the SDK's offline derivation matches LDK's
    /// `KeysManager::new(...).get_node_id(Recipient::Node)` exactly.
    /// Uses the real `wick_lightning::from_seed` (a dev-dependency)
    /// to construct the server-side signer and compare pubkeys.
    #[test]
    fn lsp_pubkey_derivation_matches_wick_lightning_from_seed() {
        // Random-looking but deterministic seed for the test.
        let seed = [
            0x42, 0x73, 0x9c, 0xab, 0x10, 0xf1, 0x88, 0x3a, 0x90, 0x71, 0xee, 0x55, 0x14, 0xc3,
            0x42, 0x99, 0x77, 0xb6, 0xfd, 0xee, 0x21, 0x09, 0x65, 0x84, 0x2c, 0x12, 0xa4, 0xb3,
            0x33, 0x07, 0x86, 0xf0,
        ];
        let sdk_pubkey = derive_node_id_from_lightning_seed(seed).expect("sdk derivation");

        let ldk_signer = wick_lightning::from_seed(seed);
        let ldk_pubkey =
            lightning::sign::NodeSigner::get_node_id(&ldk_signer, lightning::sign::Recipient::Node)
                .expect("ldk get_node_id");

        assert_eq!(
            sdk_pubkey, ldk_pubkey,
            "SDK offline derivation must agree with wick_lightning::from_seed"
        );
    }
}

impl TryFrom<wick_proto::wick::LspPendingFunding> for PendingFundingEvent {
    type Error = Error;

    fn try_from(msg: wick_proto::wick::LspPendingFunding) -> Result<Self> {
        if msg.temp_channel_id.len() != 32 {
            return Err(Error::InvalidResponse(format!(
                "LspPendingFunding.temp_channel_id must be 32 bytes, got {}",
                msg.temp_channel_id.len()
            )));
        }
        let mut temp_channel_id = [0u8; 32];
        temp_channel_id.copy_from_slice(&msg.temp_channel_id);
        let counterparty_bytes = hex::decode(&msg.counterparty_pubkey_hex)
            .map_err(|e| Error::InvalidResponse(format!("invalid counterparty_pubkey_hex: {e}")))?;
        let counterparty = PublicKey::from_slice(&counterparty_bytes).map_err(|e| {
            Error::InvalidResponse(format!("invalid counterparty pubkey bytes: {e}"))
        })?;
        let script_bytes = hex::decode(&msg.output_script_hex)
            .map_err(|e| Error::InvalidResponse(format!("invalid output_script_hex: {e}")))?;
        let output_script = ScriptBuf::from_bytes(script_bytes);
        Ok(Self {
            temp_channel_id,
            counterparty,
            value_sat: msg.value_sat,
            output_script,
        })
    }
}
