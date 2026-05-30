//! End-to-end SDK integration test for **LSPS2 JIT channels** with
//! self-custodial operator funding.
//!
//! Three in-process roles:
//!
//! 1. **Operator** — runs [`wick_sdk::OperatorClient`]. Registers the
//!    LSP's Lightning identity at runtime via the admin gRPC, owns the
//!    BDK wallet that signs JIT-channel funding txs, and runs the
//!    [`wick_sdk::run_funding_loop`] in a background task. No on-chain
//!    seed lives on the server — the LSP node has no `FundingSource`
//!    bound; every `FundingGenerationReady` parks in the existing
//!    `PendingFundingRegistry` and the operator drains it.
//! 2. **Alice** — JIT-receiver tenant (`WickClient`). Issues a JIT
//!    BOLT11 invoice with the LSP's intercept SCID embedded as a
//!    private route hint; she has no real channel before payment lands.
//! 3. **Bob** — payer tenant (`WickClient`). Funds his BDK wallet,
//!    opens a real channel to the LSP for outbound liquidity, then
//!    pays Alice's JIT invoice. The HTLC routes Bob → LSP →
//!    intercept-SCID; LSP fires `LSPS2ServiceEvent::OpenChannel`; the
//!    dispatcher wakes Alice; LSP creates the JIT channel; the
//!    operator funding loop signs + finalizes; Alice's tenant accepts
//!    0-conf via `accept_inbound_channel_from_trusted_peer_0conf`;
//!    payment settles.
//!
//! Asserts:
//!
//! - `GetLspInfo` flips `ready=true` only after `RegisterLspIdentity`.
//! - The JIT invoice carries the right route-hint shape.
//! - Alice's `transactions()` shows an inbound `Succeeded` row whose
//!   amount is `invoice − jit_fee_msat_quote`.
//!
//! ## Prerequisites
//!
//! ```sh
//! just regtest-up                # bitcoind + postgres + electrs
//! cargo test -p wick-sdk \
//!     --test jit_flow \
//!     --features regtest \
//!     -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::TcpStream;
use std::process::{Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use lightning_invoice::Bolt11Invoice;
use wick_sdk::regtest::{wait_until_async, RegtestRpc};
use wick_sdk::{
    compute_operator_lsp_pubkey, run_funding_loop, OperatorClient, PaymentStatus, WickClient,
    WickConfig, WickNetwork,
};

// ── Fixed BIP39 test vectors ──────────────────────────────────────────────────
//
// All three are well-known dev-only mnemonics. Never hold real funds.

/// JIT-receiver tenant.
const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Payer tenant. Distinct mnemonic so Alice and Bob have distinct
/// Lightning identities — same fixture used by `regtest_flow.rs`.
const BOB_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// Operator mnemonic. Drives both the on-chain BDK wallet that signs
/// JIT funding txs *and* the LSP's Lightning identity (a domain-
/// separated 32-byte derivation off the same xpriv — see
/// `Identity::lsp_lightning_seed`). Never reused by any tenant.
const OPERATOR_MNEMONIC: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

/// Shared admin secret. Operator passes it via gRPC metadata; server
/// reads it from `WICK_ADMIN_SECRET` env var. Slice 3.3a auth gate.
const ADMIN_SECRET: &str = "jit-flow-test-secret";

/// JIT payment size we'll quote for. 50 000 sats — comfortably above
/// LDK's default channel-reserve floor and within the LSP's default
/// `max_payment_size_msat` of 100M sats.
const JIT_AMOUNT_MSAT: u64 = 50_000_000;

/// Outbound channel Bob opens to the LSP so he has liquidity to pay
/// Alice's JIT invoice. 200k sats — 4× the JIT amount, enough to clear
/// reserve + commit fee.
const BOB_CHANNEL_VALUE_SAT: u64 = 200_000;

/// On-chain coinbase the regtest miner sends to Bob's BDK address.
/// 5× the channel size so a single funding tx + change fits cleanly.
const BOB_FUNDING_SAT: u64 = 1_000_000;

/// On-chain coinbase the regtest miner sends to the operator's BDK
/// address. Has to cover the JIT channel capacity (the LSP opens a
/// channel of `JIT_AMOUNT_MSAT / 1000` sats + 5% over-provisioning)
/// plus fees. 1M sats is generous.
const OPERATOR_FUNDING_SAT: u64 = 1_000_000;

/// gRPC dial timeout for the spawned server. `cargo run` with a cold
/// build cache can take a while.
const SERVER_BOOT_TIMEOUT: Duration = Duration::from_secs(180);

/// Lightning + on-chain operation timeouts. Regtest is fast but LDK's
/// event loop + electrs indexer add latency.
const LN_POLL_TIMEOUT: Duration = Duration::from_secs(30);
const ONCHAIN_SYNC_TIMEOUT: Duration = Duration::from_secs(30);

/// Toggle once slice 3.3a's full pipeline lands. With this `true` the
/// test is the load-bearing assertion that JIT settlement works
/// end-to-end with the operator's SDK signing every funding tx and no
/// seed on the server.
const ASSERT_JIT_FULLY_SETTLED: bool = true;

// ── Server subprocess ────────────────────────────────────────────────────────

struct HostedServer {
    child: std::process::Child,
    endpoint: String,
}

impl HostedServer {
    /// Spawn `wick-server` against `config.regtest.toml` with the
    /// operator's *public* LSP pubkey baked in via env override and
    /// the admin shared secret available so `RegisterLspIdentity` can
    /// authenticate. Crucially: **no LSP mnemonic / seed is ever
    /// passed** — the operator's SDK installs the signing seed at
    /// runtime via the admin gRPC.
    fn spawn(lsp_pubkey_hex: &str) -> Self {
        let workspace_root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
        let config_path = format!("{workspace_root}/deploy/docker/config.regtest.toml");

        let child = StdCommand::new("cargo")
            .current_dir(&workspace_root)
            .args([
                "run",
                "--quiet",
                "--bin",
                "wick-server",
                "--",
                "--config",
                &config_path,
            ])
            .env("WICK_LSP__ENABLED", "true")
            .env("WICK_LSP__LISTEN_ADDR", "127.0.0.1:19836")
            .env("WICK_LSP__PUBKEY_HEX", lsp_pubkey_hex)
            .env("WICK_ADMIN_SECRET", ADMIN_SECRET)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn wick-server via cargo run");

        let endpoint = "http://127.0.0.1:50051".to_owned();
        let deadline = Instant::now() + SERVER_BOOT_TIMEOUT;
        loop {
            if TcpStream::connect("127.0.0.1:50051").is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                panic!("wick-server did not bind :50051 within {SERVER_BOOT_TIMEOUT:?}");
            }
            std::thread::sleep(Duration::from_millis(250));
        }

        Self { child, endpoint }
    }
}

impl Drop for HostedServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Mint an admin macaroon by shelling out to the wick-server
/// `mint-admin-macaroon` subcommand against the regtest config. Admin
/// auth migrated from the deprecated `WICK_ADMIN_SECRET` shared secret to
/// minted macaroons; the operator passes the bytes via
/// [`OperatorClient::with_admin_macaroon`].
fn mint_admin_macaroon_for_regtest() -> Vec<u8> {
    let workspace_root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    let config_path = format!("{workspace_root}/deploy/docker/config.regtest.toml");
    let output = StdCommand::new("cargo")
        .current_dir(&workspace_root)
        .args([
            "run",
            "--quiet",
            "--bin",
            "wick-server",
            "--",
            "mint-admin-macaroon",
            "--config",
            &config_path,
        ])
        .output()
        .expect("spawn `wick-server mint-admin-macaroon`");
    if !output.status.success() {
        panic!(
            "mint-admin-macaroon failed (exit {:?}):\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let hex_line = stdout
        .lines()
        .find_map(|line| line.strip_prefix("admin_macaroon_hex="))
        .expect("`admin_macaroon_hex=…` line in mint-admin-macaroon stdout");
    hex::decode(hex_line.trim()).expect("admin macaroon hex decodes")
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual; spawns wick-server via `cargo run` and requires `just regtest-up`"]
async fn jit_invoice_carries_lsp_route_hint() {
    let network = WickNetwork::Regtest;

    // Pre-derive the LSP pubkey from the operator's mnemonic — same
    // derivation `wick_lightning::from_seed` performs server-side, but
    // computed offline in the SDK. Locked in by the parity unit test
    // in `wick_sdk::operator::tests`.
    let lsp_pubkey = compute_operator_lsp_pubkey(OPERATOR_MNEMONIC, None, network)
        .expect("compute_operator_lsp_pubkey");
    let lsp_pubkey_hex = hex::encode(lsp_pubkey.serialize());
    println!("operator-derived LSP pubkey: {lsp_pubkey_hex}");

    let server = HostedServer::spawn(&lsp_pubkey_hex);

    // Regtest chain controller (bitcoind RPC).
    let rpc =
        RegtestRpc::connect("http://127.0.0.1:18443", "wick", "wick").expect("RegtestRpc::connect");

    let config = || {
        let mut cfg = WickConfig::for_network(network);
        cfg.server_endpoint = server.endpoint.clone();
        cfg.esplora_url = "http://127.0.0.1:3002".to_owned();
        cfg
    };

    // ── 1. Operator: register LSP identity + start funding loop ───────────

    // Admin auth is macaroon-based (WICK_ADMIN_SECRET is deprecated/ignored).
    let admin_macaroon = mint_admin_macaroon_for_regtest();

    let mut operator =
        OperatorClient::with_admin_macaroon(OPERATOR_MNEMONIC, None, admin_macaroon.clone(), config())
            .await
            .expect("OperatorClient::with_admin_macaroon");
    assert_eq!(
        operator.lsp_pubkey(),
        lsp_pubkey,
        "OperatorClient must derive the same pubkey as the offline helper"
    );

    let registered = operator.register_lsp().await.expect("register_lsp");
    assert_eq!(
        registered, lsp_pubkey,
        "server must agree on the LSP pubkey"
    );
    println!("registered lsp identity; pubkey={lsp_pubkey_hex}");

    // Mine coinbase to the operator's BDK funding address so the
    // background loop has UTXOs to spend when the LSP fires
    // FundingGenerationReady. 101 blocks for coinbase maturity, then
    // send to the operator address, then mine 1 confirmation.
    let operator_addr = operator
        .next_funding_address()
        .expect("operator funding addr");
    rpc.mine(101).expect("mine coinbase maturation");
    rpc.send_to_address(&operator_addr, OPERATOR_FUNDING_SAT)
        .expect("send_to_address(operator)");
    rpc.mine(1).expect("mine operator funding conf");
    tokio::time::sleep(Duration::from_secs(2)).await;
    operator.sync_wallet().await.expect("operator sync_wallet");
    let opbal = operator.balance_sat().expect("operator balance");
    assert!(
        opbal >= OPERATOR_FUNDING_SAT - 10_000,
        "operator wallet must show the regtest top-up; got {opbal}"
    );
    println!("operator wallet ready: balance={opbal} sat, addr={operator_addr}");

    // Spawn the funding loop on a background tokio task. From this
    // point every parked LSP funding request gets signed + finalized
    // via the operator's BDK wallet. Important: the loop owns
    // `operator` for its lifetime — in the test we rebuild a separate
    // OperatorClient handle for the loop.
    let mut funding_operator = OperatorClient::with_admin_macaroon(
        OPERATOR_MNEMONIC,
        None,
        admin_macaroon.clone(),
        config(),
    )
    .await
    .expect("OperatorClient::with_admin_macaroon (funding loop)");
    funding_operator
        .sync_wallet()
        .await
        .expect("funding loop sync_wallet");
    let funding_handle = tokio::spawn(async move {
        // `run_funding_loop` returns Ok when the watch stream ends
        // (server shutdown) or the first error. For the test we don't
        // care about the outcome; the spawn just keeps the loop alive.
        if let Err(e) = run_funding_loop(&mut funding_operator).await {
            eprintln!("operator funding loop ended with error: {e}");
        }
    });

    // Give the funding loop a beat to subscribe to the watch stream
    // before we trigger the first JIT open.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ── 2. Alice: register tenant + connect to LSP ────────────────────────

    let alice = WickClient::new(ALICE_MNEMONIC, None, config())
        .await
        .expect("WickClient::new for Alice");
    alice.register("standard").await.expect("Alice register");

    // GetLspInfo should now report ready=true (the slot is occupied).
    let lsp_info = alice.lsp_info().await.expect("lsp_info");
    let lsp_pubkey_from_info = lsp_info
        .pubkey
        .expect("lsp must be enabled and registered in this test config");
    assert_eq!(lsp_pubkey_from_info, lsp_pubkey);
    assert!(
        lsp_info.ready,
        "GetLspInfo.ready must flip true after RegisterLspIdentity"
    );

    let parts: Vec<&str> = lsp_info.address.rsplitn(2, ':').collect();
    let (lsp_host, lsp_port) = match parts.as_slice() {
        [port_str, host] => (
            (*host).to_owned(),
            port_str.parse::<u16>().expect("lsp port parses"),
        ),
        _ => panic!("malformed lsp_info.address: {}", lsp_info.address),
    };
    alice
        .connect_peer(lsp_pubkey, &lsp_host, lsp_port)
        .await
        .expect("Alice connect_peer to LSP");

    // ── 3. Bob: register tenant + fund BDK + open channel to LSP ──────────

    let bob = WickClient::new(BOB_MNEMONIC, None, config())
        .await
        .expect("WickClient::new for Bob");
    bob.register("standard").await.expect("Bob register");

    let bob_addr = bob.next_address_p2wpkh().expect("bob client addr");
    rpc.send_to_address(&bob_addr, BOB_FUNDING_SAT)
        .expect("send_to_address(bob)");
    rpc.mine(1).expect("mine bob funding conf");
    tokio::time::sleep(Duration::from_secs(2)).await;
    wait_until_async(
        "bob client-side BDK sees funding UTXO",
        ONCHAIN_SYNC_TIMEOUT,
        || {
            let b = bob.clone();
            async move {
                if b.sync_onchain().await.is_err() {
                    return false;
                }
                b.onchain_spendable_sat()
                    .map(|s| s >= BOB_FUNDING_SAT - 10_000)
                    .unwrap_or(false)
            }
        },
    )
    .await;

    bob.connect_peer(lsp_pubkey, &lsp_host, lsp_port)
        .await
        .expect("Bob connect_peer to LSP");
    bob.open_channel(lsp_pubkey, BOB_CHANNEL_VALUE_SAT, 0)
        .await
        .expect("Bob open_channel to LSP");
    rpc.wait_for_mempool_size(1, Duration::from_secs(10))
        .await
        .expect("Bob's funding tx in mempool");
    rpc.mine(10).expect("mine Bob channel confs");

    wait_until_async("Bob's channel to LSP is routable", LN_POLL_TIMEOUT, || {
        let b = bob.clone();
        async move {
            b.list_channels()
                .await
                .map(|chs| {
                    chs.iter()
                        .any(|c| c.is_usable && c.outbound_capacity_msat >= JIT_AMOUNT_MSAT)
                })
                .unwrap_or(false)
        }
    })
    .await;

    // ── 4. Alice: lsps2.get_info + receive_payment_jit ───────────────────

    let quote = alice
        .lsps2_get_info(Some(JIT_AMOUNT_MSAT))
        .await
        .expect("lsps2_get_info");
    assert_eq!(quote.lsp_pubkey, lsp_pubkey);
    assert!(quote.min_fee_msat > 0);
    assert!(quote.proportional_ppm > 0);
    assert!(JIT_AMOUNT_MSAT >= quote.min_payment_size_msat);
    assert!(JIT_AMOUNT_MSAT <= quote.max_payment_size_msat);

    let invoice = alice
        .receive_payment_jit(JIT_AMOUNT_MSAT, "wick jit integration test")
        .await
        .expect("receive_payment_jit");
    assert_eq!(invoice.lsp_pubkey, lsp_pubkey);
    assert_eq!(invoice.payment_hash.len(), 32);
    assert!(invoice.jit_fee_msat_quote >= quote.min_fee_msat);

    // Decode the BOLT11 and verify the route-hint shape — this is the
    // assertion the slice-3.2 version of this test stopped at.
    let parsed: Bolt11Invoice = invoice.bolt11.parse().expect("BOLT11 must decode");
    let routes = parsed.private_routes();
    let route = routes
        .first()
        .expect("invoice must carry exactly one private route hint");
    let hop = route
        .0
        .first()
        .cloned()
        .expect("private route must contain at least one hop");
    assert_eq!(
        hop.src_node_id, lsp_pubkey,
        "route hint src_node_id must be the LSP"
    );
    assert!(
        hop.short_channel_id != 0,
        "route hint must carry a non-zero intercept SCID"
    );
    assert_eq!(hop.fees.base_msat, 0);
    assert_eq!(hop.fees.proportional_millionths, 0);
    assert!(hop.htlc_maximum_msat.is_none());
    assert_eq!(
        u64::from(parsed.min_final_cltv_expiry_delta()),
        u64::from(lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA + 2),
        "min_final_cltv_expiry_delta must satisfy LSPS2 +2 rule"
    );
    println!(
        "jit invoice: bolt11={} (route hint scid={} cltv_delta={}); jit_fee_quote={}",
        invoice.bolt11, hop.short_channel_id, hop.cltv_expiry_delta, invoice.jit_fee_msat_quote
    );

    // ── 5. Optional: full payment settlement ─────────────────────────────

    if !ASSERT_JIT_FULLY_SETTLED {
        drop(server);
        funding_handle.abort();
        return;
    }

    // Bob pays Alice's JIT invoice. The HTLC routes Bob → LSP, hits
    // the intercept SCID, the LSP fires `LSPS2ServiceEvent::OpenChannel`,
    // dispatcher wakes Alice, LSP `create_channel(...)` →
    // `FundingGenerationReady` parks → operator's funding loop signs
    // + finalizes → Alice's `OpenChannelRequest` accepts 0-conf →
    // channel opens → HTLC settles inbound on Alice.
    // LDK's router can return `RouteNotFound` on the first attempt while the
    // freshly-bought intercept SCID / Bob's just-usable channel settle into
    // the router's view. Retry briefly with a block nudge — same pattern the
    // mutinynet harness uses. Each attempt is cheap (sync graph lookup).
    let send = {
        let mut last_err: Option<wick_sdk::Error> = None;
        let mut paid = None;
        for attempt in 0..5 {
            if attempt > 0 {
                let _ = rpc.mine(1);
                tokio::time::sleep(Duration::from_millis(750)).await;
            }
            match bob.send_payment(&invoice.bolt11).await {
                Ok(p) => {
                    paid = Some(p);
                    break;
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("RouteNotFound") {
                        println!("  Bob send_payment attempt {} RouteNotFound — retrying", attempt + 1);
                        last_err = Some(e);
                        continue;
                    }
                    panic!("Bob send_payment (non-RouteNotFound): {e}");
                }
            }
        }
        paid.unwrap_or_else(|| {
            panic!(
                "Bob send_payment failed after 5 attempts; last: {}",
                last_err.map(|e| format!("{e}")).unwrap_or_default()
            )
        })
    };
    assert_eq!(send.payment_hash, invoice.payment_hash);

    // Mine a couple of blocks while we wait — the JIT funding tx
    // broadcast by the operator goes to the mempool; LDK's chain
    // monitor needs to see it confirm before the channel marks
    // ChannelReady on Bob's side (Alice already accepts 0-conf).
    let payment_deadline = Instant::now() + Duration::from_secs(60);
    let hash_hex = hex::encode(invoice.payment_hash);
    loop {
        if Instant::now() >= payment_deadline {
            panic!(
                "JIT settlement did not complete within 60s — operator funding loop or \
                 LDK pipeline stalled"
            );
        }

        // Mine a confirmation block every iteration to push pending
        // funding through. Idempotent on already-mined chains.
        let _ = rpc.mine(1);

        // Look for Alice's inbound `Succeeded` row.
        if let Ok(rows) = alice.transactions(20, None).await {
            if let Some(p) = rows.iter().find(|p| {
                hex::encode(p.payment_hash) == hash_hex
                    && !p.is_outbound
                    && p.status == PaymentStatus::Succeeded
            }) {
                let net = JIT_AMOUNT_MSAT.saturating_sub(invoice.jit_fee_msat_quote);
                // Allow a small fudge for rounding in fee deduction.
                let delta = p.amount_msat.abs_diff(net);
                assert!(
                    delta <= 1_000,
                    "alice's settled inbound amount ({} msat) should be approximately invoice − \
                     jit_fee_quote ({net} msat); delta {delta} msat",
                    p.amount_msat
                );
                println!(
                    "alice settled inbound: amount_msat={} (expected ~{net}, jit_fee={})",
                    p.amount_msat, invoice.jit_fee_msat_quote
                );
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    funding_handle.abort();
    drop(server);
}
