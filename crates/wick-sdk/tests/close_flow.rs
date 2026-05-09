//! End-to-end mutual-close test against a real, out-of-process
//! `wick-server` binary.
//!
//! Mirrors `regtest_flow.rs` for the boilerplate (HostedServer + BIP39
//! test vectors + RegtestRpc), then drives a cooperative close through
//! the full pipeline:
//!
//!   `WickClient::close_channel` → gRPC → `NodeCmd::CloseChannel` →
//!   `Node::close_channel` → LDK `ChannelManager::close_channel` → VLS
//!   signing of the closing tx → broadcast → confirmation → channel
//!   removal from the LDK `list_channels` snapshot.
//!
//! ## Phase-4 refund destination
//!
//! Phase 4 routes the on-chain refund to the *client-side* BDK wallet
//! (Alice's `next_address_p2wpkh()` / `onchain_spendable_sat`). The
//! `wick-lightning` builder wires the background `OutputSweeperSync`'s
//! change destination to a `VlsChangeDestination` that asks the SDK for
//! a fresh BIP84 change address per sweep via the `0xFD05` v2 extension
//! RPC, so closes drop the refund directly onto the user's on-device
//! wallet — the assertion below requires it.
//!
//! ## Prerequisites
//!
//! ```sh
//! just regtest-up
//! cargo test -p wick-sdk --test close_flow --features regtest -- --ignored --nocapture
//! ```
//!
//! The test spawns its own `wick-server` binary via `cargo run --bin
//! wick-server`, so no external server is required.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::TcpStream;
use std::process::{Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use wick_sdk::regtest::{wait_until_async, RegtestRpc};
use wick_sdk::{WickClient, WickConfig, WickNetwork};

// ── Fixed BIP39 test vectors ──────────────────────────────────────────────────
//
// Same vectors as `regtest_flow.rs`. Well-known and safe to commit.

const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// Channel size Alice opens. 200k sats — same as the regtest_flow test
/// so the funding-tx / on-chain math is consistent.
const CHANNEL_VALUE_SAT: u64 = 200_000;

/// Coinbase transfer to Alice's client-side BDK wallet so she has UTXOs
/// to fund the channel. 1M sats is 5× channel value — plenty of slack.
const FUNDING_TRANSFER_SAT: u64 = 1_000_000;

const LN_POLL_TIMEOUT: Duration = Duration::from_secs(30);
const ONCHAIN_SYNC_TIMEOUT: Duration = Duration::from_secs(30);

// ── Server subprocess ─────────────────────────────────────────────────────────

struct HostedServer {
    child: std::process::Child,
}

impl HostedServer {
    fn spawn() -> Self {
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
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn wick-server via cargo run");

        // `config.regtest.toml` binds :50051.
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if TcpStream::connect("127.0.0.1:50051").is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                panic!("wick-server did not bind :50051 within 120s");
            }
            std::thread::sleep(Duration::from_millis(250));
        }

        Self { child }
    }

    fn endpoint(&self) -> &str {
        "http://127.0.0.1:50051"
    }
}

impl Drop for HostedServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── The test ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires just regtest-up + compiled wick-server binary"]
async fn mutual_close_routes_refund_to_client_wallet() {
    let server = HostedServer::spawn();

    let rpc =
        RegtestRpc::connect("http://127.0.0.1:18443", "wick", "wick").expect("RegtestRpc::connect");

    let config = || {
        let mut cfg = WickConfig::for_network(WickNetwork::Regtest);
        cfg.server_endpoint = server.endpoint().to_owned();
        cfg.esplora_url = "http://127.0.0.1:3002".to_owned();
        cfg
    };

    let alice = WickClient::new(ALICE_MNEMONIC, None, config())
        .await
        .expect("alice WickClient::new");
    let bob = WickClient::new(BOB_MNEMONIC, None, config())
        .await
        .expect("bob WickClient::new");

    alice.register("free").await.expect("alice register");
    bob.register("free").await.expect("bob register");

    // Fund Alice's client-side BDK wallet via bitcoind.
    let alice_client_addr = alice.next_address_p2wpkh().expect("alice client addr");
    rpc.mine(101).expect("mine coinbase maturation");
    rpc.send_to_address(&alice_client_addr, FUNDING_TRANSFER_SAT)
        .expect("send_to_address");
    rpc.mine(1).expect("mine funding conf");

    tokio::time::sleep(Duration::from_secs(2)).await;
    wait_until_async(
        "alice client-side BDK sees funding UTXO",
        ONCHAIN_SYNC_TIMEOUT,
        || {
            let a = alice.clone();
            async move {
                if a.sync_onchain().await.is_err() {
                    return false;
                }
                a.onchain_spendable_sat()
                    .map(|s| s >= FUNDING_TRANSFER_SAT - 10_000)
                    .unwrap_or(false)
            }
        },
    )
    .await;

    // Discover Bob's listen address (rewrite 0.0.0.0 → 127.0.0.1 for
    // dial-ability) and connect Alice → Bob.
    let bob_info = bob.node_info().await.expect("bob node_info");
    let dial_host = match bob_info.host.as_str() {
        "0.0.0.0" | "" => "127.0.0.1".to_owned(),
        other => other.to_owned(),
    };
    alice
        .connect_peer(bob_info.pubkey, &dial_host, bob_info.port)
        .await
        .expect("alice connect_peer");

    // Alice opens a channel to Bob.
    alice
        .open_channel(bob_info.pubkey, CHANNEL_VALUE_SAT, 0)
        .await
        .expect("alice open_channel");

    rpc.wait_for_mempool_size(1, Duration::from_secs(10))
        .await
        .expect("funding tx in mempool");
    rpc.mine(10).expect("mine funding confs");

    // Wait for the channel to become usable.
    wait_until_async("channel is_usable", LN_POLL_TIMEOUT, || {
        let a = alice.clone();
        async move {
            a.list_channels()
                .await
                .map(|chs| chs.iter().any(|c| c.is_usable))
                .unwrap_or(false)
        }
    })
    .await;

    // Snapshot the channel id we're about to close.
    let channels = alice.list_channels().await.expect("list_channels");
    let chan = channels
        .iter()
        .find(|c| c.is_usable)
        .expect("alice has at least one usable channel");
    let channel_id = chan.channel_id;

    // ── Cooperative close ─────────────────────────────────────────────────
    //
    // This drives the full Phase-4 path: gRPC → NodeCmd::CloseChannel
    // → LDK ChannelManager::close_channel → closing-tx signing through
    // VLS → broadcast.
    alice
        .close_channel(channel_id, bob_info.pubkey)
        .await
        .expect("alice close_channel");

    // Closing tx hits the mempool, then we mine confirmations.
    rpc.wait_for_mempool_size(1, Duration::from_secs(30))
        .await
        .expect("close tx in mempool");
    rpc.mine(10).expect("mine close confs");

    // Channel should drop off Alice's snapshot once LDK acks the
    // confirmed closing tx.
    wait_until_async("channel removed from list", LN_POLL_TIMEOUT, || {
        let a = alice.clone();
        async move {
            a.list_channels()
                .await
                .map(|chs| chs.iter().all(|c| c.channel_id != channel_id))
                .unwrap_or(false)
        }
    })
    .await;

    // ── Phase-4 promise: refund to client-side BDK ────────────────────────
    //
    // The refund must land on Alice's client-side BDK wallet via the
    // `VlsChangeDestination` route (`0xFD05` v2). After a coop close of
    // a 200k-sat channel funded from a 1M-sat wallet, ignoring fees,
    // Alice should recover most of the original 1M minus mining fees —
    // require ≥ `FUNDING_TRANSFER_SAT - CHANNEL_VALUE_SAT - 50_000`
    // (i.e. she funded a 200k channel, the close refunded it, fees
    // bounded at ~50k sats end-to-end).
    alice.sync_onchain().await.expect("alice sync_onchain");
    let client_onchain = alice.onchain_spendable_sat().expect("alice onchain_spendable_sat");
    let server_onchain = alice
        .lightning_balance()
        .await
        .expect("alice lightning_balance")
        .onchain_sats;

    eprintln!(
        "mutual_close: client_onchain={client_onchain} server_onchain={server_onchain}"
    );

    assert!(
        client_onchain > FUNDING_TRANSFER_SAT - CHANNEL_VALUE_SAT - 50_000,
        "refund did not land on client-side BDK after VLS close: \
         client_onchain={client_onchain} server_onchain={server_onchain}"
    );

    let _ = server; // keep alive until end; Drop kills the subprocess
}
