//! End-to-end SDK integration test against a real, out-of-process
//! `wick-server` binary.
//!
//! Everything tenant-facing goes through [`wick_sdk::WickClient`] over
//! gRPC against a subprocess server — no in-process server types.
//!
//! The test still needs to control the regtest chain (mine blocks, send
//! coinbase to a server-side funding address). That lives in
//! [`wick_sdk::regtest::RegtestRpc`], gated on the `regtest` cargo feature.
//!
//! ## Prerequisites
//!
//! ```sh
//! just regtest-up   # docker stack: bitcoind + postgres + electrs
//! cargo test -p wick-sdk --test full_flow --features regtest -- --ignored --nocapture
//! ```
//!
//! The test spawns its own `wick-server` binary via
//! `env!("CARGO_BIN_EXE_wick-server")` so no external server is required.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::TcpStream;
use std::process::{Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::PublicKey;
use wick_core::TenantId;
use wick_sdk::regtest::{wait_until_async, RegtestRpc};
use wick_sdk::{
    CredentialKind, Error as SdkError, PaymentStatus, WickClient, WickConfig, WickNetwork,
};

// ── Fixed BIP39 test vectors ──────────────────────────────────────────────────
//
// These are the standard BIP39 test vectors. They are well-known and safe
// to commit; never hold real mainnet funds on them.

const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// Amount paid from Alice → Bob. 10_000 sats — above the 2_000-sat channel
/// reserve so Bob's `lightning_balance().lightning_msat` visibly grows.
const PAYMENT_AMOUNT_MSAT: u64 = 10_000_000;

/// Round 3 follow-up payment after the server is killed and restarted.
/// 5_000 sats — half of Round 1 — confirms the channel + signer rejoin
/// path works for a second HTLC without re-funding.
const SECOND_PAYMENT_MSAT: u64 = 5_000_000;

/// Phase 4 acceptance budget: revocation must propagate from the
/// `revoked_macaroons` INSERT to the in-memory `RevocationSet` (via
/// LISTEN/NOTIFY) and reject the next Alice RPC within this window.
const REVOKE_REJECT_DEADLINE: Duration = Duration::from_secs(1);

/// Channel size Alice opens. 200k sats — enough headroom for the payment
/// plus reserve + commit-fee reservation.
const CHANNEL_VALUE_SAT: u64 = 200_000;

/// Coinbase transfer to Alice's server-side wallet so she has UTXOs to
/// fund a channel. 1M sats is 5× the channel value — plenty of headroom.
const FUNDING_TRANSFER_SAT: u64 = 1_000_000;

/// Integer Lightning + on-chain timeouts. Regtest is fast, but LDK's
/// event loop and electrs indexer add latency that we can't sub-second.
const LN_POLL_TIMEOUT: Duration = Duration::from_secs(30);
const ONCHAIN_SYNC_TIMEOUT: Duration = Duration::from_secs(30);

// ── Server subprocess ─────────────────────────────────────────────────────────

struct HostedServer {
    child: std::process::Child,
    endpoint: String,
}

impl HostedServer {
    fn spawn() -> Self {
        // Resolve the workspace root via CARGO_MANIFEST_DIR (points at
        // wick-sdk); go up two levels to reach the workspace root, then
        // run `cargo run --bin wick-server` against the regtest config.
        //
        // Using `cargo run` rather than a pre-built path keeps the test
        // self-contained at the cost of one-time build latency on first
        // invocation.
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
        let endpoint = "http://127.0.0.1:50051".to_owned();

        // Block until the server's gRPC listener accepts connections.
        // `cargo run` on a fresh workspace can take a while to build, so
        // we allow a generous deadline.
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

        Self { child, endpoint }
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Round 3: simulate an abrupt server crash so the test can verify
    /// the SDK signer reconnects + funds survive across restart. Same
    /// shape as `Drop` but callable mid-test without dropping the
    /// struct itself.
    fn kill_hard(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for HostedServer {
    fn drop(&mut self) {
        // Best-effort SIGKILL. `kill` returns Err only if the process is
        // already gone, which is fine.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Macaroon nonce extraction (for Round 4 revocation) ───────────────────────

/// Tag for the per-issue `Nonce` caveat. Mirror of `wick_macaroon::TAG_NONCE`
/// inlined so wick-sdk's test binary doesn't need a wick-macaroon dev-dep.
const MACAROON_TAG_NONCE: u8 = 0x03;

/// Pull the 16-byte per-issue nonce out of a serialised macaroon by
/// finding the first caveat tagged `Nonce` (`0x03`). The revocation
/// table is keyed by *nonce*, not by `identifier`.
fn macaroon_nonce(bytes: &[u8]) -> Option<[u8; 16]> {
    fn read_u16(buf: &[u8], pos: &mut usize) -> Option<u16> {
        if *pos + 2 > buf.len() {
            return None;
        }
        let n = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
        *pos += 2;
        Some(n)
    }

    let mut pos = 0usize;
    let loc_len = read_u16(bytes, &mut pos)? as usize;
    pos = pos.checked_add(loc_len)?;
    pos = pos.checked_add(16)?; // identifier
    if pos > bytes.len() {
        return None;
    }
    let n_caveats = read_u16(bytes, &mut pos)? as usize;
    for _ in 0..n_caveats {
        let cav_len = read_u16(bytes, &mut pos)? as usize;
        if cav_len == 0 || pos + cav_len > bytes.len() {
            return None;
        }
        let cav = &bytes[pos..pos + cav_len];
        pos += cav_len;
        let tag = cav[0];
        let payload = &cav[1..];
        if tag == MACAROON_TAG_NONCE && payload.len() == 16 {
            let mut out = [0u8; 16];
            out.copy_from_slice(payload);
            return Some(out);
        }
    }
    None
}

/// Revoke a macaroon nonce by inserting directly into
/// `global.revoked_macaroons` via `docker exec wick-postgres psql ...`.
/// LISTEN/NOTIFY propagates to every connected `RevocationSet`.
/// Returns the wall-clock instant the INSERT completed.
fn revoke_via_psql(nonce: [u8; 16]) -> Instant {
    let hex_nonce = hex::encode(nonce);
    let sql = format!(
        "INSERT INTO global.revoked_macaroons (nonce, reason) \
         VALUES ('\\x{hex_nonce}', 'phase4-regtest-acceptance') \
         ON CONFLICT (nonce) DO NOTHING;"
    );
    let status = StdCommand::new("docker")
        .args([
            "exec",
            "-i",
            "wick-postgres",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-q",
            "-U",
            "wick",
            "-d",
            "wick",
            "-c",
            &sql,
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn docker exec psql");
    assert!(status.success(), "psql revoke INSERT failed");
    Instant::now()
}

// ── The test ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires just regtest-up + compiled wick-server binary"]
async fn full_flow_two_clients_pay_and_reload() {
    let mut server = HostedServer::spawn();

    // Regtest chain controller (bitcoind RPC). Credentials come from
    // `deploy/docker/docker-compose.yml` — fixed to `wick:wick`.
    let rpc =
        RegtestRpc::connect("http://127.0.0.1:18443", "wick", "wick").expect("RegtestRpc::connect");

    let config = || {
        let mut cfg = WickConfig::for_network(WickNetwork::Regtest);
        cfg.server_endpoint = server.endpoint().to_owned();
        cfg.esplora_url = "http://127.0.0.1:3002".to_owned();
        cfg
    };

    // ── Round 1: fresh registration, open channel, payment ────────────────

    let alice = WickClient::new(ALICE_MNEMONIC, None, config())
        .await
        .expect("alice WickClient::new");
    let bob = WickClient::new(BOB_MNEMONIC, None, config())
        .await
        .expect("bob WickClient::new");

    let alice_tenant_outcome = alice.register("free").await.expect("alice register");
    let bob_tenant_outcome = bob.register("free").await.expect("bob register");
    assert!(!alice_tenant_outcome.api_token.is_empty());
    assert!(!bob_tenant_outcome.api_token.is_empty());

    // tenant_id is deterministic: UUID-v5 over the compressed pubkey.
    let expected_alice_tid = TenantId::from_pubkey(&alice.node_id().serialize())
        .as_uuid()
        .to_string();
    let expected_bob_tid = TenantId::from_pubkey(&bob.node_id().serialize())
        .as_uuid()
        .to_string();
    assert_eq!(alice_tenant_outcome.tenant_id, expected_alice_tid);
    assert_eq!(bob_tenant_outcome.tenant_id, expected_bob_tid);

    // Fund Alice's **client-side** BDK wallet via bitcoind: mine 101
    // blocks so the first coinbase matures, send 1M sats to Alice's
    // next client-side P2WPKH address, mine 1 block to confirm.
    //
    // The SDK owns the funding UTXOs — the server never touches on-chain
    // funds in the new two-phase `OpenChannel` flow. Alice's SDK will
    // build+sign the funding tx from this wallet when `open_channel` is
    // called below.
    let alice_client_addr = alice.next_address_p2wpkh().expect("alice client addr");
    rpc.mine(101).expect("mine coinbase maturation");
    rpc.send_to_address(&alice_client_addr, FUNDING_TRANSFER_SAT)
        .expect("send_to_address");
    rpc.mine(1).expect("mine funding conf");

    // Wait for electrs to index the funding block, then sync the SDK's
    // client-side BDK so it sees the new UTXO.
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

    // Alice tells Bob which peer to be / where to reach him. Since this
    // is a same-server setup, the listen_host the server reports may be
    // 0.0.0.0 — rewrite to 127.0.0.1 for dial-ability on this machine.
    let bob_info = bob.node_info().await.expect("bob node_info");
    let dial_host = match bob_info.host.as_str() {
        "0.0.0.0" | "" => "127.0.0.1".to_owned(),
        other => other.to_owned(),
    };

    alice
        .connect_peer(bob_info.pubkey, &dial_host, bob_info.port)
        .await
        .expect("alice connect_peer");

    alice
        .open_channel(bob_info.pubkey, CHANNEL_VALUE_SAT, 0)
        .await
        .expect("alice open_channel");

    // LDK's broadcaster is fire-and-forget; wait for bitcoind to see the
    // funding tx before mining, otherwise blocks land before the tx
    // reaches the mempool and the channel gets stranded.
    rpc.wait_for_mempool_size(1, Duration::from_secs(10))
        .await
        .expect("funding tx in mempool");
    rpc.mine(10).expect("mine funding confs");

    // Wait for the channel to reach routable capacity. `is_usable` alone
    // isn't enough — LDK's scorer needs a moment to mark the channel as
    // routable for a specific amount.
    wait_until_async("channel routable for payment", LN_POLL_TIMEOUT, || {
        let a = alice.clone();
        async move {
            a.list_channels()
                .await
                .map(|chs| {
                    chs.iter()
                        .any(|c| c.is_usable && c.outbound_capacity_msat >= PAYMENT_AMOUNT_MSAT)
                })
                .unwrap_or(false)
        }
    })
    .await;

    // Bob issues a 10k-sat invoice; Alice pays it.
    let invoice = bob
        .receive_payment(Some(PAYMENT_AMOUNT_MSAT), "full-flow")
        .await
        .expect("bob receive_payment");
    assert!(!invoice.bolt11.is_empty());
    let payment_hash = invoice.payment_hash;

    let send = alice
        .send_payment(&invoice.bolt11)
        .await
        .expect("alice send_payment");
    assert_eq!(send.status, PaymentStatus::Pending);
    assert_eq!(send.payment_hash, payment_hash);

    // Poll both sides for the terminal Succeeded status.
    let hash_hex = hex::encode(payment_hash);
    {
        let a = alice.clone();
        let h = hash_hex.clone();
        wait_until_async(
            "alice sees outbound Succeeded",
            LN_POLL_TIMEOUT,
            move || {
                let a = a.clone();
                let h = h.clone();
                async move {
                    a.transactions(20, None)
                        .await
                        .map(|rows| {
                            rows.iter().any(|p| {
                                hex::encode(p.payment_hash) == h
                                    && p.is_outbound
                                    && p.status == PaymentStatus::Succeeded
                            })
                        })
                        .unwrap_or(false)
                }
            },
        )
        .await;
    }
    {
        let b = bob.clone();
        let h = hash_hex.clone();
        wait_until_async("bob sees inbound Succeeded", LN_POLL_TIMEOUT, move || {
            let b = b.clone();
            let h = h.clone();
            async move {
                b.transactions(20, None)
                    .await
                    .map(|rows| {
                        rows.iter().any(|p| {
                            hex::encode(p.payment_hash) == h
                                && !p.is_outbound
                                && p.status == PaymentStatus::Succeeded
                        })
                    })
                    .unwrap_or(false)
            }
        })
        .await;
    }

    // Verify the funds actually moved to Bob's side of the channel. On a
    // fresh channel Bob starts with 0 outbound (push_msat=0); after a
    // 10k-sat payment his outbound should be close to 10k sats minus
    // the reserve (~2k sats).
    let bob_bal_round_1 = bob
        .lightning_balance()
        .await
        .expect("bob lightning_balance after payment");
    assert!(
        bob_bal_round_1.lightning_msat >= 7_000_000,
        "bob's outbound capacity should reflect ~{PAYMENT_AMOUNT_MSAT} msat minus channel reserve, got {}",
        bob_bal_round_1.lightning_msat
    );

    let alice_bal_round_1 = alice
        .lightning_balance()
        .await
        .expect("alice lightning_balance after payment");
    assert!(
        alice_bal_round_1.lightning_msat > 0,
        "alice should still have outbound capacity; got {}",
        alice_bal_round_1.lightning_msat
    );

    // ── Round 2: drop clients, recreate from the same mnemonics ────────────
    //
    // Simulates a client process restart. Server state (tenant row,
    // channel state, payment history, balances) is all in Postgres + LDK
    // persistence — the fresh clients should observe it unchanged.

    let alice_node_id: PublicKey = alice.node_id();
    let bob_node_id: PublicKey = bob.node_id();
    drop(alice);
    drop(bob);

    let alice2 = WickClient::new(ALICE_MNEMONIC, None, config())
        .await
        .expect("alice2 WickClient::new");
    let bob2 = WickClient::new(BOB_MNEMONIC, None, config())
        .await
        .expect("bob2 WickClient::new");

    // Identity is a pure function of the mnemonic, so pubkeys must match.
    assert_eq!(alice2.node_id(), alice_node_id);
    assert_eq!(bob2.node_id(), bob_node_id);

    // Re-register. Server path is idempotent: same tenant_id (UUID-v5 of
    // the pubkey), freshly-rotated api_token.
    let alice_out_2 = alice2.register("free").await.expect("alice2 register");
    let bob_out_2 = bob2.register("free").await.expect("bob2 register");

    assert_eq!(alice_out_2.tenant_id, alice_tenant_outcome.tenant_id);
    assert_eq!(bob_out_2.tenant_id, bob_tenant_outcome.tenant_id);
    assert_ne!(
        alice_out_2.api_token, alice_tenant_outcome.api_token,
        "re-register must rotate the api_token"
    );
    assert_ne!(bob_out_2.api_token, bob_tenant_outcome.api_token);

    // Transactions persist — fresh client sees the same payment history.
    let alice_txs = alice2
        .transactions(20, None)
        .await
        .expect("alice2 transactions");
    let bob_txs = bob2
        .transactions(20, None)
        .await
        .expect("bob2 transactions");

    let alice_outbound = alice_txs
        .iter()
        .find(|p| p.is_outbound && p.status == PaymentStatus::Succeeded)
        .expect("prior outbound payment must persist across client recreation");
    assert_eq!(alice_outbound.payment_hash, payment_hash);
    assert_eq!(alice_outbound.amount_msat, PAYMENT_AMOUNT_MSAT);

    let bob_inbound = bob_txs
        .iter()
        .find(|p| !p.is_outbound && p.status == PaymentStatus::Succeeded)
        .expect("prior inbound payment must persist across client recreation");
    assert_eq!(bob_inbound.payment_hash, payment_hash);
    assert_eq!(bob_inbound.amount_msat, PAYMENT_AMOUNT_MSAT);
    // Balances also persist — they're server-held state, unchanged by
    // a client restart.
    let bob_bal_round_2 = bob2
        .lightning_balance()
        .await
        .expect("bob2 lightning_balance");
    assert_eq!(
        bob_bal_round_2.lightning_msat, bob_bal_round_1.lightning_msat,
        "balance must persist across client recreation"
    );
    eprint!(
        "bob balance after restart: {} msat\n",
        bob_bal_round_2.lightning_msat
    );

    // ── Round 3: server kill -9, restart, second payment ───────────────────
    //
    // Phase-4 acceptance: device-held VLS seed signs through a fresh
    // Noise tunnel after the server is abruptly killed. Funds must
    // survive the crash and the SDK must re-attach without re-funding.

    let alice_ln_before_crash = alice2
        .lightning_balance()
        .await
        .expect("alice lightning_balance pre-kill");
    let alice_total_before_crash =
        alice_ln_before_crash.onchain_sats.saturating_mul(1_000) + alice_ln_before_crash.lightning_msat;

    drop(alice2);
    drop(bob2);
    server.kill_hard();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let server = HostedServer::spawn();
    let config = || {
        let mut cfg = WickConfig::for_network(WickNetwork::Regtest);
        cfg.server_endpoint = server.endpoint().to_owned();
        cfg.esplora_url = "http://127.0.0.1:3002".to_owned();
        cfg
    };

    let alice3 = WickClient::new(ALICE_MNEMONIC, None, config())
        .await
        .expect("alice3 WickClient::new after server restart");
    let bob3 = WickClient::new(BOB_MNEMONIC, None, config())
        .await
        .expect("bob3 WickClient::new after server restart");

    alice3
        .register("free")
        .await
        .expect("alice3 re-register after server restart");
    bob3.register("free")
        .await
        .expect("bob3 re-register after server restart");

    // Give LDK + signer a beat to rehydrate channels under the fresh
    // Noise tunnel.
    wait_until_async(
        "channel usable after server restart",
        LN_POLL_TIMEOUT,
        || {
            let a = alice3.clone();
            async move {
                a.list_channels()
                    .await
                    .map(|chs| {
                        chs.iter()
                            .any(|c| c.is_usable && c.outbound_capacity_msat >= SECOND_PAYMENT_MSAT)
                    })
                    .unwrap_or(false)
            }
        },
    )
    .await;

    let invoice3 = bob3
        .receive_payment(Some(SECOND_PAYMENT_MSAT), "round3-postcrash")
        .await
        .expect("bob3 receive_payment after server restart");
    let hash3_hex = hex::encode(invoice3.payment_hash);

    alice3
        .send_payment(&invoice3.bolt11)
        .await
        .expect("alice3 send_payment after server restart");

    {
        let a = alice3.clone();
        let h = hash3_hex.clone();
        wait_until_async(
            "alice sees post-server-restart outbound Succeeded",
            LN_POLL_TIMEOUT,
            move || {
                let a = a.clone();
                let h = h.clone();
                async move {
                    a.transactions(20, None)
                        .await
                        .map(|rows| {
                            rows.iter().any(|p| {
                                hex::encode(p.payment_hash) == h
                                    && p.is_outbound
                                    && p.status == PaymentStatus::Succeeded
                            })
                        })
                        .unwrap_or(false)
                }
            },
        )
        .await;
    }

    let alice_ln_after_crash = alice3
        .lightning_balance()
        .await
        .expect("alice lightning_balance post-kill");
    let alice_total_after_crash = alice_ln_after_crash.onchain_sats.saturating_mul(1_000)
        + alice_ln_after_crash.lightning_msat;

    // Funds must survive the crash. Tolerance: SECOND_PAYMENT_MSAT spent
    // plus 5_000_000 msat (5k sats) of routing/HTLC fee headroom. The
    // guard is "no funds vanished", not exact accounting.
    let max_loss = SECOND_PAYMENT_MSAT + 5_000_000;
    assert!(
        alice_total_before_crash.saturating_sub(alice_total_after_crash) <= max_loss,
        "funds vanished across server crash: before={alice_total_before_crash}, \
         after={alice_total_after_crash}, max_loss={max_loss}"
    );

    eprintln!("✅ Round 3: kill -9 server → signer re-attaches → payment after restart works");

    // ── Round 4: revoke macaroon, cluster rejects within 1s ────────────────
    //
    // Phase-4 acceptance for D3 revocation latency. If the server is
    // still issuing bearer tokens (pre-D3-M3 surface), there's nothing
    // revocable; skip with a warning rather than failing.

    let cred = alice3
        .current_credential()
        .await
        .expect("alice3 has a credential post-register");

    if cred.kind != CredentialKind::Macaroon {
        eprintln!(
            "⚠ skipping Round 4 — server returned a {:?} credential, not a macaroon",
            cred.kind
        );
    } else {
        let nonce = macaroon_nonce(&cred.bytes).expect("decode nonce caveat from macaroon");
        eprintln!("Round 4: revoking macaroon nonce={}", hex::encode(nonce));

        let revoke_t = revoke_via_psql(nonce);
        let reject_deadline = revoke_t + REVOKE_REJECT_DEADLINE;

        let elapsed = loop {
            match alice3.node_info().await {
                Err(SdkError::Unauthenticated(msg)) => {
                    let elapsed = revoke_t.elapsed();
                    eprintln!("rejection seen after {elapsed:?}: {msg}");
                    break elapsed;
                }
                Err(other) => {
                    if Instant::now() >= reject_deadline {
                        panic!("revoked RPC kept failing with non-auth error: {other:?}");
                    }
                }
                Ok(_) => {
                    if Instant::now() >= reject_deadline {
                        panic!(
                            "revoked macaroon was still accepted after {:?} (target < {:?})",
                            revoke_t.elapsed(),
                            REVOKE_REJECT_DEADLINE
                        );
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        assert!(
            elapsed < REVOKE_REJECT_DEADLINE,
            "revocation rejection latency {elapsed:?} exceeded {REVOKE_REJECT_DEADLINE:?}"
        );

        eprintln!(
            "✅ Round 4: macaroon revoked → rejected within {elapsed:?} (target <1s)"
        );
    }

    let _ = server; // keep alive until end; Drop kills the subprocess
}
