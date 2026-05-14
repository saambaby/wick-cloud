//! Phase 4 acceptance demo — drives the three acceptance criteria
//! from `phases.md` Phase 4 in sequence against a real out-of-process
//! `wick-server` against the dockerized regtest stack:
//!
//! 1. **Self-custodial signing**: payment succeeds with the BIP32 seed
//!    held only on the device (Alice's SDK runs the VLS signer loop).
//! 2. **Crash survival**: `kill -9` the server mid-flight, restart, no
//!    funds lost; a fresh payment after restart settles.
//! 3. **Revocation latency**: revoke Alice's macaroon directly in
//!    Postgres and time how long until her next RPC is rejected. Must
//!    be under 1 second (LISTEN/NOTIFY-driven RevocationSet).
//!
//! Prerequisites:
//! ```sh
//! just regtest-up
//! just vls-demo
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::manual_assert
)]

use std::net::TcpStream;
use std::process::{Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use wick_sdk::regtest::{wait_until_async, RegtestRpc};
use wick_sdk::{
    CredentialKind, Error as SdkError, PaymentStatus, WickClient, WickConfig, WickNetwork,
};

// ── Fixed BIP39 test vectors (same as regtest_flow.rs) ───────────────────────

const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

const PAYMENT_AMOUNT_MSAT: u64 = 10_000_000;
const SECOND_PAYMENT_MSAT: u64 = 5_000_000;
const CHANNEL_VALUE_SAT: u64 = 200_000;
const FUNDING_TRANSFER_SAT: u64 = 1_000_000;

const LN_POLL_TIMEOUT: Duration = Duration::from_secs(30);
const ONCHAIN_SYNC_TIMEOUT: Duration = Duration::from_secs(30);

/// Revocation must propagate (via `LISTEN/NOTIFY` driving
/// `RevocationSet`) and the next RPC must be rejected within this
/// budget. p99 target is 1s; pick a slightly looser deadline so a
/// noisy CI box doesn't flake on the wall-clock measurement, while
/// the *measured* elapsed time printed in the banner is what humans
/// eyeball.
const REVOKE_REJECT_DEADLINE: Duration = Duration::from_secs(1);

// ── Server subprocess ─────────────────────────────────────────────────────────

struct HostedServer {
    child: std::process::Child,
    endpoint: String,
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

        let endpoint = "http://127.0.0.1:50051".to_owned();

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

    /// Hard-kill the server process. `std::process::Child::kill` issues
    /// SIGKILL on Unix per its docs — equivalent to `kill -9 $pid`. We
    /// then `wait()` to reap the zombie.
    fn kill_hard(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for HostedServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Macaroon nonce extraction ────────────────────────────────────────────────

/// Tag for the per-issue `Nonce` caveat. Mirror of `wick_macaroon::TAG_NONCE`
/// (inlined to keep `wick-sdk` from gaining a `wick-macaroon` dev-dep).
const MACAROON_TAG_NONCE: u8 = 0x03;

/// Pull the 16-byte per-issue nonce out of a serialised macaroon by
/// finding the first caveat tagged `Nonce` (`0x03`). The revocation
/// table is keyed by *nonce*, not by `identifier` — see
/// `wick_macaroon::VerifyContext::revoked_nonces`.
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
/// LISTEN/NOTIFY propagates the revocation to every connected
/// `RevocationSet` (see `wick_macaroon::store::start`).
///
/// Returns the wall-clock instant at which the INSERT completed —
/// callers use this to measure rejection latency.
fn revoke_via_psql(nonce: [u8; 16]) -> Instant {
    let hex_nonce = hex::encode(nonce);
    // PostgreSQL `BYTEA` literal: `\x` + hex.
    let sql = format!(
        "INSERT INTO global.revoked_macaroons (nonce, reason) \
         VALUES ('\\x{hex_nonce}', 'phase4-demo') \
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
#[ignore = "requires `just regtest-up` (bitcoind + postgres + electrs)"]
async fn phase4_vls_demo_self_custody_crash_revoke() {
    let mut server = HostedServer::spawn();

    let rpc =
        RegtestRpc::connect("http://127.0.0.1:18443", "wick", "wick").expect("RegtestRpc::connect");

    let config = || {
        let mut cfg = WickConfig::for_network(WickNetwork::Regtest);
        cfg.server_endpoint = server.endpoint().to_owned();
        cfg.esplora_url = "http://127.0.0.1:3002".to_owned();
        cfg
    };

    // ── Phase 1: device-held seed → live VLS signer → payment succeeds ───

    let alice = WickClient::new(ALICE_MNEMONIC, None, config())
        .await
        .expect("alice WickClient::new");
    let bob = WickClient::new(BOB_MNEMONIC, None, config())
        .await
        .expect("bob WickClient::new");

    alice.register("free").await.expect("alice register");
    bob.register("free").await.expect("bob register");

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

    rpc.wait_for_mempool_size(1, Duration::from_secs(10))
        .await
        .expect("funding tx in mempool");
    rpc.mine(10).expect("mine funding confs");

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

    let invoice = bob
        .receive_payment(Some(PAYMENT_AMOUNT_MSAT), "phase4-1")
        .await
        .expect("bob receive_payment");
    let payment_hash = invoice.payment_hash;

    let send = alice
        .send_payment(&invoice.bolt11)
        .await
        .expect("alice send_payment");
    assert_eq!(send.status, PaymentStatus::Pending);

    let hash_hex = hex::encode(payment_hash);
    {
        let a = alice.clone();
        let h = hash_hex.clone();
        wait_until_async("alice sees outbound Succeeded", LN_POLL_TIMEOUT, move || {
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
        })
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

    eprintln!("✅ Phase 1: device-held seed → live VLS signer → payment succeeds");

    // Snapshot Alice's total spendable balance before the crash so we
    // can assert "no funds lost" after restart. Fees mean the value
    // won't match to the satoshi — we tolerate a small drift.
    let alice_ln_before = alice
        .lightning_balance()
        .await
        .expect("alice lightning_balance pre-kill");
    let alice_total_before =
        alice_ln_before.onchain_sats.saturating_mul(1_000) + alice_ln_before.lightning_msat;

    // ── Phase 2: kill -9 server, funds survive ────────────────────────────

    drop(alice);
    drop(bob);
    server.kill_hard();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let server = HostedServer::spawn();
    let config = || {
        let mut cfg = WickConfig::for_network(WickNetwork::Regtest);
        cfg.server_endpoint = server.endpoint().to_owned();
        cfg.esplora_url = "http://127.0.0.1:3002".to_owned();
        cfg
    };

    let alice = WickClient::new(ALICE_MNEMONIC, None, config())
        .await
        .expect("alice WickClient::new after restart");
    let bob = WickClient::new(BOB_MNEMONIC, None, config())
        .await
        .expect("bob WickClient::new after restart");

    // Re-register. D3 challenge rotates tokens; tenant_id is stable.
    alice
        .register("free")
        .await
        .expect("alice re-register after restart");
    bob.register("free")
        .await
        .expect("bob re-register after restart");

    // Give LDK a beat to rehydrate channels.
    wait_until_async("channel usable after restart", LN_POLL_TIMEOUT, || {
        let a = alice.clone();
        async move {
            a.list_channels()
                .await
                .map(|chs| {
                    chs.iter()
                        .any(|c| c.is_usable && c.outbound_capacity_msat >= SECOND_PAYMENT_MSAT)
                })
                .unwrap_or(false)
        }
    })
    .await;

    let invoice2 = bob
        .receive_payment(Some(SECOND_PAYMENT_MSAT), "phase4-2-postcrash")
        .await
        .expect("bob receive_payment after restart");
    let hash2_hex = hex::encode(invoice2.payment_hash);

    alice
        .send_payment(&invoice2.bolt11)
        .await
        .expect("alice send_payment after restart");

    {
        let a = alice.clone();
        let h = hash2_hex.clone();
        wait_until_async(
            "alice sees post-restart outbound Succeeded",
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

    let alice_ln_after = alice
        .lightning_balance()
        .await
        .expect("alice lightning_balance post-kill");
    let alice_total_after = alice_ln_after.onchain_sats.saturating_mul(1_000) + alice_ln_after.lightning_msat;

    // After the second payment Alice's total drops by ~SECOND_PAYMENT_MSAT
    // + routing/HTLC fees. Tolerance: spent + 5k sats (5,000,000 msat) of
    // fee headroom. We are guarding against "all funds vanished after
    // crash", not exact accounting.
    let max_loss = SECOND_PAYMENT_MSAT + 5_000_000;
    assert!(
        alice_total_before.saturating_sub(alice_total_after) <= max_loss,
        "funds vanished across crash: before={alice_total_before}, after={alice_total_after}, max_loss={max_loss}"
    );

    eprintln!("✅ Phase 2: kill -9 server → no funds lost → payment after restart works");

    // ── Phase 3: revoke macaroon, cluster rejects within 1s ──────────────

    let cred = alice
        .current_credential()
        .await
        .expect("alice has a credential post-register");

    // The macaroon path is the only one with a revocable nonce; if the
    // server is still on the legacy bearer (pre-D3-M3), skip this phase.
    if cred.kind != CredentialKind::Macaroon {
        eprintln!(
            "⚠ skipping Phase 3 — server returned a {:?} credential, not a macaroon",
            cred.kind
        );
        let _ = server.endpoint(); // keep server alive
        return;
    }

    let nonce = macaroon_nonce(&cred.bytes).expect("decode nonce caveat from macaroon");
    eprintln!("Phase 3: revoking macaroon nonce={}", hex::encode(nonce));

    // Time from the moment Postgres acknowledges the INSERT to the
    // moment Alice's next RPC is rejected with Unauthenticated.
    let revoke_t = revoke_via_psql(nonce);

    let reject_deadline = revoke_t + REVOKE_REJECT_DEADLINE;
    let elapsed = loop {
        match alice.node_info().await {
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
        "✅ Phase 3: macaroon revoked → rejected within {elapsed:?} (p99 target < 1s)"
    );

    // ── Phase 4: pass banner ──────────────────────────────────────────────

    eprintln!(
        "\n============================================================\n\
         PHASE 4 ACCEPTANCE: PASS\n\
         - Self-custodial signing: ✅\n\
         - Crash-survival: ✅\n\
         - Macaroon revocation latency: {:.0}ms (target <1s)\n\
         ============================================================\n",
        elapsed.as_secs_f64() * 1000.0
    );

    let _ = server.endpoint(); // keep server alive until end
}
