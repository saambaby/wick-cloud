//! End-to-end **tenant-to-tenant Lightning payment** over live mutinynet.
//!
//! This is a manual-run test — `#[ignore]` keeps it out of the default
//! test suite. Invoke it explicitly when you want to validate that two
//! separate SDK clients on the same `wick-server`, both peered with
//! Mutiny's routing hub on mutinynet, can settle a real Lightning
//! payment between each other.
//!
//! ```sh
//! # 1. Bring up wick-server against the mutinynet config.
//! just migrate
//! cargo run -p wick-server -- --config deploy/docker/config.mutinynet.toml
//!
//! # 2. In another terminal, run this test.
//! cargo test -p wick-sdk --test integration_mutinynet \
//!     -- --ignored --nocapture
//! ```
//!
//! ## Idempotence across runs
//!
//! The test uses **persistent const mnemonics** for Alice, Bob, and the
//! faucet wallet so re-runs are fast and cheap. On the first run every
//! identity is fresh: the faucet funds two tenants on-chain, each
//! opens a channel to the Mutiny hub, and the payment settles. On
//! subsequent runs the test detects that both tenants already have
//! usable channels with sufficient liquidity and goes straight to the
//! payment step — no faucet top-up, no channel opens, no block
//! waiting.
//!
//! ### How existing state is classified
//!
//! For each tenant, after `register` (idempotent — upsert-style) we
//! call `list_channels()` and branch on what we see:
//!
//! - **Usable channel to hub, enough liquidity** → skip funding + open
//!   entirely; proceed to the payment step.
//! - **Channel exists but `is_usable == false`** → the channel is
//!   still confirming from a previous run; wait for it to become
//!   usable (same timeout as a fresh open).
//! - **Usable channel but liquidity is depleted** → the test can't
//!   recover automatically (you can't push funds into an existing
//!   channel from this side); panic with a clear message so the
//!   operator can close the channel manually or wipe tenant state.
//! - **No channel** → take the full faucet → fund → open path.
//!
//! The **faucet top-up prompt fires only if at least one tenant
//! actually needs funding AND the faucet balance is below threshold**.
//! In the steady state of re-runs this branch is never entered.
//!
//! ## Parked tenants
//!
//! `wick-server` parks idle tenants (Phase 2) and wakes them on the
//! first incoming RPC via `NodeManager::dispatch`. The wake latency
//! (≤ `wake_deadline`, typically a few seconds) is hidden inside the
//! gRPC call — no client-side wake bookkeeping needed. The warmup
//! call here is `list_channels()`, which tolerates a slightly longer
//! round-trip on the first run after the server restarts.
//!
//! ## Why committed const mnemonics
//!
//! Mutinynet's HTTP faucet requires a GitHub OAuth token to call
//! programmatically, so there's no clean CI-friendly way to top up on
//! demand. The committed mnemonics below only ever see mutinynet sats;
//! any funds held against them are effectively public. Do **not**
//! reuse these mnemonics for real value.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::TcpStream;
use std::str::FromStr;
use std::time::{Duration, Instant};

use bdk_esplora::{esplora_client, EsploraAsyncExt};
use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, Transaction};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use bip39::Mnemonic;
use bitcoin::secp256k1::PublicKey;
use wick_sdk::{PaymentStatus, WickClient, WickConfig, WickNetwork};

// ── Const mnemonics (mutinynet-only, dev-public) ─────────────────────────────
//
// Mnemonic provenance (2026-05-22):
//
// - FAUCET_MNEMONIC: promoted from the prior BOB role because the on-chain
//   BIP84 wallet it controls held ~10.35 M mutinynet sats — enough to fund
//   the test for many iterations without another browser faucet trip.
// - BOB_MNEMONIC: rotated to a fresh BIP39 test vector (Trezor entropy
//   `8080808080…`). Starts at 0 sats; the first run faucets it from the
//   new FAUCET above.
//
// Stranded funds: the previous FAUCET mnemonic
// `legal winner thank year wave sausage worth useful legal winner thank yellow`
// retained ~400 k sats after the last top-up. To recover, swap that string
// back in as `FAUCET_MNEMONIC` for one run and either sweep with a
// `bdk drain` or open a channel against it.

/// Faucet BDK wallet mnemonic. Operator tops up manually via the
/// browser faucet; test spends from it to fund Alice + Bob on-chain.
/// This is the previous BOB mnemonic — kept because its on-chain
/// wallet already holds enough sats for many runs.
const FAUCET_MNEMONIC: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

/// Alice — the payment sender. Persistent across runs so the Alice
/// tenant, her on-chain UTXOs, and her Lightning channel all carry
/// over.
const ALICE_MNEMONIC: &str =
    "army van defense carry jealous true garbage claim echo media make crunch";

/// Bob — the payment receiver. Fresh BIP39 test vector (Trezor entropy
/// `8080…`). On the first run the FAUCET funds him on-chain; subsequent
/// runs reuse his channel + tenant state.
const BOB_MNEMONIC: &str =
    "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge";

// ── Thresholds + timeouts ────────────────────────────────────────────────────

/// Minimum confirmed faucet balance required before the test will try
/// to fund a tenant. Only checked when at least one tenant actually
/// needs faucet money. Covers `2 × FAUCET_TO_SDK_SAT` plus fee headroom.
const FAUCET_MIN_SAT: u64 = 150_000;

/// Amount the faucet sends into each SDK's BIP84 wallet when that
/// tenant has no channel yet AND its BDK balance is below
/// `MIN_TENANT_ONCHAIN_SAT`. The faucet step is skipped per-tenant
/// when on-chain is already sufficient (saves sats across re-runs).
const FAUCET_TO_SDK_SAT: u64 = 60_000;

/// If a tenant's BDK on-chain balance already exceeds this, the
/// faucet→SDK transfer is skipped for that tenant — its existing
/// UTXOs cover the channel open. Sized at `CHANNEL_VALUE_SAT` plus a
/// generous fee buffer.
const MIN_TENANT_ONCHAIN_SAT: u64 = 40_000;

/// Channel capacity each tenant opens to the Mutiny hub on a fresh run.
/// 30k sats is small enough to be cheap but above LDK's hard minimum
/// (~20k for a healthy 2-of-2 + dust limit + commit-fee reservation).
const CHANNEL_VALUE_SAT: u64 = 30_000;

/// Bob pushes this many msat to the Mutiny hub at channel open so the
/// hub has balance on Bob's channel — that balance is what becomes
/// Bob's inbound liquidity when routing Alice → hub → Bob.
const BOB_PUSH_MSAT: u64 = 6_000_000;

/// Invoice amount Alice pays Bob. Well below Bob's expected inbound
/// after reserves.
const PAYMENT_AMOUNT_MSAT: u64 = 1_000_000;

/// Margin above `PAYMENT_AMOUNT_MSAT` required before the test will
/// reuse an existing channel on Alice's side (covers routing fees).
const ALICE_OUTBOUND_HEADROOM_MSAT: u64 = 10_000;

/// How long to wait for a newly-opened channel to become usable.
/// Mutinynet mines every ~30 s; 3 confs + buffer fits inside 4 min.
const CHANNEL_READY_TIMEOUT: Duration = Duration::from_secs(240);

/// How long to wait for a pre-existing but currently-pending channel
/// to become usable. Same budget as a fresh open — if it's stuck
/// longer, something is wrong.
const EXISTING_CHANNEL_USABLE_TIMEOUT: Duration = Duration::from_secs(240);

/// Poll cadence for any external-state wait loop.
const POLL_INTERVAL: Duration = Duration::from_secs(15);

/// Faucet top-up wait budget.
const FAUCET_TOPUP_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How long to wait for the faucet-to-SDK funding tx to confirm.
const FUNDING_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How long to wait for a payment to reach `Succeeded` / `Failed`.
const PAYMENT_SETTLE_TIMEOUT: Duration = Duration::from_secs(120);

const MUTINYNET_FAUCET_URL: &str = "https://faucet.mutinynet.com";

// ── Per-tenant state classification ──────────────────────────────────────────

/// What the test needs to do for a given tenant before the payment step.
enum TenantState {
    /// Existing usable channel with enough liquidity on the relevant
    /// side (outbound for Alice, inbound for Bob). Skip everything.
    Ready,
    /// Channel exists but `is_usable == false`. Wait for it; no faucet
    /// spend, no new open.
    Pending,
    /// No channel — run the faucet + open path from scratch.
    NeedsFunding,
}

// ── Test body ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual: requires wick-server running against mutinynet config"]
async fn tenant_to_tenant_payment_mutinynet() {
    if TcpStream::connect("127.0.0.1:50051").is_err() {
        panic!(
            "no wick-server listening on 127.0.0.1:50051 — start it first:\n  \
             cargo run -p wick-server -- --config deploy/docker/config.mutinynet.toml"
        );
    }

    let t0 = Instant::now();
    let stamp = |label: &str, since: Instant| {
        println!(
            "[+{:>5.1}s] {label}",
            since.elapsed().as_secs_f32()
        );
    };

    let esplora_url = WickNetwork::Mutinynet.default_esplora();
    let esplora = esplora_client::Builder::new(esplora_url)
        .build_async()
        .expect("esplora build_async");

    // ── Step 1: register both tenants (idempotent) ──────────────────────
    let s1 = Instant::now();
    let alice = register_client(ALICE_MNEMONIC, "alice").await;
    let bob = register_client(BOB_MNEMONIC, "bob").await;
    stamp("step1 register (alice + bob)", s1);

    let (hub_pubkey, hub_host, hub_port) = mutiny_hub();

    // ── Step 2: classify what each tenant needs ─────────────────────────
    let s2 = Instant::now();
    let alice_state = classify(&alice, "alice", hub_pubkey, true).await;
    let bob_state = classify(&bob, "bob", hub_pubkey, false).await;
    stamp("step2 classify (alice + bob)", s2);

    // ── Step 3: faucet + open for any tenant that NeedsFunding ──────────
    let alice_needs_open = matches!(alice_state, TenantState::NeedsFunding);
    let bob_needs_open = matches!(bob_state, TenantState::NeedsFunding);

    let s3 = Instant::now();
    if alice_needs_open || bob_needs_open {
        run_funding_and_open_path(
            &alice,
            &bob,
            alice_needs_open,
            bob_needs_open,
            &esplora,
            hub_pubkey,
            &hub_host,
            hub_port,
        )
        .await;
    } else {
        println!("✓ both tenants have pre-existing channel state; skipping faucet + open");
    }
    stamp("step3 funding+open path", s3);

    // ── Step 4: wait for any Pending channels to become usable ──────────
    let s4 = Instant::now();
    if matches!(alice_state, TenantState::Pending) {
        wait_for_usable(&alice, "alice", EXISTING_CHANNEL_USABLE_TIMEOUT)
            .await
            .expect("alice pending channel");
    }
    if matches!(bob_state, TenantState::Pending) {
        wait_for_usable(&bob, "bob", EXISTING_CHANNEL_USABLE_TIMEOUT)
            .await
            .expect("bob pending channel");
    }
    stamp("step4 wait Pending → Usable", s4);

    // ── Step 5: confirm post-state liquidity matches the test plan ──────
    let s5 = Instant::now();
    let alice_channels = alice.list_channels().await.expect("alice list_channels");
    let bob_channels = bob.list_channels().await.expect("bob list_channels");
    let alice_hub = alice_channels
        .iter()
        .find(|c| c.counterparty == hub_pubkey && c.is_usable)
        .expect("alice has no usable channel to hub after setup");
    let bob_hub = bob_channels
        .iter()
        .find(|c| c.counterparty == hub_pubkey && c.is_usable)
        .expect("bob has no usable channel to hub after setup");
    println!(
        "  alice channel: out={}msat in={}msat",
        alice_hub.outbound_capacity_msat, alice_hub.inbound_capacity_msat
    );
    println!(
        "  bob channel:   out={}msat in={}msat",
        bob_hub.outbound_capacity_msat, bob_hub.inbound_capacity_msat
    );

    assert!(
        alice_hub.outbound_capacity_msat >= PAYMENT_AMOUNT_MSAT + ALICE_OUTBOUND_HEADROOM_MSAT,
        "Alice outbound {}msat too low for a {}msat payment. Her channel is \
         depleted from a prior run — close it manually or wipe tenant state.",
        alice_hub.outbound_capacity_msat,
        PAYMENT_AMOUNT_MSAT
    );
    assert!(
        bob_hub.inbound_capacity_msat >= PAYMENT_AMOUNT_MSAT,
        "Bob inbound {}msat < invoice {}msat. If his channel was freshly opened, \
         wait for hub to propagate push_msat; otherwise inbound was spent by a \
         prior run and you'll need to reopen.",
        bob_hub.inbound_capacity_msat,
        PAYMENT_AMOUNT_MSAT
    );

    stamp("step5 list_channels + liquidity asserts", s5);

    // ── Step 6: Bob issues invoice, Alice pays ──────────────────────────
    let s6a = Instant::now();
    let invoice = bob
        .receive_payment(Some(PAYMENT_AMOUNT_MSAT), "tenant-to-tenant smoke")
        .await
        .expect("bob receive_payment");
    stamp("step6a bob.receive_payment (invoice)", s6a);
    println!(
        "✓ Bob issued invoice ({} chars, hash={})",
        invoice.bolt11.len(),
        hex::encode(invoice.payment_hash)
    );

    let alice_bal_before = alice.lightning_balance().await.expect("alice balance");
    let bob_bal_before = bob.lightning_balance().await.expect("bob balance");
    println!(
        "  before: alice ln={}msat bob ln={}msat",
        alice_bal_before.lightning_msat, bob_bal_before.lightning_msat
    );

    let s6b = Instant::now();
    let payment = alice
        .send_payment(&invoice.bolt11)
        .await
        .expect("alice send_payment");
    stamp("step6b alice.send_payment enqueued", s6b);
    println!(
        "→ Alice send_payment enqueued (status={:?}, hash={})",
        payment.status,
        hex::encode(payment.payment_hash)
    );
    assert_eq!(payment.payment_hash, invoice.payment_hash);

    let s6c = Instant::now();
    wait_for_payment_settled(&alice, &payment.payment_hash, true).await;
    stamp("step6c alice sees Succeeded", s6c);
    let s6d = Instant::now();
    wait_for_payment_settled(&bob, &invoice.payment_hash, false).await;
    stamp("step6d bob sees Succeeded", s6d);
    stamp("TOTAL", t0);

    let alice_bal_after = alice.lightning_balance().await.expect("alice balance");
    let bob_bal_after = bob.lightning_balance().await.expect("bob balance");
    println!(
        "  after:  alice ln={}msat bob ln={}msat",
        alice_bal_after.lightning_msat, bob_bal_after.lightning_msat
    );

    let alice_delta = alice_bal_before
        .lightning_msat
        .saturating_sub(alice_bal_after.lightning_msat);
    assert!(
        alice_delta >= PAYMENT_AMOUNT_MSAT,
        "Alice balance dropped {alice_delta}msat, expected >= {PAYMENT_AMOUNT_MSAT}msat"
    );
    let bob_delta = bob_bal_after
        .lightning_msat
        .saturating_sub(bob_bal_before.lightning_msat);
    assert_eq!(
        bob_delta, PAYMENT_AMOUNT_MSAT,
        "Bob balance grew {bob_delta}msat, expected exactly {PAYMENT_AMOUNT_MSAT}msat"
    );

    println!("✓ tenant-to-tenant payment settled: Alice -{alice_delta}msat, Bob +{bob_delta}msat");
}

// ── Classification ───────────────────────────────────────────────────────────

/// Decide what to do for `client` given the hub pubkey and whether we
/// care about outbound (sender) or inbound (receiver) liquidity.
///
/// Side-effects: none, but the first `list_channels()` call here also
/// serves as the implicit "wake the tenant if parked" warmup call — if
/// the server has parked this tenant since the last run, `dispatch`
/// transparently wakes it during this RPC. The caller doesn't need to
/// do anything special.
async fn classify(
    client: &WickClient,
    label: &str,
    hub_pubkey: PublicKey,
    is_sender: bool,
) -> TenantState {
    let channels = match client.list_channels().await {
        Ok(c) => c,
        Err(e) => panic!("{label} list_channels failed (wake error?): {e}"),
    };
    let to_hub: Vec<_> = channels
        .iter()
        .filter(|c| c.counterparty == hub_pubkey)
        .collect();

    if to_hub.is_empty() {
        println!("• {label}: no channel to hub — funding+open required");
        return TenantState::NeedsFunding;
    }

    if let Some(usable) = to_hub.iter().find(|c| c.is_usable) {
        let enough = if is_sender {
            usable.outbound_capacity_msat >= PAYMENT_AMOUNT_MSAT + ALICE_OUTBOUND_HEADROOM_MSAT
        } else {
            usable.inbound_capacity_msat >= PAYMENT_AMOUNT_MSAT
        };
        if enough {
            println!(
                "• {label}: reusing existing usable channel (out={}, in={})",
                usable.outbound_capacity_msat, usable.inbound_capacity_msat
            );
            return TenantState::Ready;
        }
        println!(
            "• {label}: usable channel exists but liquidity is too low \
             (out={}, in={}) — a previous run likely consumed it",
            usable.outbound_capacity_msat, usable.inbound_capacity_msat
        );
        panic!(
            "{label} channel to hub has insufficient liquidity for this test. \
             Close the channel manually via LDK tooling (no SDK API yet) or \
             reset the tenant's Postgres schema + start with a fresh mnemonic."
        );
    }

    println!("• {label}: pending channel to hub — waiting for usable");
    TenantState::Pending
}

// ── Funding + open path (only runs when at least one tenant needs it) ────────

#[allow(clippy::too_many_arguments)]
async fn run_funding_and_open_path(
    alice: &WickClient,
    bob: &WickClient,
    alice_needs: bool,
    bob_needs: bool,
    esplora: &esplora_client::AsyncClient,
    hub_pubkey: PublicKey,
    hub_host: &str,
    hub_port: u16,
) {
    // Skip the faucet per-tenant when its BDK on-chain balance already
    // covers a channel open. Saves real mutinynet sats across re-runs
    // when prior attempts left UTXOs in the tenant wallets.
    let alice_needs_faucet = alice_needs && {
        let _ = alice.sync_onchain().await;
        let bal = alice.onchain_spendable_sat().unwrap_or(0);
        if bal >= MIN_TENANT_ONCHAIN_SAT {
            println!("• alice on-chain already sufficient ({bal} sats) — skipping faucet");
            false
        } else {
            true
        }
    };
    let bob_needs_faucet = bob_needs && {
        let _ = bob.sync_onchain().await;
        let bal = bob.onchain_spendable_sat().unwrap_or(0);
        if bal >= MIN_TENANT_ONCHAIN_SAT {
            println!("• bob on-chain already sufficient ({bal} sats) — skipping faucet");
            false
        } else {
            true
        }
    };

    if alice_needs_faucet || bob_needs_faucet {
        let mut faucet = faucet_wallet().expect("build faucet BDK wallet");
        sync_full(&mut faucet, esplora).await;

        let tenants_needing = usize::from(alice_needs_faucet) + usize::from(bob_needs_faucet);
        let min_required = FAUCET_TO_SDK_SAT * tenants_needing as u64 + 30_000;
        ensure_faucet_funded(&mut faucet, esplora, min_required).await;

        let alice_addr = if alice_needs_faucet {
            Some(alice.next_address_p2wpkh().expect("alice addr"))
        } else {
            None
        };
        let bob_addr = if bob_needs_faucet {
            Some(bob.next_address_p2wpkh().expect("bob addr"))
        } else {
            None
        };

        let funding_tx = build_faucet_payment(
            &mut faucet,
            alice_addr.as_ref().map(|a| (a, FAUCET_TO_SDK_SAT)),
            bob_addr.as_ref().map(|a| (a, FAUCET_TO_SDK_SAT)),
        )
        .expect("build faucet payment");
        esplora
            .broadcast(&funding_tx)
            .await
            .expect("broadcast faucet payment");
        let funding_txid = funding_tx.compute_txid();
        println!("→ broadcast funding tx {funding_txid}");
        wait_for_confirmation(esplora, &funding_txid.to_string()).await;
    } else {
        println!("✓ both tenants pre-funded — faucet step skipped");
    }

    // Both tenants peer the hub (cheap even if one's already connected
    // — `connect_peer` is idempotent at the server).
    tokio::try_join!(
        async { alice.connect_peer(hub_pubkey, hub_host, hub_port).await },
        async { bob.connect_peer(hub_pubkey, hub_host, hub_port).await }
    )
    .expect("connect_peer hub");
    println!("✓ both tenants connected to Mutiny hub");

    // Only the tenants that need funding open channels now. The other
    // one already has state that `classify` labelled Ready or Pending.
    if alice_needs {
        alice.sync_onchain().await.expect("alice sync_onchain");
        let bal = alice.onchain_spendable_sat().expect("alice spendable");
        assert!(
            bal >= CHANNEL_VALUE_SAT + 5_000,
            "alice on-chain {bal} sats below channel value + fees"
        );
    }
    if bob_needs {
        bob.sync_onchain().await.expect("bob sync_onchain");
        let bal = bob.onchain_spendable_sat().expect("bob spendable");
        assert!(
            bal >= CHANNEL_VALUE_SAT + 5_000,
            "bob on-chain {bal} sats below channel value + fees"
        );
    }

    // Open in parallel when both need it; sequentially otherwise.
    // Mutinynet's public hub can drop the P2P connection between
    // `connect_peer` and `open_channel` — `open_with_retry` re-peers
    // and retries up to 3 times against the "Not connected to node"
    // error LDK surfaces in that window.
    match (alice_needs, bob_needs) {
        (true, true) => {
            let open_started = Instant::now();
            println!("→ open_channel (alice + bob, parallel)");
            tokio::try_join!(
                open_with_retry(alice, hub_pubkey, hub_host, hub_port, CHANNEL_VALUE_SAT, 0),
                open_with_retry(bob, hub_pubkey, hub_host, hub_port, CHANNEL_VALUE_SAT, BOB_PUSH_MSAT)
            )
            .expect("open_channel");
            println!(
                "[+{:>5.1}s] open_channel returned (funding tx broadcast)",
                open_started.elapsed().as_secs_f32()
            );
            let usable_started = Instant::now();
            tokio::try_join!(
                wait_for_usable(alice, "alice", CHANNEL_READY_TIMEOUT),
                wait_for_usable(bob, "bob", CHANNEL_READY_TIMEOUT)
            )
            .expect("wait_for_usable");
            println!(
                "[+{:>5.1}s] both channels usable (3 confs + channel_ready exchange)",
                usable_started.elapsed().as_secs_f32()
            );
        }
        (true, false) => {
            open_with_retry(alice, hub_pubkey, hub_host, hub_port, CHANNEL_VALUE_SAT, 0)
                .await
                .expect("alice open_channel");
            wait_for_usable(alice, "alice", CHANNEL_READY_TIMEOUT)
                .await
                .expect("alice usable");
        }
        (false, true) => {
            open_with_retry(bob, hub_pubkey, hub_host, hub_port, CHANNEL_VALUE_SAT, BOB_PUSH_MSAT)
                .await
                .expect("bob open_channel");
            wait_for_usable(bob, "bob", CHANNEL_READY_TIMEOUT)
                .await
                .expect("bob usable");
        }
        (false, false) => {
            unreachable!("run_funding_and_open_path called with no tenants needing it")
        }
    }
}

// ── SDK helpers ──────────────────────────────────────────────────────────────

/// Open a channel with up-to-3 retries on the LDK "Not connected to
/// node" misuse error. Mutinynet's public hub occasionally drops the
/// TCP/Noise connection between `connect_peer` and `open_channel`;
/// re-peering and retrying papers over the flake without changing
/// product code.
async fn open_with_retry(
    client: &WickClient,
    peer: PublicKey,
    host: &str,
    port: u16,
    value_sat: u64,
    push_msat: u64,
) -> Result<[u8; 32], wick_sdk::Error> {
    let mut last_err: Option<wick_sdk::Error> = None;
    for attempt in 0..3 {
        if attempt > 0 {
            println!("  re-peering hub before open_channel retry #{attempt}");
            let _ = client.connect_peer(peer, host, port).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        match client.open_channel(peer, value_sat, push_msat).await {
            Ok(temp_id) => return Ok(temp_id),
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("Not connected to node") {
                    println!("  open_channel saw 'Not connected' — will retry");
                    last_err = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(last_err.expect("at least one error"))
}

async fn register_client(mnemonic: &str, label: &str) -> WickClient {
    let mut cfg = WickConfig::for_network(WickNetwork::Mutinynet);
    cfg.server_endpoint = "http://127.0.0.1:50051".to_owned();
    // Local dev server's tenant pubkey doesn't match the release pin
    // baked into pinning.rs — the production wick.cloud's identity.
    // Pinning correctness is covered by `tests/pinning_mitm.rs`.
    cfg.disable_pinning = true;
    let client = WickClient::new(mnemonic, None, cfg)
        .await
        .expect("WickClient::new");
    let outcome = client.register("free").await.expect("register");
    println!("✓ {label} tenant {}", outcome.tenant_id);
    client
}

async fn wait_for_usable(client: &WickClient, label: &str, budget: Duration) -> Result<(), String> {
    let started = Instant::now();
    let deadline = started + budget;
    let mut poll_n: u32 = 0;
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "{label} channel did not become usable within {budget:?}"
            ));
        }
        let channels = client
            .list_channels()
            .await
            .map_err(|e| format!("{label} list_channels: {e}"))?;
        if channels.iter().any(|c| c.is_usable) {
            println!(
                "[+{:>5.1}s] ✓ {label} channel usable (poll #{poll_n})",
                started.elapsed().as_secs_f32()
            );
            return Ok(());
        }
        // Surface the per-poll state so we can see Pending → Usable
        // transitions (3 confs on mutinynet ~ 90s).
        if let Some(c) = channels.first() {
            println!(
                "[+{:>5.1}s] {label} poll #{poll_n}: channels={}, first \
                 is_usable={}, out={}msat in={}msat",
                started.elapsed().as_secs_f32(),
                channels.len(),
                c.is_usable,
                c.outbound_capacity_msat,
                c.inbound_capacity_msat,
            );
        } else {
            println!(
                "[+{:>5.1}s] {label} poll #{poll_n}: 0 channels yet",
                started.elapsed().as_secs_f32()
            );
        }
        poll_n += 1;
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_payment_settled(client: &WickClient, payment_hash: &[u8; 32], outbound: bool) {
    let deadline = Instant::now() + PAYMENT_SETTLE_TIMEOUT;
    let role = if outbound { "outbound" } else { "inbound" };
    loop {
        if Instant::now() >= deadline {
            panic!(
                "{role} payment {} did not settle within {PAYMENT_SETTLE_TIMEOUT:?}",
                hex::encode(payment_hash)
            );
        }
        let txs = client.transactions(20, None).await.expect("transactions");
        let hit = txs
            .iter()
            .find(|t| t.payment_hash == *payment_hash && t.is_outbound == outbound);
        if let Some(row) = hit {
            match row.status {
                PaymentStatus::Succeeded => {
                    println!(
                        "✓ {role} settled: amount={}msat fee={}msat",
                        row.amount_msat, row.fee_msat
                    );
                    return;
                }
                PaymentStatus::Failed => {
                    panic!(
                        "{role} payment {} failed — Mutiny hub rejected routing?",
                        hex::encode(payment_hash)
                    );
                }
                _ => {}
            }
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// ── BDK faucet wallet helpers ────────────────────────────────────────────────

fn faucet_wallet() -> Result<Wallet, String> {
    let parsed = Mnemonic::parse(FAUCET_MNEMONIC).map_err(|e| format!("bip39 parse: {e}"))?;
    let seed = parsed.to_seed("");
    let master = Xpriv::new_master(Network::Signet, &seed).map_err(|e| format!("xpriv: {e}"))?;
    let (ext, int) = (
        format!("wpkh({master}/84'/1'/0'/0/*)"),
        format!("wpkh({master}/84'/1'/0'/1/*)"),
    );
    Wallet::create(ext, int)
        .network(Network::Signet)
        .create_wallet_no_persist()
        .map_err(|e| format!("create wallet: {e}"))
}

async fn sync_full(wallet: &mut Wallet, client: &esplora_client::AsyncClient) {
    let request = wallet.start_full_scan().build();
    let response = client
        .full_scan(request, 20, 5)
        .await
        .expect("esplora full_scan");
    wallet.apply_update(response).expect("apply_update full");
}

async fn sync_incremental(wallet: &mut Wallet, client: &esplora_client::AsyncClient) {
    let request = wallet.start_sync_with_revealed_spks().build();
    let response = client.sync(request, 5).await.expect("esplora sync");
    wallet.apply_update(response).expect("apply_update incr");
}

async fn ensure_faucet_funded(
    faucet: &mut Wallet,
    esplora: &esplora_client::AsyncClient,
    min_required_sat: u64,
) {
    let mut balance_sat = faucet.balance().confirmed.to_sat();
    if balance_sat >= min_required_sat.max(FAUCET_MIN_SAT) {
        return;
    }
    let threshold = min_required_sat.max(FAUCET_MIN_SAT);
    let address = faucet.next_unused_address(KeychainKind::External).address;
    println!(
        "\n\
         ─── mutinynet faucet wallet needs a top-up ───────────────────\n\
         address:       {address}\n\
         current bal:   {balance_sat} sats\n\
         need at least: {threshold} sats\n\
         \n\
         Please send sats to the address above via:\n  \
         {MUTINYNET_FAUCET_URL}\n\
         \n\
         Polling balance every {poll}s for up to {timeout_min} min.\n\
         (This only runs on fresh tenants — once Alice and Bob have\n\
          channels, the faucet is never touched again.)\n\
         ──────────────────────────────────────────────────────────────\n",
        poll = POLL_INTERVAL.as_secs(),
        timeout_min = FAUCET_TOPUP_TIMEOUT.as_secs() / 60
    );

    let deadline = Instant::now() + FAUCET_TOPUP_TIMEOUT;
    let mut last_reported = balance_sat;
    while balance_sat < threshold {
        if Instant::now() >= deadline {
            panic!(
                "faucet wallet still below {threshold} sats after \
                 {timeout_min} min — aborting. Top up manually and rerun.",
                timeout_min = FAUCET_TOPUP_TIMEOUT.as_secs() / 60
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
        sync_incremental(faucet, esplora).await;
        balance_sat = faucet.balance().confirmed.to_sat();
        if balance_sat != last_reported {
            println!("  faucet balance: {balance_sat} sats");
            last_reported = balance_sat;
        }
    }
    println!("✓ faucet funded ({balance_sat} sats)\n");
}

/// Build a single tx that pays either one or both recipients. Passing
/// `None` for a slot skips it. At least one slot must be `Some`.
fn build_faucet_payment(
    wallet: &mut Wallet,
    to_a: Option<(&Address, u64)>,
    to_b: Option<(&Address, u64)>,
) -> Result<Transaction, String> {
    if to_a.is_none() && to_b.is_none() {
        return Err("build_faucet_payment called with no recipients".to_owned());
    }
    let mut tx_builder = wallet.build_tx();
    if let Some((addr, amt)) = to_a {
        tx_builder.add_recipient(addr.script_pubkey(), Amount::from_sat(amt));
    }
    if let Some((addr, amt)) = to_b {
        tx_builder.add_recipient(addr.script_pubkey(), Amount::from_sat(amt));
    }
    tx_builder.fee_rate(FeeRate::from_sat_per_vb_unchecked(2));
    tx_builder.nlocktime(LockTime::ZERO);
    let mut psbt = tx_builder
        .finish()
        .map_err(|e| format!("TxBuilder::finish: {e}"))?;
    let finalised = wallet
        .sign(&mut psbt, SignOptions::default())
        .map_err(|e| format!("sign: {e}"))?;
    if !finalised {
        return Err("psbt not finalised".to_owned());
    }
    psbt.extract_tx().map_err(|e| format!("extract_tx: {e}"))
}

async fn wait_for_confirmation(client: &esplora_client::AsyncClient, txid_str: &str) {
    use bdk_wallet::bitcoin::Txid;
    let txid = Txid::from_str(txid_str).expect("txid parse");
    let deadline = Instant::now() + FUNDING_CONFIRM_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            panic!("funding tx {txid_str} unconfirmed after {FUNDING_CONFIRM_TIMEOUT:?}");
        }
        match client.get_tx_status(&txid).await {
            Ok(status) => {
                if status.confirmed {
                    println!("  funding tx confirmed at height {:?}", status.block_height);
                    return;
                }
            }
            Err(e) => {
                eprintln!("  get_tx_status error (will retry): {e}");
            }
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn mutiny_hub() -> (PublicKey, String, u16) {
    let (hub_pubkey_hex, hub_host_port) = WickNetwork::Mutinynet
        .seed_peers()
        .first()
        .copied()
        .expect("mutinynet has at least one seed peer");
    let hub_pubkey_bytes = hex::decode(hub_pubkey_hex).expect("hub pubkey hex");
    let hub_pubkey = PublicKey::from_slice(&hub_pubkey_bytes).expect("hub pubkey");
    let (hub_host, hub_port_str) = hub_host_port.split_once(':').expect("host:port");
    let hub_port: u16 = hub_port_str.parse().expect("hub port");
    (hub_pubkey, hub_host.to_owned(), hub_port)
}
