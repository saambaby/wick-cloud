//! End-to-end integration tests for the real LDK assembly.
//!
//! Two tests here, both `#[ignore]` by default because they require the
//! docker-compose stack in `deploy/docker/` (bitcoind + esplora + Postgres).
//!
//! 1. [`two_node_payment_over_channel`] — provisions Alice + Bob, funds
//!    Alice's BDK wallet with a coinbase, peers them, opens a real 200 k
//!    sat channel from Alice to Bob (exercises the `FundingSource`
//!    callback), mines the funding tx to usable, then pays a Bob invoice
//!    and asserts the balance + `PaymentStore` row on Alice.
//!
//! 2. [`channel_state_survives_restart`] — provisions Alice, opens a
//!    channel, shuts down, re-runs `NodeBuilder::build` against the same
//!    tenant schema, asserts the channel reloaded from Postgres.
//!
//! ## Running
//!
//! ```sh
//! just regtest-up
//! cargo test -p wick-testkit --test ldk_assembly -- --ignored --nocapture
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use lightning_invoice::Bolt11Invoice;
use sqlx::PgPool;
use wick_core::TenantId;
use wick_lightning::{from_seed, LocalKeysManager, NodeApi, NodeBuilder};
use wick_testkit::{deterministic_seed, stub_deps, Regtest, StubDepsConfig, TestWallet};

// ── Shared helpers ────────────────────────────────────────────────────────────

fn tenant_ddl(schema: &str) -> Vec<String> {
    vec![
        format!(
            r#"CREATE TABLE IF NOT EXISTS "{schema}".payments (
                id BIGSERIAL PRIMARY KEY,
                payment_hash BYTEA NOT NULL,
                preimage BYTEA,
                direction TEXT NOT NULL CHECK (direction IN ('inbound','outbound')),
                amount_msat BIGINT NOT NULL,
                fee_msat BIGINT NOT NULL DEFAULT 0,
                status TEXT NOT NULL CHECK (status IN ('pending','succeeded','failed')),
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )"#
        ),
        format!(
            r#"CREATE UNIQUE INDEX IF NOT EXISTS payments_hash_direction_uniq
                ON "{schema}".payments(payment_hash, direction)"#
        ),
        format!(
            r#"CREATE TABLE IF NOT EXISTS "{schema}".peers (
                pubkey BYTEA PRIMARY KEY,
                address TEXT,
                alias TEXT,
                last_seen_at TIMESTAMPTZ
            )"#
        ),
        format!(
            r#"CREATE TABLE IF NOT EXISTS "{schema}".vss_objects (
                key TEXT PRIMARY KEY,
                version BIGINT NOT NULL,
                value BYTEA NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )"#
        ),
    ]
}

async fn ensure_tenant_schema(pool: &PgPool, tenant_id: TenantId) {
    let schema = tenant_id.schema_name();
    sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS \"{schema}\""))
        .execute(pool)
        .await
        .expect("create schema");
    for ddl in tenant_ddl(&schema) {
        sqlx::query(&ddl).execute(pool).await.expect("DDL");
    }
}

/// Poll `predicate` until it returns `true` or `timeout` elapses. Panics
/// with `label` on timeout. Poll cadence is 200 ms.
async fn wait_until_async<F, Fut>(label: &str, timeout: Duration, mut predicate: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while !predicate().await {
        if tokio::time::Instant::now() >= deadline {
            panic!("wait_until `{label}` timed out after {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Mine `confirmations` blocks with coinbase outputs going to a fresh address
/// derived from `wallet`, then sync the wallet via Electrs so the UTXOs are
/// visible to BDK.
///
/// Coinbase outputs require 100 confirmations before they're spendable on
/// regtest, so we mine an extra 100 blocks after the initial set.
async fn fund_bdk_wallet(
    regtest: &Regtest,
    wallet: &TestWallet,
    confirmations: u64,
    electrum_url: &str,
) {
    let addr = wallet.next_address().expect("next_address");
    regtest.mine_to(confirmations, &addr).expect("mine_to");
    // Mine 100 more blocks so coinbase maturity kicks in.
    regtest.mine(100).expect("mature coinbase");
    wallet.sync(electrum_url).expect("wallet sync");
}

/// Provision a real `Node<LocalKeysManager>` for `tenant_id`. If
/// `with_wallet` is `Some`, bind it as both the `FundingSource` and the
/// `change_destination` (via `next_address().script_pubkey()`).
async fn provision_node(
    tenant_id: TenantId,
    pool: &PgPool,
    with_wallet: Option<Arc<TestWallet>>,
) -> Arc<dyn NodeApi> {
    ensure_tenant_schema(pool, tenant_id).await;

    let deps = stub_deps(&StubDepsConfig::default()).expect("stub_deps");
    let signer = Arc::new(from_seed(deterministic_seed(tenant_id)));

    let mut builder =
        NodeBuilder::<LocalKeysManager>::new(tenant_id, deps).with_signer(signer);

    if let Some(wallet) = with_wallet.as_ref() {
        builder = builder.with_funding_source(wallet.clone());
        let addr = wallet.next_address().expect("change dest");
        builder = builder.with_change_destination(addr.script_pubkey());
    }

    builder.build().await.expect("NodeBuilder::build")
}

/// Idempotent setup: bitcoind reachable, wallet loaded, minimum height.
async fn bootstrap_regtest() -> Regtest {
    let rt = Regtest::default_connect().expect("bitcoind connect");
    rt.wait_ready(Duration::from_secs(10))
        .await
        .expect("bitcoind ready");
    rt.ensure_wallet("testkit").expect("ensure_wallet");
    // Initial maturity pad so `validate_best_block_header` sees a non-empty chain.
    let h = rt.tip_height().unwrap_or(0);
    if h < 101 {
        rt.mine(101 - u64::from(h)).expect("initial mine");
    }
    rt
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("wick_lightning=info,ldk=info")
        .with_test_writer()
        .try_init();
}

async fn shared_pool(cfg: &StubDepsConfig) -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&cfg.database_url)
        .await
        .expect("postgres connect")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires bitcoind regtest + esplora + postgres (just regtest-up)"]
async fn two_node_payment_over_channel() {
    init_tracing();
    let regtest = bootstrap_regtest().await;
    let cfg = StubDepsConfig::default();
    let pool = shared_pool(&cfg).await;

    let alice_id = TenantId::new(9_001);
    let bob_id = TenantId::new(9_002);

    // Alice has a BDK wallet for funding; Bob doesn't open channels.
    let alice_wallet = Arc::new(
        TestWallet::new(deterministic_seed(alice_id), cfg.network).expect("TestWallet::new"),
    );
    fund_bdk_wallet(&regtest, &alice_wallet, 1, &cfg.electrum_url).await;
    assert!(
        alice_wallet.spendable_sat().unwrap_or(0) > 50_000_000,
        "Alice should have > 0.5 BTC after coinbase maturity"
    );

    let alice = provision_node(alice_id, &pool, Some(alice_wallet.clone())).await;
    let bob = provision_node(bob_id, &pool, None).await;

    let alice_pk = alice.node_id();
    let bob_pk = bob.node_id();
    assert_ne!(alice_pk, bob_pk, "tenants must have distinct node ids");

    let bob_addr = bob
        .local_listen_addr()
        .expect("Bob must have a listen address after build");

    // Alice dials Bob.
    alice
        .connect_peer(bob_pk, "127.0.0.1", bob_addr.port())
        .await
        .expect("connect_peer");

    // Open a 200_000 sat channel. `FundingGenerationReady` triggers the
    // BDK wallet to produce a signed funding tx which LDK broadcasts.
    alice
        .open_channel(bob_pk, 200_000, 0)
        .await
        .expect("open_channel");

    // Mine funding confirmations. Poll Alice's channel list until a
    // channel with the right counterparty is reported as usable.
    let alice_for_wait = alice.clone();
    wait_until_async(
        "alice sees a pending channel",
        Duration::from_secs(30),
        move || {
            let a = alice_for_wait.clone();
            async move {
                a.list_channels()
                    .await
                    .map(|chs| chs.iter().any(|c| c.counterparty == bob_pk))
                    .unwrap_or(false)
            }
        },
    )
    .await;

    // LDK funding-confirm requires 6 blocks by default. Mine more to be safe.
    regtest.mine(10).expect("mine funding confs");

    let alice_for_wait = alice.clone();
    wait_until_async(
        "channel is usable on Alice's side",
        Duration::from_secs(60),
        move || {
            let a = alice_for_wait.clone();
            async move {
                a.list_channels()
                    .await
                    .map(|chs| chs.iter().any(|c| c.counterparty == bob_pk && c.is_usable))
                    .unwrap_or(false)
            }
        },
    )
    .await;

    // Bob produces an invoice; Alice pays it.
    let invoice_str = bob
        .receive_payment(Some(10_000), "e2e")
        .await
        .expect("receive_payment");
    let invoice = Bolt11Invoice::from_str(&invoice_str).expect("parse invoice");
    let payment_hash_hex = hex::encode(invoice.payment_hash().as_ref() as &[u8]);

    let result = alice
        .send_payment(&invoice_str)
        .await
        .expect("send_payment enqueue");
    assert_eq!(result.status, "pending");

    // Wait for PaymentSent → PaymentStore → status=succeeded.
    let alice_for_wait = alice.clone();
    let hash_needle = payment_hash_hex.clone();
    wait_until_async(
        "Alice's PaymentStore reports the outbound payment as succeeded",
        Duration::from_secs(30),
        move || {
            let a = alice_for_wait.clone();
            let hash_needle = hash_needle.clone();
            async move {
                let txns = a.get_transactions(20).await.unwrap_or_default();
                txns.iter().any(|p| {
                    hex::encode(&p.payment_hash) == hash_needle
                        && p.is_outbound
                        && p.status == "succeeded"
                })
            }
        },
    )
    .await;

    // Balance assertions.
    let alice_bal = alice.get_balance().await.expect("balance");
    assert!(
        alice_bal.lightning_balance_msat < 200_000_000,
        "Alice's outbound capacity must decrease after payment: got {}",
        alice_bal.lightning_balance_msat
    );
    assert!(
        alice_bal.lightning_balance_msat > 190_000_000,
        "Alice should not have lost more than ~10M msat to fees + payment: got {}",
        alice_bal.lightning_balance_msat
    );

    let bob_bal = bob.get_balance().await.expect("balance");
    assert!(
        bob_bal.lightning_balance_msat >= 10_000,
        "Bob should have at least the received 10k msat as outbound capacity: got {}",
        bob_bal.lightning_balance_msat
    );

    // Clean shutdown.
    alice.shutdown().await;
    bob.shutdown().await;

    // Silence unused bindings on the assertion path.
    let _: PublicKey = alice_pk;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires bitcoind regtest + esplora + postgres (just regtest-up)"]
async fn channel_state_survives_restart() {
    init_tracing();
    let regtest = bootstrap_regtest().await;
    let cfg = StubDepsConfig::default();
    let pool = shared_pool(&cfg).await;

    let alice_id = TenantId::new(9_101);
    let bob_id = TenantId::new(9_102);

    let alice_wallet = Arc::new(
        TestWallet::new(deterministic_seed(alice_id), cfg.network).expect("TestWallet::new"),
    );
    fund_bdk_wallet(&regtest, &alice_wallet, 1, &cfg.electrum_url).await;

    let alice = provision_node(alice_id, &pool, Some(alice_wallet.clone())).await;
    let bob = provision_node(bob_id, &pool, None).await;

    let bob_pk = bob.node_id();
    let bob_addr = bob.local_listen_addr().expect("bob listen addr");

    alice
        .connect_peer(bob_pk, "127.0.0.1", bob_addr.port())
        .await
        .expect("connect_peer");
    alice
        .open_channel(bob_pk, 150_000, 0)
        .await
        .expect("open_channel");

    // Wait until the channel at least appears on Alice's side — we don't
    // need it to be `is_usable` for the persistence round-trip to be
    // meaningful; the `ChannelMonitor` write happens as soon as the
    // funding tx is generated.
    let alice_for_wait = alice.clone();
    wait_until_async(
        "alice records at least one channel",
        Duration::from_secs(30),
        move || {
            let a = alice_for_wait.clone();
            async move {
                a.list_channels()
                    .await
                    .map(|c| !c.is_empty())
                    .unwrap_or(false)
            }
        },
    )
    .await;

    regtest.mine(6).expect("mine funding confs");
    // Tolerate eventual consistency — give the event loop a tick to
    // persist monitor + manager state.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let pre_channels = alice.list_channels().await.expect("list_channels pre");
    let pre_counts = pre_channels.len();
    let pre_channel_id = pre_channels
        .first()
        .map(|c| c.channel_id.clone())
        .expect("at least one channel before restart");

    // Shutdown Alice — background tasks stop cleanly and persist their
    // final state into Postgres on exit.
    alice.shutdown().await;
    bob.shutdown().await;
    drop(alice);
    drop(bob);
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Re-provision Alice against the same tenant schema + Postgres pool.
    // The load path in `NodeBuilder::build` should read monitors + manager
    // from the `vss_objects` table.
    let alice2 = provision_node(alice_id, &pool, Some(alice_wallet.clone())).await;

    let post_channels = alice2.list_channels().await.expect("list_channels post");
    assert_eq!(
        post_channels.len(),
        pre_counts,
        "channel count must survive restart: pre={pre_counts} post={}",
        post_channels.len()
    );
    assert!(
        post_channels.iter().any(|c| c.channel_id == pre_channel_id),
        "original channel id must be present after restart"
    );

    alice2.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires bitcoind regtest + esplora + postgres (just regtest-up)"]
async fn node_builder_rejects_missing_signer() {
    let deps = stub_deps(&StubDepsConfig::default()).expect("stub_deps");
    let err = NodeBuilder::<LocalKeysManager>::new(TenantId::new(42_000), deps)
        .build()
        .await
        .expect_err("build must fail when no signer is bound");
    assert!(err.to_string().contains("signer is required"));
}
