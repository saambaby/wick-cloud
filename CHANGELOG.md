# Changelog

All notable changes to Wick Cloud are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it leaves
the pre-release phase.

## [Unreleased]

### Added

- **SDK network awareness.** `wick_sdk::WickConfig.network` is now
  `WickNetwork` (not `bitcoin::Network`), so Mutinynet is distinguishable
  from Signet at the SDK boundary. `WickConfig::for_network(WickNetwork)`
  auto-selects the right Esplora endpoint; `WickConfig::faucet_url()`
  exposes the per-network faucet without requiring callers to reach into
  `wick-core`. `WickNetwork` is re-exported at the `wick_sdk` crate root.
- **Decode-failure quarantine for critical LDK state.** `PgKvStore::quarantine`
  copies undecodable bytes to `quarantine/<unix_ts>/<original_key>` before
  `WickLightningError::PersistenceDecode` propagates out of
  `NodeBuilder::build`. A new `ProvisionError::CorruptState` variant maps to
  gRPC `FAILED_PRECONDITION` so clients know retry won't help and operator
  intervention is required. Gossip state (`NetworkGraph`, `ProbabilisticScorer`)
  deliberately keeps the silent-fresh-fallback because RGS re-seeds it within
  minutes.
- **Durable `PendingFundingRegistry`.** New `FundingStore` persists parked
  funding requests to `tenant_*.pending_funding`. `park` mirrors to Postgres
  as fire-and-forget (in-memory remains authoritative); `take` deletes the
  row on delivery; `rehydrate_from_store` repopulates the in-memory `ready`
  map on boot after sweeping rows older than `FUNDING_TTL` (1 h). An actor
  crash between `park` and `take` no longer drops the client's in-flight
  channel open.
- **RGS exponential backoff.** `gossip::spawn_gossip_tasks` steps through
  `[1 min, 5 min, 30 min, 2 h]` on consecutive `apply_rgs` failures, then
  falls back to the normal 24 h cadence. Success resets the counter. Covered
  by `gossip::rgs_backoff_tests`.
- **Per-network scorer decay tuning.** `gossip::decay_params_for(WickNetwork)`
  returns: Regtest 5 min / 30 min (fast-decay for sub-second-block test
  runs); Mutinynet 10 min / 2 days (tuned for 30-second blocks); Signet
  default LDK values (matches mainnet cadence). `init_gossip` and
  `load_or_init_scorer` take `WickNetwork` so the chosen params flow into
  both the fresh constructor and the `ProbabilisticScorer::read` rehydrate
  path.
- **Tenant-to-tenant mutinynet integration test**
  (`crates/wick-sdk/tests/integration_mutinynet.rs`, `#[ignore]`). Two SDK
  clients (Alice, Bob) on the same `wick-server` settle a real Lightning
  payment over the Mutiny hub. Alice opens with `push_msat = 0` (pure
  outbound); Bob opens with `push_msat = 30 000 000` so the hub has balance
  on Bob's channel (= Bob's inbound liquidity). Bob issues a 5 000-sat
  invoice, Alice pays, the test polls both sides' `transactions()` until
  the row flips to `Succeeded` and asserts `lightning_balance` deltas
  (Alice ≥ payment + routing fee; Bob exactly payment).
- **Idempotent re-runs of the mutinynet test.** Alice, Bob, and the faucet
  all use **persistent const BIP39 mnemonics** (committed, dev-public). A
  `TenantState::{Ready, Pending, NeedsFunding}` classification step calls
  `list_channels()` and decides whether to reuse an existing usable
  channel (skip faucet + open entirely), wait for a pending channel to
  confirm, or run the full funding + open path. Steady-state re-runs take
  ~10 seconds instead of ~10 minutes; the faucet prompt only fires when
  at least one tenant genuinely needs funding.

### Changed

- **`wick-sdk` depends on `wick-core`.** Added to enable the `WickNetwork`
  refactor. The custody boundary is intact: `wick-sdk → wick-lightning`
  is still forbidden. `wick-core` is pure types (`WickNetwork`, `TenantId`,
  `WickIdentity`), safe to share across the seed-slice / device-slice
  boundary.
- **Existing SDK integration test (`regtest_flow.rs`)** updated to
  `WickConfig::for_network(WickNetwork::Regtest)` — was previously
  `bitcoin::Network::Regtest`.
- **Mutinynet test helpers restructured.** Funding is now batched into a
  single BDK transaction that pays both tenants' on-chain addresses at
  once, avoiding the pitfall of building two sequential sends from the
  same wallet before the first tx's change output is visible. The faucet
  top-up prompt logs only on balance change (not every 15 s tick).
- **Node builder wires `FundingStore`.** `NodeBuilder::build` now
  constructs a `FundingStore` from the tenant's Postgres pool, passes it
  to `PendingFundingRegistry::with_store`, and calls `rehydrate_from_store`
  before the node begins accepting dispatches.
- **`init_gossip` signature** widened from `bitcoin::Network` to
  `WickNetwork` so the per-network decay parameters are threaded through.

### Fixed

- **`WickConfig::for_network(bitcoin::Network::Signet)` silently collapsing
  Mutinynet to Signet.** Callers previously had to hand-override
  `esplora_url` to point at `https://mutinynet.com/api` or the SDK would
  fetch from the wrong chain. Now `WickNetwork::Mutinynet` picks the right
  defaults automatically.
- **Silent state loss on `ChannelManager` / `ChannelMonitor` decode
  failure.** Previously the builder logged a warning and fell through to
  a fresh `ChannelManager`, which could orphan in-flight HTLCs and channel
  state. Now decode failures quarantine the bytes and hard-fail boot with
  `FAILED_PRECONDITION`.
- **`PendingFundingRegistry` evaporating on actor crash.** In-memory-only
  storage meant any crash between `park` and the client's
  `open_channel_finalize` dropped the request silently. Durable backing
  rehydrates surviving rows on boot (subject to the 1 h TTL).
- **24-hour gaps in graph freshness after a transient RGS fetch failure.**
  Previously a single failed fetch waited the full 24 h until the next
  tick. Now exponential backoff retries within minutes.

### Security

- **Observation: `CreateTenantRequest` authenticates by pubkey alone, no
  signature challenge.** `wick-server::grpc::create_tenant` accepts any
  hex-encoded secp256k1 pubkey and upserts a tenant bearer token against
  it. Anyone who knows a tenant's pubkey can rotate its bearer token and
  adopt its on-chain state including open channels. Mitigations:
  server-side LDK keys are HMAC-derived from the server master seed (not
  the client pubkey), so an adopter cannot unilaterally move channel
  funds on-chain without the server's cooperation; but the hole is real
  as a deanonymisation / DoS vector. Phase 4 VLS / signed-attestation
  fix target.

### Known Issues

- **Lost-mnemonic orphan channels are sunk cost.** The SDK-side BDK seed
  and Lightning identity share a mnemonic; losing it makes the on-chain
  refund path unreachable from the SDK. Server-side LDK still has signing
  keys and could in principle drive a mutual close, but no operator RPC
  exists for this yet. Always use persistent const mnemonics in
  integration tests for this reason. Tracking issue: `wick-server`
  operator-driven close RPC (not scheduled).

---

## Historical milestones (pre-changelog, preserved from project notes)

### 2026-04-23 — Phase 5 slice 1: self-custodial SDK

- `wick-sdk` Rust client (`WickClient`) landed, composing BIP39 identity,
  dual BDK BIP84/BIP86 wallets, an Esplora client, and a tonic gRPC
  client with a bearer-token interceptor.
- **Channel open is now two-phase and self-custodial**: `OpenChannelInit`
  returns the 2-of-2 multisig `output_script` from LDK's
  `FundingGenerationReady`; the client builds and signs the funding tx on
  its own BDK wallet; `OpenChannelFinalize` hands the signed tx to LDK's
  `ChannelManager::funding_transaction_generated`.
- Server is **no longer custodial of channel-funding UTXOs**.
  `TenantFundingWallet`, `per_tenant_funding` config, and the
  `GetOnchainAddress` RPC were removed.
- `PendingFundingRegistry` introduced in `wick-lightning` to cross the
  sync-LDK-event / async-RPC-caller boundary via oneshot-per-key +
  re-check (not `tokio::sync::Notify`, which has a miss-the-wake race).
- `wick-testkit` deleted; dev/test workflows now use
  `wick_sdk::regtest::{RegtestRpc, wait_until_async}` (feature-gated).

### 2026-04-23 — Phase 2 closeout

- `park_never_parks_with_pending_activity` proptest (256 cases).
- Notify-race regression test.
- `just park-wake-demo` acceptance target backed by
  `examples/park_wake_demo.rs`: 100 tenants, 50 concurrent wakes,
  p50/p95/p99 latency snapshot.
- `just ci-local` runs the `loom` model.
- Event-during-park buffer scaffold (`node::event_buffer::PendingEventStore`).
- Signet + mutinynet support via `deploy/docker/config.{signet,mutinynet}.toml`
  + `just {signet,mutinynet}-run`.
- Five Phase-2 correctness fixes in commit `ca7680f`: Notify enable before
  state re-check; emergency evict via `force_park` not `Shutdown`;
  `wake_loading` CAS-fail rollback via `force_park`; recovery probes at
  `WakePriority::Payment`; Shutdown-during-Park drops `resp` rather than
  lying with `RequeuedDueToActivity`.

### 2026-04-18 — Test harness consolidation

- Merged `ldk_assembly.rs` + `multi_tenant.rs` into
  `tests/integration/mod.rs` in `wick-testkit`. Registered `[[test]]`
  binary in `Cargo.toml`. Migrated `TenantId` to UUID across all test
  files. Eliminated the `wick-tests` crate. Moved `Harness`,
  `ProvisionalWallet`, `wait_until_async` into `wick-testkit/src/harness.rs`.

### 2026-04-14 — Phase 1: real LDK 0.2 assembly

- `Node<S: WickSigner>` with real `ChannelManager`, `ChainMonitor`,
  `PeerManager`, `BackgroundProcessor`, SPV loop, peer-reconnect loop.
- `NodeBuilder` + `EventHandler` + `FundingSource` + `OutputSweeperSync`.
- `ChannelManager` restart-load via `read_channel_monitors` +
  `ChannelManagerReadArgs` + `init::synchronize_listeners`.
- Stub `Node` / `stub_factory` / redundant mock tests deleted.
- Real HMAC-derived `NodeFactory` in `wick-server`'s `main.rs`.

### 2026-04-13 — Phase 0 scaffolding + v0.2 security audit

- 13-crate Cargo workspace; rust-toolchain pin; justfile; deny.toml;
  clippy.toml; CI workflow (fmt/clippy/test+postgres/audit/deny).
- Global + `tenant_template` migrations.
- Docker-compose dev stack: bitcoind regtest, postgres, electrs, esplora.
- `wick-core` with `TenantId` validator + proptest.
- `wick-db` with `tenant_tx` (`SET LOCAL` + `AfterRelease RESET ALL` +
  runtime guard emitting `tenant_guard_mismatch_total`).
- v0.2 security audit: 24 vulnerabilities catalogued and fixed inline in
  `docs/wick_architecture.md` (multi-tenancy, reorg, griefing,
  wake-storm, SSRF, macaroon revocation, WASM seed, key pinning,
  privacy).

[Unreleased]: https://github.com/saambaby/wick-cloud/compare/main...HEAD
