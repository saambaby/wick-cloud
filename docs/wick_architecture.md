**WICK**

Platform Architecture

*wick.cloud*

Self-custodial Bitcoin Lightning infrastructure.

Open-source stack. Hosted cloud. Open SDK.

Version 0.2 --- April 2026

*Confidential --- Internal Architecture Reference*

**Table of Contents**

**1 Executive Summary**

Wick is a self-custodial Bitcoin Lightning platform built in three fully open-source tiers: infrastructure server, developer SDK, and reference wallet application. Every tier is independently deployable --- developers can self-host the entire stack, consume the hosted cloud instance, or combine both.

The foundational design principle is that user seeds and signing keys never leave the user\'s device. A Validating Lightning Signer (VLS) running on-device enforces a strict policy engine on every signature request. The hosted ldk-server handles channel management, routing, and LSP liquidity without ever having access to private keys, giving users Lightning-speed transactions with genuine self-custodial guarantees.

On top of this infrastructure sits a developer SDK targeting Rust, Flutter/Dart, JavaScript/WASM, and any platform supporting NWC (Nostr Wallet Connect). Developers integrate Wick into their products via a clean API --- the SDK handles the VLS signer, channel state, VSS backups, and the encrypted tunnel to the server transparently. The reference Flutter wallet serves both as a consumer product and as a live demonstration of the SDK\'s capabilities.

**2 System Overview**

**2.1 Three-Tier Architecture**

The platform is organised into three tiers with clean separation of concerns. Each tier can be consumed independently by third-party developers.

  ------------ ------------------- ---------------------------------------------------------------------------------------
  **Tier**     **Name**            **Responsibility**

  **1**        Infrastructure      ldk-server, VSS server, relay mailbox, LSP daemon --- all hosted, all open-source

  **2**        SDK                 Rust core, VLS signer, Noise tunnel, Macaroon engine, Flutter bridge, WebLN/WASM, NWC

  **3**        Product             Reference Flutter wallet, on-chain portfolio view, WebLN browser provider
  ------------ ------------------- ---------------------------------------------------------------------------------------

**2.2 Core Design Decisions**

**LDK, not LND.** LDK (Lightning Dev Kit) is modular, Rust-native, and designed for embedding. It gives fine-grained control over channel state, persistence, signing, and networking that LND\'s monolithic architecture does not.

**VLS on device, node on server.** The seed and all signing keys remain on the user\'s device inside the VLS signer. The ldk-server manages channel logic and routing but cannot produce signatures. Blind signing is explicitly rejected as a security anti-pattern.

**Actor model, not shared state.** Each wallet tenant is an isolated WalletActor owning its LdkNode exclusively via a tokio mpsc channel. No Arc\<Mutex\<LdkNode\>\> anywhere. This eliminates memory races and enables safe park/wake lifecycle management.

**Multi-tenant single process.** One ldk-server process hosts thousands of wallets. Shared resources (Esplora pool, NetworkGraph, RGS cache, PgPool) are injected via Arc into each actor. Per-tenant state is isolated in separate Postgres schemas.

**One LiquidityManager for all wallets.** The LSP daemon runs a single LiquidityManager as the CustomMessageHandler for the LSP node. Events are dispatched to the correct WalletActor via a peer_registry DashMap lookup.

**Noise_KK for the signing channel.** The VLS signer communicates with ldk-server over a Noise_KK-authenticated WebSocket tunnel, providing mutual authentication using Lightning keypairs and forward secrecy. Macaroons layer on top for scoped authorisation without database lookups.

**3 Tier 1 --- Infrastructure**

**3.1 ldk-server**

ldk-server is a multi-tenant Rust server exposing a gRPC API. It hosts one LdkNode per wallet tenant, manages the full Lightning lifecycle, and integrates with the LSP daemon for liquidity. It is the component that third-party developers point their SDK at --- either the hosted cloud instance at wick.cloud or their own self-hosted deployment.

Key server-wide shared resources (created once at startup, injected via Arc into every actor):

- EsploraClient pool --- shared across all tenants for chain data and fee estimation

- NetworkGraph + RapidGossipSync (RGS) --- single graph updated from the network, serving all routing decisions

- PgPool --- Postgres connection pool; queries route to the correct tenant schema automatically via search_path

- LiquidityManager --- single instance as CustomMessageHandler of the LSP node

- WebhookDispatcher --- fires LSPS5 push notifications on behalf of the LSP

**3.2 WalletManager**

WalletManager owns the full lifecycle of all wallet tenants. Its primary data structure is a DashMap\<TenantId, WalletHandle\> --- a lock-free concurrent hashmap enabling O(1) lookups without contention. A global AtomicUsize tracks total RAM consumed across all active wallets, enforcing a configurable memory budget with LRU eviction when approaching the limit.

  --------------------- --------------------------- ------------------------------------------------------------
  **Field**             **Type**                    **Purpose**

  tx                    mpsc::Sender\<WalletCmd\>   Sends commands to the actor task

  state                 Arc\<AtomicU8\>             Parked(0) / Loading(1) / Active(2) / Error(3)

  last_active           Arc\<AtomicU64\>            Unix timestamp, SeqCst ordering, drives LRU eviction

  mem_bytes             Arc\<AtomicUsize\>          RAM reserved for this wallet, counted toward global budget

  wake_notify           Arc\<Notify\>               Signals concurrent wake waiters when loading completes
  --------------------- --------------------------- ------------------------------------------------------------

**3.3 WalletActor**

Each tenant runs as a dedicated tokio task --- the WalletActor. It owns its LdkNode exclusively (never shared via Arc). All interaction happens through the mpsc channel, serialising access and eliminating any need for internal mutexes. The actor processes one WalletCmd at a time and updates last_active on every message.

WalletCmd variants:

- SendPayment, ReceivePayment, GetBalance, GetTransactions --- user-facing operations

- OpenJitChannel --- triggered by the LSP daemon on a JIT HTLC intercept

- LspEvent(LiquidityEvent) --- dispatched from the LspEventLoop after peer_registry lookup

- Park --- queued by the activity poller; processed safely after the current command completes

- Activate { node, tasks } --- sent during the wake path to install a freshly loaded LdkNode

**3.4 Park / Wake Lifecycle**

Wallets are parked (serialised to Postgres and dropped from RAM) after five minutes of inactivity with no pending HTLCs. Two background tasks manage this:

- Activity poller (30s interval) --- scans last_active timestamps, sends Park to idle wallets

- Memory pressure evictor (10s interval) --- at 80% budget, evicts the LRU wallet; at 95%, emergency eviction

Wake uses a compare-and-exchange on the state AtomicU8 so that exactly one task wins the Parked → Loading transition. Concurrent callers wait on wake_notify rather than spinning. Wake is always wrapped in timeout_at(deadline) to ensure it completes within the CLTV window when triggered by an incoming payment.

Three additional mechanisms bound the wake path under adversarial load:

- **Global wake semaphore.** `Semaphore::new(max_concurrent_wakes)` sized at `memory_budget / avg_wallet_bytes * 0.5`. Every wake acquires a permit before loading; over-subscription blocks rather than OOMs.
- **Priority queue.** Two tiers: `Priority::Payment` (HTLC-driven, CLTV-bounded) preempts `Priority::User` (GetBalance, etc.). Under congestion, payment wakes always land first.
- **Per-tenant rate limit.** Token bucket per tenant (default 3 wakes/min). Exhaustion returns "parked, try later" to user wakes; HTLCs fail back early rather than starving other tenants.
- **Headroom reservation.** The memory evictor always preserves 20% of the budget for incoming wakes; emergency eviction never consumes this headroom.

Race conditions and mitigations:

  -------------------------------- -------------------------------------------------------------------------------------
  **Race**                         **Mitigation**

  **Double wake-up**               compare_exchange(Parked, Loading) --- only one winner; losers await Notify

  **Park during active request**   Park cmd queued on mpsc; actor processes it after current command

  **Park with in-flight HTLC**     Post-drain check in Park handler: has_pending_htlcs() || has_inflight_payment() || has_unresolved_monitor_event() --- if true, CAS back to Active and requeue Park after park_retry_delay_s

  **Event during park/loading**    LspEventLoop checks state before dispatch; events for Parked/Loading wallets queue in a persistent dispatch buffer that drains on next wake

  **Budget overshoot**             fetch_add reserves budget atomically before loading; evict-then-retry if over limit

  **Wake storm**                   Global semaphore + priority queue + per-tenant rate limit bound concurrent wakes to a memory-safe envelope

  **Error state stuck**            error_recovery_loop (60s) re-probes Error wallets; after max_error_attempts, force-park and free budget (see §3.4.1)

  **Stale last_active read**       AtomicU64 with SeqCst ordering guarantees visibility across threads
  -------------------------------- -------------------------------------------------------------------------------------

**3.4.1 Error-State Recovery**

The Error(3) state is structured: `Error { reason: ErrorReason, since: Instant, attempts: u8 }`. A background `error_recovery_loop` (60s interval) probes each Error wallet with a health check (actor task alive, VSS reachable, monitors load-able). On success, the wallet transitions Error → Parked and its memory budget is released. On failure, `attempts` increments with exponential backoff. After `max_error_attempts` (default 5), the wallet is force-parked, its actor task aborted, and a persistent error flag stored in the wallets table. The next user-driven operation attempts a fresh wake. Memory budget is never held in Error for more than 30 seconds --- the diagnostic window --- after which bytes are released regardless of recovery state.

**3.5 LSP Daemon**

The LSP daemon runs as a component of the same process as ldk-server. It owns a single LiquidityManager instance (from the lightning-liquidity crate, part of the rust-lightning monorepo since LDK 0.1) configured as the CustomMessageHandler of the dedicated LSP LdkNode.

**Dispatch keying.** Events are routed to the correct WalletActor via a `peer_registry: DashMap<Scid, (TenantId, RegistryEpoch)>`. SCID is used as the dispatch key rather than peer pubkey --- peer pubkey is ambiguous across wallet restores and multi-channel-per-peer scenarios. A monotonic `registry_epoch: AtomicU64` is incremented on every insert and attached to each entry; dispatch validates `entry.epoch <= current_epoch` before firing.

**Ordering invariant.** The `lsps2.buy` handler performs these steps in strict order: (1) allocate SCID, (2) increment registry_epoch, (3) insert `(scid, tenant_id, epoch)` into peer_registry, (4) fsync the JIT request record to Postgres, (5) return SCID to the client. Only after step (4) is the SCID observable in the dispatch path. Unknown-SCID events park in a short retry queue (max 30s, bounded capacity); if still unresolvable, the HTLC is failed back with `unknown_next_peer`. Registry entries are immutable after insert --- mutations are delete-then-reinsert with a fresh epoch.

The diagram below shows the full event dispatch path from an incoming LSPS BOLT8 message through to the correct WalletActor:

![](media/72dbb2e2001f3a50b53781693820c98979ee25f5.png){width="6.5in" height="4.947916666666667in"}

*Figure 1 --- LiquidityManager → LspEventLoop → WalletActor dispatch*

Supported LSPS specifications:

- bLIP-50 / LSPS0 --- transport protocol over BOLT8 custom messages

- bLIP-51 / LSPS1 --- channel purchase: client pays on-chain to buy a sized channel (secondary flow)

- bLIP-52 / LSPS2 --- JIT channels: fee deducted from first incoming payment, zero-balance onboarding (primary flow)

- bLIP-53 / LSPS5 --- webhook notifications: LSP fires signed HTTPS push to wake parked wallets

**3.6 LSPS2 JIT Channel Flow**

The full LSPS2 flow from the LSP server perspective:

1.  Client calls lsps2.get_info --- LSP returns signed fee params (promise = HMAC-SHA256 of all param fields)

2.  Client calls lsps2.buy --- LSP verifies promise, checks valid_until, allocates a SCID, persists a JIT request record

3.  Client embeds SCID and LSP node pubkey as a route hint in their BOLT11 invoice

4.  Payer routes a payment --- HTLC arrives at the LSP node on the JIT SCID

5.  LiquidityManager fires LSPS2ServiceEvent::OpenChannel --- LspEventLoop dispatches to WalletActor

6.  In parallel: LSPS5 webhook fires (async, best-effort) to wake any parked client

7.  WalletActor reserves UTXOs, opens a 0-conf channel to the client wallet, deducts opening fee, forwards HTLC

8.  Client sends preimage via update_fulfill_htlc --- payment complete

The entire sequence --- from HTLC intercept to payment forwarded --- must complete before the HTLC\'s CLTV expiry. The timing budget and fast-path optimisations are shown in the diagram below:

![](media/bc6993c4fd408359318a037a7aeb829363c98d60.png){width="6.5in" height="3.9791666666666665in"}

*Figure 2 --- CLTV wake timing budget per JIT payment*

**3.6.1 Reorg Policy**

Zero-confirmation channels carry reorg risk: if the funding tx is orphaned after the LSP has forwarded the HTLC and the client has released the preimage, the LSP is left holding a channel referencing a dead txid. The LSP absorbs this risk end-to-end --- clients never bear reorg loss.

- **Reorg reserve.** A segregated pool of UTXOs, unavailable for JIT funding, sized to cover cumulative at-risk exposure across all currently-unconfirmed 0-conf channels.
- **Per-tx exposure cap.** `reorg_exposure_cap_sats` (default 2,000,000 sats) per funding tx.
- **Global unconfirmed cap.** `reorg_exposure_global_cap_sats` across all unconfirmed 0-conf channels; new JIT buys block when exceeded.
- **Safety threshold.** Above `reorg_safety_threshold_sats` (default 500,000 sats), JIT falls back to LSPS1 (purchased channels with minconf); 0-conf only below threshold.
- **Anchor funding.** Every JIT funding tx uses anchor outputs and has a CPFP child pre-signed at broadcast time.

The reserve, caps, and threshold together bound maximum reorg loss to a figure the LSP treats as operational cost, comparable to on-chain fee variance.

**3.6.2 Griefing Mitigation**

A client can call `lsps2.buy`, cause a self-payment, then withhold `update_fulfill_htlc`, stranding LSP liquidity. Layered defence:

- **Grief score.** `client_reputation` table tracks per-client-pubkey failure events with exponential decay. Thresholds throttle or block further buys.
- **Macaroon-bound rate limits.** Per-developer-macaroon cap on concurrent unfulfilled JIT requests (default 10) and per-hour cap (default 100). Developers carry reputational skin-in-the-game.
- **Aggressive timeout.** If the HTLC is not fulfilled within `jit_fulfil_timeout_blocks` (default 40) below CLTV, the LSP initiates `close_channel` and blacklists the client.
- **Capacity tiers.** First N JIT channels per new client are small (`first_jit_cap_sats`, default 100k sats); cap raises with successful history.
- **Setup deposit (high-value tier).** For large JIT channels, `lsps2.buy` requires a small BOLT11 paid upfront, refunded on fulfilment.

**3.7 Fee Param Signing**

Fee params offered to clients are HMAC-signed to prevent replay and tampering attacks. The construction and verification flow is shown below:

![](media/8b21762b85189868dd05f13da4b78d245ad50738.png){width="6.5in" height="3.6770833333333335in"}

*Figure 3 --- Fee param HMAC construction and attack prevention*

A FeeParamCache pre-generates signed params valid for 30 minutes and rotates automatically, avoiding per-request HMAC computation under load. The cache is hardened against key compromise with three layers:

- **Short key rotation.** HMAC signing key rotates every 5 minutes; compromised keys have a bounded blast radius of 5 min + in-flight valid_until window.
- **Param identification.** Every issued fee-param bundle carries a unique `param_id` (128-bit) and `key_version`. A short revocation set keyed by `param_id` allows surgical invalidation without waiting for natural expiry.
- **Binding to buy context.** At `lsps2.buy` time, the server additionally HMACs `(client_pubkey, amount_msat_range, scid)` into the promise. Replaying a valid fee-param bundle to a different client, amount, or SCID fails verification.

A Postgres-persisted key ring coordinates rotation across the fleet; old keys are retained only for the duration of their outstanding `valid_until` windows.

**3.8 UTXO Management**

The LSP maintains a pool of confirmed UTXOs for funding 0-conf channels. The state machine, coin selection logic, batch-open window, and CPFP fee bumping strategy are shown below:

![](media/ca488b32228cfb065bb487ea3b40bcd97f6fcd69.png){width="6.5in" height="4.291666666666667in"}

*Figure 4 --- UTXO pool states, coin selection, batching, and CPFP*

Key rules:

- Reservation uses SELECT FOR UPDATE SKIP LOCKED --- prevents concurrent double-spend on the same UTXO

- Coin selection is largest-first to minimise input count and reduce transaction fees

- Batch window: 200ms. Batch size adapts to mempool pressure: up to 10 at p50 mempool fee, up to 5 at p75--p90, solo (size 1) above p90. Bounds blast radius of a stalled tx during fee spikes.

- Every funding tx is flagged BIP125 replaceable; change output is sized to at least 10 * target_confirm_fee_sats so a single CPFP child can fee-bump the whole batch.

- CPFP: child transaction spends the change output of a stalled funding tx at a high fee rate, pulling the parent into the next block via package fee rate

- Per-client escape hatch: if a batch tx remains unconfirmed for solo_escape_timeout_s (default 30s), affected clients are rerouted into fresh solo funding txs. On RBF eviction, a replacement batch is constructed from still-valid reservations; evicted-channel clients are notified.

- Expired reservations (reserved_at + 5 minutes, no channel opened) are automatically released

**3.9 VSS Server**

VSS (Versioned Storage Service) provides encrypted, versioned key-value storage for LDK channel state. Wick implements VSS natively in the tenant Postgres schema via the vss_objects table, colocated with all other tenant data and serving the same interface as the VSS spec.

> key TEXT, version BIGINT, value BYTEA, updated_at TIMESTAMPTZ

Versioned writes use optimistic locking --- a write that does not match the expected version fails with a conflict error, allowing the client to retry with fresh state. All values are encrypted client-side before upload; the server never sees plaintext channel state.

**3.10 Relay (Mailbox)**

The relay is a dumb-pipe WebSocket server that routes encrypted binary blobs between the VLS signer on device and ldk-server, identified by stream IDs. It is architecturally equivalent to Lightning Labs\' Aperture but written in Rust and fully open-source.

- Routes encrypted blobs without reading them --- cannot inspect VLS signing messages

- Both the signer and ldk-server dial outbound; the relay pipes them together by stream ID

- Stream IDs are 128-bit cryptographically random, server-issued (OsRng), and exchanged inside the Noise_KK channel --- never as URL path parameters. Client-chosen IDs are rejected with a protocol error.

- Per-IP connection rate limit (default 30/min) bounds stream-squatting throughput.

- Authentication is end-to-end via the Noise_KK session --- the relay itself requires no auth

- Self-hostable: developers running their own stack can run their own relay instance

**4 Data Architecture**

**4.1 PostgreSQL Schema Design**

The database uses a two-schema design: a global schema for server-wide data and per-tenant schemas (tenant\_{id}) for wallet-specific data. Tenant routing uses **transaction-scoped** `SET LOCAL` inside an explicit transaction opened per request:

> BEGIN;
>
> SET LOCAL search_path TO tenant\_{id}, global;
>
> SET LOCAL app.current_tenant_id = \'{id}\'; \-- used by Postgres RLS policies
>
> \-- tenant queries execute here
>
> COMMIT;

`SET LOCAL` is scoped to the transaction and discarded on COMMIT/ROLLBACK regardless of connection-pool behaviour, eliminating the class of bug where a pooled connection leaks the prior tenant\'s search_path. Defence in depth layers three additional safeguards:

- **AfterRelease reset.** sqlx AfterRelease hook executes `RESET search_path; RESET app.current_tenant_id;` as belt-and-braces in case a transaction was ever accidentally omitted.
- **Tenant-ID validation.** `tenant_id` is validated against `^[0-9]+$` (or UUID v4) before any schema-name formatting. Adversarial strings are rejected at the SDK boundary; no user-influenced value is ever interpolated into SQL.
- **Runtime assertion.** Every tenant-scoped transaction issues `SELECT current_setting('app.current_tenant_id')::bigint = $1` as its first statement; mismatch aborts with `tenant_guard_mismatch_total` metric incremented.

**4.2 Global Schema Tables**

  ----------------------- -----------------------------------------------------------------------------------------------
  **Table**               **Contains**

  wallets                 Tenant registry: id, pubkey, created_at, plan tier, suspended flag

  macaroon_roots          Root HMAC keys per developer, expiry, caveat policies

  utxo_set                LSP UTXO pool: txid, vout, amount, state, reserved_for_tenant, reserved_at, spent_txid

  lsp_channels            All JIT and LSPS1 channels: channel_id, tenant_id, capacity, opening_fee, routing_fees_earned

  jit_requests            Pending and completed LSPS2 buy requests with SCID, fee params, and state machine

  channel_orders          LSPS1 channel purchase orders with invoice, expiry, and fulfillment state

  webhook_registrations   LSPS5 webhook URLs per tenant with app_data and last-delivered timestamp

  rgs_snapshots           Cached RGS gossip snapshots keyed by block height for fast resync

  fee_params              Historical fee param sets for auditability and analytics
  ----------------------- -----------------------------------------------------------------------------------------------

**4.3 Tenant Schema Tables**

  ----------------------- ----------------------------------------------------------------------------------------------
  **Table**               **Contains**

  channel_manager_state   Serialised LDK ChannelManager bytes, updated on every persistence event

  channels                Human-readable channel index: channel_id, peer_pubkey, capacity, balance, state

  payments                Full payment history: hash, preimage, direction, amount, fee, status, timestamp

  vss_objects             VSS KV store: key, version, encrypted_value --- implements the VSS spec natively in Postgres

  monitors                Serialised ChannelMonitor bytes, one row per channel, updated on each event

  peers                   Known Lightning peers: pubkey, address, alias --- populated on first connect
  ----------------------- ----------------------------------------------------------------------------------------------

**5 Tier 2 --- SDK**

**5.1 Overview**

The SDK abstracts the entire platform into a clean, language-idiomatic API. Developers call functions like send_payment, receive_payment, get_balance --- the SDK handles VLS signing, Noise tunnel, Macaroon authorisation, and VSS backups transparently.

SDK targets:

- Rust --- native crate on crates.io, the canonical implementation

- Flutter / Dart --- flutter_rust_bridge FFI bindings, published on pub.dev

- JavaScript / WASM --- wasm-pack compiled module for browser and Node.js, published on npmjs

- NWC --- any application implementing NIP-47 (Nostr Wallet Connect) can connect to a user\'s Wick wallet

**5.2 VLS Signer**

The VLS (Validating Lightning Signer) runs on the user\'s device and holds the seed. Every signing request from ldk-server must pass the VLS policy engine before a signature is produced.

- Seed never transmitted --- all key derivation happens inside the signer

- Policy engine enforces 50+ validation rules: max payment size, allowed channel peers, HTLC expiry checks, penalty transaction validation, and more

- Blind signing is explicitly not supported --- VLS refuses any request it cannot validate, regardless of server instructions

- If ldk-server is fully compromised, it can only deny service --- it cannot steal funds

**Hardware binding (seed at rest).** The seed is wrapped at rest by a hardware-backed key on every target platform:

  ------------------- ----------------------------------------------------------------------------------------------
  **Platform**        **Wrapping**

  iOS                 Secure Enclave key, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, `kSecAttrSynchronizable=false`. Biometry-gated unwrap on foreground; iCloud Keychain sync disabled for the wrapping key.

  Android             Keystore key, `setIsStrongBoxBacked(true)` where available else TEE. `setUserAuthenticationRequired(true)`, `setInvalidatedByBiometricEnrollment(true)`. Manifest `android:allowBackup="false"`.

  Web                 WebAuthn PRF extension (or passkey-bound encryption). Seed never materialised as raw bytes in WASM memory --- see §5.7.

  Desktop             OS keychain (Secret Service / Keychain / DPAPI) with user-unlock gating.
  ------------------- ----------------------------------------------------------------------------------------------

**Zeroize discipline.** All Rust structs bearing seed, signing keys, unwrapped macaroon roots, or Noise session keys use `Zeroizing<_>` wrappers and derive `ZeroizeOnDrop`. `Clone` is forbidden on sensitive types; sharing is via `Arc<Zeroizing<_>>` only. CI lint enforces.

**Device attestation.** On startup, the SDK performs platform attestation (DeviceCheck / Play Integrity / WebAuthn attestation). Attestation failure (rooted/jailbroken device, untrusted attestation) surfaces a clear warning and refuses to unlock the wallet.

**5.3 Secure Tunnel --- Four-Layer Defence**

The channel between the VLS signer and ldk-server uses four independent security layers. Defeating any single layer is not sufficient to compromise the system.

  -------- ------------------- --------------------------------- ----------------------------------------------------------------------------
  **\#**   **Layer**           **Mechanism**                     **Provides**

  **1**    TLS (outer)         Standard TLS 1.3                  NAT traversal, certificate validation, basic encryption

  **2**    Noise_KK            Mutual auth, Lightning keypairs   Cryptographic identity of both parties, forward secrecy, no PKI dependency

  **3**    Macaroons           HMAC chain + revocation set       Scoped permissions, delegation, expiry, fast-path validation with revocation support

  **4**    VLS Policy Engine   50+ rules on-device               Last-line defence: refuses invalid requests regardless of upper layers
  -------- ------------------- --------------------------------- ----------------------------------------------------------------------------

**ldk-server pubkey pinning.** Noise_KK requires both parties to know each other\'s static pubkey in advance. The ldk-server pubkey is pinned in SDK release artefacts (version-tagged in `Cargo.toml` / `pubspec.yaml` / `package.json`), cross-published on an append-only transparency log (Nostr-backed) and on the wick.cloud website over HSTS, and additionally verifiable out-of-band via a fingerprint displayed in the Settings screen. The SDK performs triple-source verification at first connect. Pubkey rotation is a major SDK version bump accompanied by a signed rotation certificate. Self-hosters pin their own ldk-server pubkey via SDK config.

**5.4 Macaroon Cascade**

Macaroons provide delegatable, scoped authorisation. Authentication is stateless (HMAC chain, no DB lookup); a small in-memory revocation set adds targeted revocability without sacrificing hot-path performance. Caveats can only be added (not removed) as a token is delegated downward.

- Root key --- HMAC seed held server-side, derives all downstream tokens

- Developer macaroon --- issued at SDK registration; carries LSP node pubkey caveat, expiry caveat, and a unique `nonce` caveat

- User macaroon --- scoped to a single wallet; carries permission caveats (e.g. send-only, max_payment_msat_single, max_payment_msat_per_window_h24, allowed-peer) plus a unique `nonce` caveat

A user macaroon cannot remove caveats imposed by the developer macaroon. Delegation is strictly additive.

**Revocation.** A `revoked_macaroons` Postgres table keyed by `nonce` is replicated to an in-memory set on each server via Postgres LISTEN/NOTIFY. The request path checks the nonce against the in-memory set (~100ns); a match rejects immediately. Revocation propagation latency across the fleet is bounded at p99 < 1s; during partition, individual servers fall back to a Postgres lookup. Default lifetimes are tightened: user 24h, developer 30d, root 1y --- short lifetimes bound exposure when revocation propagation lags. The SDK rotates user macaroons automatically using the developer macaroon.

**Spend-window enforcement.** The `max_payment_msat_per_window_h24` caveat is enforced server-side via the `macaroon_spend_window` table with composite index `(macaroon_nonce, window_start)` and atomic `INSERT ... ON CONFLICT DO UPDATE` check-and-increment per payment. This closes the per-request caveat splitting attack while adding only one row-level DB op on a path that already touches Postgres for payment recording (~2ms p99 overhead).

**5.5 Key Derivation**

- m/84\'/0\'/0\' --- native SegWit on-chain wallet (P2WPKH)

- m/86\'/0\'/0\' --- Taproot on-chain (P2TR)

- Lightning node keypair --- derived via LDK\'s standard key manager from the seed

- VLS signing key --- derived via tagged hash from the Lightning node key

- Noise_KK static key --- derived from the Lightning node keypair for tunnel authentication

- NWC keypair --- derived via NIP-06 path (`m/44\'/1237\'/0\'`) with explicit domain separation. Never reuses the Lightning node key --- cross-protocol signature oracles are prevented by design.

The seed is held exclusively in the VLS signer\'s memory on device, wrapped at rest by a hardware-backed key (§5.2). It is never transmitted, never written to disk in plaintext, and never exposed to the Flutter or JavaScript layer.

**Import-path coverage.** The wallet import wizard supports `m/44\'/0\'/0\'`, `m/49\'/0\'/0\'`, `m/84\'/0\'/0\'`, and `m/86\'/0\'/0\'`, each user-opted with a gap-limit scan. New wallets default to `m/84\'` + `m/86\'`; legacy paths are opt-in to avoid silent zero-balance surprises on restore from legacy wallets.

**5.6 Flutter Bridge**

The Flutter layer uses flutter_rust_bridge (FRB) to call the Rust SDK core via FFI. All async Rust futures become Dart Futures; Rust Streams become Dart Streams. Primary API surface:

- WickWallet.new(seed) --- initialises VLS signer and connects to ldk-server

- WickWallet.send(bolt11) --- signs and sends a payment; returns PaymentResult

- WickWallet.receive(amount_msat, memo) --- creates BOLT11 invoice via ldk-server

- WickWallet.balance() --- returns local + pending balance in msat

- WickWallet.transactions() --- returns paginated payment history

- WickWallet.onchainAddresses() --- derives next unused P2WPKH and P2TR addresses

- WickWallet.eventStream() --- Dart Stream of wallet events (payment received, channel opened, etc.)

**5.7 WebLN / WASM Provider**

The JavaScript SDK is compiled via wasm-pack and implements the WebLN provider interface. Web applications call window.webln.sendPayment(bolt11) as they would with any WebLN provider --- the SDK handles the Noise tunnel and VLS signing transparently in the browser. This makes Wick immediately compatible with the full existing WebLN ecosystem: BTCPay Server, Fountain, and any other WebLN-enabled application.

**Web seed protection.** WASM linear memory is readable by the hosting JS context --- a malicious or XSS-compromised page could read a seed materialised in WASM. Wick\'s web target accepts this as a fundamental WASM property and moves secret material out of WASM entirely:

- Seed-at-rest is wrapped by a WebAuthn PRF-derived key (or passkey-bound encryption). If WebAuthn PRF is unavailable, the SDK refuses to initialise with a seed and falls back to read-only mode (balance, history only).

- Signing operations route through an isolated SignerWorker (Web Worker) that receives encrypted key material unwrapped by a WebAuthn-gated key at the start of each user-approved signing session. The seed never exists as raw bytes in the hosting page\'s WASM memory.

- Every signing operation above a configurable sats threshold prompts a user gesture + WebAuthn challenge. Per-site spending limits and approval UX are enforced at the WebLN provider boundary.

- Seed material in the worker is wrapped in Zeroize-equivalent constructs and scrubbed at session end.

**5.8 NWC Integration**

NWC (Nostr Wallet Connect, NIP-47) is supported as a second app-integration path alongside WebLN. It enables any application that speaks NIP-47 to request payments from a user\'s Wick wallet, regardless of platform.

Architectural position: NWC connects third-party apps to the SDK layer. It does not replace the Noise tunnel --- the Noise tunnel is the VLS signer-to-ldk-server signing channel; NWC is the application-to-wallet payment request channel. They solve different problems at different layers and are complementary.

Wick runs its own NWC relay (alongside the existing relay infrastructure) --- public Nostr relays see message timing and pubkeys, so a private relay prevents payment metadata leakage to third parties.

**6 Tier 3 --- Product**

**6.1 Reference Flutter Wallet**

The reference wallet is a Flutter application targeting iOS, Android, and desktop. It serves both as a consumer product and as a live demonstration of the complete SDK integration. All functionality is implemented via the SDK --- the Flutter layer is intentionally thin, containing only UI and navigation logic.

Primary screens:

- Home --- balance (Lightning + on-chain), recent transactions, send/receive buttons

- Send --- BOLT11 invoice scanner, LNURL support, manual address entry

- Receive --- QR code display, amount input for fixed invoices, LSPS2 JIT onboarding for new wallets with zero balance

- Transactions --- paginated payment history with direction, amount, fee, and timestamp

- Portfolio --- on-chain address explorer

- Settings --- channel management, VLS policy review (with signed manifest hash for out-of-band verification), ldk-server pubkey fingerprint, backup verification, LSP info

**6.2 On-Chain Portfolio View**

The portfolio view provides a MetaMask-style overview of on-chain Bitcoin holdings derived from the user\'s seed. It pulls data from Esplora and displays confirmed balance, unconfirmed transactions, and address history. Derivation path coverage: m/84\'/0\'/0\' (native SegWit) and m/86\'/0\'/0\' (Taproot), scanning up to a gap limit of 20 consecutive unused addresses.

**Endpoint isolation.** Portfolio queries bypass wick.cloud infrastructure entirely. The SDK config lists multiple public Esplora endpoints (mempool.space, blockstream.info, user-configured) and round-robins queries across them to prevent any single endpoint from building a complete address graph. Optional Tor integration via `arti` routes queries through the Tor network where supported. The shared internal Esplora pool hosted by ldk-server is used **only** for Lightning-routing fee estimation, never for user-address queries. Documentation enumerates which queries leave the device and where they go.

**6.3 WebLN Browser Provider**

The browser extension (Chrome/Firefox) installs the WASM SDK as a WebLN provider, making it available to any website via window.webln. The extension UI allows the user to review and approve payment requests, with configurable spending limits and per-site permissions.

**7 Security Model**

**7.1 Non-Custodial Guarantee**

The non-custodial property is formally defined: only the entity holding the VLS-protected seed can authorise fund movements. The server can route payments and manage channels but cannot produce signatures, cannot close channels unilaterally to an arbitrary address, and cannot move funds without user consent expressed through a VLS-validated signing request.

This differs from blind-signing architectures (such as Greenlight\'s default mode) where the signer produces signatures for any valid-looking request from the node, effectively creating shared custody. Wick explicitly rejects blind signing.

**7.2 Threat Model**

  ----------------------------------- ---------------------- -----------------------------------------------------------------------------------------------------
  **Threat**                          **Attacker**           **Mitigation**

  Malicious ldk-server                Wick operator          VLS policy engine refuses invalid requests regardless of server instructions

  Compromised server                  External attacker      No keys on server; attacker can only deny service, not steal funds

  Replay of old fee params            Cheating client        HMAC promise, 5-min key rotation, param_id revocation set, binding to (client_pubkey, amount, scid) at lsps2.buy time (§3.7)

  HTLC routing theft                  Compromised node       VLS validates HTLC preimage and value before signing

  Channel force-close to wrong addr   Compromised server     VLS validates closing transaction output addresses

  Macaroon theft                      Token interception     Caveats limit scope; Noise_KK verifies identity separately; nonce-keyed revocation set propagated via LISTEN/NOTIFY (p99 < 1s); short default lifetimes (§5.4)

  Macaroon spend splitting            Stolen token           Sliding-window spend caveat `max_payment_msat_per_window_h24` enforced via Postgres table (§5.4)

  Cross-tenant data access            Multi-tenant exploit   Transaction-scoped SET LOCAL search_path + RLS + AfterRelease reset + tenant_id validation + runtime current_tenant_id assertion; actor model enforces single-tenant LdkNode ownership (§4.1)

  Cross-tenant HTLC dispatch          Race at channel open   SCID-keyed peer_registry with monotonic epoch; lsps2.buy strictly orders SCID allocate → epoch bump → insert → fsync → return (§3.5)

  UTXO double-spend                   Race condition         SELECT FOR UPDATE SKIP LOCKED prevents concurrent reservation

  Reorg of 0-conf funding tx          Chain reorg            Segregated reorg reserve + per-tx cap + global unconfirmed cap + safety threshold above which JIT falls back to minconf LSPS1 (§3.6.1)

  JIT channel griefing                Adversarial client     Grief score, macaroon-bound rate limits, aggressive fulfil timeout, capacity tiers, setup deposit for high-value channels (§3.6.2)

  Wake-storm DoS                      Coordinated HTLC burst Global wake semaphore + priority queue + per-tenant rate limit + memory headroom reservation (§3.4)

  Webhook SSRF                        Malicious tenant URL   Strict URL validator (https only, public-IP only, DNS rebinding defence) + dedicated egress network namespace + signed payloads (§7.3)

  Bootstrap MITM on first connect     Network attacker       Triple-source pubkey verification: SDK-release pin + transparency log + out-of-band fingerprint in Settings (§5.3)

  Seed extraction from device         Device compromise      Hardware-backed wrapping (Secure Enclave / StrongBox / WebAuthn PRF); device attestation refuses unlock on tampered devices (§5.2)

  Seed extraction from WASM           XSS on host page       Seed never in WASM memory; signing routes through WebAuthn-gated Web Worker; no-PRF browsers fall back to read-only (§5.7)

  On-chain address correlation        Server operator        Portfolio queries bypass wick.cloud; multi-endpoint round-robin; optional Tor (§6.2)

  VSS metadata inference              Server operator        Fixed-size write buckets, dummy writes, jittered timestamps (§7.4)

  Relay stream squatting              External attacker      128-bit server-issued stream IDs exchanged inside Noise_KK; client-chosen IDs rejected; per-IP connect rate limit (§3.10)

  Suspended-wallet griefing           Adversarial client     Suspension is admin-only (no self-suspend API); incoming HTLCs fail back with temporary_node_failure at LSP boundary (§7.5)
  ----------------------------------- ---------------------- -----------------------------------------------------------------------------------------------------

**7.3 Operational Security**

**LSPS5 webhook egress.** Client-controlled webhook URLs fire server-side HTTPS POSTs. The dispatcher applies strict validation at registration and at every fire:

- Scheme is https only; all other schemes rejected.
- Hostname resolved; rejected if any resolved IP is in RFC1918, 127.0.0.0/8, 169.254.0.0/16 (link-local + metadata), ::1, fc00::/7, fe80::/10, 224.0.0.0/4, 100.64.0.0/10.
- Re-resolve on every fire (DNS rebinding defence) and pin the IP for the request duration.
- HTTP redirects are not followed. Request timeout 5s. Response body capped at 4KB (body is discarded).
- Dispatcher runs in a dedicated Linux network namespace with no route to internal subnets; public-Internet egress only via a restricted NAT.
- Payloads signed with the LSP Ed25519 key; tenants verify signatures; unsigned or invalid requests are undeliverable.
- Per-tenant webhook rate limit bounds amplification.

**Observability for every fix.** Every security-relevant mechanism above exports a Prometheus metric. Notable counters: `tenant_guard_mismatch_total`, `reorg_exposure_unconfirmed_sats`, `reorg_reserve_sats`, `reorg_loss_events_total`, `lsp_dispatch_unknown_scid_total`, `peer_registry_epoch`, `wake_semaphore_blocked_total`, `wake_latency_seconds{priority}`, `jit_grief_score_p99`, `jit_first_fulfil_rate`, `webhook_fire_rejected_total{reason}`, `webhook_egress_violations_total`, `macaroon_revocation_propagation_seconds`, `macaroon_window_rejections_total`. A red-team test suite in CI exercises SSRF payloads, DNS rebinders, macaroon replay, reorg simulation, wake flood, and grief automation; failures block deploys.

**7.4 Privacy Hardening**

**VSS metadata side-channel.** The VSS server sees object keys, encrypted payload sizes, and write timing. To bound inference:

- Writes are padded to fixed-size buckets (64KB / 256KB / 1MB tiers).
- A per-tenant scheduler emits at least one write per `vss_dummy_write_interval_s` (default 60s) whether or not real state changed.
- Write timestamps are jittered ±5s to obscure HTLC arrival timing.

After padding and dummy traffic, the operator can learn a tenant\'s write *cadence* but not its *content* or *event triggers*.

**NWC relay privacy.** The Wick-operated NWC relay is private rather than a public Nostr relay --- public Nostr relays expose message timing and pubkeys to all connected clients, which is a non-trivial payment-metadata leak. A self-hosted relay restricts visibility to the operator only.

**RGS source diversity.** Routing decisions consume RapidGossipSync snapshots from at least three independent feeds (LDK public snapshot, self-hosted mirror, partner feed). Gossip deltas are applied only when 2-of-3 agree; divergence triggers an investigation alert. No routing decision is taken from a lone feed.

**7.5 Wallet Lifecycle Controls**

**Suspension semantics.** The `wallets.suspended` flag is administrative only; there is no self-suspend API. Admin suspension is gated on a signed request with audit log. Suspended wallets refuse new HTLCs at the LSP boundary via `LiquidityManager` interception (returning `update_fail_htlc` with `temporary_node_failure`). In-flight HTLCs complete normally; suspension takes effect after drain. The UI shows a clear banner with contact/appeal info, and send functionality is disabled. Resume requires admin action and a forced monitor reload.

**8 LSP Economics**

**8.1 Fee Model Parameters**

Each JIT channel open involves three fee parameters negotiated at invoice time:

- min_fee_msat --- floor fee regardless of payment size; must cover on-chain open cost (typically 2,000--10,000 sats depending on mempool fee rate)

- proportional_ppm --- fee as parts-per-million of the forwarded payment; competitive range is 5,000--10,000 ppm for JIT channels

- valid_until --- expiry time for the signed fee param set; default 30-minute validity window via FeeParamCache

**8.2 Capital Efficiency Tracking**

The lsp_channels table records routing_fees_earned per channel, enabling calculation of actual ROI per channel and per-cohort fee sensitivity analysis over time. Capital efficiency is measured as:

> ROI = routing_fees_earned / (capacity_sats x days_open)

The liquidity_pool record tracks total deployed vs available capital at the LSP level, and the utxo_set table exposes real-time available liquidity. These two signals drive dynamic fee adjustment --- when liquidity is constrained, proportional_ppm increases; when the pool is deep, it decreases to remain competitive.

*Wick --- wick.cloud --- Architecture v0.2 --- April 2026*
