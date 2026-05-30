# Wick — Product Spec

**Reverse-engineered from existing code and architecture doc.**
**Version 0.1 — May 2026**

---

## Vision

Wick is a self-custodial Bitcoin Lightning platform built for developers. It gives any application Bitcoin Lightning payments without asking users to trust a custodian — the user's signing keys never leave their device, ever.

The thesis: Lightning is the right payment rail for most applications (low fees, instant settlement, global), but the dominant hosted implementations (custodial wallets, blind-signing cloud nodes) trade away the thing that makes Bitcoin worth using. Wick solves this by splitting the problem — the signing key lives on-device inside a VLS (Validating Lightning Signer); channel management and routing live in the cloud. The cloud layer can be fully compromised and the attacker can only deny service, not steal funds.

---

## Audience

**Primary: developers building payment-native applications.** They want a clean Lightning API — `send`, `receive`, `balance` — without operating a full node or managing channel liquidity. They integrate via the Rust SDK, Flutter SDK, WASM module, or NWC.

**Secondary: self-hosting operators.** Every tier of the stack is fully open-source and independently deployable. An operator can run their own ldk-server, relay, and VSS server and point the SDK at it. This drives trust: even if wick.cloud is compromised or shut down, the user's funds are recoverable.

**Not the audience (yet):** end-consumers without developer access. The reference Flutter wallet serves as a demo surface, not a consumer product in Phase 0/1.

---

## The Three-Tier Architecture

The product is three independent open-source tiers that compose into the full platform:

| Tier | Name | What it is |
|------|------|-----------|
| 1 | Infrastructure | `wick-server` (multi-tenant LDK node), `wick-lsp` (LSPS2 JIT channels), `wick-vss-server` (encrypted channel state), `wick-relay` (Noise-tunneled WebSocket mailbox) |
| 2 | SDK | `wick-sdk` (Rust core), `wick-vls` (on-device VLS signer), `wick-noise` (Noise_KK tunnel), `wick-macaroon` (auth cascade), `wick-sdk-ffi` (Flutter), `wick-sdk-wasm` (browser/Node), `wick-nwc` (Nostr Wallet Connect) |
| 3 | Product | Reference Flutter wallet, WebLN browser extension (deferred) |

---

## Core Capabilities

### What it does today (PoC / Phase 0 — as of May 2026)

- **Multi-tenant ldk-server.** One process hosts many wallet tenants. Each tenant is an isolated WalletActor with its own LDK node, never shared. Park/wake lifecycle serialises idle wallets to Postgres and loads them on demand with CLTV-bounded deadlines for incoming payments.
- **LSPS2 JIT channels.** Zero-balance onboarding: a new user with no Lightning balance receives a payment through a JIT channel opened by the LSP. Fee deducted from first payment; no on-chain deposit required.
- **VLS on-device signer.** Seed and signing keys live on the user's device inside the VLS policy engine. The server never has access. Policy engine enforces 50+ validation rules before producing any signature.
- **Noise_KK secure tunnel.** VLS signer and ldk-server communicate through a Noise_KK-authenticated WebSocket tunnel via the relay. Mutual authentication using Lightning keypairs. Macaroons layer on top for scoped authorisation.
- **Macaroon auth cascade.** Root → developer → user macaroon chain. Stateless validation (HMAC chain), Postgres-backed revocation set propagated via LISTEN/NOTIFY, spend-window caveats enforced per-request.
- **VSS encrypted storage.** Channel state stored as encrypted key-value objects in the tenant Postgres schema. Versioned writes with optimistic locking.
- **Relay mailbox.** Dumb-pipe WebSocket relay routes encrypted blobs between VLS signer and ldk-server by stream ID. No auth required — security is end-to-end via Noise_KK.
- **Rust SDK.** Client-side SDK orchestrating VLS, Noise tunnel, Macaroon auth, and VSS transparently.

### What is not yet built

- Flutter SDK (FFI bindings scaffold exists, end-to-end not validated)
- WASM/WebLN provider (module scaffold exists, not production-ready)
- NWC relay (stub exists)
- Reference Flutter wallet UI
- WebLN browser extension
- LSPS1 channel purchase flow (secondary flow, deferred)
- LSPS5 webhooks for wake-on-payment (architecture designed, not implemented)
- Reorg reserve and griefing mitigation subsystems (designed, not implemented)

---

## Non-Goals

- **Not a custodial wallet.** The server can never steal funds. This is a hard architectural constraint, not a policy choice.
- **Not a consumer product in Phase 0/1.** The reference wallet is a developer demo, not a polished consumer experience.
- **Not multi-chain.** Bitcoin Lightning only. No stablecoins, no EVM, no other L1.
- **Not a channel routing hub.** The LSP is the routing/liquidity provider. Users do not route payments for others.

---

## Success Criteria (Phase 0 / PoC)

1. Multi-tenant JIT payment round-trip works on mutinynet with two SDK instances (tenant-to-tenant).
2. VLS signer enforces policy correctly — a compromised server cannot move funds.
3. Park/wake lifecycle handles concurrent wakes without OOM or deadlock.
4. Macaroon auth (revocation, spend-window) passes automated test suite.
5. All of the above run in a single Docker Compose stack pointing at mutinynet.

---

## Technology Decisions (Captured)

**LDK not LND.** Modular, Rust-native, embeddable. LND's monolithic architecture doesn't allow the key isolation Wick requires.

**VLS on device, node on server.** Blind-signing is explicitly rejected as a security anti-pattern. VLS enforces this structurally.

**Actor model for multi-tenancy.** Each wallet is a tokio task with an mpsc channel. No `Arc<Mutex<LdkNode>>` anywhere. Eliminates lock contention and enables clean park/wake semantics.

**Noise_KK for the signing channel.** Lightning keypairs as static keys. Provides mutual authentication and forward secrecy without PKI dependency.

**SCID not peer pubkey for LSP dispatch.** Peer pubkeys are ambiguous across wallet restores and multi-channel scenarios. SCIDs are stable and unique.

**SET LOCAL not SET SESSION for tenant routing.** Transaction-scoped `search_path` is discarded on COMMIT/ROLLBACK regardless of connection pool behaviour, eliminating the cross-tenant data leak class entirely.

---

## Open Questions

- What is the fee model for the hosted LSP at wick.cloud? (proportional_ppm, min_fee_msat — designed but not fixed as business parameters)
- When does Phase 1 (developer SDK beta) begin? What's the exact gate from PoC?
- LSPS5 webhooks — prioritised for Phase 1 or Phase 2?
- Flutter SDK validation — when does this go from scaffold to tested?
