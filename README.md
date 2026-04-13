# Wick Cloud

Self-custodial Bitcoin Lightning infrastructure. Open-source stack, hosted cloud, open SDK.

User seeds never leave the device. A Validating Lightning Signer (VLS) running on-device enforces policy on every signature request. The hosted `ldk-server` manages channels, routing, and LSP liquidity without ever holding private keys — Lightning-speed transactions with genuine self-custody.

**Status:** Phase 0 scaffolding. See [`docs/wick_architecture.md`](docs/wick_architecture.md) for the full v0.2 spec.

---

## Stack

| Layer | Tech |
|---|---|
| Server core | Rust, tokio, LDK (Lightning Dev Kit), PostgreSQL |
| On-device signer | VLS (Validating Lightning Signer), Noise_KK tunnel |
| SDK | Rust canonical crate, Flutter/Dart via flutter_rust_bridge, JS/WASM via wasm-pack, NWC (NIP-47) |
| Reference wallet | Flutter (iOS, Android, desktop) |
| Browser | Chrome/Firefox WebLN extension (WebAuthn PRF-gated seed) |
| LSP | LSPS0/1/2/5 via `lightning-liquidity` |

---

## Quick start

Prerequisites: Rust toolchain (auto-pinned via `rust-toolchain.toml`), Docker, [just](https://github.com/casey/just).

```bash
just regtest-up    # start bitcoind regtest + postgres + electrs + esplora
just migrate       # apply global schema migrations
just build         # compile the workspace
just demo          # Phase 0: boot wick-server stub against regtest
```

All dev commands: `just --list`.

---

## Repository layout

```
wick-cloud/
├── crates/
│   ├── wick-core/           shared types, config, errors, tenant id, metrics
│   ├── wick-proto/          gRPC + LSPS wire types
│   ├── wick-server/         [bin] multi-tenant ldk-server
│   ├── wick-lsp/            LSP daemon (LiquidityManager wrapper)
│   ├── wick-relay/          [bin] dumb-pipe WebSocket mailbox
│   ├── wick-vss-server/     [bin] Versioned Storage Service
│   ├── wick-db/             Postgres pool with tenant-isolation discipline
│   ├── wick-macaroon/       HMAC chain + nonce revocation + spend window
│   ├── wick-sdk/            canonical Rust SDK
│   ├── wick-vls/            Validating Lightning Signer
│   ├── wick-noise/          Noise_KK tunnel
│   ├── wick-nwc/            NIP-47 Nostr Wallet Connect
│   ├── wick-sdk-ffi/        flutter_rust_bridge bindings
│   ├── wick-sdk-wasm/       wasm-pack target + WebLN provider
│   └── wick-testkit/        regtest harness, chaos injectors, red-team fixtures
├── flutter/wick_wallet/     reference wallet (Phase 5)
├── web/extension/           WebLN browser extension (Phase 6)
├── migrations/
│   ├── global/              server-wide schema
│   └── tenant_template/     per-tenant schema template
├── deploy/
│   └── docker/              local dev compose
├── docs/
│   └── wick_architecture.md authoritative spec (v0.2)
└── scripts/                 ops utilities
```

---

## Architecture highlights

- **Three tiers, independently deployable**: Infrastructure → SDK → Reference wallet.
- **VLS on device, node on server**: seed and signing keys stay on the user's device inside VLS. `ldk-server` cannot sign. Blind signing is explicitly rejected.
- **Actor model per tenant**: each wallet is an isolated `WalletActor` owning its `LdkNode` exclusively via `tokio::mpsc`. No `Arc<Mutex<LdkNode>>` anywhere.
- **Multi-tenant single process**: one ldk-server hosts thousands of wallets. Shared resources (`EsploraClient`, `NetworkGraph`, `RGS`, `PgPool`) injected via `Arc`. Per-tenant state isolated in separate Postgres schemas.
- **Four-layer defence**: TLS → Noise_KK (pinned pubkeys) → Macaroons (HMAC + revocation set) → VLS policy engine.
- **Hardened against 24 vulnerabilities** from the v0.2 audit pass: tenant-isolation leaks, reorg on 0-conf, dispatch races, wake storms, JIT griefing, SSRF, macaroon replay, WASM seed exposure. See architecture doc §7.

---

## Testing discipline

Tests live at every level and every phase gates merges:

| Kind | Tool | When |
|---|---|---|
| Unit | `cargo test` | every PR |
| Property | `proptest` | every PR |
| Fuzz | `cargo-fuzz` | seeded Phase 0, grown per phase |
| Concurrency | `loom` | state machines (park/wake, dispatch) |
| Integration | `tests/` + `wick-testkit` | regtest harness in CI |
| Chaos | fault injectors | staging (Phase 7+) |
| Red-team | SSRF, DNS rebinder, macaroon replay, reorg, wake flood, grief | merge-to-main gate |
| Flutter | `flutter test` + `integration_test` | Phase 5+ |
| WASM | `wasm-pack test --headless` | Phase 6+ |

CI gates on every PR: `fmt` + `clippy -D warnings` + `test` (with Postgres service) + `cargo audit` + `cargo deny`.

---

## Phased roadmap

| Phase | Goal | Status |
|---|---|---|
| 0 | Foundation: workspace, tenant-isolation discipline, regtest single-tenant demo | **in progress** |
| 1 | Multi-tenant actor model | not started |
| 2 | Park/wake + error recovery | not started |
| 3 | LSP + LSPS2 JIT channels + reorg reserve + grief mitigations | not started |
| 4 | VLS signer + Noise_KK tunnel + macaroon revocation | not started |
| 5 | Rust SDK + Flutter bridge + reference wallet | not started |
| 6 | WASM/WebLN + NWC | not started |
| 7 | Production hardening | ongoing from Phase 6 |
| 8 | Portfolio + LSPS1 + polish | not started |

Each phase ends with a runnable `just <phase>-demo` command that exercises the slice.

---

## Contributing

Private pre-release. Public contribution guidelines will land with the v0.3 spec.

## License

MIT OR Apache-2.0 (finalised at public release).
