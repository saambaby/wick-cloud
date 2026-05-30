# Wick Cloud

Self-custodial Bitcoin Lightning platform — Rust workspace, LDK 0.2, multi-tenant.

## Half Cycle Method — Layer 2 Docs

- `docs/product-spec.md` — product vision, capabilities, non-goals, decisions
- `docs/architecture-overview.md` — container-level Mermaid diagram (the system as it is)
- `docs/invariants.md` — cross-cutting rules; reference by ID (e.g. `[INV-CUSTODY-1]`)
- `docs/features/INDEX.md` — all features with status; write a spec before coding anything new
- `docs/phases/poc.md` — current phase; done-when checklist; what's in/out of scope

## Full architecture detail

`docs/wick_architecture.md` — in-depth reference (v0.2, April 2026)

## Vault context

`Projects/WickCloud.md` — stack decisions, gotchas, session notes

## Crate map

| Crate | Role |
|-------|------|
| `wick-server` | gRPC API, WalletManager, WalletActor, park/wake |
| `wick-lightning` | LDK wrappers, PgKvStore, event handling |
| `wick-lsp` | LSP daemon — LSPS0/1/2/5 |
| `wick-relay` | Noise WebSocket relay (mailbox) |
| `wick-vss-server` | Encrypted versioned KV server |
| `wick-db` | Postgres migrations + query helpers |
| `wick-macaroon` | HMAC-chain macaroons, revocation, spend windows |
| `wick-vls` | VLS on-device signer + policy engine |
| `wick-noise` | Noise_KK_25519 primitives |
| `wick-sdk` | Rust SDK core (client) |
| `wick-nwc` | NWC / NIP-47 |
| `wick-sdk-ffi` | Flutter FFI bridge |
| `wick-sdk-wasm` | WASM / WebLN provider |
| `wick-proto` | gRPC protobuf definitions |
| `wick-core` | Shared core types |
| `wick-loom-models` | Concurrency test models (loom) |

## Session rules

- End every session with a context update — route changes to this file, `.claude/context/*`, or project memory.
- Before starting any new feature: check `docs/features/INDEX.md`, then write a spec in `docs/features/{name}.md` before touching code.
- New invariants go in `docs/invariants.md` first; reference by ID from feature specs and code.
