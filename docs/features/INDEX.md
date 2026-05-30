# Features Index

One-line summary per feature. Feature specs live in `docs/features/{feature-name}.md`. Specs are created just-in-time per the Half Cycle Method — this index tracks existence, not completion.

Status legend: `shipped` | `in progress` | `designed` | `deferred`

---

## Tier 1 — Infrastructure (wick-server)

| Feature | Status | Spec | Notes |
|---------|--------|------|-------|
| Multi-tenant wallet actor (park/wake) | shipped | no spec (stable) | Core actor model; DashMap + mpsc; park/wake with CLTV bounds |
| WalletManager memory budget + LRU eviction | shipped | no spec (stable) | AtomicUsize budget; priority wake queue; global semaphore |
| gRPC API (WalletService) | shipped | no spec (stable) | send, receive, balance, transactions; Macaroon interceptor |
| LSP daemon — LSPS2 JIT channels | in progress | — | Zero-balance onboarding; SCID dispatch; JIT channel open |
| LSP daemon — LSPS0/1 | designed | — | Channel purchase (secondary flow); BOLT8 transport |
| LSPS5 webhooks | designed | — | Push notification to wake parked wallets on incoming payment |
| VSS server | shipped | no spec (stable) | Encrypted versioned KV; optimistic locking; Postgres-backed |
| Relay (Noise WebSocket mailbox) | shipped | no spec (stable) | Stream-ID routing; Noise_KK; per-IP rate limit |
| UTXO management (coin selection, CPFP, RBF) | designed | — | Batch funding; reorg reserve; griefing mitigation |
| Error-state recovery loop | designed | — | Error(3) state; exponential backoff; force-park after max_attempts |

## Tier 2 — SDK

| Feature | Status | Spec | Notes |
|---------|--------|------|-------|
| VLS on-device signer | shipped | no spec (stable) | Seed + policy engine; hardware-binding; zeroize discipline |
| Noise_KK client tunnel | shipped | no spec (stable) | wick-noise; Noise_KK_25519 + BOLT8 rekey |
| Macaroon client + credential store | shipped | no spec (stable) | HMAC chain; caveat attachment; rotation loop |
| Server pubkey pinning | shipped | no spec (stable) | Triple-source verification; transparency log seam |
| Rust SDK core (send/receive/balance) | shipped | no spec (stable) | Orchestrates VLS + Noise + Macaroon + VSS |
| Flutter FFI bridge | in progress | — | flutter_rust_bridge; FRB async/stream mapping |
| WASM / WebLN provider | in progress | — | wasm-pack; WebLN interface; SignerWorker isolation |
| NWC (Nostr Wallet Connect) | in progress | — | NIP-47; private Nostr relay |
| Key derivation (BIP32 paths) | shipped | no spec (stable) | m/84', m/86', Lightning key, NWC key with domain separation |

## Tier 3 — Product

| Feature | Status | Spec | Notes |
|---------|--------|------|-------|
| Reference Flutter wallet | deferred | — | Demo surface; all functionality via SDK |
| WebLN browser extension | deferred | — | Chrome/Firefox; per-site spend limits |

---

## Next spec to write

When picking up the next feature from `in progress`, create `docs/features/{name}.md` using the template in `docs/features/_template.md` before writing any code.
