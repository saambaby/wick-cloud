# Architecture Overview

Container-level diagram of the Wick platform as it exists today (May 2026), kept in sync with `docs/product-spec.md`.

```mermaid
graph TB
    subgraph Device["User Device (Tier 2 — SDK)"]
        VLS["wick-vls\nVLS Signer\n(seed, policy engine)"]
        SDK["wick-sdk\nRust SDK Core\n(send, receive, balance)"]
        FFI["wick-sdk-ffi\nFlutter FFI Bridge"]
        WASM["wick-sdk-wasm\nWASM / WebLN"]
        NWC["wick-nwc\nNWC Client (NIP-47)"]
        NOISE_C["wick-noise\nNoise_KK client"]
        MAC_C["wick-macaroon\nMacaroon client\n(caveat chain)"]
    end

    subgraph Server["wick.cloud / Self-hosted (Tier 1 — Infrastructure)"]
        RELAY["wick-relay\nNoise WebSocket Relay\n(stream-ID mailbox)"]
        GRPC["wick-server\ngRPC API\n(WalletService, SignerService)"]
        WALLETMGR["WalletManager\nDashMap actor registry\npark/wake lifecycle"]
        ACTOR["WalletActor × N\ntokio task per tenant\nmpsc channel"]
        LDK["ldk-node × N\nLDK node per wallet\n(channel state, routing)"]
        LSP["wick-lsp\nLSP Daemon\nLiquidityManager\nLSPS0/1/2/5"]
        VSS["wick-vss-server\nVSS KV Store\n(encrypted channel state)"]
        NOISE_S["Noise_KK server side\n(inside wick-server)"]
        MAC_S["wick-macaroon\nMacaroon validator\n+ revocation set"]
    end

    subgraph DB["PostgreSQL"]
        GLOBAL["global schema\nwallets, macaroon_roots\nutxo_set, lsp_channels\njit_requests, webhooks"]
        TENANT["tenant_{id} schemas\nchannel_manager_state\nchannels, payments\nvss_objects, monitors"]
    end

    subgraph External["External"]
        ESPLORA["Esplora\n(chain data + fee est)"]
        RGS["RapidGossipSync\n(network graph)"]
        MUTINY["mutinynet / mainnet\n(Bitcoin network)"]
    end

    %% SDK internal
    SDK --> VLS
    SDK --> NOISE_C
    SDK --> MAC_C
    FFI --> SDK
    WASM --> SDK
    NWC --> SDK

    %% Device → Relay → Server signing channel
    VLS -- "Noise_KK\nEncrypted blobs" --> RELAY
    RELAY -- "Noise_KK\nEncrypted blobs" --> NOISE_S
    NOISE_S --> GRPC

    %% SDK → Server gRPC
    SDK -- "gRPC + Macaroon\n(send, receive, balance)" --> GRPC

    %% Server internals
    GRPC --> WALLETMGR
    GRPC --> MAC_S
    WALLETMGR --> ACTOR
    ACTOR --> LDK
    ACTOR --> LSP

    %% Persistence
    WALLETMGR --> DB
    ACTOR --> TENANT
    LSP --> GLOBAL
    MAC_S --> GLOBAL

    %% VSS
    SDK -- "VSS put/get\n(encrypted channel state)" --> VSS
    VSS --> TENANT

    %% External
    LDK --> ESPLORA
    LDK --> RGS
    LDK --> MUTINY
    LSP --> MUTINY
```

## Container Responsibilities

| Container | Crate | Responsibility |
|-----------|-------|---------------|
| VLS Signer | `wick-vls` | Holds seed; policy engine validates every signing request |
| Rust SDK Core | `wick-sdk` | Orchestrates VLS, Noise tunnel, Macaroon auth, VSS transparently |
| Flutter FFI | `wick-sdk-ffi` | flutter_rust_bridge bindings to SDK core |
| WASM / WebLN | `wick-sdk-wasm` | wasm-pack module; WebLN provider interface |
| NWC Client | `wick-nwc` | NIP-47 Nostr Wallet Connect integration |
| Noise_KK (client) | `wick-noise` | Noise_KK handshake + session on device side |
| Macaroon (client) | `wick-macaroon` | HMAC chain construction, caveat attachment |
| Relay | `wick-relay` | Dumb-pipe WebSocket relay; routes blobs by stream ID |
| gRPC API | `wick-server` | External API; Macaroon interceptor; routes to WalletManager |
| WalletManager | `wick-server` | Actor registry (DashMap); park/wake lifecycle; memory budget |
| WalletActor | `wick-server` / `wick-lightning` | Tokio task; owns LdkNode exclusively; serialised via mpsc |
| LSP Daemon | `wick-lsp` | LSPS0/1/2/5 flows; LiquidityManager; SCID dispatch |
| VSS Server | `wick-vss-server` | Encrypted versioned KV storage for channel state |
| Macaroon (server) | `wick-macaroon` | HMAC chain validation; revocation set; spend-window enforcement |
| PostgreSQL | — | Global schema (server-wide) + per-tenant schemas (wallet state) |

## Diagrams disagree with architecture doc?

Any gap between this diagram and `docs/wick_architecture.md` should be treated as one of:
- **(a) bug** — code does not yet match the intended design
- **(b) deferred feature** — design intended but not yet implemented
- **(c) forgotten decision** — intent changed but architecture doc not updated

Flag divergences in `docs/invariants.md` or as an open question in the relevant feature spec.
