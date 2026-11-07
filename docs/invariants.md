# Invariants

Cross-cutting rules for wick-cloud. Code and docs cite them by ID (for example `[INV-CUSTODY-1]`). Retired rules stay under Deprecated with their original ID.

---

## Custody & Key Safety

### [INV-CUSTODY-1] — Seed and signing keys never leave the user's device

**Rule.** The seed and all derived signing keys live exclusively inside `wick-vls` on the user's device. They are never transmitted to the server, never written to disk in plaintext on the device, and never exposed to the Flutter or JavaScript layer.

**Rationale.** This is the non-custodial guarantee. Violating it at any surface turns Wick into a custodial product. It is an architectural constraint, not a policy choice.

**Applies to.** Every crate that handles signing (wick-vls, wick-noise, wick-sdk). Any new feature touching key material.

**Exceptions.** None.

---

### [INV-CUSTODY-2] — Blind signing is explicitly rejected

**Rule.** The VLS signer refuses any signing request it cannot validate against its policy engine. The server may instruct the signer to sign only requests that pass all 50+ policy checks.

**Rationale.** Blind signing (signing any valid-looking request) creates shared custody. A compromised server could direct blind signing to steal funds. Wick's threat model requires that a fully compromised server can only deny service, not move funds.

**Applies to.** wick-vls policy engine; any RPC that requests a signature.

**Exceptions.** None.

---

### [INV-CUSTODY-3] — Sensitive Rust types zeroize on drop

**Rule.** All structs bearing seed bytes, signing keys, unwrapped macaroon roots, or Noise session keys must derive `ZeroizeOnDrop`. `Clone` is forbidden on these types. Sharing uses `Arc<Zeroizing<_>>` only.

**Rationale.** Memory that isn't zeroed leaks secrets into heap dumps, swap, and crash reports.

**Applies to.** wick-vls, wick-noise, wick-macaroon, wick-sdk — any type holding secret material.

**Exceptions.** None.

---

## Multi-Tenancy & Isolation

### [INV-TENANT-1] — Tenant schema isolation via transaction-scoped SET LOCAL

**Rule.** Every tenant-scoped database operation runs inside an explicit transaction that begins with `SET LOCAL search_path TO tenant_{id}, global` and `SET LOCAL app.current_tenant_id = '{id}'`. `SET LOCAL` is used, never `SET SESSION`. Every transaction also issues a runtime assertion: `SELECT current_setting('app.current_tenant_id')::bigint = $1` as its first statement.

**Rationale.** `SET LOCAL` is discarded on COMMIT/ROLLBACK regardless of connection pool behaviour, eliminating the cross-tenant data leak class from pooled connections. `SET SESSION` would persist across connection reuse.

**Applies to.** All database queries in wick-db and wick-server that touch tenant schemas.

**Exceptions.** Global-schema-only queries that never need a tenant context.

---

### [INV-TENANT-2] — One LdkNode per tenant, never shared

**Rule.** Each WalletActor owns its LdkNode exclusively via an `mpsc` channel. No `Arc<Mutex<LdkNode>>` anywhere. All interaction happens through the mpsc channel, serialising access.

**Rationale.** Shared mutable state between tenants is a cross-tenant contamination risk. The actor model eliminates this class of bug and enables clean park/wake lifecycle management.

**Applies to.** wick-server WalletManager, WalletActor; wick-lightning.

**Exceptions.** Shared resources injected via `Arc` (EsploraClient pool, NetworkGraph, PgPool, LiquidityManager) are read-shared across tenants and contain no per-tenant state.

---

### [INV-TENANT-3] — tenant_id validated before any schema-name interpolation

**Rule.** `tenant_id` is validated against `^[0-9]+$` (or UUID v4) before being used to construct any schema name. Adversarial strings are rejected at the SDK boundary.

**Rationale.** SQL injection via schema name construction. No user-influenced value is ever interpolated into SQL without validation.

**Applies to.** wick-db, wick-server — any point where a tenant ID enters a database call.

**Exceptions.** None.

---

## Auth & Authorisation

### [INV-AUTH-1] — Macaroon cascade: root → developer → user

**Rule.** All API access uses a three-tier Macaroon chain. Root key on server. Developer macaroon issued at SDK registration (carries LSP node pubkey caveat, expiry, nonce). User macaroon scoped to a single wallet (carries permission caveats, max_payment_msat limits, nonce). Caveats are strictly additive — a user macaroon cannot remove developer-imposed caveats.

**Rationale.** Stateless auth (HMAC chain, no DB lookup on hot path) with targeted revocability and delegatable scoping. Enables per-developer rate limits and per-user spend controls.

**Applies to.** wick-macaroon; wick-server gRPC interceptor; wick-sdk credential store.

**Exceptions.** Internal service-to-service calls (e.g. relay stream handshake) use Noise_KK identity instead of macaroons.

---

### [INV-AUTH-2] — Macaroon revocation via nonce + LISTEN/NOTIFY

**Rule.** Every macaroon carries a unique `nonce` caveat. Revoked nonces are stored in `revoked_macaroons` Postgres table and replicated to an in-memory set per server via `LISTEN/NOTIFY`. Hot-path check is in-memory (~100ns). Propagation p99 < 1s.

**Rationale.** Revocation without per-request DB round-trips. Short default lifetimes (user 24h, developer 30d) bound exposure when propagation lags.

**Applies to.** wick-macaroon; wick-server interceptor.

**Exceptions.** During partition, individual servers fall back to a direct Postgres lookup.

---

### [INV-AUTH-3] — Spend-window caveat enforced server-side atomically

**Rule.** `max_payment_msat_per_window_h24` caveats are enforced via the `macaroon_spend_window` table with atomic `INSERT ... ON CONFLICT DO UPDATE` per payment. This closes the caveat-splitting attack.

**Rationale.** Client-side enforcement of spend limits is trivially bypassed by splitting payments across multiple macaroon copies.

**Applies to.** wick-macaroon spend-window enforcement; wick-server payment path.

**Exceptions.** None.

---

## Money & Units

### [INV-MONEY-1] — Lightning amounts in integer millisatoshis

**Rule.** All Lightning monetary values in storage and on the wire use integer millisatoshis (`u64`). No floats. Display formatting (BTC, sats) happens at the presentation layer only.

**Rationale.** Floats lose precision. Millisatoshis are the smallest indivisible unit on Lightning. Single-unit storage prevents conversion bugs.

**Applies to.** All database columns for payment amounts; all gRPC/SDK API fields for payment amounts; internal WalletActor and LSP calculations.

**Exceptions.** On-chain amounts (UTXO values, channel capacity) use integer satoshis. LSP fee calculations may produce intermediate millisatoshi values that are then rounded to satoshis for on-chain use.

---

### [INV-MONEY-2] — Fee params HMAC-signed; replay bound to (client, amount, scid)

**Rule.** Fee params issued at `lsps2.get_info` are HMAC-signed. At `lsps2.buy`, the server additionally HMACs `(client_pubkey, amount_msat_range, scid)` into the promise. Replaying a valid fee-param bundle to a different client, amount, or SCID fails verification.

**Rationale.** Prevents fee-param replay and tampering. Without the binding, a client could use another client's cheaper signed params.

**Applies to.** wick-lsp FeeParamCache; lsps2.buy handler.

**Exceptions.** None.

---

## Concurrency & State

### [INV-CONCURRENCY-1] — Park only after in-flight HTLCs drain

**Rule.** Before parking a wallet, the WalletActor checks: `has_pending_htlcs() || has_inflight_payment() || has_unresolved_monitor_event()`. If true, CAS back to Active and requeue Park after `park_retry_delay_s`.

**Rationale.** Parking a wallet mid-HTLC would lose the preimage, causing a payment failure and potential channel force-close.

**Applies to.** wick-server WalletActor Park command handler.

**Exceptions.** None.

---

### [INV-CONCURRENCY-2] — Wake uses compare-and-exchange; concurrent callers await Notify

**Rule.** The Parked → Loading state transition uses `compare_exchange(Parked, Loading)` so exactly one task wins. Concurrent callers wait on `wake_notify` rather than retrying.

**Rationale.** Without CAS, concurrent callers could each load the LDK node independently, doubling memory use and causing corruption.

**Applies to.** wick-server WalletManager wake path.

**Exceptions.** None.

---

### [INV-CONCURRENCY-3] — SCID keyed LSP dispatch with monotonic epoch

**Rule.** LSP events are dispatched to WalletActors via `peer_registry: DashMap<Scid, (TenantId, RegistryEpoch)>`. SCID (not peer pubkey) is the dispatch key. `lsps2.buy` performs: (1) allocate SCID, (2) increment epoch, (3) insert registry, (4) fsync JIT record, (5) return SCID. Only after step 4 is the SCID observable in the dispatch path.

**Rationale.** Peer pubkeys are ambiguous across wallet restores. The ordered insert prevents HTLC dispatch before the JIT record exists.

**Applies to.** wick-lsp; wick-server LspEventLoop.

**Exceptions.** Unknown-SCID events park in a retry queue (max 30s); if still unresolvable, HTLC failed back with `unknown_next_peer`.

---

## Cryptography

### [INV-CRYPTO-1] — Noise_KK with Lightning keypairs for the signing channel

**Rule.** The VLS signer–ldk-server channel uses Noise_KK (known-known static keys). Both parties' static keys are derived from their Lightning keypairs. The Noise session provides mutual authentication and forward secrecy without PKI dependency.

**Rationale.** Lightning keypairs are already on-device. Reusing them for Noise_KK eliminates a separate key management surface. Noise_KK provides stronger guarantees than TLS alone.

**Applies to.** wick-noise; wick-relay; wick-vls SignerService.Attach RPC.

**Exceptions.** TLS is used as the outer transport layer (NAT traversal, certificate validation). Noise_KK is the inner layer that actually provides identity.

---

### [INV-CRYPTO-2] — ldk-server pubkey pinned in SDK artefacts with triple-source verification

**Rule.** The ldk-server Noise_KK static pubkey is pinned in SDK release artefacts (version-tagged). On first connect, the SDK performs triple-source verification: SDK-pinned value + transparency log (Nostr-backed) + out-of-band fingerprint displayed in Settings. Rotation requires a major SDK version bump with a signed rotation certificate.

**Rationale.** Noise_KK requires both parties to know each other's static pubkey in advance. A MITM that substitutes a different pubkey would defeat authentication. Triple-source verification prevents a single-point compromise.

**Applies to.** wick-sdk server pubkey pinning; wick-noise handshake.

**Exceptions.** Self-hosters pin their own ldk-server pubkey via SDK config and skip the triple-source check.

---

## Observability

### [INV-OBS-1] — Every security-relevant mechanism exports a Prometheus metric

**Rule.** All security-relevant mechanisms must export named Prometheus counters or gauges. Named metrics include: `tenant_guard_mismatch_total`, `reorg_exposure_unconfirmed_sats`, `wake_semaphore_blocked_total`, `wake_latency_seconds{priority}`, `jit_grief_score_p99`, `jit_first_fulfil_rate`, `macaroon_revocation_propagation_seconds`, `macaroon_window_rejections_total`, `webhook_fire_rejected_total{reason}`.

**Rationale.** Security mechanisms that don't alert are security mechanisms in name only. Observable metrics are also the feedback loop for tuning thresholds.

**Applies to.** Any new security-relevant mechanism must add a counter on introduction.

**Exceptions.** None — a feature PR that adds a security mechanism without a corresponding metric should be rejected in review.

---

## Privacy

### [INV-PRIVACY-1] — On-chain portfolio queries bypass wick.cloud infrastructure

**Rule.** On-chain address lookups (balance, UTXO history, portfolio view) must query public Esplora endpoints directly from the device. They must not route through wick.cloud's internal Esplora pool. Multiple public endpoints must be round-robined to prevent any single endpoint from building a complete address graph.

**Rationale.** Routing through the server would give the operator a complete address graph of every user's Bitcoin holdings. This is a privacy violation inconsistent with the non-custodial positioning.

**Applies to.** wick-sdk on-chain portfolio queries; wick-sdk-wasm; wick-sdk-ffi.

**Exceptions.** The shared Esplora pool hosted by ldk-server is used for Lightning routing fee estimation only — it never receives user address queries.

---

## Deprecated
