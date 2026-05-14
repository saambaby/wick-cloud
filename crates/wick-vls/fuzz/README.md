# wick-vls-fuzz

`cargo-fuzz` harness for the `wick-vls` wire codec and the Wick extension
RPC response parsers (`0xFD01–0xFD05`).

## What this covers

Three fuzz targets:

- **`wire_decode`** — exercises both inbound (`[req_id][status][body]`)
  and outbound (`[req_id][kind][reserved][...]`) frame decoders. Asserts
  no input panics and successful decodes preserve length invariants.

- **`signer_dispatch`** — feeds arbitrary bytes through the inbound
  signer-routing parser. Asserts the routing decision (`request_id`,
  `status`, body) is structurally well-formed and the parser never
  produces a signature (it _cannot_ at this layer — `wick-vls` only
  routes messages; actual signing happens inside the SDK via
  `vls_protocol_signer::handler::RootHandler`).

- **`extension_rpc`** — hammers the hand-rolled `0xFD01–0xFD05` response
  parsers (`parse_get_ldk_node_keys_response`,
  `parse_get_wallet_address_response`,
  `parse_get_splice_new_funding_pubkey_response`, plus the pass-through
  VSS encrypt/decrypt parsers). These are the highest-risk surface
  because they hand-roll their length prefixes.

## What this _doesn't_ cover

The full Phase 4 acceptance property — "fuzz the VLS policy with
malformed signing requests; none produce a signature" — needs to be
checked on the **SDK side**, where the actual VLS `RootHandler` runs.
This harness covers the server-side parsers only. A follow-up SDK fuzz
target (out of scope here, tracked as a `TODO` in
`fuzz_targets/signer_dispatch.rs`) should mirror this layout against
`vls_protocol_signer::handler::RootHandler` so the signature-production
property is fuzzed end-to-end.

## Run

`cargo-fuzz` needs nightly Rust:

```bash
rustup install nightly      # one-time
cd crates/wick-vls/fuzz

# Build all targets (verifies the harness compiles).
cargo +nightly fuzz build

# Run a target for 5 minutes each.
cargo +nightly fuzz run wire_decode      -- -max_total_time=300
cargo +nightly fuzz run signer_dispatch  -- -max_total_time=300
cargo +nightly fuzz run extension_rpc    -- -max_total_time=300
```

A crash drops a reproducer under `artifacts/<target>/`; reproduce with:

```bash
cargo +nightly fuzz run <target> artifacts/<target>/crash-<hash>
```

## Corpus

Seed files live under `corpus/<target>/` and are materialized by
`build.rs` on first build. Each file is a small hand-crafted boundary
case (empty, too-short, exactly-too-short, valid-minimal,
length-overflow, non-UTF-8). libfuzzer mutates from these — you don't
need to regenerate them unless the wire format changes (in which case,
edit `build.rs` and delete the affected files).

## Workspace integration

This crate is deliberately **excluded** from the parent workspace (see
the root `Cargo.toml`'s `workspace.exclude`) so its nightly-only `-Z`
rustflags don't leak into stable workspace builds. The fuzz crate
depends on `wick-vls` via a `path = ".."` reference and uses its own
target directory under `crates/wick-vls/fuzz/target/`.
