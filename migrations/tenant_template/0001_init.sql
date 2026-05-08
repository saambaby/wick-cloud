-- Tenant schema template.
-- `scripts/tenant-provision.sh` applies this template to a fresh
-- `tenant_{id}` schema when a wallet is created.
-- See docs/wick_architecture.md §4.3.
-- The `{{SCHEMA}}` placeholder is substituted by the provisioning script.

CREATE SCHEMA IF NOT EXISTS "{{SCHEMA}}";

-- RLS policies use `current_setting('app.current_tenant_id')` to enforce
-- row-level access control. Phase 1 turns these on; Phase 0 creates the
-- tables so their shape is stable.

CREATE TABLE IF NOT EXISTS "{{SCHEMA}}".payments (
    id              BIGSERIAL PRIMARY KEY,
    payment_hash    BYTEA NOT NULL,
    preimage        BYTEA,
    direction       TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    amount_msat     BIGINT NOT NULL,
    fee_msat        BIGINT NOT NULL DEFAULT 0,
    status          TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS payments_hash_idx ON "{{SCHEMA}}".payments(payment_hash);
CREATE INDEX IF NOT EXISTS payments_status_idx ON "{{SCHEMA}}".payments(status);

-- Channel index — human-readable view over LDK's opaque state.
CREATE TABLE IF NOT EXISTS "{{SCHEMA}}".channels (
    channel_id      BYTEA PRIMARY KEY,
    peer_pubkey     BYTEA NOT NULL,
    capacity_sat    BIGINT NOT NULL,
    local_balance_msat BIGINT NOT NULL,
    state           TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Serialised LDK ChannelManager bytes. One row.
CREATE TABLE IF NOT EXISTS "{{SCHEMA}}".channel_manager_state (
    id              SMALLINT PRIMARY KEY DEFAULT 1,
    bytes           BYTEA NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT channel_manager_singleton CHECK (id = 1)
);

-- Serialised ChannelMonitor bytes, one row per channel.
CREATE TABLE IF NOT EXISTS "{{SCHEMA}}".monitors (
    channel_id      BYTEA PRIMARY KEY,
    bytes           BYTEA NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Known Lightning peers.
CREATE TABLE IF NOT EXISTS "{{SCHEMA}}".peers (
    pubkey          BYTEA PRIMARY KEY,
    address         TEXT,
    alias           TEXT,
    last_seen_at    TIMESTAMPTZ
);

-- VSS KV. Phase 4 adds size-padding; here we just shape the table.
CREATE TABLE IF NOT EXISTS "{{SCHEMA}}".vss_objects (
    key             TEXT PRIMARY KEY,
    version         BIGINT NOT NULL,
    value           BYTEA NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Durable backing for the two-phase channel-open flow. Rows are written
-- by the LDK event handler on `FundingGenerationReady` and deleted when
-- the client finalises the open. Rows that survive a crash are
-- rehydrated on the next boot; anything older than ~1h is swept as
-- unrecoverable.
CREATE TABLE IF NOT EXISTS "{{SCHEMA}}".pending_funding (
    temp_channel_id BYTEA PRIMARY KEY,
    counterparty    BYTEA NOT NULL,
    value_sat       BIGINT NOT NULL,
    output_script   BYTEA NOT NULL,
    parked_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS pending_funding_parked_at_idx
    ON "{{SCHEMA}}".pending_funding(parked_at);

-- Per-tenant signer state needed to reattach a VLS-backed `SignerSession`
-- after a wick-server restart. LDK rehydrates `ChannelMonitor`s + the
-- `ChannelManager` from `monitors` / `channel_manager_state`; for every
-- restored channel it then calls `SignerProvider::derive_channel_signer`,
-- which must hand back a signer bound to the SAME `dbid` + cached
-- pubkeys the SDK last used — otherwise VLS sees a fresh `dbid` and
-- rejects every subsequent signing call with "channel not found".
--
-- One row per VLS channel; `channel_keys_id` is the canonical identity
-- LDK uses, `dbid` is the protocol-level field VLS keys per-channel
-- state on. `pubkeys` is the 5×33-byte concatenation of
-- (funding, revocation, payment, delayed_payment, htlc) basepoints
-- returned by the SDK's `GetChannelBasepoints` reply. `peer_id` stays
-- the SENTINEL_PUBKEY until `SetupChannel` lands; once it does,
-- `setup_funding_txid` + `setup_funding_index` mark the channel as
-- promoted so a fresh `SignerSession` skips the redundant SetupChannel
-- on restart.
CREATE TABLE IF NOT EXISTS "{{SCHEMA}}".signer_channel_meta (
    channel_keys_id      BYTEA PRIMARY KEY,
    dbid                 BIGINT NOT NULL,
    peer_id              BYTEA NOT NULL,
    setup_funding_txid   BYTEA,
    setup_funding_index  INTEGER,
    push_value_msat      BIGINT NOT NULL DEFAULT 0,
    pubkeys              BYTEA,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

