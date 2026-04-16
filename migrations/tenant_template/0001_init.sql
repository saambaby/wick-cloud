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
