-- Phase 3 — operator-mode LSP global tables.
--
-- The LSP daemon (wick-lsp crate) owns all of these. Per-tenant
-- channel state continues to live in `tenant_<id>` schemas; the LSP
-- itself is just a reserved tenant whose schema follows the same
-- template.
--
-- All tables use IF NOT EXISTS so re-applying this migration on an
-- existing dev/test cluster is idempotent.

-- ── UTXO pool ────────────────────────────────────────────────────────────────
-- The LSP's confirmed on-chain UTXOs available for 0-conf channel
-- funding. Manipulated under SELECT FOR UPDATE SKIP LOCKED — multiple
-- concurrent JIT opens reserve disjoint subsets without contention.
CREATE TABLE IF NOT EXISTS global.utxo_set (
    txid                  BYTEA       NOT NULL,
    vout                  INT         NOT NULL,
    amount_sat            BIGINT      NOT NULL,
    state                 TEXT        NOT NULL CHECK (state IN ('confirmed','reserved','spent')),
    reserved_for_tenant   UUID,
    reserved_at           TIMESTAMPTZ,
    spent_txid            BYTEA,
    confirmations         INT         NOT NULL DEFAULT 0,
    inserted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (txid, vout)
);
CREATE INDEX IF NOT EXISTS utxo_set_state_idx ON global.utxo_set(state);
CREATE INDEX IF NOT EXISTS utxo_set_reservation_idx
    ON global.utxo_set(reserved_for_tenant)
    WHERE reserved_for_tenant IS NOT NULL;

-- ── LSP channels ─────────────────────────────────────────────────────────────
-- Every JIT or LSPS1 channel the LSP has opened. Observability +
-- routing-fee accounting; not authoritative state for LDK (that's in
-- the LSP's tenant schema).
CREATE TABLE IF NOT EXISTS global.lsp_channels (
    channel_id                BYTEA       PRIMARY KEY,
    tenant_id                 UUID        NOT NULL,
    capacity_sat              BIGINT      NOT NULL,
    opening_fee_sat           BIGINT      NOT NULL,
    routing_fees_earned_msat  BIGINT      NOT NULL DEFAULT 0,
    state                     TEXT        NOT NULL,
    opened_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at                 TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS lsp_channels_tenant_idx ON global.lsp_channels(tenant_id);
CREATE INDEX IF NOT EXISTS lsp_channels_state_idx  ON global.lsp_channels(state);

-- ── JIT requests ─────────────────────────────────────────────────────────────
-- Every lsps2.buy allocation. Mirrors PeerRegistry's in-memory map
-- for crash recovery — see PeerRegistry::rehydrate_from_pg.
CREATE TABLE IF NOT EXISTS global.jit_requests (
    scid              BIGINT      PRIMARY KEY,
    epoch             BIGINT      NOT NULL,
    tenant_id         UUID        NOT NULL,
    client_pubkey     BYTEA       NOT NULL,
    amount_msat       BIGINT,
    state             TEXT        NOT NULL CHECK (state IN
                          ('pending','opened','fulfilled','failed','expired')),
    channel_id        BYTEA,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS jit_requests_tenant_idx ON global.jit_requests(tenant_id);
CREATE INDEX IF NOT EXISTS jit_requests_state_idx  ON global.jit_requests(state);

-- ── Fee params (audit log) ───────────────────────────────────────────────────
-- LDK's lightning_liquidity owns promise generation in memory; this
-- table is an append-only audit log of fee menus the LSP has served.
-- Useful for ops + dispute resolution.
CREATE TABLE IF NOT EXISTS global.fee_params (
    param_id          UUID        PRIMARY KEY,
    key_version       INT         NOT NULL,
    min_fee_msat      BIGINT      NOT NULL,
    proportional_ppm  INT         NOT NULL,
    valid_until       TIMESTAMPTZ NOT NULL,
    revoked           BOOLEAN     NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS fee_params_key_version_idx ON global.fee_params(key_version);

-- ── Client reputation (slice 3.3 grief scoring) ─────────────────────────────
CREATE TABLE IF NOT EXISTS global.client_reputation (
    pubkey            BYTEA       PRIMARY KEY,
    score             DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_decayed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_event_at     TIMESTAMPTZ
);

-- ── LSPS5 webhook registrations ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS global.webhook_registrations (
    tenant_id              UUID        PRIMARY KEY,
    url                    TEXT        NOT NULL,
    app_data               JSONB,
    last_delivered_at      TIMESTAMPTZ,
    consecutive_failures   INT         NOT NULL DEFAULT 0,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
