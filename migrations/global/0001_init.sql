-- Global schema — server-wide state shared across tenants.
-- See docs/wick_architecture.md §4.2.
-- Phase 0 ships the minimum tables needed for single-tenant boot; subsequent
-- phases add macaroon_roots, utxo_set, jit_requests, etc. via numbered migrations.

CREATE SCHEMA IF NOT EXISTS global;

-- `wallets` is the tenant registry. Every tenant's Postgres schema name is
-- derived from `wallets.id`.
CREATE TABLE IF NOT EXISTS global.wallets (
    id              BIGSERIAL PRIMARY KEY,
    pubkey          BYTEA NOT NULL UNIQUE,
    plan_tier       TEXT NOT NULL DEFAULT 'free',
    suspended       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS wallets_pubkey_idx ON global.wallets(pubkey);
CREATE INDEX IF NOT EXISTS wallets_suspended_idx ON global.wallets(suspended) WHERE suspended = TRUE;

-- Custom GUC used by the tenant-isolation runtime guard.
-- Configured via ALTER DATABASE so every fresh connection sees the default.
-- `tenant_tx` overrides it with SET LOCAL inside each request-scoped transaction.
DO $$
BEGIN
    EXECUTE format('ALTER DATABASE %I SET app.current_tenant_id TO ''0''', current_database());
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'skipping ALTER DATABASE SET app.current_tenant_id — insufficient privileges';
END $$;
