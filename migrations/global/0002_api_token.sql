-- Phase-1 auth: per-tenant API token hashes.
-- Adds the api_token_hash column used by the bearer-token auth layer
-- in wick-server. Only the SHA-256 hash is stored; the raw token is
-- returned once at CreateTenant time and never persisted server-side.
-- Phase 4 replaces bearer tokens with macaroons (architecture §5.4).

ALTER TABLE global.wallets
    ADD COLUMN IF NOT EXISTS api_token_hash BYTEA NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS wallets_api_token_hash_idx
    ON global.wallets(api_token_hash);

-- Enforce plan_tier to known values. Any previously stored arbitrary
-- strings that don't match will cause this migration to fail — that is
-- intentional: they must be corrected before the constraint is added.
ALTER TABLE global.wallets
    ADD CONSTRAINT wallets_plan_tier_check
    CHECK (plan_tier IN ('free', 'standard', 'premium'));
