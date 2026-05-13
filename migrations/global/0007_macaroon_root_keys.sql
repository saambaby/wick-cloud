-- Phase 4 / D3 M3 — server-issued macaroon root keys, scope-keyed
-- spend window, and a TTL column on the revocation set.
--
-- Three additions on top of 0006_macaroon.sql:
--
-- 1. `global.macaroon_root_keys` — per-issuance root key + 16-byte
--    identifier. Each macaroon carries its identifier; the verifier
--    looks up the matching `root_key` to replay the HMAC chain.
--    `rotated_at` is nullable: when set, the row can verify but cannot
--    mint new macaroons. Issuance picks the most recently inserted
--    row with `rotated_at IS NULL` for the scope; verification accepts
--    any row whose identifier matches.
--
-- 2. `global.macaroon_spend_window_by_scope` — scope-keyed companion
--    to the existing nonce-keyed `global.macaroon_spend_window`. The
--    research note for M3 ("Macaroons auto-rotate") concludes the
--    user-facing payment cap must follow the user across rotations, so
--    we key on `(tenant_id, scope_kind)` and write **both** rows per
--    spend. The nonce-keyed table remains for per-token allowance.
--
-- 3. `valid_until` column on `global.revoked_macaroons` — supports the
--    30-second rotation-grace TTL described in the research note.
--    NULL means "no TTL, hard-revoked." A Phase-7 ops sweep can delete
--    rows where `valid_until < now()`; this migration does NOT install
--    the sweep — the in-memory `RevocationSet` ignores TTL anyway
--    (once a nonce hits the set, it's revoked even if Postgres later
--    culls the row). The column purely informs the future sweep.

CREATE TABLE IF NOT EXISTS global.macaroon_root_keys (
    identifier BYTEA PRIMARY KEY CHECK (octet_length(identifier) = 16),
    root_key   BYTEA NOT NULL CHECK (octet_length(root_key) = 32),
    -- Coarse scope bucket the root key belongs to. Matches the
    -- `SCOPE_*` byte tags in `wick_macaroon::Scope::payload`:
    -- 0 = User, 1 = Developer, 2 = Admin, 3 = Root.
    scope_kind SMALLINT NOT NULL,
    -- Subject identifier — tenant_id (UUID bytes) for User/Developer,
    -- NULL for Admin/Root. Lets issuance look up the right root key
    -- per (scope_kind, subject).
    subject    BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Nullable; if set, the root key cannot mint new macaroons but
    -- existing ones still verify until their nonces get revoked /
    -- expire.
    rotated_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_macaroon_root_keys_lookup
    ON global.macaroon_root_keys(scope_kind, subject)
    WHERE rotated_at IS NULL;

CREATE TABLE IF NOT EXISTS global.macaroon_spend_window_by_scope (
    -- Tenant the user-scoped cap applies to. For developer-scope rows
    -- this stores the developer_id (16 bytes embedded in a UUID).
    tenant_id     UUID NOT NULL,
    -- Coarse scope kind, same encoding as macaroon_root_keys.scope_kind.
    scope_kind    SMALLINT NOT NULL,
    spent_msat    BIGINT NOT NULL CHECK (spent_msat >= 0),
    window_start  TIMESTAMPTZ NOT NULL,
    window_secs   INTEGER NOT NULL CHECK (window_secs > 0),
    PRIMARY KEY (tenant_id, scope_kind)
);

CREATE INDEX IF NOT EXISTS idx_spend_window_scope_window_start
    ON global.macaroon_spend_window_by_scope(window_start);

ALTER TABLE global.revoked_macaroons
    ADD COLUMN IF NOT EXISTS valid_until TIMESTAMPTZ;
