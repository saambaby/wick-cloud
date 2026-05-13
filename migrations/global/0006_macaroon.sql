-- Phase 4 / D3 M2 — macaroon revocation set + spend-window enforcement.
--
-- Two global tables:
--
-- 1. `global.revoked_macaroons` — set of revoked macaroon nonces. An AFTER
--    INSERT trigger fires `pg_notify('wick_macaroon_revoked', hex(nonce))`
--    so every wick-server process LISTENing on that channel loads the new
--    row into its in-memory RevocationSet within ~1s (see project
--    architecture gotcha #383). Target steady-state row count is small
--    (≤100k worst case); a BYTEA PK is fine for direct membership probes
--    if a fast-path needs to bypass the cache.
--
-- 2. `global.macaroon_spend_window` — 24h rolling spend tracking per
--    macaroon nonce. Each authorized payment performs an atomic
--    INSERT … ON CONFLICT DO UPDATE … WHERE upsert (single round-trip)
--    so concurrent wick-server processes cannot race-double-count under
--    a per-window msat cap. The `idx_spend_window_window_start` index is
--    sized for the periodic sweep (delete where
--    `window_start + window_secs < now()`); the sweep itself is a
--    Phase-7 ops task, not part of M2.

CREATE TABLE IF NOT EXISTS global.revoked_macaroons (
    nonce      BYTEA PRIMARY KEY CHECK (octet_length(nonce) = 16),
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason     TEXT
);

CREATE OR REPLACE FUNCTION global.notify_macaroon_revoked() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('wick_macaroon_revoked', encode(NEW.nonce, 'hex'));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS macaroon_revoked_notify ON global.revoked_macaroons;
CREATE TRIGGER macaroon_revoked_notify
    AFTER INSERT ON global.revoked_macaroons
    FOR EACH ROW EXECUTE FUNCTION global.notify_macaroon_revoked();

CREATE TABLE IF NOT EXISTS global.macaroon_spend_window (
    nonce         BYTEA PRIMARY KEY CHECK (octet_length(nonce) = 16),
    spent_msat    BIGINT NOT NULL CHECK (spent_msat >= 0),
    window_start  TIMESTAMPTZ NOT NULL,
    -- window_secs is informational: cap enforcement happens in the caller,
    -- but the configured window is stored so ops can audit which cap was
    -- applied to a given spend.
    window_secs   INTEGER NOT NULL CHECK (window_secs > 0)
);

CREATE INDEX IF NOT EXISTS idx_spend_window_window_start
    ON global.macaroon_spend_window(window_start);
