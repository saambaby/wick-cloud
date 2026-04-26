-- Phase 3 slice 3.3b — JIT request expiry + capacity tracking.
--
-- 1. `valid_until` — fee-param promise expiry. Pending entries past
--    this are dead and must be swept on `PeerRegistry::rehydrate_from_pg`.
--    Opened entries persist past `valid_until` because the channel is
--    live and the promise is no longer load-bearing.
--
-- 2. `capacity_sat` — populated when `state` transitions to `'opened'`
--    (operator's `create_jit_channel` succeeded). Sum over rows in
--    state `'opened'` is the reorg-reserve guard's "unconfirmed
--    exposure" input until 6-confirmations bookkeeping lands.
--
-- Defaults make the migration safe on existing dev/test rows: any
-- pre-existing `pending` entry inherits a 30-min `valid_until` and
-- a NULL capacity (which the guard treats as zero exposure).

ALTER TABLE global.jit_requests
    ADD COLUMN IF NOT EXISTS valid_until TIMESTAMPTZ NOT NULL
        DEFAULT (now() + interval '30 minutes'),
    ADD COLUMN IF NOT EXISTS capacity_sat BIGINT;

CREATE INDEX IF NOT EXISTS jit_requests_valid_until_idx
    ON global.jit_requests(valid_until);
