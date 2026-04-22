-- Migrate global.wallets.id from BIGSERIAL to UUID.
--
-- Sequential integer ids are enumerable; replacing them with UUIDs closes
-- the tenant-enumeration risk described in architecture §4.1.
--
-- Phase 1 has no client data to preserve, so we truncate first. In a
-- future phase with real tenants, a data-preserving migration would be
-- needed (backfill UUIDs, update FK references, drop old column).
--
-- Entire body wrapped in a DO block that short-circuits when `id` is
-- already UUID-typed, so re-running `just migrate` is a no-op instead of
-- destroying tenant data via the `TRUNCATE`.

DO $$
DECLARE
    id_type TEXT;
BEGIN
    SELECT data_type INTO id_type
    FROM information_schema.columns
    WHERE table_schema = 'global'
      AND table_name = 'wallets'
      AND column_name = 'id';

    IF id_type = 'uuid' THEN
        RAISE NOTICE 'global.wallets.id is already UUID — skipping migration';
        RETURN;
    END IF;

    TRUNCATE global.wallets CASCADE;

    -- Drop the BIGSERIAL default + sequence.
    ALTER TABLE global.wallets ALTER COLUMN id DROP DEFAULT;
    DROP SEQUENCE IF EXISTS global.wallets_id_seq;

    -- Cast the now-empty integer column to UUID. gen_random_uuid()
    -- provides a value for the USING clause (required even though the
    -- table is empty).
    ALTER TABLE global.wallets
        ALTER COLUMN id TYPE UUID USING gen_random_uuid();

    -- New rows get a random UUID by default.
    ALTER TABLE global.wallets
        ALTER COLUMN id SET DEFAULT gen_random_uuid();

    -- Reset the GUC sentinel to an empty string — UUIDs have no sensible
    -- integer default.
    BEGIN
        EXECUTE format('ALTER DATABASE %I SET app.current_tenant_id TO ''''',
                       current_database());
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'skipping ALTER DATABASE SET app.current_tenant_id — insufficient privileges';
    END;
END $$;
