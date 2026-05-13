-- Phase-4 D1 N2 — per-tenant Noise_KK static public key.
--
-- The SDK derives a Curve25519 static keypair from the tenant's master
-- xprv at BIP32 path m/13039'/<coin>'/<index>' (see `wick_noise`) and
-- registers the 32-byte public component during `CreateTenant`. The
-- server uses it as the responder's `expected_initiator` when accepting
-- a `SignerService.Attach` stream, so every signer session is mutually
-- authenticated and the inner gRPC payload rides inside a fresh AEAD
-- tunnel.
--
-- Nullable so pre-N2 tenants (registered before this column existed)
-- continue to work — the server falls back to the legacy bearer-only
-- attach path with a warning log. New registrations always populate
-- the column; the phase-out plan is to flip NULLs to NOT NULL once
-- every active tenant has rotated.

ALTER TABLE global.wallets
    ADD COLUMN IF NOT EXISTS noise_static_pk BYTEA;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'wallets_noise_static_pk_len_check'
          AND conrelid = 'global.wallets'::regclass
    ) THEN
        ALTER TABLE global.wallets
            ADD CONSTRAINT wallets_noise_static_pk_len_check
            CHECK (noise_static_pk IS NULL OR octet_length(noise_static_pk) = 32);
    END IF;
END $$;
