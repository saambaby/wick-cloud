//! Strongly-typed tenant identifier backed by UUID v4/v5.
//!
//! `TenantId` wraps a `uuid::Uuid` so tenant schema names are unpredictable
//! UUIDs rather than sequential integers, closing the enumeration risk from
//! `§4.1` of the architecture doc.
//!
//! `schema_name()` renders as `tenant_<32-hex-chars>` — no dashes, safe SQL
//! identifier — and is the *only* accepted way to embed a tenant id in DDL.

use std::fmt;

use uuid::Uuid;

/// A validated tenant identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(Uuid);

impl TenantId {
    /// Generate a fresh random tenant id (UUID v4).
    ///
    /// Each call produces a unique id — safe to use in tests where schema
    /// reuse across runs would cause state accumulation.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wrap an existing UUID (e.g. read back from the database).
    #[must_use]
    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Derive a deterministic UUID v5 from a compressed SEC1 pubkey.
    ///
    /// Used by `create_tenant` so the server can always recompute the same
    /// `TenantId` from a known pubkey without storing a separate mapping.
    #[must_use]
    pub fn from_pubkey(pubkey: &[u8]) -> Self {
        Self(Uuid::new_v5(&Uuid::NAMESPACE_OID, pubkey))
    }

    /// The underlying UUID.
    #[must_use]
    pub fn as_uuid(self) -> Uuid {
        self.0
    }

    /// Render as a Postgres schema-name component (`tenant_<32 hex chars>`).
    ///
    /// Uses the simple (no-dash) UUID format so the result is a safe SQL
    /// identifier with no special characters.
    #[must_use]
    pub fn schema_name(self) -> String {
        format!("tenant_{}", self.0.simple())
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_unique_ids() {
        let a = TenantId::generate();
        let b = TenantId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn from_uuid_round_trips() {
        let u = Uuid::new_v4();
        assert_eq!(TenantId::from_uuid(u).as_uuid(), u);
    }

    #[test]
    fn from_pubkey_is_deterministic() {
        let pk = [0xdeu8; 33];
        let a = TenantId::from_pubkey(&pk);
        let b = TenantId::from_pubkey(&pk);
        assert_eq!(a, b);
    }

    #[test]
    fn from_pubkey_distinct_for_different_keys() {
        let a = TenantId::from_pubkey(&[0u8; 33]);
        let b = TenantId::from_pubkey(&[1u8; 33]);
        assert_ne!(a, b);
    }

    #[test]
    fn schema_name_has_no_dashes() {
        let tid = TenantId::generate();
        let name = tid.schema_name();
        assert!(name.starts_with("tenant_"));
        assert!(!name.contains('-'));
        assert_eq!(name.len(), "tenant_".len() + 32);
    }
}
