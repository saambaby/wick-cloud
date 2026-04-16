//! Strongly-typed tenant identifier.
//!
//! `TenantId` is the *only* type permitted as a schema-name component in
//! SQL formatting. Construction requires an explicit validation step and
//! rejects any value that does not match `^[0-9]+$`. This closes the
//! SQL-injection class of bug enumerated in `§4.1` of the architecture doc.

use std::fmt;
use std::str::FromStr;

use crate::error::WickError;

/// A validated tenant identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(u64);

impl TenantId {
    /// Construct a tenant-id from a raw integer.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the underlying integer.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Render as a Postgres schema-name component (`tenant_{id}`).
    #[must_use]
    pub fn schema_name(self) -> String {
        format!("tenant_{}", self.0)
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for TenantId {
    type Err = WickError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(WickError::InvalidTenantId(s.to_owned()));
        }
        s.parse::<u64>()
            .map(Self)
            .map_err(|_| WickError::InvalidTenantId(s.to_owned()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_simple_digits() {
        assert_eq!(TenantId::from_str("42").unwrap().as_u64(), 42);
    }

    #[test]
    fn rejects_empty() {
        assert!(TenantId::from_str("").is_err());
    }

    #[test]
    fn rejects_non_digits() {
        for bad in ["abc", "1; DROP TABLE", "1 OR 1=1", "-1", "1.0", " 1"] {
            assert!(TenantId::from_str(bad).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn schema_name_is_well_formed() {
        assert_eq!(TenantId::new(7).schema_name(), "tenant_7");
    }

    proptest! {
        #[test]
        fn rejects_adversarial_strings(s in "[^0-9]{1,32}") {
            // Any string containing a non-digit must be rejected.
            prop_assert!(TenantId::from_str(&s).is_err());
        }

        #[test]
        fn accepts_any_u64_as_digits(n in any::<u64>()) {
            prop_assert_eq!(TenantId::from_str(&n.to_string()).unwrap().as_u64(), n);
        }
    }
}
