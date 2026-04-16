//! Config loading helper.
//!
//! Each binary crate defines its own `Config` struct and calls
//! [`load`] to hydrate it from a TOML file plus `WICK_*` environment
//! variable overrides.

use std::path::Path;

use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::de::DeserializeOwned;

use crate::error::{Result, WickError};

/// Load a typed config from a TOML file, overridden by `WICK_` env vars.
pub fn load<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    Figment::new()
        .merge(Toml::file(path.as_ref()))
        .merge(Env::prefixed("WICK_").split("__"))
        .extract()
        .map_err(|e| WickError::Config(e.to_string()))
}
