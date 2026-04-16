//! Tracing subscriber bootstrap.
//!
//! Binaries call [`install`] exactly once at startup. The subscriber emits
//! JSON to stdout when `WICK_LOG_FORMAT=json`, otherwise pretty-printed.

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialise the global tracing subscriber.
pub fn install() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,hyper=warn"));

    let json = std::env::var("WICK_LOG_FORMAT").as_deref() == Ok("json");

    let registry = tracing_subscriber::registry().with(filter);
    if json {
        registry.with(fmt::layer().json()).init();
    } else {
        registry.with(fmt::layer().compact()).init();
    }
}
