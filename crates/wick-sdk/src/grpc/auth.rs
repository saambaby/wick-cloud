//! Tonic interceptor that stamps `authorization: Bearer <token>` onto
//! every outbound request.
//!
//! The token lives behind an `Arc<RwLock<Option<String>>>` so
//! [`crate::WickClient::register`] can rotate it in place without
//! rebuilding the underlying `Channel` (which would re-open the HTTP/2
//! connection).

use std::sync::Arc;

use parking_lot::RwLock;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::{Request, Status};

/// Shared bearer token. `None` when the client has not yet registered /
/// been handed a token manually.
pub(crate) type SharedToken = Arc<RwLock<Option<String>>>;

/// Build an empty [`SharedToken`].
pub(crate) fn empty_token() -> SharedToken {
    Arc::new(RwLock::new(None))
}

/// Interceptor that reads the current token at every call and stamps the
/// `authorization` metadata header when one is set.
#[derive(Clone)]
pub(crate) struct AuthInterceptor {
    token: SharedToken,
}

impl AuthInterceptor {
    pub(crate) fn new(token: SharedToken) -> Self {
        Self { token }
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> std::result::Result<Request<()>, Status> {
        let guard = self.token.read();
        if let Some(tok) = guard.as_deref() {
            let value: MetadataValue<_> = format!("Bearer {tok}")
                .parse()
                .map_err(|_| Status::invalid_argument("bearer token is not valid ASCII"))?;
            req.metadata_mut().insert("authorization", value);
        }
        Ok(req)
    }
}
