//! Tonic interceptor that stamps outbound auth metadata.
//!
//! Carries either the legacy `Authorization: Bearer <hex>` (Phase-1
//! bearer) or `x-wick-macaroon: <base64-standard with padding>` (Phase-4
//! macaroon), depending on the credential kind currently held in the
//! shared slot. The slot lives behind an `Arc<RwLock<…>>` so
//! [`crate::WickClient::register`] can rotate it in place without
//! rebuilding the underlying `Channel` (which would re-open the HTTP/2
//! connection).
//!
//! Encoding: when the credential is a macaroon, the value rides as
//! `base64::engine::general_purpose::STANDARD` (with padding). The
//! server decoder at `crates/wick-server/src/macaroon_auth.rs::
//! extract_macaroon_bytes` mirrors this — both sides must agree.

use std::sync::Arc;

use base64::Engine;
use parking_lot::RwLock;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::{Request, Status};

use crate::credential::CredentialKind;

/// Header used for the Phase-4 macaroon path.
const MACAROON_HEADER: &str = "x-wick-macaroon";

/// Shared outbound credential for the [`crate::grpc::LightningClient`]
/// interceptor. `None` when the client has not yet registered. Bytes
/// are the raw credential — the interceptor encodes them per kind at
/// call time.
pub(crate) type SharedCredential = Arc<RwLock<Option<(CredentialKind, Vec<u8>)>>>;

/// Build an empty [`SharedCredential`].
pub(crate) fn empty_credential() -> SharedCredential {
    Arc::new(RwLock::new(None))
}

/// Legacy bearer-only shared token used by [`crate::signer::SignerLoop`]
/// for the outer `SignerService.Attach` auth (which is still bearer-only
/// in Phase 4; macaroon-with-pk is verified per-`AttachInner` frame
/// inside the Noise tunnel).
pub(crate) type SharedToken = Arc<RwLock<Option<String>>>;

/// Build an empty [`SharedToken`].
pub(crate) fn empty_token() -> SharedToken {
    Arc::new(RwLock::new(None))
}

/// Interceptor that reads the current credential at every call and
/// stamps the appropriate metadata header (`authorization: Bearer …`
/// for bearers, `x-wick-macaroon: <base64>` for macaroons).
#[derive(Clone)]
pub(crate) struct AuthInterceptor {
    cred: SharedCredential,
}

impl AuthInterceptor {
    pub(crate) fn new(cred: SharedCredential) -> Self {
        Self { cred }
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> std::result::Result<Request<()>, Status> {
        let guard = self.cred.read();
        if let Some((kind, bytes)) = guard.as_ref() {
            match kind {
                CredentialKind::Bearer => {
                    // Bearer is UTF-8 text (a 64-char lowercase hex
                    // string); send it verbatim after the `Bearer ` prefix.
                    let tok = std::str::from_utf8(bytes).map_err(|_| {
                        Status::invalid_argument("bearer token is not valid UTF-8")
                    })?;
                    let value: MetadataValue<_> = format!("Bearer {tok}")
                        .parse()
                        .map_err(|_| Status::invalid_argument("bearer token is not valid ASCII"))?;
                    req.metadata_mut().insert("authorization", value);
                }
                CredentialKind::Macaroon => {
                    // Encoding: base64-standard with padding. Server
                    // decoder at wick-server/src/macaroon_auth.rs::
                    // extract_macaroon_bytes must use the same engine.
                    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
                    let value: MetadataValue<_> = encoded.parse().map_err(|_| {
                        Status::invalid_argument("macaroon base64 is not valid ASCII")
                    })?;
                    req.metadata_mut().insert(MACAROON_HEADER, value);
                }
            }
        }
        Ok(req)
    }
}
