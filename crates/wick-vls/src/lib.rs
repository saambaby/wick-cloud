//! VLS-protocol remote-signer adapter for Wick.
//!
//! `wick-vls` implements LDK 0.2's signer trait surface
//! (`EntropySource + NodeSigner + SignerProvider + OutputSpender + EcdsaChannelSigner`)
//! over the Validating Lightning Signer wire protocol, transported as raw
//! binary frames inside a tonic gRPC bidi stream.
//!
//! The crate has no seed material of its own. Every signing call is dispatched
//! through a per-tenant [`SignerConnection`], which round-trips the request
//! to the SDK device that holds the BIP39-derived Lightning seed and runs the
//! VLS policy engine locally.
//!
//! ## Wire layout
//!
//! Outbound (server → SDK), wrapped inside `SignerRequest.vls_payload`:
//!
//! - Node call:    `[4B request_id BE][0x01][3B reserved][vls_bytes]`
//! - Channel call: `[4B request_id BE][0x02][3B reserved][8B dbid BE][33B peer_id][vls_bytes]`
//!
//! Inbound (SDK → server), wrapped inside `SignerResponse.vls_payload`:
//!
//! - `[4B request_id BE][1B status][body]` — `status=0x00` = OK; otherwise body is
//!   a UTF-8 error message.
//!
//! `vls_bytes` itself is `[u16 type BE][data]` — the output of
//! [`vls_protocol::msgs::SerBolt::as_vec`].
//!
//! ## Crate boundary
//!
//! - [`SignerConnection`] / [`SignerSessionRegistry`] — transport-agnostic;
//!   live in `wick-server` (registered when the SDK connects on the gRPC
//!   bidi stream) and resolved per-tenant by the per-Node signer.
//! - [`rpc`] — typed async wrappers around every VLS message we exchange.
//!   Inputs/outputs are plain primitives (`[u8;33]`, `[u8;64]`, `Vec<u8>`),
//!   so the LDK adapter stays free of `vls_protocol` types.

mod change_destination;
mod connection;
mod meta_store;
mod registry;
mod session;

pub mod rpc;

pub use change_destination::VlsChangeDestination;
pub use connection::SignerConnection;
pub use meta_store::{ChannelMetaStore, ChannelMetaStoreRef, StoredChannelMeta};
pub use registry::{ConnLookup, OutboundSignerFrame, SignerSessionRegistry, StateSyncChannel};
pub use session::{SignerSession, VlsRemoteChannelSigner};
