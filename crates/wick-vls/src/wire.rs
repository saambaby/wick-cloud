//! Pure wire-format codecs exposed for property/fuzz testing.
//!
//! These mirror the framing used by [`crate::SignerConnection`] and the
//! Wick extension RPCs in [`crate::rpc`]. They are deliberately
//! side-effect-free and panic-free: every malformed input yields `Err`,
//! never a partial accept or a signature.
//!
//! See module-level docs in [`crate`] for the exact wire layout.

use thiserror::Error;

/// Errors returned by the parsers in this module. The exact variant
/// is informational; the property the fuzz harness checks is
/// "parse rejects, never panics, never produces a typed value from garbage."
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("frame too short: got {got} bytes, need at least {need}")]
    TooShort { got: usize, need: usize },
    #[error("frame length mismatch: got {got} bytes, expected {expected}")]
    LengthMismatch { got: usize, expected: usize },
    #[error("unknown message type: 0x{0:02x}")]
    UnknownType(u8),
    #[error("invalid UTF-8 in {field}")]
    InvalidUtf8 { field: &'static str },
    #[error("trailing length prefix overflows buffer ({need} > {have})")]
    Overflow { need: usize, have: usize },
}

/// Decoded inbound response frame: `[4B request_id BE][1B status][body]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundFrame {
    pub request_id: u32,
    pub status: u8,
    pub body: Vec<u8>,
}

impl InboundFrame {
    /// `status == 0x00` signals success (body is the typed VLS reply bytes).
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status == 0x00
    }
}

/// Decode an inbound VLS response frame.
///
/// Wire layout: `[4B request_id BE][1B status][body]` (minimum 5 bytes).
///
/// Returns `Err` for any input shorter than 5 bytes. Never panics.
pub fn decode_inbound_frame(data: &[u8]) -> Result<InboundFrame, WireError> {
    if data.len() < 5 {
        return Err(WireError::TooShort {
            got: data.len(),
            need: 5,
        });
    }
    let request_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let status = data[4];
    let body = data[5..].to_vec();
    Ok(InboundFrame {
        request_id,
        status,
        body,
    })
}

/// Decoded outbound node-call frame:
/// `[4B request_id BE][0x01][3B reserved][vls_bytes]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundNodeCall {
    pub request_id: u32,
    pub vls_bytes: Vec<u8>,
}

/// Decoded outbound channel-call frame:
/// `[4B request_id BE][0x02][3B reserved][8B dbid BE][33B peer_id][vls_bytes]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundChannelCall {
    pub request_id: u32,
    pub dbid: u64,
    pub peer_id: [u8; 33],
    pub vls_bytes: Vec<u8>,
}

/// Typed result of dispatching an outbound frame by its kind tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundFrame {
    Node(OutboundNodeCall),
    Channel(OutboundChannelCall),
}

/// Decode an outbound frame produced by `wick-vls`'s server-side encoder.
///
/// Branches on the kind byte at offset 4:
/// - `0x01` → node call
/// - `0x02` → channel call
///
/// Any other kind byte, or a frame shorter than the kind-specific header,
/// returns `Err`. Never panics.
pub fn decode_outbound_frame(data: &[u8]) -> Result<OutboundFrame, WireError> {
    if data.len() < 8 {
        return Err(WireError::TooShort {
            got: data.len(),
            need: 8,
        });
    }
    let request_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let kind = data[4];
    // bytes 5..8 are reserved/zero; we tolerate any value but require length.
    match kind {
        0x01 => Ok(OutboundFrame::Node(OutboundNodeCall {
            request_id,
            vls_bytes: data[8..].to_vec(),
        })),
        0x02 => {
            const CHANNEL_HEADER: usize = 8 + 8 + 33;
            if data.len() < CHANNEL_HEADER {
                return Err(WireError::TooShort {
                    got: data.len(),
                    need: CHANNEL_HEADER,
                });
            }
            let mut dbid_bytes = [0u8; 8];
            dbid_bytes.copy_from_slice(&data[8..16]);
            let dbid = u64::from_be_bytes(dbid_bytes);
            let mut peer_id = [0u8; 33];
            peer_id.copy_from_slice(&data[16..49]);
            Ok(OutboundFrame::Channel(OutboundChannelCall {
                request_id,
                dbid,
                peer_id,
                vls_bytes: data[CHANNEL_HEADER..].to_vec(),
            }))
        }
        other => Err(WireError::UnknownType(other)),
    }
}

// ── Extension RPC response parsers ────────────────────────────────────────────
//
// These mirror the response-decoding logic embedded in
// [`crate::rpc::rpc_get_ldk_node_keys`], [`crate::rpc::rpc_get_wallet_address`],
// [`crate::rpc::rpc_get_wallet_address_v2`] and
// [`crate::rpc::rpc_get_splice_new_funding_pubkey`]. They are split out
// here so the fuzz harness can hammer arbitrary bytes through them without
// instantiating a live [`crate::SignerConnection`].

/// Three 32-byte LDK-only node keys (`0xFD01` response body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdkNodeKeysFrame {
    pub peer_storage_key: [u8; 32],
    pub inbound_payment_key: [u8; 32],
    pub receive_auth_key: [u8; 32],
}

/// Parse the `0xFD01` response body: exactly 96 bytes (`[32B][32B][32B]`).
pub fn parse_get_ldk_node_keys_response(data: &[u8]) -> Result<LdkNodeKeysFrame, WireError> {
    if data.len() != 96 {
        return Err(WireError::LengthMismatch {
            got: data.len(),
            expected: 96,
        });
    }
    let mut peer_storage_key = [0u8; 32];
    let mut inbound_payment_key = [0u8; 32];
    let mut receive_auth_key = [0u8; 32];
    peer_storage_key.copy_from_slice(&data[0..32]);
    inbound_payment_key.copy_from_slice(&data[32..64]);
    receive_auth_key.copy_from_slice(&data[64..96]);
    Ok(LdkNodeKeysFrame {
        peer_storage_key,
        inbound_payment_key,
        receive_auth_key,
    })
}

/// Parsed `0xFD05` v1/v2 wallet-address response: `[u16 LE len][addr][script]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletAddressFrame {
    pub address: String,
    pub script_pubkey: Vec<u8>,
}

/// Parse the `0xFD05` wallet-address response. UTF-8-validated; any
/// malformed length prefix or non-UTF-8 address bytes yield `Err`.
pub fn parse_get_wallet_address_response(data: &[u8]) -> Result<WalletAddressFrame, WireError> {
    if data.len() < 2 {
        return Err(WireError::TooShort {
            got: data.len(),
            need: 2,
        });
    }
    let addr_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let after_len = 2usize
        .checked_add(addr_len)
        .ok_or(WireError::Overflow {
            need: addr_len,
            have: data.len(),
        })?;
    if data.len() < after_len {
        return Err(WireError::Overflow {
            need: after_len,
            have: data.len(),
        });
    }
    let address = std::str::from_utf8(&data[2..after_len])
        .map_err(|_| WireError::InvalidUtf8 { field: "address" })?
        .to_owned();
    let script_pubkey = data[after_len..].to_vec();
    Ok(WalletAddressFrame {
        address,
        script_pubkey,
    })
}

/// Parse the `0xFD04` splice-funding-pubkey response: exactly 33 bytes.
pub fn parse_get_splice_new_funding_pubkey_response(data: &[u8]) -> Result<[u8; 33], WireError> {
    if data.len() != 33 {
        return Err(WireError::LengthMismatch {
            got: data.len(),
            expected: 33,
        });
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(data);
    Ok(out)
}

/// Parsers for the `0xFD02` (vss_encrypt) and `0xFD03` (vss_decrypt)
/// responses: the underlying RPC returns the raw response bytes verbatim
/// (`Vec<u8>`), so there is no typed parse step. These wrappers exist for
/// symmetry with the fuzz harness — they validate that the response is
/// well-formed (any byte string is valid) and never panic.
pub fn parse_vss_encrypt_response(data: &[u8]) -> Result<Vec<u8>, WireError> {
    Ok(data.to_vec())
}

pub fn parse_vss_decrypt_response(data: &[u8]) -> Result<Vec<u8>, WireError> {
    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_too_short_errors() {
        assert!(decode_inbound_frame(&[]).is_err());
        assert!(decode_inbound_frame(&[0; 4]).is_err());
    }

    #[test]
    fn inbound_minimum_ok() {
        let frame = decode_inbound_frame(&[0, 0, 0, 7, 0]).unwrap();
        assert_eq!(frame.request_id, 7);
        assert_eq!(frame.status, 0x00);
        assert!(frame.body.is_empty());
        assert!(frame.is_ok());
    }

    #[test]
    fn outbound_node_call_roundtrip() {
        let mut buf = vec![];
        buf.extend_from_slice(&42u32.to_be_bytes());
        buf.push(0x01);
        buf.extend_from_slice(&[0, 0, 0]);
        buf.extend_from_slice(b"vls-bytes");
        let OutboundFrame::Node(call) = decode_outbound_frame(&buf).unwrap() else {
            panic!("expected node call");
        };
        assert_eq!(call.request_id, 42);
        assert_eq!(call.vls_bytes, b"vls-bytes");
    }

    #[test]
    fn outbound_unknown_kind_errors() {
        let buf = [0, 0, 0, 0, 0xAB, 0, 0, 0];
        assert!(matches!(
            decode_outbound_frame(&buf),
            Err(WireError::UnknownType(0xAB))
        ));
    }

    #[test]
    fn ldk_node_keys_wrong_len_errors() {
        assert!(parse_get_ldk_node_keys_response(&[]).is_err());
        assert!(parse_get_ldk_node_keys_response(&[0; 95]).is_err());
        assert!(parse_get_ldk_node_keys_response(&[0; 96]).is_ok());
        assert!(parse_get_ldk_node_keys_response(&[0; 97]).is_err());
    }

    #[test]
    fn wallet_address_overflow_errors() {
        // addr_len declares 1000 bytes but we only have 4 total.
        let buf = [0xE8, 0x03, 0, 0];
        assert!(parse_get_wallet_address_response(&buf).is_err());
    }

    #[test]
    fn wallet_address_invalid_utf8_errors() {
        let buf = [2, 0, 0xFF, 0xFE];
        assert!(parse_get_wallet_address_response(&buf).is_err());
    }
}
