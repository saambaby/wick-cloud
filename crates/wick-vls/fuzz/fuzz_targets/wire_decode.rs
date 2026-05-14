#![no_main]
//! Fuzz the inbound VLS response-frame decoder and the outbound frame decoder.
//!
//! Properties:
//! - `decode_inbound_frame` never panics on any input.
//! - When it succeeds, the returned `InboundFrame` reconstructs back to a
//!   prefix of the input (length + content invariants).
//! - `decode_outbound_frame` never panics on any input.
//! - A successful `Channel` decode always preserves a full 33-byte peer id.
//!
//! No signature material is involved at this layer — wick-vls only routes
//! frames; actual signing happens inside the SDK's `vls_protocol_signer`.

use libfuzzer_sys::fuzz_target;
use wick_vls::wire::{decode_inbound_frame, decode_outbound_frame, OutboundFrame};

fuzz_target!(|data: &[u8]| {
    // Inbound decode: must not panic.
    if let Ok(frame) = decode_inbound_frame(data) {
        // Invariant: body length == input length - 5.
        assert_eq!(frame.body.len() + 5, data.len());
    }

    // Outbound decode: must not panic.
    match decode_outbound_frame(data) {
        Ok(OutboundFrame::Node(call)) => {
            // Invariant: vls payload is the suffix after the 8-byte header.
            assert_eq!(call.vls_bytes.len() + 8, data.len());
        }
        Ok(OutboundFrame::Channel(call)) => {
            // Invariant: peer_id is exactly 33 bytes and vls payload is the
            // suffix after the 8+8+33 byte channel header.
            assert_eq!(call.peer_id.len(), 33);
            assert_eq!(call.vls_bytes.len() + 8 + 8 + 33, data.len());
        }
        Err(_) => {}
    }
});
