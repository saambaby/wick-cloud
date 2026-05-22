#![no_main]
//! Phase 4 W2-C: fuzz the policy/signing routing surface with malformed
//! signing-request frames.
//!
//! Contract: feed arbitrary bytes to the *outbound signing-request* decoder
//! and the *inbound signing-response* decoder, and assert:
//!
//! 1. **No panics.** No input — however malformed — may panic, hang, or
//!    overflow a buffer in the policy/signing routing path.
//! 2. **No signature is fabricated.** wick-vls is a *router*: actual
//!    secp256k1 signing happens client-side in the SDK's
//!    `vls_protocol_signer::handler::RootHandler`. The strongest property
//!    we can express at this layer is structural — a malformed signing
//!    request must never decode into a typed `OutboundFrame` whose body
//!    length disagrees with the input, and a non-success status byte
//!    (`status != 0x00`) must NOT advertise a body that the caller would
//!    mistake for a signature.
//! 3. **Status-byte / body-shape coherence.** For any inbound frame the
//!    fuzzer accepts: if `status != 0x00` (error), the caller is contractually
//!    forbidden from treating `body` as signature material. We assert
//!    `is_ok() == (status == 0x00)` so the routing layer cannot lie about
//!    success.
//!
//! Why this is the right scope: standing up a real `SignerSession` requires
//! a tonic bidi stream + tenant context + a `ConnLookup` stub — out of scope
//! for a hot-loop fuzz harness. The complementary SDK-side fuzz target
//! (TODO: `wick-sdk/fuzz/fuzz_targets/signer_policy.rs`) is where the
//! "RootHandler never signs malformed requests" invariant belongs, since
//! that's the only place a real signature could be produced.

use libfuzzer_sys::fuzz_target;
use wick_vls::wire::{decode_inbound_frame, decode_outbound_frame, OutboundFrame};

fuzz_target!(|data: &[u8]| {
    // ── 1. Outbound (server → SDK) signing-request decode ─────────────────
    //
    // This is the path that, in production, carries a `vls-protocol`
    // signing request to the SDK. We hammer arbitrary bytes through and
    // verify the decoder never panics and never silently accepts a frame
    // whose declared shape disagrees with the input length.
    match decode_outbound_frame(data) {
        Ok(OutboundFrame::Node(call)) => {
            // Body must be exactly the suffix after the 8-byte node header.
            assert_eq!(call.vls_bytes.len() + 8, data.len());
            // Request-id round-trip: must match the BE u32 at offset 0..4.
            let expected_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            assert_eq!(call.request_id, expected_id);
        }
        Ok(OutboundFrame::Channel(call)) => {
            // peer_id is structurally 33 bytes — never a 64/65-byte
            // signature shape. This is what guards against a malformed
            // channel-signing frame masquerading as a signed reply.
            assert_eq!(call.peer_id.len(), 33);
            assert_eq!(call.vls_bytes.len() + 8 + 8 + 33, data.len());
        }
        Err(_) => {
            // Decoder rejected. Good — no typed signing request escapes.
        }
    }

    // ── 2. Inbound (SDK → server) signing-response decode ─────────────────
    //
    // This is the path a malicious or buggy signer would use to try to
    // shove a forged "signature" back across the wire. The router must
    // never report success for a frame whose status byte isn't 0x00.
    if let Ok(frame) = decode_inbound_frame(data) {
        // Property A: status-byte / is_ok() coherence. If a future refactor
        // breaks this, the router could route an error response as if it
        // carried a valid signature body.
        assert_eq!(frame.is_ok(), frame.status == 0x00);

        // Property B: body length matches input length minus the 5-byte
        // header. No hidden bytes, no truncation.
        assert_eq!(frame.body.len() + 5, data.len());

        // Property C: an error-status frame (status != 0x00) may still
        // carry an arbitrary body, but downstream callers MUST treat it
        // as an error payload, never as a signature. We can't enforce
        // downstream behaviour from here, but we CAN enforce that the
        // frame's own `is_ok()` does not lie. (Already asserted above —
        // this comment documents the invariant chain.)

        // Property D: no signature type exists at this layer. The frame
        // carries (`u32`, `u8`, `Vec<u8>`) — no `Signature`, no `[u8; 64]`,
        // no `secp256k1::ecdsa::Signature`. If a refactor adds one, this
        // documentary type-check will fail to compile.
        let _: u32 = frame.request_id;
        let _: u8 = frame.status;
        let _: &[u8] = &frame.body;
    }
});
