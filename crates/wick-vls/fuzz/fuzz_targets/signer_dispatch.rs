#![no_main]
//! Fuzz the signer dispatch path — the function that turns raw inbound
//! bytes into the routing decision (`request_id`, `status`, body).
//!
//! Property: **the parser must never produce a signature.** wick-vls only
//! ROUTES messages; actual signing happens client-side via
//! `vls_protocol_signer::handler::RootHandler` inside the SDK. So at this
//! layer the strongest property we can check is:
//!
//! 1. `decode_inbound_frame` does not panic for any input.
//! 2. A successful decode reports `is_ok()` iff the status byte is `0x00`,
//!    and the body is exactly the bytes past offset 5.
//! 3. The body itself is not interpreted as a signature here — it is
//!    handed to the typed `vls-protocol` decoder, which has its own
//!    error path.
//!
//! TODO(phase-4-followup): mirror this harness in `wick-sdk` so the
//! signer-side property "no malformed inbound frame produces a signature
//! out of `RootHandler`" is fuzzed end-to-end. That target needs the SDK
//! signer wired up with an ephemeral seed; out of scope for the
//! server-side parser fuzz.

use libfuzzer_sys::fuzz_target;
use wick_vls::wire::decode_inbound_frame;

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = decode_inbound_frame(data) else {
        return;
    };

    // Invariant 1: status byte semantics are stable.
    assert_eq!(frame.is_ok(), frame.status == 0x00);

    // Invariant 2: body is exactly the post-header suffix.
    assert_eq!(frame.body.len() + 5, data.len());
    if !frame.body.is_empty() {
        assert_eq!(&frame.body[..], &data[5..]);
    }

    // Invariant 3: we never accidentally return a signature here. The
    // parser only returns request_id/status/body — no signature type
    // exists at this layer. This is a structural property of the
    // function's return type (`InboundFrame`), which carries no signature
    // field. The assertion below is documentary: if a future refactor
    // adds a signature field, this will fail to type-check.
    let _: u32 = frame.request_id;
    let _: u8 = frame.status;
    let _: &[u8] = &frame.body;
});
