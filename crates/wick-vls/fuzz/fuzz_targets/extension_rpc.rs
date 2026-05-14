#![no_main]
//! Fuzz the `0xFD01–0xFD05` Wick extension RPC response parsers.
//!
//! These hand-rolled wire formats are the highest-risk surface inside
//! `wick-vls`: they decode arbitrary bytes the SDK responds with, and a
//! malformed response must never silently become a valid typed value.
//!
//! Properties:
//! - No parser panics on any input.
//! - On `Err`, no typed result escapes.
//! - On `Ok`, basic length/UTF-8 invariants hold (encoded in each parser's
//!   return type — e.g. `LdkNodeKeysFrame` always carries three 32-byte
//!   arrays).
//!
//! The parsers are response decoders (server-side, decoding what the SDK
//! sent back), not request handlers — so "no signature production" is
//! vacuously true: none of these parsers ever return a signature. The
//! property we ARE checking is "garbage never decodes to a valid typed
//! value that a downstream caller would treat as authoritative."

use libfuzzer_sys::fuzz_target;
use wick_vls::wire::{
    parse_get_ldk_node_keys_response, parse_get_splice_new_funding_pubkey_response,
    parse_get_wallet_address_response, parse_vss_decrypt_response, parse_vss_encrypt_response,
};

fuzz_target!(|data: &[u8]| {
    // 0xFD01: must reject anything that is not exactly 96 bytes.
    match parse_get_ldk_node_keys_response(data) {
        Ok(frame) => {
            assert_eq!(data.len(), 96);
            assert_eq!(frame.peer_storage_key.len(), 32);
            assert_eq!(frame.inbound_payment_key.len(), 32);
            assert_eq!(frame.receive_auth_key.len(), 32);
        }
        Err(_) => {
            assert_ne!(data.len(), 96);
        }
    }

    // 0xFD04: must accept exactly 33 bytes, reject everything else.
    match parse_get_splice_new_funding_pubkey_response(data) {
        Ok(pk) => {
            assert_eq!(data.len(), 33);
            assert_eq!(pk.len(), 33);
            assert_eq!(&pk[..], data);
        }
        Err(_) => {
            assert_ne!(data.len(), 33);
        }
    }

    // 0xFD05: the wallet-address parser must always agree on its
    // declared length prefix. A successful parse means addr_len fits and
    // the address is valid UTF-8.
    if let Ok(frame) = parse_get_wallet_address_response(data) {
        let claimed_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        assert!(data.len() >= 2 + claimed_len);
        assert_eq!(frame.address.len(), claimed_len);
        assert_eq!(frame.script_pubkey.len(), data.len() - 2 - claimed_len);
        // UTF-8 is enforced by the return type (`String`).
    }

    // 0xFD02 / 0xFD03 are pass-through: any bytes are valid. Just
    // exercise the path to confirm no panic.
    let _ = parse_vss_encrypt_response(data);
    let _ = parse_vss_decrypt_response(data);
});
