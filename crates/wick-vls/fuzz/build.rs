//! Build script: materialize the seed corpus before each fuzz build.
//!
//! Each seed is small and hand-crafted to cover a boundary case (empty,
//! too-short, exactly-too-short, valid-minimal, length-overflow,
//! non-UTF-8). Encoding the seeds in Rust source keeps the working tree
//! free of opaque binary blobs while still giving libfuzzer real seed
//! files at runtime. Existing seeds are left untouched; new ones are
//! written only when missing.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

fn write_if_absent(path: &Path, data: &[u8]) {
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("mkdir corpus parent");
    }
    let mut f = fs::File::create(path).expect("create corpus seed");
    f.write_all(data).expect("write corpus seed");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let corpus_root = manifest_dir.join("corpus");

    let seeds: &[(&str, &[u8])] = &[
        // ── wire_decode corpus ────────────────────────────────────────
        ("wire_decode/empty.bin", &[]),
        ("wire_decode/one_byte.bin", &[0x00]),
        ("wire_decode/too_short_4b.bin", &[0x00, 0x00, 0x00, 0x01]),
        // minimal valid inbound: req_id=7, status=0
        ("wire_decode/minimal_inbound_ok.bin", &[0x00, 0x00, 0x00, 0x07, 0x00]),
        // inbound with error body
        (
            "wire_decode/inbound_err.bin",
            &[0x00, 0x00, 0x00, 0x07, 0x01, b'E', b'R', b'R'],
        ),
        // minimal valid outbound node call
        (
            "wire_decode/outbound_node_empty.bin",
            &[0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00],
        ),
        // outbound node call with VLS msg-type prefix (HsmdInit2 = 11)
        (
            "wire_decode/outbound_node_hsmdinit_prefix.bin",
            &[0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0B],
        ),
        // outbound channel call: req_id, kind=0x02, reserved=0, dbid=1, 33-byte peer_id
        (
            "wire_decode/outbound_channel_min.bin",
            &[
                // request_id BE
                0x00, 0x00, 0x00, 0x02,
                // kind + reserved
                0x02, 0x00, 0x00, 0x00,
                // dbid BE = 1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                // 33-byte peer_id
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00,
            ],
        ),
        // outbound channel call with trailing VLS payload
        (
            "wire_decode/outbound_channel_with_vls.bin",
            &[
                0x00, 0x00, 0x00, 0x03, 0x02, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                0x03, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                0xAB,
                // vls payload
                0x00, 0x10, 0xDE, 0xAD, 0xBE, 0xEF,
            ],
        ),
        // unknown kind byte
        (
            "wire_decode/outbound_unknown_kind.bin",
            &[0x00, 0x00, 0x00, 0x09, 0xFE, 0x00, 0x00, 0x00],
        ),
        // channel call truncated inside peer_id
        (
            "wire_decode/outbound_channel_too_short.bin",
            &[
                0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
        ),
        // ── signer_dispatch corpus (inbound-frame subset) ─────────────
        ("signer_dispatch/empty.bin", &[]),
        ("signer_dispatch/too_short.bin", &[0x00, 0x00, 0x00, 0x01]),
        ("signer_dispatch/minimal_ok.bin", &[0x00, 0x00, 0x00, 0x07, 0x00]),
        (
            "signer_dispatch/ok_with_body.bin",
            &[
                0x00, 0x00, 0x00, 0x07, 0x00,
                b'r', b'e', b'p', b'l', b'y', b'_', b'b', b'y', b't', b'e', b's',
            ],
        ),
        (
            "signer_dispatch/err_status.bin",
            &[
                0x00, 0x00, 0x00, 0x07, 0x01,
                b'o', b'u', b't', b' ', b'o', b'f', b' ', b'b', b'o', b'u', b'n', b'd', b's',
            ],
        ),
        ("signer_dispatch/large_req_id.bin", &[0xFF, 0xFF, 0xFF, 0xFF, 0x00]),
        (
            "signer_dispatch/non_utf8_err_body.bin",
            &[0x00, 0x00, 0x00, 0x07, 0x02, 0xFF, 0xFE, 0xFD, 0xFC],
        ),
        // ── extension_rpc corpus ──────────────────────────────────────
        ("extension_rpc/fd01_valid_96b.bin", &[0u8; 96]),
        ("extension_rpc/fd01_too_short.bin", &[0u8; 95]),
        ("extension_rpc/fd01_too_long.bin", &[0u8; 97]),
        ("extension_rpc/fd01_empty.bin", &[]),
        (
            "extension_rpc/fd04_valid_33b.bin",
            &[
                0x02, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11,
            ],
        ),
        (
            "extension_rpc/fd04_wrong_len.bin",
            &[
                0x02, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            ],
        ),
        // 0xFD05 valid v1 wallet address response: addr_len=13 LE, "bcrt1qexample", scriptPubKey
        (
            "extension_rpc/fd05_valid.bin",
            &[
                0x0D, 0x00,
                b'b', b'c', b'r', b't', b'1', b'q', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
                0x00, 0x14,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            ],
        ),
        // 0xFD05 length-overflow (declares 1000 byte addr with only 4 total bytes)
        (
            "extension_rpc/fd05_overflow.bin",
            &[0xE8, 0x03, 0x00, 0x00],
        ),
        // 0xFD05 non-UTF8 address
        (
            "extension_rpc/fd05_invalid_utf8.bin",
            &[0x02, 0x00, 0xFF, 0xFE],
        ),
        // 0xFD05 truncated length prefix
        ("extension_rpc/fd05_no_prefix.bin", &[0x00]),
        ("extension_rpc/empty.bin", &[]),
    ];

    for (rel, bytes) in seeds {
        write_if_absent(&corpus_root.join(rel), bytes);
    }
}
