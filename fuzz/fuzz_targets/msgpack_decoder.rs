#![no_main]

use libfuzzer_sys::fuzz_target;
use mitm_http::{decode_msgpack_structure, MsgPackDecodeLimits};

fuzz_target!(|data: &[u8]| {
    let seed = data.first().copied().unwrap_or(0) as usize;
    let limits = MsgPackDecodeLimits {
        max_input_bytes: data.len().saturating_add(64),
        max_depth: 1 + (seed % 32),
        max_container_len: 1 + (seed % 256),
        max_text_bytes: 1 + ((seed + 11) % 4096),
        max_binary_bytes: 1 + ((seed + 17) % 4096),
        max_extension_bytes: 1 + ((seed + 23) % 4096),
    };

    let _ = decode_msgpack_structure(data, limits);
});
