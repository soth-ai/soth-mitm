#![no_main]

use libfuzzer_sys::fuzz_target;
use mitm_sidecar::{parse_http1_request_head_bytes, parse_http1_response_head_bytes};

fuzz_target!(|data: &[u8]| {
    let split = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());
    let request = &data[..split];
    let response = if split < data.len() {
        &data[split + 1..]
    } else {
        data
    };

    let _ = parse_http1_request_head_bytes(request);

    let method = if request.starts_with(b"HEAD") {
        "HEAD"
    } else {
        "GET"
    };
    let _ = parse_http1_response_head_bytes(response, method);
});
