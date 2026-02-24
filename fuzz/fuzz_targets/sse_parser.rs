#![no_main]

use libfuzzer_sys::fuzz_target;
use mitm_http::SseParser;

fuzz_target!(|data: &[u8]| {
    let mut parser = SseParser::new();
    for chunk in data.chunks(5) {
        let _ = parser.push_bytes(chunk);
    }
    let _ = parser.finish();
});
