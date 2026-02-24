#![no_main]

use libfuzzer_sys::fuzz_target;
use mitm_http::{GrpcEnvelopeParser, GrpcEnvelopeParserLimits};

fuzz_target!(|data: &[u8]| {
    let max_message_len = data
        .first()
        .map(|byte| ((*byte as usize) + 1) * 64)
        .unwrap_or(1024);
    let mut parser = GrpcEnvelopeParser::new(GrpcEnvelopeParserLimits { max_message_len });

    for chunk in data.chunks(7) {
        let _ = parser.push_chunk(chunk);
    }
    let _ = parser.finish();
});
