#![no_main]

use libfuzzer_sys::fuzz_target;
use soth_mitm::test_engine::{
    parse_connect_request_head_with_mode, parse_connect_request_line_with_mode, ConnectParseMode,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_connect_request_head_with_mode(data, ConnectParseMode::Strict);

    if let Ok(text) = std::str::from_utf8(data) {
        for line in text.lines().take(8) {
            let _ = parse_connect_request_line_with_mode(line, ConnectParseMode::Strict);
        }
    }

    if data.len() < 4096 {
        let mut head = data.to_vec();
        if !head.windows(4).any(|window| window == b"\r\n\r\n") {
            head.extend_from_slice(b"\r\n\r\n");
        }
        let _ = parse_connect_request_head_with_mode(&head, ConnectParseMode::Strict);
    }
});
