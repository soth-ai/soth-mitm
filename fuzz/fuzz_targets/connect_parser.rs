#![no_main]

use libfuzzer_sys::fuzz_target;
use mitm_core::{parse_connect_request_head, parse_connect_request_line};

fuzz_target!(|data: &[u8]| {
    let _ = parse_connect_request_head(data);

    if let Ok(text) = std::str::from_utf8(data) {
        for line in text.lines().take(8) {
            let _ = parse_connect_request_line(line);
        }
    }

    if data.len() < 4096 {
        let mut head = data.to_vec();
        if !head.windows(4).any(|window| window == b"\r\n\r\n") {
            head.extend_from_slice(b"\r\n\r\n");
        }
        let _ = parse_connect_request_head(&head);
    }
});
