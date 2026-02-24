use mitm_sidecar::{parse_http1_request_head_bytes, parse_http1_response_head_bytes};

#[test]
fn request_smuggling_corpus_rejects_ambiguous_heads() {
    let fixtures: [(&str, &[u8], &str); 7] = [
        (
            "te_cl_conflict",
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
            "conflicting Transfer-Encoding",
        ),
        (
            "conflicting_content_length_lines",
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nContent-Length: 7\r\n\r\n",
            "conflicting Content-Length",
        ),
        (
            "conflicting_content_length_list",
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4, 7\r\n\r\n",
            "conflicting Content-Length",
        ),
        (
            "unsupported_transfer_encoding",
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip\r\n\r\n",
            "unsupported Transfer-Encoding",
        ),
        (
            "duplicate_chunked_transfer_encoding",
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
            "invalid Transfer-Encoding value",
        ),
        (
            "signed_content_length",
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: +5\r\n\r\n",
            "invalid Content-Length value",
        ),
        (
            "folded_header",
            b"GET /hello HTTP/1.1\r\nHost: example.com\r\n X-Injected: 1\r\n\r\n",
            "folded HTTP headers",
        ),
    ];

    for (name, raw, expected_error) in fixtures {
        let error = match parse_http1_request_head_bytes(raw) {
            Ok(()) => panic!("{name} should fail to parse"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(expected_error),
            "{name} expected error containing {expected_error:?}, got: {error}"
        );
    }
}

#[test]
fn response_smuggling_corpus_rejects_ambiguous_heads() {
    let fixtures: [(&str, &[u8], &str); 3] = [
        (
            "te_cl_conflict",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n",
            "conflicting Transfer-Encoding",
        ),
        (
            "conflicting_content_length_lines",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 8\r\n\r\n",
            "conflicting Content-Length",
        ),
        (
            "whitespace_in_header_name",
            b"HTTP/1.1 200 OK\r\nContent-Length : 8\r\n\r\n",
            "invalid HTTP header name",
        ),
    ];

    for (name, raw, expected_error) in fixtures {
        let error = match parse_http1_response_head_bytes(raw, "GET") {
            Ok(()) => panic!("{name} should fail to parse"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(expected_error),
            "{name} expected error containing {expected_error:?}, got: {error}"
        );
    }
}

#[test]
fn request_absolute_form_corpus_accepts_valid_cases() {
    let fixtures: [(&str, &[u8]); 2] = [
        (
            "http_absolute_form",
            b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ),
        (
            "origin_form",
            b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ),
    ];

    for (name, raw) in fixtures {
        parse_http1_request_head_bytes(raw)
            .unwrap_or_else(|error| panic!("{name} should parse: {error}"));
    }
}
