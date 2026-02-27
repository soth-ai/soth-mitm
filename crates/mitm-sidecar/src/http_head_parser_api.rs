pub fn parse_http1_request_head_bytes(raw: &[u8]) -> io::Result<()> {
    parse_http_request_head(raw).map(|_| ())
}

pub fn parse_http1_response_head_bytes(raw: &[u8], request_method: &str) -> io::Result<()> {
    parse_http_response_head(raw, request_method).map(|_| ())
}

#[cfg(test)]
mod http_head_parser_api_tests {
    use super::{
        parse_http1_request_head_bytes, parse_http1_response_head_bytes,
        parse_http_request_head_with_mode, parse_http_response_head_with_mode,
    };

    #[test]
    fn request_head_api_accepts_basic_head() {
        let raw = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
        parse_http1_request_head_bytes(raw).expect("request head should parse");
    }

    #[test]
    fn request_head_api_preserves_absolute_form_proxy_target() {
        let raw =
            b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        parse_http1_request_head_bytes(raw).expect("absolute-form request head should parse");
    }

    #[test]
    fn response_head_api_accepts_basic_head() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        parse_http1_response_head_bytes(raw, "GET").expect("response head should parse");
    }

    #[test]
    fn request_rejects_transfer_encoding_content_length_conflict() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n";
        let error = parse_http1_request_head_bytes(raw).expect_err("request should fail");
        assert!(error.to_string().contains("conflicting Transfer-Encoding"));
    }

    #[test]
    fn request_rejects_conflicting_content_length_values() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nContent-Length: 7\r\n\r\n";
        let error = parse_http1_request_head_bytes(raw).expect_err("request should fail");
        assert!(error.to_string().contains("conflicting Content-Length"));
    }

    #[test]
    fn request_accepts_repeated_identical_content_length_values() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n";
        parse_http1_request_head_bytes(raw).expect("request should parse");
    }

    #[test]
    fn request_rejects_unsupported_transfer_encoding() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip\r\n\r\n";
        let error = parse_http1_request_head_bytes(raw).expect_err("request should fail");
        assert!(error.to_string().contains("unsupported Transfer-Encoding"));
    }

    #[test]
    fn request_rejects_duplicate_chunked_transfer_encoding() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked, chunked\r\n\r\n";
        let error = parse_http1_request_head_bytes(raw).expect_err("request should fail");
        assert!(error.to_string().contains("invalid Transfer-Encoding value"));
    }

    #[test]
    fn request_rejects_content_length_with_sign_prefix() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: +4\r\n\r\n";
        let error = parse_http1_request_head_bytes(raw).expect_err("request should fail");
        assert!(error.to_string().contains("invalid Content-Length value"));
    }

    #[test]
    fn request_rejects_folded_headers() {
        let raw = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n X-Folded: yes\r\n\r\n";
        let error = parse_http1_request_head_bytes(raw).expect_err("request should fail");
        assert!(error.to_string().contains("folded HTTP headers"));
    }

    #[test]
    fn request_rejects_invalid_header_name() {
        let raw = b"GET /hello HTTP/1.1\r\nBad Header: value\r\n\r\n";
        let error = parse_http1_request_head_bytes(raw).expect_err("request should fail");
        assert!(error.to_string().contains("invalid HTTP header name"));
    }

    #[test]
    fn request_rejects_whitespace_before_header_colon() {
        let raw = b"GET /hello HTTP/1.1\r\nHost : example.com\r\n\r\n";
        let error = parse_http1_request_head_bytes(raw).expect_err("request should fail");
        assert!(error.to_string().contains("invalid HTTP header name"));
    }

    #[test]
    fn response_rejects_transfer_encoding_content_length_conflict() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n";
        let error = parse_http1_response_head_bytes(raw, "GET").expect_err("response should fail");
        assert!(error.to_string().contains("conflicting Transfer-Encoding"));
    }

    #[test]
    fn response_rejects_conflicting_content_length_values() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 8\r\n\r\n";
        let error = parse_http1_response_head_bytes(raw, "GET").expect_err("response should fail");
        assert!(error.to_string().contains("conflicting Content-Length"));
    }

    #[test]
    fn strict_header_mode_rejects_http10_request_version() {
        let raw = b"GET /legacy HTTP/1.0\r\nHost: example.com\r\n\r\n";
        let error = parse_http_request_head_with_mode(raw, true).expect_err("request should fail");
        assert!(
            error
                .to_string()
                .contains("strict_header_mode requires HTTP/1.1 request version")
        );
    }

    #[test]
    fn strict_header_mode_rejects_http10_response_version() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let error =
            parse_http_response_head_with_mode(raw, "GET", true).expect_err("response should fail");
        assert!(
            error
                .to_string()
                .contains("strict_header_mode requires HTTP/1.1 response version")
        );
    }
}
