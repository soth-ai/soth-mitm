pub fn parse_http1_request_head_bytes(raw: &[u8]) -> io::Result<()> {
    parse_http_request_head(raw).map(|_| ())
}

pub fn parse_http1_response_head_bytes(raw: &[u8], request_method: &str) -> io::Result<()> {
    parse_http_response_head(raw, request_method).map(|_| ())
}

#[cfg(test)]
mod http_head_parser_api_tests {
    use super::{parse_http1_request_head_bytes, parse_http1_response_head_bytes};

    #[test]
    fn request_head_api_accepts_basic_head() {
        let raw = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
        parse_http1_request_head_bytes(raw).expect("request head should parse");
    }

    #[test]
    fn response_head_api_accepts_basic_head() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        parse_http1_response_head_bytes(raw, "GET").expect("response head should parse");
    }
}
