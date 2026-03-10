use super::{
    parse_connect_request_head, parse_connect_request_head_with_mode, parse_connect_request_line,
    parse_connect_request_line_with_mode, ConnectParseError, ConnectParseMode,
};

#[test]
fn parses_connect_request_line_with_domain_authority() {
    let parsed = parse_connect_request_line("CONNECT api.example.com:443 HTTP/1.1").expect("must parse");
    assert_eq!(parsed.server_host, "api.example.com");
    assert_eq!(parsed.server_port, 443);
}

#[test]
fn parses_connect_request_line_with_ipv6_authority() {
    let parsed = parse_connect_request_line("CONNECT [2001:db8::1]:8443 HTTP/1.1").expect("must parse");
    assert_eq!(parsed.server_host, "2001:db8::1");
    assert_eq!(parsed.server_port, 8443);
}

#[test]
fn rejects_non_connect_method() {
    let error = parse_connect_request_line("GET / HTTP/1.1").expect_err("must fail");
    assert_eq!(error, ConnectParseError::MethodNotConnect);
}

#[test]
fn rejects_unbracketed_ipv6_authority() {
    let error =
        parse_connect_request_line("CONNECT 2001:db8::1:443 HTTP/1.1").expect_err("must fail");
    assert_eq!(error, ConnectParseError::InvalidAuthority);
}

#[test]
fn parses_connect_head_and_returns_header_len() {
    let raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nhello";
    let (parsed, header_len) = parse_connect_request_head(raw).expect("must parse");
    assert_eq!(parsed.server_host, "example.com");
    assert_eq!(parsed.server_port, 443);
    assert_eq!(&raw[header_len..], b"hello");
}

#[test]
fn rejects_incomplete_headers() {
    let raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n";
    let error = parse_connect_request_head(raw).expect_err("must fail");
    assert_eq!(error, ConnectParseError::IncompleteHeaders);
}

#[test]
fn lenient_mode_accepts_lowercase_method_and_missing_port() {
    let parsed = parse_connect_request_line_with_mode(
        "connect api.example.com HTTP/1.1",
        ConnectParseMode::Lenient,
    )
    .expect("must parse in lenient mode");
    assert_eq!(parsed.server_host, "api.example.com");
    assert_eq!(parsed.server_port, 443);
}

#[test]
fn lenient_mode_accepts_absolute_form_authority() {
    let parsed = parse_connect_request_line_with_mode(
        "CONNECT https://api.example.com:8443/path HTTP/1.1",
        ConnectParseMode::Lenient,
    )
    .expect("must parse in lenient mode");
    assert_eq!(parsed.server_host, "api.example.com");
    assert_eq!(parsed.server_port, 8443);
}

#[test]
fn strict_mode_rejects_lowercase_connect_method() {
    let error = parse_connect_request_line_with_mode(
        "connect api.example.com:443 HTTP/1.1",
        ConnectParseMode::Strict,
    )
    .expect_err("strict mode must reject lowercase method");
    assert_eq!(error, ConnectParseError::MethodNotConnect);
}

#[test]
fn lenient_mode_parses_head_with_absolute_authority() {
    let raw = b"CONNECT https://example.com/resource HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let (parsed, header_len) =
        parse_connect_request_head_with_mode(raw, ConnectParseMode::Lenient).expect("must parse");
    assert_eq!(parsed.server_host, "example.com");
    assert_eq!(parsed.server_port, 443);
    assert_eq!(header_len, raw.len());
}
