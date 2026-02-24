use mitm_core::{
    parse_connect_request_head_with_mode, parse_connect_request_line_with_mode, ConnectParseError,
    ConnectParseMode,
};
use proptest::prelude::*;

fn host_strategy() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-z0-9](?:[a-z0-9.-]{0,30}[a-z0-9])?")
        .expect("valid hostname regex")
}

proptest! {
    #[test]
    fn strict_parser_accepts_canonical_connect_lines(host in host_strategy(), port in 1_u16..=u16::MAX) {
        let line = format!("CONNECT {host}:{port} HTTP/1.1");
        let parsed = parse_connect_request_line_with_mode(&line, ConnectParseMode::Strict)
            .expect("strict parser should accept canonical CONNECT line");
        prop_assert_eq!(parsed.server_host, host);
        prop_assert_eq!(parsed.server_port, port);
    }

    #[test]
    fn strict_parser_rejects_lowercase_method(host in host_strategy(), port in 1_u16..=u16::MAX) {
        let line = format!("connect {host}:{port} HTTP/1.1");
        let error = parse_connect_request_line_with_mode(&line, ConnectParseMode::Strict)
            .expect_err("strict parser must reject lowercase method");
        prop_assert_eq!(error, ConnectParseError::MethodNotConnect);
    }

    #[test]
    fn lenient_parser_accepts_lowercase_absolute_form_with_default_port(host in host_strategy()) {
        let line = format!("connect https://{host}/chat HTTP/1.1");
        let parsed = parse_connect_request_line_with_mode(&line, ConnectParseMode::Lenient)
            .expect("lenient parser should normalize absolute-form authority");
        prop_assert_eq!(parsed.server_host, host);
        prop_assert_eq!(parsed.server_port, 443);
    }

    #[test]
    fn lenient_head_parser_accepts_missing_port(host in host_strategy()) {
        let head = format!(
            "CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: proptest\r\n\r\n"
        );
        let (parsed, consumed) = parse_connect_request_head_with_mode(head.as_bytes(), ConnectParseMode::Lenient)
            .expect("lenient head parser should default to port 443");
        prop_assert_eq!(parsed.server_host, host);
        prop_assert_eq!(parsed.server_port, 443);
        prop_assert_eq!(consumed, head.len());
    }
}
