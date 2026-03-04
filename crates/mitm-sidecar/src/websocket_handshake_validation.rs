fn validate_websocket_upgrade_request_head(request: &HttpRequestHead) -> io::Result<()> {
    if !request.method.eq_ignore_ascii_case("GET") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket_upgrade_request:invalid_method",
        ));
    }
    if !has_header_token(&request.headers, "connection", "upgrade") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket_upgrade_request:missing_connection_upgrade",
        ));
    }
    if !has_header_value(&request.headers, "upgrade", "websocket") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket_upgrade_request:missing_upgrade_websocket",
        ));
    }

    let version = first_header_value(&request.headers, "sec-websocket-version").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket_upgrade_request:missing_sec_websocket_version",
        )
    })?;
    if version.trim() != "13" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "websocket_upgrade_request:unsupported_sec_websocket_version:{}",
                version.trim()
            ),
        ));
    }

    let key = first_header_value(&request.headers, "sec-websocket-key").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket_upgrade_request:missing_sec_websocket_key",
        )
    })?;
    if !is_valid_websocket_key_shape(key.trim()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket_upgrade_request:invalid_sec_websocket_key_shape",
        ));
    }

    Ok(())
}

fn validate_websocket_upgrade_response_head(response: &HttpResponseHead) -> io::Result<()> {
    if response.status_code != 101 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "websocket_upgrade_response:invalid_status_code:{}",
                response.status_code
            ),
        ));
    }
    if !has_header_token(&response.headers, "connection", "upgrade") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket_upgrade_response:missing_connection_upgrade",
        ));
    }
    if !has_header_value(&response.headers, "upgrade", "websocket") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket_upgrade_response:missing_upgrade_websocket",
        ));
    }
    Ok(())
}

fn first_header_value<'a>(headers: &'a [HttpHeader], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn is_valid_websocket_key_shape(value: &str) -> bool {
    // RFC6455: base64 nonce of 16 bytes => exactly 24 ASCII characters with "==" padding.
    if value.len() != 24 {
        return false;
    }
    if !value.ends_with("==") {
        return false;
    }
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'=')
}

#[cfg(test)]
mod websocket_handshake_validation_tests {
    use std::io;

    use crate::{HttpBodyMode, HttpHeader, HttpRequestHead, HttpResponseHead, HttpVersion};

    use super::{
        is_valid_websocket_key_shape, validate_websocket_upgrade_request_head,
        validate_websocket_upgrade_response_head,
    };

    fn request_headers() -> Vec<HttpHeader> {
        vec![
            HttpHeader {
                name: "Connection".to_string(),
                value: "Upgrade".to_string(),
            },
            HttpHeader {
                name: "Upgrade".to_string(),
                value: "websocket".to_string(),
            },
            HttpHeader {
                name: "Sec-WebSocket-Version".to_string(),
                value: "13".to_string(),
            },
            HttpHeader {
                name: "Sec-WebSocket-Key".to_string(),
                value: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            },
        ]
    }

    fn response_headers() -> Vec<HttpHeader> {
        vec![
            HttpHeader {
                name: "Connection".to_string(),
                value: "Upgrade".to_string(),
            },
            HttpHeader {
                name: "Upgrade".to_string(),
                value: "websocket".to_string(),
            },
        ]
    }

    #[test]
    fn websocket_key_shape_validation_matches_rfc6455_structure() {
        assert!(is_valid_websocket_key_shape("dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(!is_valid_websocket_key_shape("bad-key"));
        assert!(!is_valid_websocket_key_shape("dGhlIHNhbXBsZSBub25jZQ="));
    }

    #[test]
    fn request_validation_accepts_well_formed_upgrade_head() {
        let request = HttpRequestHead {
            raw: Vec::new(),
            method: "GET".to_string(),
            target: "/ws".to_string(),
            version: HttpVersion::Http11,
            headers: request_headers(),
            body_mode: HttpBodyMode::None,
            connection_close: false,
        };
        validate_websocket_upgrade_request_head(&request).expect("must be valid");
    }

    #[test]
    fn request_validation_rejects_invalid_ws_version() {
        let mut headers = request_headers();
        headers[2].value = "12".to_string();
        let request = HttpRequestHead {
            raw: Vec::new(),
            method: "GET".to_string(),
            target: "/ws".to_string(),
            version: HttpVersion::Http11,
            headers,
            body_mode: HttpBodyMode::None,
            connection_close: false,
        };
        let error = validate_websocket_upgrade_request_head(&request).expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("unsupported_sec_websocket_version")
        );
    }

    #[test]
    fn response_validation_accepts_well_formed_upgrade_head() {
        let response = HttpResponseHead {
            raw: Vec::new(),
            version: HttpVersion::Http11,
            status_code: 101,
            reason_phrase: "Switching Protocols".to_string(),
            headers: response_headers(),
            body_mode: HttpBodyMode::None,
            connection_close: false,
        };
        validate_websocket_upgrade_response_head(&response).expect("must be valid");
    }

    #[test]
    fn response_validation_rejects_non_101_status() {
        let response = HttpResponseHead {
            raw: Vec::new(),
            version: HttpVersion::Http11,
            status_code: 200,
            reason_phrase: "OK".to_string(),
            headers: response_headers(),
            body_mode: HttpBodyMode::None,
            connection_close: false,
        };
        let error = validate_websocket_upgrade_response_head(&response).expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("invalid_status_code:200"));
    }
}
