fn canonicalize_http_headers(headers: Vec<HttpHeader>) -> io::Result<Vec<HttpHeader>> {
    let mut canonical = Vec::with_capacity(headers.len());
    for header in headers {
        let name = header.name.trim();
        if name.is_empty() || !is_valid_http_header_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTP header name",
            ));
        }

        let value = header.value.trim();
        if !is_valid_http_header_value(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTP header value",
            ));
        }

        canonical.push(HttpHeader {
            name: name.to_ascii_lowercase(),
            value: value.to_string(),
        });
    }
    Ok(canonical)
}

fn is_valid_http_header_name(name: &str) -> bool {
    name.bytes().all(is_http_token_char)
}

fn is_http_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_valid_http_header_value(value: &str) -> bool {
    !value
        .as_bytes()
        .iter()
        .any(|byte| matches!(*byte, 0x00..=0x08 | 0x0A..=0x1F | 0x7F))
}

fn parse_content_length(headers: &[HttpHeader]) -> io::Result<Option<u64>> {
    let mut value = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            for raw in header.value.split(',') {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Content-Length value",
                    ));
                }
                if !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Content-Length value",
                    ));
                }
                let parsed = trimmed.parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length value")
                })?;
                if let Some(existing) = value {
                    if existing != parsed {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "conflicting Content-Length values",
                        ));
                    }
                } else {
                    value = Some(parsed);
                }
            }
        }
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedTransferEncoding {
    chunked: bool,
}

fn parse_transfer_encoding(headers: &[HttpHeader]) -> io::Result<ParsedTransferEncoding> {
    let mut parsed = ParsedTransferEncoding { chunked: false };
    for header in headers {
        if !header.name.eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        for coding in header.value.split(',') {
            let token = coding.split(';').next().unwrap_or("").trim();
            if token.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Transfer-Encoding value",
                ));
            }
            if token.eq_ignore_ascii_case("chunked") {
                if parsed.chunked {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Transfer-Encoding value",
                    ));
                }
                parsed.chunked = true;
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported Transfer-Encoding value",
            ));
        }
    }
    Ok(parsed)
}
