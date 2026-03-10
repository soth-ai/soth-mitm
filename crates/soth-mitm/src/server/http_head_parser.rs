use super::http_head_parser_smuggling::{
    canonicalize_http_headers, parse_content_length, parse_transfer_encoding,
};
use super::io_timeouts::{read_with_idle_timeout, with_stream_stage_timeout};
use super::{
    runtime_governor, BufferedConn, HttpBodyMode, HttpHeader, HttpRequestHead, HttpResponseHead,
    HttpVersion, IO_CHUNK_SIZE,
};
use std::io;
use std::sync::Arc;
use tokio::io::AsyncRead;

pub(crate) async fn read_connect_head<S>(
    stream: &mut S,
    max_connect_head_bytes: usize,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let _in_flight_lease =
        runtime_governor.reserve_in_flight_or_error(max_connect_head_bytes, "connect_head_read")?;

    with_stream_stage_timeout("connect_head_total", async {
        let mut data = Vec::with_capacity(1024);
        let mut byte = [0_u8; 1];

        while !data.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = read_with_idle_timeout(stream, &mut byte, "connect_head_read").await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "client closed before CONNECT headers completed ({})",
                        describe_connect_head_prefix(&data)
                    ),
                ));
            }

            data.push(byte[0]);
            if looks_like_tls_client_hello_prefix(&data) {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "proxy expected HTTP CONNECT but received TLS ClientHello ({})",
                        describe_connect_head_prefix(&data)
                    ),
                ));
            }
            if data.len() > max_connect_head_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CONNECT header exceeded configured limit",
                ));
            }
        }

        Ok(data)
    })
    .await
}

fn describe_connect_head_prefix(data: &[u8]) -> String {
    const PREFIX_LIMIT: usize = 16;
    let prefix = &data[..data.len().min(PREFIX_LIMIT)];
    let mut hex = String::with_capacity(prefix.len().saturating_mul(2));
    for byte in prefix {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }

    let ascii = prefix
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect::<String>();

    format!(
        "received {} bytes; prefix_hex={hex}; prefix_ascii={ascii}",
        data.len()
    )
}

fn looks_like_tls_client_hello_prefix(data: &[u8]) -> bool {
    if data.len() < 3 {
        return false;
    }
    data[0] == 0x16 && data[1] == 0x03 && (0x00..=0x04).contains(&data[2])
}

pub(crate) async fn read_until_pattern<S: AsyncRead + Unpin>(
    conn: &mut BufferedConn<S>,
    pattern: &[u8],
    max_bytes: usize,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
) -> io::Result<Option<Vec<u8>>> {
    read_until_pattern_inner(conn, pattern, max_bytes, runtime_governor, true).await
}

pub(crate) async fn read_until_pattern_no_stage_timeout<S: AsyncRead + Unpin>(
    conn: &mut BufferedConn<S>,
    pattern: &[u8],
    max_bytes: usize,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
) -> io::Result<Option<Vec<u8>>> {
    read_until_pattern_inner(conn, pattern, max_bytes, runtime_governor, false).await
}

async fn read_until_pattern_inner<S: AsyncRead + Unpin>(
    conn: &mut BufferedConn<S>,
    pattern: &[u8],
    max_bytes: usize,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    apply_stage_timeout: bool,
) -> io::Result<Option<Vec<u8>>> {
    let _in_flight_lease =
        runtime_governor.reserve_in_flight_or_error(max_bytes, "http_head_read")?;
    let body = async {
        loop {
            if let Some(start) = find_subsequence(&conn.read_buf, pattern) {
                let end = start + pattern.len();
                let bytes = conn.read_buf.drain(..end).collect::<Vec<_>>();
                return Ok(Some(bytes));
            }

            if conn.read_buf.len() > max_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP header exceeded configured limit",
                ));
            }

            let mut chunk = [0_u8; IO_CHUNK_SIZE];
            let read =
                read_with_idle_timeout(&mut conn.stream, &mut chunk, "http_head_pattern_read")
                    .await?;
            if read == 0 {
                if conn.read_buf.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before message boundary was reached",
                ));
            }
            conn.read_buf.extend_from_slice(&chunk[..read]);
        }
    };
    if apply_stage_timeout {
        with_stream_stage_timeout("http_head_pattern_total", body).await
    } else {
        body.await
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub(crate) fn parse_http_request_head(raw: &[u8]) -> io::Result<HttpRequestHead> {
    let text = std::str::from_utf8(raw).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "request headers were not valid UTF-8",
        )
    })?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request line is missing"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request method is missing"))?;
    let target = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request target is missing"))?;
    let version_text = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP version is missing"))?;
    if parts.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request line had too many fields",
        ));
    }
    let version = parse_http_version(version_text)?;

    let headers = canonicalize_http_headers(parse_http_headers(lines)?)?;
    let body_mode = parse_request_body_mode(&headers)?;
    let connection_close = is_connection_close(version, &headers);

    Ok(HttpRequestHead {
        raw: raw.to_vec(),
        method: method.to_string(),
        target: target.to_string(),
        version,
        headers,
        body_mode,
        connection_close,
    })
}

pub(crate) fn parse_http_request_head_with_mode(
    raw: &[u8],
    strict_header_mode: bool,
) -> io::Result<HttpRequestHead> {
    let parsed = parse_http_request_head(raw)?;
    if strict_header_mode && parsed.version != HttpVersion::Http11 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "strict_header_mode requires HTTP/1.1 request version",
        ));
    }
    Ok(parsed)
}

pub(crate) fn parse_http_response_head(
    raw: &[u8],
    request_method: &str,
) -> io::Result<HttpResponseHead> {
    let text = std::str::from_utf8(raw).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "response headers were not valid UTF-8",
        )
    })?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "response status line is missing",
        )
    })?;
    let mut parts = status_line.split_whitespace();
    let version_text = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "response version is missing"))?;
    let status_text = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "response status is missing"))?;
    let reason_phrase = parts.collect::<Vec<_>>().join(" ");
    let version = parse_http_version(version_text)?;
    let status_code = status_text
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid response status code"))?;

    let headers = canonicalize_http_headers(parse_http_headers(lines)?)?;
    let mut connection_close = is_connection_close(version, &headers);
    let body_mode = parse_response_body_mode(&headers, request_method, status_code)?;
    if body_mode == HttpBodyMode::CloseDelimited {
        connection_close = true;
    }

    Ok(HttpResponseHead {
        raw: raw.to_vec(),
        version,
        status_code,
        reason_phrase,
        headers,
        body_mode,
        connection_close,
    })
}

pub(crate) fn parse_http_response_head_with_mode(
    raw: &[u8],
    request_method: &str,
    strict_header_mode: bool,
) -> io::Result<HttpResponseHead> {
    let parsed = parse_http_response_head(raw, request_method)?;
    if strict_header_mode && parsed.version != HttpVersion::Http11 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "strict_header_mode requires HTTP/1.1 response version",
        ));
    }
    Ok(parsed)
}

fn parse_http_version(text: &str) -> io::Result<HttpVersion> {
    match text {
        "HTTP/1.0" => Ok(HttpVersion::Http10),
        "HTTP/1.1" => Ok(HttpVersion::Http11),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "only HTTP/1.0 and HTTP/1.1 are supported in MITM mode",
        )),
    }
}

fn parse_http_headers<'a>(lines: impl Iterator<Item = &'a str>) -> io::Result<Vec<HttpHeader>> {
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "folded HTTP headers are not supported",
            ));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed header line"))?;
        if name != name.trim() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTP header name",
            ));
        }
        headers.push(HttpHeader {
            name: name.to_string(),
            value: value.trim().to_string(),
        });
    }
    Ok(headers)
}

fn parse_request_body_mode(headers: &[HttpHeader]) -> io::Result<HttpBodyMode> {
    let transfer_encoding = parse_transfer_encoding(headers)?;
    let content_length = parse_content_length(headers)?;
    if transfer_encoding.chunked && content_length.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "conflicting Transfer-Encoding and Content-Length",
        ));
    }
    if transfer_encoding.chunked {
        return Ok(HttpBodyMode::Chunked);
    }
    if let Some(length) = content_length {
        return Ok(if length == 0 {
            HttpBodyMode::None
        } else {
            HttpBodyMode::ContentLength(length)
        });
    }
    Ok(HttpBodyMode::None)
}

fn parse_response_body_mode(
    headers: &[HttpHeader],
    request_method: &str,
    status_code: u16,
) -> io::Result<HttpBodyMode> {
    if request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status_code)
        || status_code == 204
        || status_code == 304
    {
        return Ok(HttpBodyMode::None);
    }

    let transfer_encoding = parse_transfer_encoding(headers)?;
    let content_length = parse_content_length(headers)?;
    if transfer_encoding.chunked && content_length.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "conflicting Transfer-Encoding and Content-Length",
        ));
    }
    if transfer_encoding.chunked {
        return Ok(HttpBodyMode::Chunked);
    }
    if let Some(length) = content_length {
        return Ok(if length == 0 {
            HttpBodyMode::None
        } else {
            HttpBodyMode::ContentLength(length)
        });
    }

    Ok(HttpBodyMode::CloseDelimited)
}

pub(crate) fn has_header_token(headers: &[HttpHeader], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .flat_map(|header| header.value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case(token))
}

pub(crate) fn has_header_value(headers: &[HttpHeader], name: &str, expected: &str) -> bool {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .any(|header| header.value.trim().eq_ignore_ascii_case(expected))
}

pub(crate) fn is_sse_response(response: &HttpResponseHead) -> bool {
    response.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("content-type")
            && header
                .value
                .split(';')
                .next()
                .map(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
                .unwrap_or(false)
    })
}

fn is_connection_close(version: HttpVersion, headers: &[HttpHeader]) -> bool {
    if has_header_token(headers, "connection", "close") {
        return true;
    }
    if version == HttpVersion::Http10 && !has_header_token(headers, "connection", "keep-alive") {
        return true;
    }
    false
}
