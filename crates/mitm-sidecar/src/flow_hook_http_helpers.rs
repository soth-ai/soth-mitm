use std::collections::HashSet;
use std::io::Read;
use std::net::Ipv6Addr;

use bytes::Bytes;
use http::{header::HeaderName, HeaderMap};

const HANDLER_STRIP_HEADERS: &[&str] = &[
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "upgrade",
];

struct BodyCaptureObserver {
    body: Vec<u8>,
    max_handler_bytes: usize,
    truncated: bool,
}

impl BodyCaptureObserver {
    fn new(max_handler_bytes: usize) -> Self {
        Self {
            body: Vec::new(),
            max_handler_bytes,
            truncated: false,
        }
    }
}

impl HttpBodyObserver for BodyCaptureObserver {
    fn on_chunk<'a>(
        &'a mut self,
        chunk: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if !self.truncated {
                let remaining = self.max_handler_bytes.saturating_sub(self.body.len());
                if remaining >= chunk.len() {
                    self.body.extend_from_slice(chunk);
                } else {
                    if remaining > 0 {
                        self.body.extend_from_slice(&chunk[..remaining]);
                    }
                    self.truncated = true;
                }
            }
            Ok(())
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_http_body_with_capture<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
    mode: HttpBodyMode,
    max_http_head_bytes: usize,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    max_capture_bytes: usize,
) -> io::Result<(u64, Bytes, bool)>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut observer = BodyCaptureObserver::new(max_capture_bytes);
    let forwarded = relay_http_body(
        engine,
        context,
        event_kind,
        source,
        sink,
        mode,
        max_http_head_bytes,
        runtime_governor,
        &mut observer,
    )
    .await?;
    Ok((forwarded, Bytes::from(observer.body), observer.truncated))
}

fn build_handler_header_map(headers: &[HttpHeader]) -> HeaderMap {
    let mut map = HeaderMap::with_capacity(headers.len());
    for header in headers {
        let Ok(name) = HeaderName::from_bytes(header.name.as_bytes()) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::from_str(&header.value) else {
            continue;
        };
        map.append(name, value);
    }
    strip_hop_by_hop_and_transport_headers(&mut map);
    map
}

fn strip_hop_by_hop_and_transport_headers(headers: &mut HeaderMap) {
    let mut blocked = HashSet::new();
    for name in HANDLER_STRIP_HEADERS {
        blocked.insert(HeaderName::from_static(name));
    }
    for token in connection_tokens(headers) {
        if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
            blocked.insert(name);
        }
    }
    for name in blocked {
        headers.remove(name);
    }
}

fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    for value in headers.get_all(HeaderName::from_static("connection")) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        for token in raw.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                out.push(token.to_ascii_lowercase());
            }
        }
    }
    out
}

fn normalize_request_path_for_handler(target: &str) -> String {
    if target.starts_with('/') || target == "*" {
        return target.to_string();
    }
    if let Ok(uri) = target.parse::<http::Uri>() {
        return uri
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
    }
    target.to_string()
}

fn normalize_h2_path_for_handler(uri: &http::Uri) -> String {
    uri.path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string())
}

fn ensure_handler_host_header_from_target(
    headers: &mut HeaderMap,
    context: &FlowContext,
    target: &str,
) {
    let authority_hint = target
        .parse::<http::Uri>()
        .ok()
        .and_then(|uri| authority_from_uri(&uri));
    ensure_handler_host_header(headers, context, authority_hint.as_deref());
}

fn ensure_handler_host_header_from_uri(
    headers: &mut HeaderMap,
    context: &FlowContext,
    uri: &http::Uri,
) {
    let authority_hint = authority_from_uri(uri);
    ensure_handler_host_header(headers, context, authority_hint.as_deref());
}

fn ensure_handler_host_header(
    headers: &mut HeaderMap,
    context: &FlowContext,
    authority_hint: Option<&str>,
) {
    if headers.contains_key(http::header::HOST) {
        return;
    }

    let host_value = authority_hint
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| authority_from_context(context));
    let Some(host_value) = host_value else {
        return;
    };
    let Ok(host_header) = http::HeaderValue::from_str(&host_value) else {
        return;
    };
    headers.insert(http::header::HOST, host_header);
}

fn authority_from_uri(uri: &http::Uri) -> Option<String> {
    let host = uri.host()?;
    let port = uri.port_u16();
    Some(format_authority(host, port))
}

fn authority_from_context(context: &FlowContext) -> Option<String> {
    let host = context.server_host.trim();
    if host.is_empty() || host == "<unknown>" {
        return None;
    }
    Some(format_authority(host, Some(context.server_port)))
}

fn format_authority(host: &str, port: Option<u16>) -> String {
    let trimmed = host.trim();
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(trimmed);
    let host_text = if unbracketed.parse::<Ipv6Addr>().is_ok() && !trimmed.starts_with('[') {
        format!("[{unbracketed}]")
    } else {
        trimmed.to_string()
    };
    match port {
        Some(port) if port != 80 && port != 443 => format!("{host_text}:{port}"),
        _ => host_text,
    }
}

fn build_handler_header_map_from_h2(headers: &http::HeaderMap) -> HeaderMap {
    let mut map = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        map.append(name.clone(), value.clone());
    }
    strip_hop_by_hop_and_transport_headers(&mut map);
    map
}

fn is_ndjson_response(response: &HttpResponseHead) -> bool {
    for header in &response.headers {
        if !header.name.eq_ignore_ascii_case("content-type") {
            continue;
        }
        let base = header
            .value
            .split(';')
            .next()
            .map(str::trim)
            .unwrap_or_default();
        if base.eq_ignore_ascii_case("application/x-ndjson")
            || base.eq_ignore_ascii_case("application/jsonl")
        {
            return true;
        }
    }
    false
}

fn is_grpc_request(headers: &[HttpHeader]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("content-type")
            && is_grpc_content_type_value(&header.value)
    })
}

fn is_grpc_response(response: &HttpResponseHead) -> bool {
    response.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("content-type")
            && is_grpc_content_type_value(&header.value)
    })
}

fn normalize_grpc_request_body_for_handler(headers: &mut HeaderMap, body: Bytes) -> Bytes {
    match strip_grpc_frame_header(body.as_ref()) {
        Ok(payload) => payload,
        Err(_) => {
            headers.insert(
                HeaderName::from_static("x-soth-grpc-frame-error"),
                http::HeaderValue::from_static("true"),
            );
            body
        }
    }
}

fn strip_grpc_frame_header(payload: &[u8]) -> Result<Bytes, &'static str> {
    if payload.len() < 5 {
        return Err("grpc frame too short");
    }
    let frame_len = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
    if payload.len() < 5 + frame_len {
        return Err("grpc frame truncated");
    }
    Ok(Bytes::copy_from_slice(&payload[5..5 + frame_len]))
}

fn is_grpc_content_type_value(value: &str) -> bool {
    value
        .split(';')
        .next()
        .map(|head| {
            head.trim()
                .to_ascii_lowercase()
                .starts_with("application/grpc")
        })
        .unwrap_or(false)
}

fn normalize_request_body_for_handler(headers: &mut HeaderMap, body: Bytes) -> Bytes {
    normalize_encoded_body_for_handler(headers, body)
}

fn normalize_response_body_for_handler(headers: &mut HeaderMap, body: Bytes) -> Bytes {
    normalize_encoded_body_for_handler(headers, body)
}

fn normalize_encoded_body_for_handler(headers: &mut HeaderMap, body: Bytes) -> Bytes {
    let encoding = headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    headers.remove("content-encoding");
    let Some(encoding) = encoding else {
        return body;
    };

    let decoded = match encoding.as_str() {
        "gzip" => decompress_gzip(body.as_ref()),
        "br" => decompress_brotli(body.as_ref()),
        "zstd" => decompress_zstd(body.as_ref()),
        _ => Err(format!("unsupported content-encoding: {encoding}")),
    };
    match decoded {
        Ok(bytes) => Bytes::from(bytes),
        Err(_) => {
            headers.insert(
                HeaderName::from_static("x-soth-encoding-error"),
                http::HeaderValue::from_static("true"),
            );
            body
        }
    }
}

fn mark_body_truncated(headers: &mut HeaderMap) {
    headers.insert(
        HeaderName::from_static("x-soth-body-truncated"),
        http::HeaderValue::from_static("true"),
    );
}

fn sanitize_block_status(status: u16) -> u16 {
    if (100..=599).contains(&status) {
        status
    } else {
        tracing::warn!(
            invalid_status = status,
            "handler returned invalid block status; coercing to 403"
        );
        403
    }
}

fn decompress_gzip(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = flate2::read::GzDecoder::new(input);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|error| format!("gzip decode failed: {error}"))?;
    Ok(out)
}

fn decompress_brotli(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = brotli::Decompressor::new(input, 4096);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|error| format!("brotli decode failed: {error}"))?;
    Ok(out)
}

fn decompress_zstd(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = zstd::stream::read::Decoder::new(input)
        .map_err(|error| format!("zstd init failed: {error}"))?;
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|error| format!("zstd decode failed: {error}"))?;
    Ok(out)
}

#[cfg(test)]
mod flow_hook_http_helpers_tests {
    use super::*;
    use mitm_http::ApplicationProtocol;

    fn context(server_host: &str, server_port: u16) -> FlowContext {
        FlowContext {
            flow_id: 1,
            client_addr: "127.0.0.1:55000".to_string(),
            server_host: server_host.to_string(),
            server_port,
            protocol: ApplicationProtocol::Http2,
        }
    }

    #[test]
    fn ensure_host_from_h2_uri_authority() {
        let mut headers = HeaderMap::new();
        let uri: http::Uri = "https://api.example.com:8443/v1/models"
            .parse()
            .expect("uri");
        ensure_handler_host_header_from_uri(&mut headers, &context("fallback.example", 443), &uri);
        assert_eq!(
            headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok()),
            Some("api.example.com:8443")
        );
    }

    #[test]
    fn ensure_host_from_context_when_h2_uri_has_no_authority() {
        let mut headers = HeaderMap::new();
        let uri: http::Uri = "/v1/models".parse().expect("uri");
        ensure_handler_host_header_from_uri(&mut headers, &context("api.openai.com", 443), &uri);
        assert_eq!(
            headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok()),
            Some("api.openai.com")
        );
    }

    #[test]
    fn ensure_host_keeps_existing_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::HOST,
            http::HeaderValue::from_static("existing.example"),
        );
        let uri: http::Uri = "/v1/models".parse().expect("uri");
        ensure_handler_host_header_from_uri(&mut headers, &context("api.openai.com", 443), &uri);
        assert_eq!(
            headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok()),
            Some("existing.example")
        );
    }

    #[test]
    fn ensure_host_formats_ipv6_context_authority() {
        let mut headers = HeaderMap::new();
        let uri: http::Uri = "/v1/models".parse().expect("uri");
        ensure_handler_host_header_from_uri(&mut headers, &context("::1", 8443), &uri);
        assert_eq!(
            headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok()),
            Some("[::1]:8443")
        );
    }

    #[test]
    fn ensure_host_from_http1_absolute_target() {
        let mut headers = HeaderMap::new();
        ensure_handler_host_header_from_target(
            &mut headers,
            &context("fallback.example", 443),
            "https://anthropic.com/v1/messages",
        );
        assert_eq!(
            headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok()),
            Some("anthropic.com")
        );
    }
}
