#[derive(Debug, Clone, PartialEq, Eq)]
struct GrpcRequestObservation {
    path: String,
    service: Option<String>,
    method: Option<String>,
    detection_mode: &'static str,
    content_type: Option<String>,
}

#[derive(Debug)]
struct H2BodyRelayOutcome {
    bytes_forwarded: u64,
    trailers: Option<http::HeaderMap>,
}

fn configure_h2_server(builder: &mut h2::server::Builder, max_header_list_size: u32) {
    builder.max_header_list_size(max_header_list_size);
    builder.max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
    builder.initial_window_size(H2_INITIAL_WINDOW_SIZE);
    builder.initial_connection_window_size(H2_INITIAL_CONNECTION_WINDOW_SIZE);
    builder.max_send_buffer_size(H2_MAX_SEND_BUFFER_SIZE);
}

fn configure_h2_client(builder: &mut h2::client::Builder, max_header_list_size: u32) {
    builder.max_header_list_size(max_header_list_size);
    builder.max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
    builder.initial_window_size(H2_INITIAL_WINDOW_SIZE);
    builder.initial_connection_window_size(H2_INITIAL_CONNECTION_WINDOW_SIZE);
    builder.max_send_buffer_size(H2_MAX_SEND_BUFFER_SIZE);
}

fn is_h2_transport_close_error(error: &h2::Error) -> bool {
    if let Some(io_error) = error.get_io() {
        matches!(
            io_error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        )
    } else {
        error.is_go_away() && error.is_remote() && error.reason() == Some(h2::Reason::NO_ERROR)
    }
}

fn h2_error_to_io(context: &str, error: h2::Error) -> io::Error {
    io::Error::other(format!("{context}: {error}"))
}

fn enforce_h2_request_header_limit(
    parts: &http::request::Parts,
    max_header_list_size: u32,
) -> io::Result<()> {
    let mut header_list_size = estimate_header_map_size(&parts.headers);
    header_list_size += header_field_size(":method", parts.method.as_str());
    header_list_size += header_field_size(":scheme", parts.uri.scheme_str().unwrap_or("https"));
    if let Some(authority) = parts.uri.authority() {
        header_list_size += header_field_size(":authority", authority.as_str());
    }
    let path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    header_list_size += header_field_size(":path", path);
    enforce_h2_header_limit("request", header_list_size, max_header_list_size)
}

fn enforce_h2_response_header_limit(
    parts: &http::response::Parts,
    max_header_list_size: u32,
) -> io::Result<()> {
    let mut header_list_size = estimate_header_map_size(&parts.headers);
    header_list_size += header_field_size(":status", parts.status.as_str());
    enforce_h2_header_limit("response", header_list_size, max_header_list_size)
}

fn detect_grpc_request(parts: &http::request::Parts) -> Option<GrpcRequestObservation> {
    let path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    let content_type = parts
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let has_grpc_content_type = content_type
        .as_deref()
        .map(is_grpc_content_type)
        .unwrap_or(false);
    let service_method = grpc_service_method_from_path(&path);

    let detection_mode = match (has_grpc_content_type, service_method.is_some()) {
        (true, true) => "content_type_and_path",
        (true, false) => "content_type",
        (false, true) => "path_pattern",
        (false, false) => return None,
    };
    let (service, method) = match service_method {
        Some((service, method)) => (Some(service), Some(method)),
        None => (None, None),
    };

    Some(GrpcRequestObservation {
        path,
        service,
        method,
        detection_mode,
        content_type,
    })
}

fn is_grpc_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .map(|head| head.trim().to_ascii_lowercase().starts_with("application/grpc"))
        .unwrap_or(false)
}

fn grpc_service_method_from_path(path: &str) -> Option<(String, String)> {
    let path_only = path.split('?').next().unwrap_or(path);
    let trimmed = path_only.strip_prefix('/')?;
    let mut parts = trimmed.split('/');
    let service = parts.next()?;
    let method = parts.next()?;
    if service.is_empty() || method.is_empty() || parts.next().is_some() {
        return None;
    }
    Some((service.to_string(), method.to_string()))
}

fn enforce_h2_header_limit(
    direction: &str,
    observed_size: usize,
    max_header_list_size: u32,
) -> io::Result<()> {
    let limit = max_header_list_size as usize;
    if observed_size > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "HTTP/2 {direction} header list size {observed_size} exceeded configured limit {limit}"
            ),
        ));
    }
    Ok(())
}

fn estimate_header_map_size(headers: &http::HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| header_field_size(name.as_str(), value.as_bytes()))
        .sum()
}

fn header_field_size(name: &str, value: impl AsRef<[u8]>) -> usize {
    name.len() + value.as_ref().len() + 32
}

#[cfg(test)]
mod tests {
    use super::detect_grpc_request;

    #[test]
    fn detects_grpc_from_path_pattern_without_content_type() {
        let request = http::Request::builder()
            .method("POST")
            .uri("https://unit.test/greeter.Service/SayHello")
            .body(())
            .expect("request");
        let (parts, _) = request.into_parts();
        let observation = detect_grpc_request(&parts).expect("must detect grpc");
        assert_eq!(observation.detection_mode, "path_pattern");
        assert_eq!(observation.service.as_deref(), Some("greeter.Service"));
        assert_eq!(observation.method.as_deref(), Some("SayHello"));
    }
}
