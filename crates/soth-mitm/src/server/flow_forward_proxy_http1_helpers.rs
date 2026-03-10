use super::http_head_parser::parse_http_request_head;
use super::route_planner_model::{RouteTarget, UpstreamRequestTargetMode};
use super::HttpRequestHead;
use http::Uri;
use std::io;
use std::net::IpAddr;

pub(crate) fn is_forward_http1_request_candidate(input: &[u8]) -> bool {
    if let Ok(request) = parse_http_request_head(input) {
        return !request.method.eq_ignore_ascii_case("CONNECT");
    }
    is_non_connect_http1_request_line(input)
}

fn is_non_connect_http1_request_line(input: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(input) else {
        return false;
    };
    let Some(line) = text.split("\r\n").next() else {
        return false;
    };
    let mut parts = line.split_whitespace();
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(_target) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        return false;
    }
    matches!(version, "HTTP/1.0" | "HTTP/1.1")
}

pub(crate) fn resolve_forward_http_route(request: &HttpRequestHead) -> io::Result<RouteTarget> {
    if request.target.starts_with("http://") || request.target.starts_with("https://") {
        return resolve_absolute_form_forward_http_route(request);
    }
    resolve_origin_form_forward_http_route(request)
}

pub(crate) fn is_self_listener_target(
    target_host: &str,
    target_port: u16,
    listen_addr: &str,
    listen_port: u16,
) -> bool {
    if target_port != listen_port {
        return false;
    }

    let target_host = normalize_authority_host(target_host);
    let listen_addr = normalize_authority_host(listen_addr.trim());

    if target_host.eq_ignore_ascii_case(listen_addr) {
        return true;
    }

    let target_ip = target_host.parse::<IpAddr>().ok();
    let listen_ip = listen_addr.parse::<IpAddr>().ok();

    if let (Some(target_ip), Some(listen_ip)) = (target_ip, listen_ip) {
        if target_ip == listen_ip {
            return true;
        }
        if target_ip.is_loopback() && listen_ip.is_loopback() {
            return true;
        }
        if listen_ip.is_unspecified() && target_ip.is_loopback() {
            return true;
        }
    }

    if is_localhost_name(target_host) {
        if is_localhost_name(listen_addr) {
            return true;
        }
        if let Some(listen_ip) = listen_ip {
            return listen_ip.is_loopback() || listen_ip.is_unspecified();
        }
    }

    false
}

fn normalize_authority_host(value: &str) -> &str {
    value
        .strip_prefix('[')
        .and_then(|trimmed| trimmed.strip_suffix(']'))
        .unwrap_or(value)
}

fn is_localhost_name(value: &str) -> bool {
    value.eq_ignore_ascii_case("localhost")
}

fn resolve_absolute_form_forward_http_route(request: &HttpRequestHead) -> io::Result<RouteTarget> {
    let uri = request.target.parse::<Uri>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy request target was not a valid URI",
        )
    })?;
    match uri.scheme_str() {
        Some("http") => {}
        Some("https") => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTPS absolute-form requires CONNECT",
            ));
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "only http absolute-form is supported for cleartext proxying",
            ));
        }
    }
    let server_host = uri
        .host()
        .map(str::to_string)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "absolute URI missing host"))?;
    let server_port = uri.port_u16().unwrap_or(80);
    let policy_path = uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Ok(RouteTarget::new(
        server_host,
        server_port,
        Some(policy_path),
    ))
}

fn resolve_origin_form_forward_http_route(request: &HttpRequestHead) -> io::Result<RouteTarget> {
    let host_header = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value.as_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "origin-form request missing Host header",
            )
        })?;
    let authority = host_header.parse::<http::uri::Authority>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "origin-form request had invalid Host header authority",
        )
    })?;
    let server_host = authority.host().to_string();
    let server_port = authority.port_u16().unwrap_or(80);
    let policy_path = if request.target.starts_with('/') || request.target == "*" {
        request.target.clone()
    } else {
        "/".to_string()
    };
    Ok(RouteTarget::new(
        server_host,
        server_port,
        Some(policy_path),
    ))
}

pub(crate) fn build_upstream_http1_request_head(
    request: &HttpRequestHead,
    target_mode: UpstreamRequestTargetMode,
) -> io::Result<Vec<u8>> {
    let target = match target_mode {
        UpstreamRequestTargetMode::OriginForm => {
            normalize_forward_proxy_target_for_upstream_origin_form(&request.target)?
        }
        UpstreamRequestTargetMode::AbsoluteForm => {
            normalize_forward_proxy_target_for_upstream_absolute_form(&request.target)?
        }
    };
    let mut out = Vec::new();
    out.extend_from_slice(request.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.push(b' ');
    out.extend_from_slice(request.version.as_str().as_bytes());
    out.extend_from_slice(b"\r\n");
    for header in &request.headers {
        if header.name.eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

fn normalize_forward_proxy_target_for_upstream_origin_form(target: &str) -> io::Result<String> {
    if target.starts_with('/') || target == "*" {
        return Ok(target.to_string());
    }
    let uri = target.parse::<Uri>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy request target was not a valid URI",
        )
    })?;
    if uri.scheme_str() != Some("http") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "only http absolute-form can be rewritten for upstream",
        ));
    }
    Ok(uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string()))
}

fn normalize_forward_proxy_target_for_upstream_absolute_form(target: &str) -> io::Result<String> {
    let uri = target.parse::<Uri>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy request target was not a valid URI",
        )
    })?;
    if uri.scheme_str() != Some("http") || uri.host().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream HTTP proxy mode requires http absolute-form target",
        ));
    }
    Ok(target.to_string())
}
