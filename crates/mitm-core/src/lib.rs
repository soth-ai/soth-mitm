use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use mitm_http::ApplicationProtocol;
use mitm_observe::{Event, EventSink, EventType, FlowContext};
use mitm_policy::{FlowAction, PolicyDecision, PolicyEngine, PolicyInput};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub server_host: String,
    pub server_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectParseError {
    IncompleteHeaders,
    InvalidUtf8,
    EmptyRequestLine,
    InvalidRequestLine,
    MethodNotConnect,
    InvalidHttpVersion,
    InvalidAuthority,
    MissingPort,
    InvalidPort,
}

impl ConnectParseError {
    pub fn code(self) -> &'static str {
        match self {
            Self::IncompleteHeaders => "incomplete_headers",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::EmptyRequestLine => "empty_request_line",
            Self::InvalidRequestLine => "invalid_request_line",
            Self::MethodNotConnect => "method_not_connect",
            Self::InvalidHttpVersion => "invalid_http_version",
            Self::InvalidAuthority => "invalid_authority",
            Self::MissingPort => "missing_port",
            Self::InvalidPort => "invalid_port",
        }
    }
}

pub fn parse_connect_request_line(request_line: &str) -> Result<ConnectRequest, ConnectParseError> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(ConnectParseError::EmptyRequestLine)?;
    let authority = parts.next().ok_or(ConnectParseError::InvalidRequestLine)?;
    let version = parts.next().ok_or(ConnectParseError::InvalidRequestLine)?;

    if parts.next().is_some() {
        return Err(ConnectParseError::InvalidRequestLine);
    }

    if method != "CONNECT" {
        return Err(ConnectParseError::MethodNotConnect);
    }

    if !version.starts_with("HTTP/") {
        return Err(ConnectParseError::InvalidHttpVersion);
    }

    let (server_host, server_port) = parse_connect_authority(authority)?;
    Ok(ConnectRequest {
        server_host,
        server_port,
    })
}

pub fn parse_connect_request_head(
    input: &[u8],
) -> Result<(ConnectRequest, usize), ConnectParseError> {
    let header_end = header_terminator_index(input).ok_or(ConnectParseError::IncompleteHeaders)?;
    let head =
        std::str::from_utf8(&input[..header_end]).map_err(|_| ConnectParseError::InvalidUtf8)?;
    let request_line = head
        .split("\r\n")
        .next()
        .ok_or(ConnectParseError::EmptyRequestLine)?;
    let request = parse_connect_request_line(request_line)?;
    Ok((request, header_end))
}

fn header_terminator_index(input: &[u8]) -> Option<usize> {
    input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn parse_connect_authority(authority: &str) -> Result<(String, u16), ConnectParseError> {
    if authority.starts_with('[') {
        let bracket_close = authority
            .find(']')
            .ok_or(ConnectParseError::InvalidAuthority)?;
        let host = &authority[1..bracket_close];
        if host.is_empty() {
            return Err(ConnectParseError::InvalidAuthority);
        }

        let suffix = &authority[bracket_close + 1..];
        if !suffix.starts_with(':') {
            return Err(ConnectParseError::MissingPort);
        }

        let port_text = &suffix[1..];
        if port_text.is_empty() {
            return Err(ConnectParseError::MissingPort);
        }

        let server_port = port_text
            .parse::<u16>()
            .map_err(|_| ConnectParseError::InvalidPort)?;
        return Ok((host.to_string(), server_port));
    }

    let (host, port_text) = authority
        .rsplit_once(':')
        .ok_or(ConnectParseError::MissingPort)?;

    if host.is_empty() {
        return Err(ConnectParseError::InvalidAuthority);
    }

    if host.contains(':') {
        return Err(ConnectParseError::InvalidAuthority);
    }

    if port_text.is_empty() {
        return Err(ConnectParseError::MissingPort);
    }

    let server_port = port_text
        .parse::<u16>()
        .map_err(|_| ConnectParseError::InvalidPort)?;
    Ok((host.to_string(), server_port))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub max_http_head_bytes: usize,
    pub ca_cert_pem_path: Option<String>,
    pub ca_key_pem_path: Option<String>,
    pub ca_common_name: String,
    pub ca_organization: String,
    pub leaf_cert_cache_capacity: usize,
    pub ca_rotate_after_seconds: Option<u64>,
    pub ignore_hosts: Vec<String>,
    pub blocked_hosts: Vec<String>,
    pub http2_enabled: bool,
    pub http2_max_header_list_size: u32,
    pub http3_passthrough: bool,
    pub upstream_tls_insecure_skip_verify: bool,
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 8080,
            max_http_head_bytes: 64 * 1024,
            ca_cert_pem_path: None,
            ca_key_pem_path: None,
            ca_common_name: "soth-mitm Local CA".to_string(),
            ca_organization: "soth-mitm".to_string(),
            leaf_cert_cache_capacity: 1024,
            ca_rotate_after_seconds: None,
            ignore_hosts: Vec::new(),
            blocked_hosts: Vec::new(),
            http2_enabled: true,
            http2_max_header_list_size: 64 * 1024,
            http3_passthrough: true,
            upstream_tls_insecure_skip_verify: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectOutcome {
    pub flow_id: u64,
    pub action: FlowAction,
    pub reason: String,
}

pub struct MitmEngine<P, S>
where
    P: PolicyEngine,
    S: EventSink,
{
    pub config: MitmConfig,
    policy: P,
    sink: S,
    next_flow_id: AtomicU64,
}

impl<P, S> MitmEngine<P, S>
where
    P: PolicyEngine,
    S: EventSink,
{
    pub fn new(config: MitmConfig, policy: P, sink: S) -> Self {
        Self {
            config,
            policy,
            sink,
            next_flow_id: AtomicU64::new(1),
        }
    }

    pub fn decide_connect(
        &self,
        client_addr: impl Into<String>,
        server_host: impl Into<String>,
        server_port: u16,
        path: Option<String>,
    ) -> ConnectOutcome {
        let flow_id = self.allocate_flow_id();
        let client_addr = client_addr.into();
        let server_host = server_host.into();

        let context = FlowContext {
            flow_id,
            client_addr: client_addr.clone(),
            server_host: server_host.clone(),
            server_port,
            protocol: ApplicationProtocol::Tunnel,
        };

        self.sink
            .emit(Event::new(EventType::ConnectReceived, context.clone()));

        let input = PolicyInput {
            server_host: server_host.clone(),
            server_port,
            path,
        };
        let decision = self.policy.decide(&input);
        self.emit_connect_decision_event(&context, &decision);

        ConnectOutcome {
            flow_id,
            action: decision.action,
            reason: decision.reason,
        }
    }

    fn emit_connect_decision_event(&self, context: &FlowContext, decision: &PolicyDecision) {
        let mut event = Event::new(EventType::ConnectDecision, context.clone());
        event.attributes = BTreeMap::from([("reason".to_string(), decision.reason.clone())]);
        self.sink.emit(event);
    }

    pub fn emit_event(&self, event: Event) {
        self.sink.emit(event);
    }

    pub fn allocate_flow_id(&self) -> u64 {
        self.next_flow_id.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_connect_request_head, parse_connect_request_line, ConnectParseError};

    #[test]
    fn parses_connect_request_line_with_domain_authority() {
        let parsed =
            parse_connect_request_line("CONNECT api.example.com:443 HTTP/1.1").expect("must parse");
        assert_eq!(parsed.server_host, "api.example.com");
        assert_eq!(parsed.server_port, 443);
    }

    #[test]
    fn parses_connect_request_line_with_ipv6_authority() {
        let parsed =
            parse_connect_request_line("CONNECT [2001:db8::1]:8443 HTTP/1.1").expect("must parse");
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
}
