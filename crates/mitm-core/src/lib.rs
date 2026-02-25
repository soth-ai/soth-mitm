use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use mitm_http::ApplicationProtocol;
use mitm_observe::{Event, EventConsumer, EventEnvelope, EventType, FlowContext};
use mitm_policy::{
    FlowAction, PolicyDecision, PolicyEngine, PolicyInput, PolicyOverrideState,
    ProcessInfo as PolicyProcessInfo,
};

mod config;
mod flow_state;
pub mod server;
pub use config::{
    CompatibilityOverrideConfig, ConnectParseMode, DownstreamCertProfile, DownstreamTlsBackend,
    EventSinkConfig, EventSinkKind, MitmConfig, MitmConfigError, RouteEndpointConfig, RouteMode,
    TlsProfile, UpstreamSniMode,
};
use flow_state::FlowStateTracker;

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
    parse_connect_request_line_with_mode(request_line, ConnectParseMode::Strict)
}

pub fn parse_connect_request_line_with_mode(
    request_line: &str,
    mode: ConnectParseMode,
) -> Result<ConnectRequest, ConnectParseError> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(ConnectParseError::EmptyRequestLine)?;
    let authority = parts.next().ok_or(ConnectParseError::InvalidRequestLine)?;
    let version = parts.next().ok_or(ConnectParseError::InvalidRequestLine)?;

    if parts.next().is_some() {
        return Err(ConnectParseError::InvalidRequestLine);
    }

    let method_matches = match mode {
        ConnectParseMode::Strict => method == "CONNECT",
        ConnectParseMode::Lenient => method.eq_ignore_ascii_case("CONNECT"),
    };
    if !method_matches {
        return Err(ConnectParseError::MethodNotConnect);
    }

    if !version.starts_with("HTTP/") {
        return Err(ConnectParseError::InvalidHttpVersion);
    }

    let normalized_authority = normalize_connect_authority(authority, mode);
    let (server_host, server_port) =
        parse_connect_authority_with_mode(&normalized_authority, mode)?;
    Ok(ConnectRequest {
        server_host,
        server_port,
    })
}

pub fn parse_connect_request_head(
    input: &[u8],
) -> Result<(ConnectRequest, usize), ConnectParseError> {
    parse_connect_request_head_with_mode(input, ConnectParseMode::Strict)
}

pub fn parse_connect_request_head_with_mode(
    input: &[u8],
    mode: ConnectParseMode,
) -> Result<(ConnectRequest, usize), ConnectParseError> {
    let header_end = header_terminator_index(input).ok_or(ConnectParseError::IncompleteHeaders)?;
    let head =
        std::str::from_utf8(&input[..header_end]).map_err(|_| ConnectParseError::InvalidUtf8)?;
    let request_line = head
        .split("\r\n")
        .next()
        .ok_or(ConnectParseError::EmptyRequestLine)?;
    let request = parse_connect_request_line_with_mode(request_line, mode)?;
    Ok((request, header_end))
}

fn header_terminator_index(input: &[u8]) -> Option<usize> {
    input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn parse_connect_authority_with_mode(
    authority: &str,
    mode: ConnectParseMode,
) -> Result<(String, u16), ConnectParseError> {
    if authority.starts_with('[') {
        let bracket_close = authority
            .find(']')
            .ok_or(ConnectParseError::InvalidAuthority)?;
        let host = &authority[1..bracket_close];
        if host.is_empty() {
            return Err(ConnectParseError::InvalidAuthority);
        }

        let suffix = &authority[bracket_close + 1..];
        if suffix.is_empty() {
            if mode == ConnectParseMode::Lenient {
                return Ok((host.to_string(), 443));
            }
            return Err(ConnectParseError::MissingPort);
        }
        if !suffix.starts_with(':') {
            return Err(ConnectParseError::MissingPort);
        }

        let port_text = &suffix[1..];
        if port_text.is_empty() {
            if mode == ConnectParseMode::Lenient {
                return Ok((host.to_string(), 443));
            }
            return Err(ConnectParseError::MissingPort);
        }

        let server_port = port_text
            .parse::<u16>()
            .map_err(|_| ConnectParseError::InvalidPort)?;
        return Ok((host.to_string(), server_port));
    }

    let (host, port_text) = match authority.rsplit_once(':') {
        Some(pair) => pair,
        None if mode == ConnectParseMode::Lenient => {
            if authority.is_empty() {
                return Err(ConnectParseError::InvalidAuthority);
            }
            return Ok((authority.to_string(), 443));
        }
        None => return Err(ConnectParseError::MissingPort),
    };

    if host.is_empty() {
        return Err(ConnectParseError::InvalidAuthority);
    }

    if host.contains(':') {
        if mode == ConnectParseMode::Lenient && authority.parse::<IpAddr>().is_ok() {
            return Ok((authority.to_string(), 443));
        }
        return Err(ConnectParseError::InvalidAuthority);
    }

    if port_text.is_empty() {
        if mode == ConnectParseMode::Lenient {
            return Ok((host.to_string(), 443));
        }
        return Err(ConnectParseError::MissingPort);
    }

    let server_port = port_text
        .parse::<u16>()
        .map_err(|_| ConnectParseError::InvalidPort)?;
    Ok((host.to_string(), server_port))
}

fn normalize_connect_authority(authority: &str, mode: ConnectParseMode) -> String {
    if mode == ConnectParseMode::Strict {
        return authority.to_string();
    }
    let trimmed = authority.trim();
    let without_scheme = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let authority_only = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .trim();
    authority_only.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectOutcome {
    pub flow_id: u64,
    pub action: FlowAction,
    pub reason: String,
    pub override_state: PolicyOverrideState,
}

pub struct MitmEngine<P, S>
where
    P: PolicyEngine,
    S: EventConsumer,
{
    pub config: MitmConfig,
    policy: P,
    sink: S,
    next_flow_id: AtomicU64,
    next_sequence_id: AtomicU64,
    flow_state_tracker: FlowStateTracker,
    process_started_at: Instant,
    last_monotonic_ns: AtomicU64,
    recently_closed_flows: Mutex<VecDeque<u64>>,
}

impl<P, S> MitmEngine<P, S>
where
    P: PolicyEngine,
    S: EventConsumer,
{
    pub fn new(config: MitmConfig, policy: P, sink: S) -> Self {
        config
            .validate()
            .expect("invalid MitmConfig: validation failed");
        Self::new_unchecked(config, policy, sink)
    }

    pub fn new_checked(config: MitmConfig, policy: P, sink: S) -> Result<Self, MitmConfigError> {
        config.validate()?;
        Ok(Self::new_unchecked(config, policy, sink))
    }

    fn new_unchecked(config: MitmConfig, policy: P, sink: S) -> Self {
        Self {
            config,
            policy,
            sink,
            next_flow_id: AtomicU64::new(1),
            next_sequence_id: AtomicU64::new(1),
            flow_state_tracker: FlowStateTracker::default(),
            process_started_at: Instant::now(),
            last_monotonic_ns: AtomicU64::new(0),
            recently_closed_flows: Mutex::new(VecDeque::new()),
        }
    }

    pub fn decide_connect(
        &self,
        flow_id: u64,
        client_addr: impl Into<String>,
        server_host: impl Into<String>,
        server_port: u16,
        path: Option<String>,
        process_info: Option<PolicyProcessInfo>,
    ) -> ConnectOutcome {
        let client_addr = client_addr.into();
        let server_host = server_host.into();

        let context = FlowContext {
            flow_id,
            client_addr: client_addr.clone(),
            server_host: server_host.clone(),
            server_port,
            protocol: ApplicationProtocol::Tunnel,
        };

        self.emit_event(Event::new(EventType::ConnectReceived, context.clone()));

        let input = PolicyInput {
            server_host: server_host.clone(),
            server_port,
            path,
            process_info,
        };
        let mut decision = self.policy.decide(&input);
        self.config
            .apply_compatibility_overrides(&server_host, &mut decision);
        self.emit_connect_decision_event(&context, &decision);

        ConnectOutcome {
            flow_id,
            action: decision.action,
            reason: decision.reason,
            override_state: decision.override_state,
        }
    }

    pub fn emit_event(&self, mut event: Event) {
        if event.kind == EventType::StreamClosed
            && !self.register_stream_closed(event.context.flow_id)
        {
            return;
        }

        event.sequence_id = self.next_sequence_id.fetch_add(1, Ordering::Relaxed);
        let flow_sequence_id = self.flow_state_tracker.on_event(
            event.context.flow_id,
            event.context.protocol,
            event.kind,
        );
        if flow_sequence_id as usize > self.config.max_flow_event_backlog
            && event.kind != EventType::StreamClosed
        {
            return;
        }
        event.flow_sequence_id = flow_sequence_id;
        event.occurred_at_monotonic_ns = u128::from(self.reserve_monotonic_ns());
        self.sink.consume(EventEnvelope::from_event(event));
    }

    pub fn allocate_flow_id(&self) -> u64 {
        self.next_flow_id.fetch_add(1, Ordering::Relaxed)
    }

    fn reserve_monotonic_ns(&self) -> u64 {
        let observed_ns = self
            .process_started_at
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        loop {
            let previous = self.last_monotonic_ns.load(Ordering::Relaxed);
            let next = if observed_ns > previous {
                observed_ns
            } else {
                previous.saturating_add(1)
            };
            if self
                .last_monotonic_ns
                .compare_exchange(previous, next, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return next;
            }
        }
    }

    fn register_stream_closed(&self, flow_id: u64) -> bool {
        const RECENT_CLOSED_FLOW_IDS: usize = 16_384;
        let mut closed = self
            .recently_closed_flows
            .lock()
            .expect("recently_closed_flows lock poisoned");
        if closed.iter().any(|existing| *existing == flow_id) {
            return false;
        }
        closed.push_back(flow_id);
        while closed.len() > RECENT_CLOSED_FLOW_IDS {
            closed.pop_front();
        }
        true
    }
}

include!("engine_policy_decision.rs");

#[cfg(test)]
mod tests {
    include!("tests_config_schema.rs");
    include!("tests_connect_parser.rs");
    include!("tests_engine_guardrails.rs");
}
