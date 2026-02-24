use serde::{Deserialize, Serialize};
use thiserror::Error;

include!("config_route.rs");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectParseMode {
    Strict,
    Lenient,
}

impl Default for ConnectParseMode {
    fn default() -> Self {
        Self::Strict
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownstreamTlsBackend {
    Rustls,
    Openssl,
}

impl Default for DownstreamTlsBackend {
    fn default() -> Self {
        Self::Rustls
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsProfile {
    Strict,
    Default,
    Compat,
}

impl Default for TlsProfile {
    fn default() -> Self {
        Self::Default
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamSniMode {
    Required,
    Auto,
    Disabled,
}

impl Default for UpstreamSniMode {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownstreamCertProfile {
    Modern,
    Compat,
}

impl Default for DownstreamCertProfile {
    fn default() -> Self {
        Self::Modern
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSinkKind {
    Queue,
    Uds,
    Grpc,
    File,
}

impl Default for EventSinkKind {
    fn default() -> Self {
        Self::Queue
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EventSinkConfig {
    pub kind: EventSinkKind,
    pub endpoint: Option<String>,
    pub path: Option<String>,
}

impl Default for EventSinkConfig {
    fn default() -> Self {
        Self {
            kind: EventSinkKind::Queue,
            endpoint: None,
            path: None,
        }
    }
}

impl EventSinkConfig {
    pub fn validate(&self) -> Result<(), MitmConfigError> {
        match self.kind {
            EventSinkKind::Queue => Ok(()),
            EventSinkKind::Uds => require_non_empty(
                self.path.as_deref(),
                "event_sink.path",
                MitmConfigError::MissingEventSinkPath,
            ),
            EventSinkKind::File => require_non_empty(
                self.path.as_deref(),
                "event_sink.path",
                MitmConfigError::MissingEventSinkPath,
            ),
            EventSinkKind::Grpc => require_non_empty(
                self.endpoint.as_deref(),
                "event_sink.endpoint",
                MitmConfigError::MissingEventSinkEndpoint,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MitmConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub connect_parse_mode: ConnectParseMode,
    pub downstream_tls_backend: DownstreamTlsBackend,
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
    pub route_mode: RouteMode,
    pub reverse_upstream: Option<RouteEndpointConfig>,
    pub upstream_http_proxy: Option<RouteEndpointConfig>,
    pub upstream_socks5_proxy: Option<RouteEndpointConfig>,
    pub tls_profile: TlsProfile,
    pub upstream_sni_mode: UpstreamSniMode,
    pub downstream_cert_profile: DownstreamCertProfile,
    pub upstream_tls_insecure_skip_verify: bool,
    pub max_flow_body_buffer_bytes: usize,
    pub max_flow_decoder_buffer_bytes: usize,
    pub max_flow_event_backlog: usize,
    pub max_in_flight_bytes: usize,
    pub max_concurrent_flows: usize,
    pub event_sink: EventSinkConfig,
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 8080,
            connect_parse_mode: ConnectParseMode::Strict,
            downstream_tls_backend: DownstreamTlsBackend::Rustls,
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
            route_mode: RouteMode::Direct,
            reverse_upstream: None,
            upstream_http_proxy: None,
            upstream_socks5_proxy: None,
            tls_profile: TlsProfile::Default,
            upstream_sni_mode: UpstreamSniMode::Auto,
            downstream_cert_profile: DownstreamCertProfile::Modern,
            upstream_tls_insecure_skip_verify: false,
            max_flow_body_buffer_bytes: 8 * 1024 * 1024,
            max_flow_decoder_buffer_bytes: 4 * 1024 * 1024,
            max_flow_event_backlog: 8 * 1024,
            max_in_flight_bytes: 64 * 1024 * 1024,
            max_concurrent_flows: 2048,
            event_sink: EventSinkConfig::default(),
        }
    }
}

impl MitmConfig {
    pub fn validate(&self) -> Result<(), MitmConfigError> {
        if self.listen_addr.trim().is_empty() {
            return Err(MitmConfigError::EmptyListenAddr);
        }
        if self.max_http_head_bytes == 0 {
            return Err(MitmConfigError::ZeroValue("max_http_head_bytes"));
        }
        if self.http2_max_header_list_size == 0 {
            return Err(MitmConfigError::ZeroValue("http2_max_header_list_size"));
        }
        if self.leaf_cert_cache_capacity == 0 {
            return Err(MitmConfigError::ZeroValue("leaf_cert_cache_capacity"));
        }
        if self.max_flow_body_buffer_bytes == 0 {
            return Err(MitmConfigError::ZeroValue("max_flow_body_buffer_bytes"));
        }
        if self.max_flow_decoder_buffer_bytes == 0 {
            return Err(MitmConfigError::ZeroValue("max_flow_decoder_buffer_bytes"));
        }
        if self.max_flow_event_backlog == 0 {
            return Err(MitmConfigError::ZeroValue("max_flow_event_backlog"));
        }
        if self.max_in_flight_bytes == 0 {
            return Err(MitmConfigError::ZeroValue("max_in_flight_bytes"));
        }
        if self.max_concurrent_flows == 0 {
            return Err(MitmConfigError::ZeroValue("max_concurrent_flows"));
        }
        if self.max_flow_decoder_buffer_bytes > self.max_flow_body_buffer_bytes {
            return Err(MitmConfigError::DecoderBudgetExceedsBodyBudget);
        }
        if let Some(seconds) = self.ca_rotate_after_seconds {
            if seconds == 0 {
                return Err(MitmConfigError::ZeroValue("ca_rotate_after_seconds"));
            }
        }
        if self.ca_cert_pem_path.is_some() != self.ca_key_pem_path.is_some() {
            return Err(MitmConfigError::InvalidCaPathPair);
        }
        validate_route_endpoint(self.reverse_upstream.as_ref(), "reverse_upstream")?;
        validate_route_endpoint(self.upstream_http_proxy.as_ref(), "upstream_http_proxy")?;
        validate_route_endpoint(self.upstream_socks5_proxy.as_ref(), "upstream_socks5_proxy")?;
        validate_route_mode_bindings(self)?;
        if self.tls_profile == TlsProfile::Strict
            && self.upstream_sni_mode == UpstreamSniMode::Disabled
        {
            return Err(MitmConfigError::StrictTlsProfileRequiresSni);
        }
        require_non_empty(
            Some(&self.ca_common_name),
            "ca_common_name",
            MitmConfigError::EmptyCaCommonName,
        )?;
        require_non_empty(
            Some(&self.ca_organization),
            "ca_organization",
            MitmConfigError::EmptyCaOrganization,
        )?;
        validate_host_list(&self.ignore_hosts, "ignore_hosts")?;
        validate_host_list(&self.blocked_hosts, "blocked_hosts")?;
        self.event_sink.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum MitmConfigError {
    #[error("listen_addr must not be empty")]
    EmptyListenAddr,
    #[error("{0} must be greater than zero")]
    ZeroValue(&'static str),
    #[error("ca_cert_pem_path and ca_key_pem_path must be provided together")]
    InvalidCaPathPair,
    #[error("ca_common_name must not be empty")]
    EmptyCaCommonName,
    #[error("ca_organization must not be empty")]
    EmptyCaOrganization,
    #[error("{field} contains an empty host entry")]
    EmptyHostEntry { field: &'static str },
    #[error("max_flow_decoder_buffer_bytes must be <= max_flow_body_buffer_bytes")]
    DecoderBudgetExceedsBodyBudget,
    #[error("event_sink.path is required for event_sink kind file|uds")]
    MissingEventSinkPath,
    #[error("event_sink.endpoint is required for event_sink kind grpc")]
    MissingEventSinkEndpoint,
    #[error("tls_profile=strict requires upstream_sni_mode to be auto|required")]
    StrictTlsProfileRequiresSni,
    #[error("{field}.host must not be empty")]
    EmptyRouteEndpointHost { field: &'static str },
    #[error("{field}.port must be greater than zero")]
    ZeroRouteEndpointPort { field: &'static str },
    #[error("route_mode={route_mode} requires {field}")]
    MissingRouteEndpoint {
        route_mode: &'static str,
        field: &'static str,
    },
    #[error("route_mode={route_mode} does not allow {field}")]
    UnexpectedRouteEndpoint {
        route_mode: &'static str,
        field: &'static str,
    },
}

fn validate_host_list(hosts: &[String], field: &'static str) -> Result<(), MitmConfigError> {
    if hosts.iter().any(|host| host.trim().is_empty()) {
        return Err(MitmConfigError::EmptyHostEntry { field });
    }
    Ok(())
}

fn require_non_empty(
    value: Option<&str>,
    _field: &'static str,
    error: MitmConfigError,
) -> Result<(), MitmConfigError> {
    match value {
        Some(text) if !text.trim().is_empty() => Ok(()),
        _ => Err(error),
    }
}
