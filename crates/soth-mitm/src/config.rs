use std::net::SocketAddr;
use std::path::PathBuf;

use crate::destination::parse_destination_rule;
use crate::MitmError;
use crate::TlsVersion;

/// Controls whether the proxy runs in observe-only or store-and-forward mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptMode {
    /// Streaming tee: forward request to upstream immediately while capturing
    /// a copy for the handler. Handler observes but cannot block.
    Monitor,
    /// Store-and-forward: buffer request body, call handler, then forward or block.
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmConfig {
    pub bind: SocketAddr,
    pub unix_socket_path: Option<PathBuf>,
    pub interception: InterceptionScope,
    pub process_attribution: ProcessAttributionConfig,
    pub tls: TlsConfig,
    pub http2_enabled: bool,
    pub http2_max_header_list_size: u32,
    pub http3_passthrough: bool,
    pub max_http_head_bytes: usize,
    pub accept_retry_backoff_ms: u64,
    pub max_flow_event_backlog: usize,
    pub max_in_flight_bytes: usize,
    pub max_concurrent_flows: usize,
    pub upstream: UpstreamConfig,
    pub connection_pool: ConnectionPoolConfig,
    pub body: BodyConfig,
    pub intercept_mode: InterceptMode,
    pub handler: HandlerConfig,
    pub flow_runtime: FlowRuntimeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptionScope {
    pub destinations: Vec<String>,
    pub passthrough_unlisted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub min_version: TlsVersion,
    pub capture_fingerprint: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessAttributionConfig {
    pub enabled: bool,
    pub lookup_timeout_ms: u64,
    pub cache_capacity: usize,
    pub cache_ttl_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub timeout_ms: u64,
    pub h2_header_stage_timeout_ms: u64,
    pub h2_body_idle_timeout_ms: u64,
    pub h2_response_overflow_mode: H2ResponseOverflowMode,
    pub connect_timeout_ms: u64,
    pub retry_on_failure: bool,
    pub retry_delay_ms: u64,
    pub verify_upstream_tls: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2ResponseOverflowMode {
    TruncateContinue,
    StrictFail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPoolConfig {
    pub max_connections_per_host: u32,
    pub idle_timeout_ms: u64,
    pub max_idle_per_host: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyConfig {
    pub max_size_bytes: usize,
    pub buffer_request_bodies: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerConfig {
    pub request_timeout_ms: u64,
    pub response_timeout_ms: u64,
    pub recover_from_panics: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRuntimeConfig {
    pub dispatch_queue_capacity: Option<usize>,
    pub closed_flow_lru_capacity: Option<usize>,
    pub stale_flow_ttl_ms: Option<u64>,
    pub stale_reap_max_batch: Option<usize>,
    pub dispatch_queue_send_timeout_ms: Option<u64>,
    pub dispatch_close_join_timeout_ms: Option<u64>,
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080"
                .parse()
                .expect("default bind address must parse"),
            unix_socket_path: None,
            interception: InterceptionScope::default(),
            process_attribution: ProcessAttributionConfig::default(),
            tls: TlsConfig::default(),
            http2_enabled: true,
            http2_max_header_list_size: 64 * 1024,
            http3_passthrough: true,
            max_http_head_bytes: 64 * 1024,
            accept_retry_backoff_ms: 100,
            max_flow_event_backlog: 8 * 1024,
            max_in_flight_bytes: 64 * 1024 * 1024,
            max_concurrent_flows: 2_048,
            upstream: UpstreamConfig::default(),
            connection_pool: ConnectionPoolConfig::default(),
            body: BodyConfig::default(),
            intercept_mode: InterceptMode::Monitor,
            handler: HandlerConfig::default(),
            flow_runtime: FlowRuntimeConfig::default(),
        }
    }
}

impl Default for InterceptionScope {
    fn default() -> Self {
        Self {
            destinations: Vec::new(),
            passthrough_unlisted: true,
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            ca_cert_path: PathBuf::from("./certs/soth-mitm-ca.pem"),
            ca_key_path: PathBuf::from("./certs/soth-mitm-ca-key.pem"),
            min_version: TlsVersion::Tls12,
            capture_fingerprint: true,
        }
    }
}

impl Default for ProcessAttributionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            lookup_timeout_ms: 5_000,
            cache_capacity: 4_096,
            cache_ttl_ms: None,
        }
    }
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            h2_header_stage_timeout_ms: 30_000,
            h2_body_idle_timeout_ms: 120_000,
            h2_response_overflow_mode: H2ResponseOverflowMode::TruncateContinue,
            connect_timeout_ms: 10_000,
            retry_on_failure: false,
            retry_delay_ms: 200,
            verify_upstream_tls: true,
        }
    }
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 32,
            idle_timeout_ms: 600_000,
            max_idle_per_host: 8,
        }
    }
}

impl Default for BodyConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 32 * 1024 * 1024,
            buffer_request_bodies: false,
        }
    }
}

impl Default for HandlerConfig {
    fn default() -> Self {
        Self {
            request_timeout_ms: 15_000,
            response_timeout_ms: 15_000,
            recover_from_panics: true,
        }
    }
}

impl Default for FlowRuntimeConfig {
    fn default() -> Self {
        Self {
            dispatch_queue_capacity: None,
            closed_flow_lru_capacity: None,
            stale_flow_ttl_ms: None,
            stale_reap_max_batch: None,
            dispatch_queue_send_timeout_ms: None,
            dispatch_close_join_timeout_ms: None,
        }
    }
}

impl MitmConfig {
    pub fn validate(&self) -> Result<(), MitmError> {
        if self.interception.destinations.is_empty() {
            return Err(MitmError::InvalidConfig(
                "interception.destinations must not be empty".to_string(),
            ));
        }
        for destination in &self.interception.destinations {
            parse_destination_rule(destination)?;
        }
        if self.process_attribution.enabled && self.process_attribution.lookup_timeout_ms == 0 {
            return Err(MitmError::InvalidConfig(
                "process_attribution.lookup_timeout_ms must be greater than zero".to_string(),
            ));
        }
        if self.process_attribution.cache_capacity == 0 {
            return Err(MitmError::InvalidConfig(
                "process_attribution.cache_capacity must be greater than zero".to_string(),
            ));
        }
        if self.process_attribution.cache_ttl_ms == Some(0) {
            return Err(MitmError::InvalidConfig(
                "process_attribution.cache_ttl_ms must be greater than zero when set".to_string(),
            ));
        }
        if self.max_http_head_bytes == 0 {
            return Err(MitmError::InvalidConfig(
                "max_http_head_bytes must be greater than zero".to_string(),
            ));
        }
        if self.accept_retry_backoff_ms == 0 {
            return Err(MitmError::InvalidConfig(
                "accept_retry_backoff_ms must be greater than zero".to_string(),
            ));
        }
        if self.http2_max_header_list_size == 0 {
            return Err(MitmError::InvalidConfig(
                "http2_max_header_list_size must be greater than zero".to_string(),
            ));
        }
        if self.max_flow_event_backlog == 0 {
            return Err(MitmError::InvalidConfig(
                "max_flow_event_backlog must be greater than zero".to_string(),
            ));
        }
        if self.max_in_flight_bytes == 0 {
            return Err(MitmError::InvalidConfig(
                "max_in_flight_bytes must be greater than zero".to_string(),
            ));
        }
        if self.max_concurrent_flows == 0 {
            return Err(MitmError::InvalidConfig(
                "max_concurrent_flows must be greater than zero".to_string(),
            ));
        }
        if self.upstream.timeout_ms == 0 {
            return Err(MitmError::InvalidConfig(
                "upstream.timeout_ms must be greater than zero".to_string(),
            ));
        }
        if self.upstream.h2_header_stage_timeout_ms == 0 {
            return Err(MitmError::InvalidConfig(
                "upstream.h2_header_stage_timeout_ms must be greater than zero".to_string(),
            ));
        }
        if self.upstream.h2_body_idle_timeout_ms == 0 {
            return Err(MitmError::InvalidConfig(
                "upstream.h2_body_idle_timeout_ms must be greater than zero".to_string(),
            ));
        }
        if self.upstream.connect_timeout_ms == 0 {
            return Err(MitmError::InvalidConfig(
                "upstream.connect_timeout_ms must be greater than zero".to_string(),
            ));
        }
        if self.body.max_size_bytes == 0 {
            return Err(MitmError::InvalidConfig(
                "body.max_size_bytes must be greater than zero".to_string(),
            ));
        }
        if self.handler.request_timeout_ms == 0 {
            return Err(MitmError::InvalidConfig(
                "handler.request_timeout_ms must be greater than zero".to_string(),
            ));
        }
        if self.handler.response_timeout_ms == 0 {
            return Err(MitmError::InvalidConfig(
                "handler.response_timeout_ms must be greater than zero".to_string(),
            ));
        }
        if self.flow_runtime.dispatch_queue_capacity == Some(0) {
            return Err(MitmError::InvalidConfig(
                "flow_runtime.dispatch_queue_capacity must be greater than zero when set"
                    .to_string(),
            ));
        }
        if self.flow_runtime.closed_flow_lru_capacity == Some(0) {
            return Err(MitmError::InvalidConfig(
                "flow_runtime.closed_flow_lru_capacity must be greater than zero when set"
                    .to_string(),
            ));
        }
        if self.flow_runtime.stale_flow_ttl_ms == Some(0) {
            return Err(MitmError::InvalidConfig(
                "flow_runtime.stale_flow_ttl_ms must be greater than zero when set".to_string(),
            ));
        }
        if self.flow_runtime.stale_reap_max_batch == Some(0) {
            return Err(MitmError::InvalidConfig(
                "flow_runtime.stale_reap_max_batch must be greater than zero when set".to_string(),
            ));
        }
        if self.flow_runtime.dispatch_queue_send_timeout_ms == Some(0) {
            return Err(MitmError::InvalidConfig(
                "flow_runtime.dispatch_queue_send_timeout_ms must be greater than zero when set"
                    .to_string(),
            ));
        }
        if self.flow_runtime.dispatch_close_join_timeout_ms == Some(0) {
            return Err(MitmError::InvalidConfig(
                "flow_runtime.dispatch_close_join_timeout_ms must be greater than zero when set"
                    .to_string(),
            ));
        }
        if self.connection_pool.max_connections_per_host == 0 {
            return Err(MitmError::InvalidConfig(
                "connection_pool.max_connections_per_host must be greater than zero".to_string(),
            ));
        }
        if self.connection_pool.idle_timeout_ms == 0 {
            return Err(MitmError::InvalidConfig(
                "connection_pool.idle_timeout_ms must be greater than zero".to_string(),
            ));
        }
        if self.connection_pool.max_idle_per_host == 0 {
            return Err(MitmError::InvalidConfig(
                "connection_pool.max_idle_per_host must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MitmConfig;

    fn valid_config() -> MitmConfig {
        let mut config = MitmConfig::default();
        config
            .interception
            .destinations
            .push("api.example.com:443".to_string());
        config
    }

    #[test]
    fn default_runtime_knobs_match_expected_values() {
        let config = MitmConfig::default();
        assert!(config.http2_enabled);
        assert_eq!(config.http2_max_header_list_size, 64 * 1024);
        assert!(config.http3_passthrough);
        assert_eq!(config.max_http_head_bytes, 64 * 1024);
        assert_eq!(config.accept_retry_backoff_ms, 100);
        assert_eq!(config.max_flow_event_backlog, 8 * 1024);
        assert_eq!(config.max_in_flight_bytes, 64 * 1024 * 1024);
        assert_eq!(config.max_concurrent_flows, 2_048);
        assert_eq!(config.process_attribution.cache_capacity, 4_096);
        assert_eq!(config.process_attribution.cache_ttl_ms, None);
        assert_eq!(config.upstream.h2_header_stage_timeout_ms, 30_000);
        assert_eq!(config.upstream.h2_body_idle_timeout_ms, 120_000);
        assert_eq!(config.body.max_size_bytes, 32 * 1024 * 1024);
        assert_eq!(config.handler.request_timeout_ms, 15_000);
        assert_eq!(config.handler.response_timeout_ms, 15_000);
    }

    #[test]
    fn validate_rejects_zero_core_runtime_knobs() {
        let mut config = valid_config();
        config.max_concurrent_flows = 0;
        let error = config
            .validate()
            .expect_err("zero runtime budget must fail");
        let message = error.to_string();
        assert!(message.contains("max_concurrent_flows"));
    }

    #[test]
    fn validate_rejects_zero_h2_timeout_knobs() {
        let mut config = valid_config();
        config.upstream.h2_header_stage_timeout_ms = 0;
        let error = config
            .validate()
            .expect_err("zero h2 header timeout must fail");
        assert!(error.to_string().contains("h2_header_stage_timeout_ms"));

        config.upstream.h2_header_stage_timeout_ms = 30_000;
        config.upstream.h2_body_idle_timeout_ms = 0;
        let error = config
            .validate()
            .expect_err("zero h2 body idle timeout must fail");
        assert!(error.to_string().contains("h2_body_idle_timeout_ms"));
    }

    #[test]
    fn validate_rejects_zero_flow_runtime_overrides() {
        let mut config = valid_config();
        config.flow_runtime.dispatch_queue_capacity = Some(0);
        let error = config.validate().expect_err("zero flow override must fail");
        let message = error.to_string();
        assert!(message.contains("flow_runtime.dispatch_queue_capacity"));
    }
}
