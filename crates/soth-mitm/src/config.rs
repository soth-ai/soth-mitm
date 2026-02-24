use std::net::SocketAddr;
use std::path::PathBuf;

use crate::destination::normalize_destination_key;
use crate::MitmError;
use crate::TlsVersion;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmConfig {
    pub bind: SocketAddr,
    pub interception: InterceptionScope,
    pub tls: TlsConfig,
    pub upstream: UpstreamConfig,
    pub connection_pool: ConnectionPoolConfig,
    pub body: BodyConfig,
    pub handler: HandlerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptionScope {
    pub destinations: Vec<String>,
    pub process_allowlist: Vec<String>,
    pub passthrough_unlisted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub min_version: TlsVersion,
    pub capture_fingerprint: bool,
    pub process_info: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub retry_on_failure: bool,
    pub retry_delay_ms: u64,
    pub verify_upstream_tls: bool,
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
    pub buffer_streaming: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerConfig {
    pub timeout_ms: u64,
    pub recover_from_panics: bool,
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080"
                .parse()
                .expect("default bind address must parse"),
            interception: InterceptionScope::default(),
            tls: TlsConfig::default(),
            upstream: UpstreamConfig::default(),
            connection_pool: ConnectionPoolConfig::default(),
            body: BodyConfig::default(),
            handler: HandlerConfig::default(),
        }
    }
}

impl Default for InterceptionScope {
    fn default() -> Self {
        Self {
            destinations: Vec::new(),
            process_allowlist: Vec::new(),
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
            process_info: true,
        }
    }
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
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
            idle_timeout_ms: 60_000,
            max_idle_per_host: 8,
        }
    }
}

impl Default for BodyConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 10 * 1024 * 1024,
            buffer_streaming: false,
        }
    }
}

impl Default for HandlerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5_000,
            recover_from_panics: true,
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
            normalize_destination_key(destination)?;
        }
        if self.upstream.timeout_ms == 0 {
            return Err(MitmError::InvalidConfig(
                "upstream.timeout_ms must be greater than zero".to_string(),
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
        if self.handler.timeout_ms == 0 {
            return Err(MitmError::InvalidConfig(
                "handler.timeout_ms must be greater than zero".to_string(),
            ));
        }
        if self.connection_pool.max_connections_per_host == 0 {
            return Err(MitmError::InvalidConfig(
                "connection_pool.max_connections_per_host must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}
