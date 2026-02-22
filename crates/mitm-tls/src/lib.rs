use std::collections::{HashMap, VecDeque};
use std::error::Error as StdError;
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use mitm_http::configured_http_alpn_protocols;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFailureReason {
    UnknownCa,
    CertValidation,
    HandshakeAlert,
    Timeout,
    EofOrReset,
    Other,
}

impl TlsFailureReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnknownCa => "unknown_ca",
            Self::CertValidation => "cert_validation",
            Self::HandshakeAlert => "handshake",
            Self::Timeout => "timeout",
            Self::EofOrReset => "eof_or_reset",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFailure {
    pub host: String,
    pub reason: TlsFailureReason,
    pub detail: String,
}

pub fn classify_tls_error(error_text: &str) -> TlsFailureReason {
    let lower = error_text.to_ascii_lowercase();

    if contains_any(
        &lower,
        &[
            "unknown ca",
            "unknown_ca",
            "unknown issuer",
            "unknown_issuer",
            "unknownissuer",
            "self signed",
            "self-signed",
            "unknown authority",
            "unable to get local issuer certificate",
        ],
    ) {
        return TlsFailureReason::UnknownCa;
    }
    if contains_any(
        &lower,
        &[
            "timed out",
            "timeout",
            "deadline has elapsed",
            "operation timed out",
        ],
    ) {
        return TlsFailureReason::Timeout;
    }
    if contains_any(
        &lower,
        &[
            "unexpected eof",
            "eof",
            "connection reset",
            "broken pipe",
            "connection aborted",
        ],
    ) {
        return TlsFailureReason::EofOrReset;
    }
    if contains_any(
        &lower,
        &[
            "certificate verify failed",
            "invalid peer certificate",
            "certificate",
            "cert",
            "x509",
            "hostname mismatch",
            "name mismatch",
            "expired",
            "not valid",
        ],
    ) {
        return TlsFailureReason::CertValidation;
    }
    if contains_any(
        &lower,
        &[
            "handshake",
            "alert",
            "protocol version",
            "decrypt error",
            "insufficient security",
        ],
    ) {
        return TlsFailureReason::HandshakeAlert;
    }

    TlsFailureReason::Other
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

#[derive(Debug)]
pub enum TlsConfigError {
    CertificateGeneration(rcgen::Error),
    ConfigBuild(rustls::Error),
    Io(std::io::Error),
    LockPoisoned,
    InvalidConfiguration(String),
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertificateGeneration(error) => {
                write!(f, "certificate generation failed: {error}")
            }
            Self::ConfigBuild(error) => write!(f, "TLS config build failed: {error}"),
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::LockPoisoned => write!(f, "certificate store lock poisoned"),
            Self::InvalidConfiguration(reason) => write!(f, "invalid TLS configuration: {reason}"),
        }
    }
}

impl StdError for TlsConfigError {}

impl From<rcgen::Error> for TlsConfigError {
    fn from(value: rcgen::Error) -> Self {
        Self::CertificateGeneration(value)
    }
}

impl From<rustls::Error> for TlsConfigError {
    fn from(value: rustls::Error) -> Self {
        Self::ConfigBuild(value)
    }
}

impl From<std::io::Error> for TlsConfigError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn build_http1_server_config_for_host(host: &str) -> Result<Arc<ServerConfig>, TlsConfigError> {
    build_http_server_config_for_host(host, false)
}

pub fn build_http_server_config_for_host(
    host: &str,
    http2_enabled: bool,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    let cert_store = MitmCertificateStore::new(CertificateAuthorityConfig::default())?;
    let issued = cert_store.server_config_for_host_with_http2(host, http2_enabled)?;
    Ok(issued.server_config)
}

pub fn build_http1_client_config(insecure_skip_verify: bool) -> Arc<ClientConfig> {
    build_http_client_config(insecure_skip_verify, false)
}

pub fn build_http_client_config(
    insecure_skip_verify: bool,
    http2_enabled: bool,
) -> Arc<ClientConfig> {
    let mut config = if insecure_skip_verify {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureSkipVerifyServerCertVerifier))
            .with_no_client_auth()
    } else {
        let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    config.alpn_protocols = configured_http_alpn_protocols(http2_enabled);
    Arc::new(config)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthorityConfig {
    pub ca_cert_pem_path: Option<String>,
    pub ca_key_pem_path: Option<String>,
    pub ca_common_name: String,
    pub ca_organization: String,
    pub leaf_cert_cache_capacity: usize,
    pub ca_rotate_after_seconds: Option<u64>,
}

impl Default for CertificateAuthorityConfig {
    fn default() -> Self {
        Self {
            ca_cert_pem_path: None,
            ca_key_pem_path: None,
            ca_common_name: "soth-mitm Local CA".to_string(),
            ca_organization: "soth-mitm".to_string(),
            leaf_cert_cache_capacity: 1024,
            ca_rotate_after_seconds: None,
        }
    }
}

impl CertificateAuthorityConfig {
    fn validate(&self) -> Result<(), TlsConfigError> {
        match (
            self.ca_cert_pem_path.as_ref(),
            self.ca_key_pem_path.as_ref(),
        ) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => {
                return Err(TlsConfigError::InvalidConfiguration(
                    "ca_cert_pem_path and ca_key_pem_path must either both be set or both be unset"
                        .to_string(),
                ));
            }
        }

        if self.ca_common_name.trim().is_empty() {
            return Err(TlsConfigError::InvalidConfiguration(
                "ca_common_name must not be empty".to_string(),
            ));
        }
        if self.ca_organization.trim().is_empty() {
            return Err(TlsConfigError::InvalidConfiguration(
                "ca_organization must not be empty".to_string(),
            ));
        }

        if matches!(self.ca_rotate_after_seconds, Some(0)) {
            return Err(TlsConfigError::InvalidConfiguration(
                "ca_rotate_after_seconds must be greater than zero when set".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafCacheStatus {
    Hit,
    Miss,
}

impl LeafCacheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
        }
    }
}

#[derive(Debug, Clone)]
pub struct IssuedServerConfig {
    pub server_config: Arc<ServerConfig>,
    pub cache_status: LeafCacheStatus,
    pub leaf_cert_der: CertificateDer<'static>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CertStoreMetricsSnapshot {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub leaves_issued: u64,
    pub ca_rotations: u64,
}

pub struct MitmCertificateStore {
    config: CertificateAuthorityConfig,
    state: Mutex<CertStoreState>,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    leaves_issued: AtomicU64,
    ca_rotations: AtomicU64,
}

struct CertStoreState {
    ca: CaMaterial,
    leaf_cache: HashMap<String, CachedLeaf>,
    cache_lru: VecDeque<String>,
    ca_created_at: SystemTime,
}

struct CachedLeaf {
    server_config: Arc<ServerConfig>,
    leaf_cert_der: CertificateDer<'static>,
}

struct CaMaterial {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    key_pem: String,
}

include!("certificate_store_impl.rs");

#[cfg(test)]
mod tests {
    include!("tests_tls_basics.rs");
    include!("tests_cert_store_persistence.rs");
}
