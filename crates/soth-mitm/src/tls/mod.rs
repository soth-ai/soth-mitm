use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, ServerConfig};

use crate::protocol::configured_http_alpn_protocols;

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

impl fmt::Display for TlsFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
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

#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error("certificate generation failed: {0}")]
    CertificateGeneration(#[from] rcgen::Error),
    #[error("TLS config build failed: {0}")]
    ConfigBuild(#[from] rustls::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("certificate store lock poisoned")]
    LockPoisoned,
    #[error("invalid TLS configuration: {0}")]
    InvalidConfiguration(String),
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
    build_http_client_config_with_policy(
        insecure_skip_verify,
        http2_enabled,
        UpstreamTlsProfile::Default,
        UpstreamTlsSniMode::Auto,
        "localhost",
    )
    .expect("default TLS client profile must build")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthorityConfig {
    pub ca_cert_pem_path: Option<String>,
    pub ca_key_pem_path: Option<String>,
    pub ca_common_name: String,
    pub ca_organization: String,
    pub leaf_cert_cache_capacity: usize,
    pub ca_rotate_after_seconds: Option<u64>,
    pub downstream_cert_profile: DownstreamCertProfile,
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
            downstream_cert_profile: DownstreamCertProfile::Modern,
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
    pub leaf_identity: IssuedLeafIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedLeafIdentity {
    pub leaf_cert_pem: String,
    pub leaf_key_pem: String,
    pub ca_cert_pem: String,
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
    leaf_identity: IssuedLeafIdentity,
}

struct CaMaterial {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    key_pem: String,
}

mod certificate_store_openssl;
mod certificate_store_verifier;
mod tls_profile_policy;

// Kept as include!() because the impl block requires direct access to the private
// fields CertStoreState, CachedLeaf, and CaMaterial defined in this module.
include!("certificate_store_impl.rs");

pub use tls_profile_policy::{
    build_http_client_config_with_policy, build_http_client_config_with_policy_and_client_auth,
    parse_upstream_client_auth_material, resolve_upstream_server_name, DownstreamCertProfile,
    UpstreamClientAuthMode, UpstreamTlsConfigCache, UpstreamTlsProfile, UpstreamTlsSniMode,
};

#[cfg(test)]
mod tests {
    include!("tests_tls_basics.rs");
    include!("tests_cert_store_persistence.rs");
}
