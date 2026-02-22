use std::collections::{HashMap, VecDeque};
use std::error::Error as StdError;
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
    let cert_store = MitmCertificateStore::new(CertificateAuthorityConfig::default())?;
    let issued = cert_store.server_config_for_host(host)?;
    Ok(issued.server_config)
}

pub fn build_http1_client_config(insecure_skip_verify: bool) -> Arc<ClientConfig> {
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

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
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

impl MitmCertificateStore {
    pub fn new(config: CertificateAuthorityConfig) -> Result<Self, TlsConfigError> {
        config.validate()?;
        let ca = load_or_generate_ca_material(&config)?;
        let state = CertStoreState {
            ca,
            leaf_cache: HashMap::new(),
            cache_lru: VecDeque::new(),
            ca_created_at: SystemTime::now(),
        };
        Ok(Self {
            config,
            state: Mutex::new(state),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            leaves_issued: AtomicU64::new(0),
            ca_rotations: AtomicU64::new(0),
        })
    }

    pub fn server_config_for_host(&self, host: &str) -> Result<IssuedServerConfig, TlsConfigError> {
        let normalized_host = normalize_host(host);
        let mut state = self
            .state
            .lock()
            .map_err(|_| TlsConfigError::LockPoisoned)?;
        self.maybe_rotate_locked(&mut state)?;

        if let Some((server_config, leaf_cert_der)) =
            state.leaf_cache.get(&normalized_host).map(|cached| {
                (
                    Arc::clone(&cached.server_config),
                    cached.leaf_cert_der.clone(),
                )
            })
        {
            touch_lru(&mut state.cache_lru, &normalized_host);
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(IssuedServerConfig {
                server_config,
                cache_status: LeafCacheStatus::Hit,
                leaf_cert_der,
            });
        }

        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        let (server_config, leaf_cert_der) = issue_leaf_server_config(&state.ca, &normalized_host)?;
        self.leaves_issued.fetch_add(1, Ordering::Relaxed);

        if self.config.leaf_cert_cache_capacity > 0 {
            if state.leaf_cache.len() >= self.config.leaf_cert_cache_capacity {
                evict_lru_entry(&mut state);
            }
            state.leaf_cache.insert(
                normalized_host.clone(),
                CachedLeaf {
                    server_config: Arc::clone(&server_config),
                    leaf_cert_der: leaf_cert_der.clone(),
                },
            );
            touch_lru(&mut state.cache_lru, &normalized_host);
        }

        Ok(IssuedServerConfig {
            server_config,
            cache_status: LeafCacheStatus::Miss,
            leaf_cert_der,
        })
    }

    pub fn force_rotate(&self) -> Result<(), TlsConfigError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| TlsConfigError::LockPoisoned)?;
        self.rotate_locked(&mut state)
    }

    pub fn metrics_snapshot(&self) -> CertStoreMetricsSnapshot {
        CertStoreMetricsSnapshot {
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            leaves_issued: self.leaves_issued.load(Ordering::Relaxed),
            ca_rotations: self.ca_rotations.load(Ordering::Relaxed),
        }
    }

    pub fn ca_certificate_pem(&self) -> Result<String, TlsConfigError> {
        let state = self
            .state
            .lock()
            .map_err(|_| TlsConfigError::LockPoisoned)?;
        Ok(state.ca.cert_pem.clone())
    }

    fn maybe_rotate_locked(&self, state: &mut CertStoreState) -> Result<(), TlsConfigError> {
        let Some(rotate_after_seconds) = self.config.ca_rotate_after_seconds else {
            return Ok(());
        };

        let elapsed = state
            .ca_created_at
            .elapsed()
            .unwrap_or_else(|_| std::time::Duration::from_secs(0));
        if elapsed.as_secs() >= rotate_after_seconds {
            self.rotate_locked(state)?;
        }
        Ok(())
    }

    fn rotate_locked(&self, state: &mut CertStoreState) -> Result<(), TlsConfigError> {
        let next_ca = generate_ca_material(&self.config)?;
        persist_ca_material_if_configured(&self.config, &next_ca)?;

        state.ca = next_ca;
        state.ca_created_at = SystemTime::now();
        state.leaf_cache.clear();
        state.cache_lru.clear();
        self.ca_rotations.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn load_or_generate_ca_material(
    config: &CertificateAuthorityConfig,
) -> Result<CaMaterial, TlsConfigError> {
    match (&config.ca_cert_pem_path, &config.ca_key_pem_path) {
        (Some(ca_cert_path), Some(ca_key_path)) => {
            let cert_exists = Path::new(ca_cert_path).exists();
            let key_exists = Path::new(ca_key_path).exists();

            match (cert_exists, key_exists) {
                (true, true) => load_ca_material(ca_cert_path, ca_key_path, config),
                (false, false) => {
                    let generated = generate_ca_material(config)?;
                    persist_ca_material(ca_cert_path, ca_key_path, &generated)?;
                    Ok(generated)
                }
                _ => Err(TlsConfigError::InvalidConfiguration(
                    "CA cert and key files must both exist or both be absent".to_string(),
                )),
            }
        }
        (None, None) => generate_ca_material(config),
        _ => Err(TlsConfigError::InvalidConfiguration(
            "ca_cert_pem_path and ca_key_pem_path must be set together".to_string(),
        )),
    }
}

fn generate_ca_material(config: &CertificateAuthorityConfig) -> Result<CaMaterial, TlsConfigError> {
    let ca_key = KeyPair::generate()?;
    let ca_key_pem = ca_key.serialize_pem();
    let ca_params = build_ca_params(config);
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let cert_pem = ca_cert.pem();
    let cert_der = ca_cert.der().clone();
    let issuer = Issuer::new(ca_params, ca_key);

    Ok(CaMaterial {
        issuer,
        cert_pem,
        cert_der,
        key_pem: ca_key_pem,
    })
}

fn load_ca_material(
    ca_cert_path: &str,
    ca_key_path: &str,
    _config: &CertificateAuthorityConfig,
) -> Result<CaMaterial, TlsConfigError> {
    let cert_pem = fs::read_to_string(ca_cert_path)?;
    let key_pem = fs::read_to_string(ca_key_path)?;
    let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).map_err(|error| {
        TlsConfigError::InvalidConfiguration(format!(
            "failed to parse CA certificate PEM from {ca_cert_path}: {error}"
        ))
    })?;
    let ca_key = KeyPair::from_pem(&key_pem)?;
    let issuer = Issuer::from_ca_cert_der(&cert_der, ca_key).map_err(|error| {
        TlsConfigError::InvalidConfiguration(format!(
            "failed to parse issuer metadata from CA certificate {ca_cert_path}: {error}"
        ))
    })?;

    Ok(CaMaterial {
        issuer,
        cert_pem,
        cert_der,
        key_pem,
    })
}

fn persist_ca_material_if_configured(
    config: &CertificateAuthorityConfig,
    ca: &CaMaterial,
) -> Result<(), TlsConfigError> {
    if let (Some(ca_cert_path), Some(ca_key_path)) =
        (&config.ca_cert_pem_path, &config.ca_key_pem_path)
    {
        persist_ca_material(ca_cert_path, ca_key_path, ca)?;
    }
    Ok(())
}

fn persist_ca_material(
    ca_cert_path: &str,
    ca_key_path: &str,
    ca: &CaMaterial,
) -> Result<(), TlsConfigError> {
    ensure_parent_exists(ca_cert_path)?;
    ensure_parent_exists(ca_key_path)?;

    fs::write(ca_cert_path, ca.cert_pem.as_bytes())?;
    fs::write(ca_key_path, ca.key_pem.as_bytes())?;
    Ok(())
}

fn ensure_parent_exists(path: &str) -> Result<(), TlsConfigError> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn issue_leaf_server_config(
    ca: &CaMaterial,
    host: &str,
) -> Result<(Arc<ServerConfig>, CertificateDer<'static>), TlsConfigError> {
    let leaf_params = build_leaf_params(host)?;
    let leaf_key = KeyPair::generate()?;
    let leaf_key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca.issuer)?;
    let leaf_cert_der = leaf_cert.der().clone();

    let chain = vec![leaf_cert_der.clone(), ca.cert_der.clone()];
    let private_key = PrivateKeyDer::from(leaf_key_der);

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, private_key)?;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok((Arc::new(server_config), leaf_cert_der))
}

fn build_ca_params(config: &CertificateAuthorityConfig) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, config.ca_common_name.clone());
    distinguished_name.push(DnType::OrganizationName, config.ca_organization.clone());
    params.distinguished_name = distinguished_name;
    params
}

fn build_leaf_params(host: &str) -> Result<CertificateParams, TlsConfigError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.use_authority_key_identifier_extension = true;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, host.to_string());
    params.distinguished_name = distinguished_name;

    if let Ok(ip) = host.parse::<IpAddr>() {
        params.subject_alt_names.push(SanType::IpAddress(ip));
    } else {
        params
            .subject_alt_names
            .push(SanType::DnsName(host.try_into()?));
    }

    Ok(params)
}

fn normalize_host(host: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(_) => host.to_string(),
        Err(_) => host.to_ascii_lowercase(),
    }
}

fn touch_lru(lru: &mut VecDeque<String>, key: &str) {
    if let Some(position) = lru.iter().position(|entry| entry == key) {
        lru.remove(position);
    }
    lru.push_back(key.to_string());
}

fn evict_lru_entry(state: &mut CertStoreState) {
    if let Some(oldest) = state.cache_lru.pop_front() {
        state.leaf_cache.remove(&oldest);
    }
}

#[derive(Debug)]
struct InsecureSkipVerifyServerCertVerifier;

impl ServerCertVerifier for InsecureSkipVerifyServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use x509_parser::extensions::GeneralName;
    use x509_parser::parse_x509_certificate;

    use super::{
        build_http1_client_config, build_http1_server_config_for_host, classify_tls_error,
        CertStoreMetricsSnapshot, CertificateAuthorityConfig, LeafCacheStatus,
        MitmCertificateStore, TlsFailureReason,
    };

    #[test]
    fn classifies_unknown_ca_error_text() {
        assert_eq!(
            classify_tls_error("certificate verify failed: unknown ca"),
            TlsFailureReason::UnknownCa
        );
    }

    #[test]
    fn tls_failure_reason_codes_are_stable() {
        assert_eq!(TlsFailureReason::UnknownCa.code(), "unknown_ca");
        assert_eq!(TlsFailureReason::CertValidation.code(), "cert_validation");
        assert_eq!(TlsFailureReason::HandshakeAlert.code(), "handshake");
        assert_eq!(TlsFailureReason::Timeout.code(), "timeout");
        assert_eq!(TlsFailureReason::EofOrReset.code(), "eof_or_reset");
        assert_eq!(TlsFailureReason::Other.code(), "other");
    }

    #[test]
    fn tls_failure_taxonomy_fixture_corpus_meets_accuracy_target() {
        let fixtures = vec![
            (
                "certificate verify failed: unknown ca",
                TlsFailureReason::UnknownCa,
            ),
            (
                "x509: certificate signed by unknown issuer",
                TlsFailureReason::UnknownCa,
            ),
            (
                "tls: self-signed certificate in certificate chain",
                TlsFailureReason::UnknownCa,
            ),
            (
                "unable to get local issuer certificate",
                TlsFailureReason::UnknownCa,
            ),
            (
                "invalid peer certificate: Expired",
                TlsFailureReason::CertValidation,
            ),
            (
                "x509 certificate has expired",
                TlsFailureReason::CertValidation,
            ),
            (
                "x509: certificate is not valid for any names",
                TlsFailureReason::CertValidation,
            ),
            (
                "certificate name mismatch",
                TlsFailureReason::CertValidation,
            ),
            (
                "invalid peer certificate: HostnameMismatch",
                TlsFailureReason::CertValidation,
            ),
            (
                "remote error: tls: handshake failure",
                TlsFailureReason::HandshakeAlert,
            ),
            (
                "tls alert protocol version",
                TlsFailureReason::HandshakeAlert,
            ),
            (
                "received fatal alert: decrypt error",
                TlsFailureReason::HandshakeAlert,
            ),
            (
                "handshake alert: insufficient security",
                TlsFailureReason::HandshakeAlert,
            ),
            ("operation timed out", TlsFailureReason::Timeout),
            (
                "request timed out during handshake",
                TlsFailureReason::Timeout,
            ),
            ("connect timeout", TlsFailureReason::Timeout),
            ("deadline has elapsed", TlsFailureReason::Timeout),
            (
                "unexpected eof while reading handshake",
                TlsFailureReason::EofOrReset,
            ),
            ("connection reset by peer", TlsFailureReason::EofOrReset),
            ("broken pipe", TlsFailureReason::EofOrReset),
            ("connection aborted", TlsFailureReason::EofOrReset),
            ("some unrelated network error", TlsFailureReason::Other),
        ];

        let matched = fixtures
            .iter()
            .filter(|(detail, expected)| classify_tls_error(detail) == *expected)
            .count();
        let accuracy = matched as f64 / fixtures.len() as f64;
        assert!(
            accuracy >= 0.95,
            "taxonomy fixture accuracy {accuracy:.2} below target"
        );
    }

    #[test]
    fn builds_server_tls_config_for_dns_host() {
        let config = build_http1_server_config_for_host("example.com").expect("server config");
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn builds_client_tls_config_for_secure_and_insecure_modes() {
        let secure = build_http1_client_config(false);
        assert_eq!(secure.alpn_protocols, vec![b"http/1.1".to_vec()]);

        let insecure = build_http1_client_config(true);
        assert_eq!(insecure.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn cert_store_cache_reports_hits_and_misses() {
        let store =
            MitmCertificateStore::new(CertificateAuthorityConfig::default()).expect("cert store");

        let first = store
            .server_config_for_host("api.example.com")
            .expect("first leaf");
        assert_eq!(first.cache_status, LeafCacheStatus::Miss);

        let second = store
            .server_config_for_host("api.example.com")
            .expect("second leaf");
        assert_eq!(second.cache_status, LeafCacheStatus::Hit);
        assert!(Arc::ptr_eq(&first.server_config, &second.server_config));

        let metrics = store.metrics_snapshot();
        assert_eq!(
            metrics,
            CertStoreMetricsSnapshot {
                cache_hits: 1,
                cache_misses: 1,
                leaves_issued: 1,
                ca_rotations: 0,
            }
        );
    }

    #[test]
    fn cert_store_with_zero_capacity_never_hits_cache() {
        let config = CertificateAuthorityConfig {
            leaf_cert_cache_capacity: 0,
            ..CertificateAuthorityConfig::default()
        };
        let store = MitmCertificateStore::new(config).expect("cert store");

        let first = store
            .server_config_for_host("api.example.com")
            .expect("first leaf");
        let second = store
            .server_config_for_host("api.example.com")
            .expect("second leaf");

        assert_eq!(first.cache_status, LeafCacheStatus::Miss);
        assert_eq!(second.cache_status, LeafCacheStatus::Miss);
        assert!(!Arc::ptr_eq(&first.server_config, &second.server_config));

        let metrics = store.metrics_snapshot();
        assert_eq!(metrics.cache_hits, 0);
        assert_eq!(metrics.cache_misses, 2);
        assert_eq!(metrics.leaves_issued, 2);
    }

    #[test]
    fn cert_store_force_rotate_changes_ca_and_resets_cache() {
        let store =
            MitmCertificateStore::new(CertificateAuthorityConfig::default()).expect("cert store");
        let before_ca = store.ca_certificate_pem().expect("ca cert");
        let _ = store
            .server_config_for_host("api.example.com")
            .expect("first leaf");
        store.force_rotate().expect("force rotate");
        let after_ca = store.ca_certificate_pem().expect("ca cert");
        assert_ne!(before_ca, after_ca);

        let post_rotate = store
            .server_config_for_host("api.example.com")
            .expect("leaf after rotate");
        assert_eq!(post_rotate.cache_status, LeafCacheStatus::Miss);
        assert_eq!(store.metrics_snapshot().ca_rotations, 1);
    }

    #[test]
    fn cert_store_auto_rotates_after_configured_interval() {
        let config = CertificateAuthorityConfig {
            ca_rotate_after_seconds: Some(1),
            ..CertificateAuthorityConfig::default()
        };
        let store = MitmCertificateStore::new(config).expect("cert store");
        let before_ca = store.ca_certificate_pem().expect("ca cert");

        let _ = store
            .server_config_for_host("first.example.com")
            .expect("first leaf");
        std::thread::sleep(Duration::from_millis(1_200));
        let _ = store
            .server_config_for_host("second.example.com")
            .expect("second leaf");
        let after_ca = store.ca_certificate_pem().expect("ca cert");

        assert_ne!(before_ca, after_ca);
        assert_eq!(store.metrics_snapshot().ca_rotations, 1);
    }

    #[test]
    fn cert_store_leaf_san_and_cn_cover_domain_wildcard_and_ip() {
        let store =
            MitmCertificateStore::new(CertificateAuthorityConfig::default()).expect("cert store");

        let domain = store
            .server_config_for_host("api.example.com")
            .expect("domain leaf");
        assert_leaf_dns_name(&domain.leaf_cert_der, "api.example.com");
        assert_leaf_common_name(&domain.leaf_cert_der, "api.example.com");

        let wildcard = store
            .server_config_for_host("*.example.com")
            .expect("wildcard leaf");
        assert_leaf_dns_name(&wildcard.leaf_cert_der, "*.example.com");
        assert_leaf_common_name(&wildcard.leaf_cert_der, "*.example.com");

        let ip = store.server_config_for_host("127.0.0.1").expect("ip leaf");
        assert_leaf_ip(&ip.leaf_cert_der, [127, 0, 0, 1]);
        assert_leaf_common_name(&ip.leaf_cert_der, "127.0.0.1");
    }

    #[test]
    fn cert_store_loads_existing_ca_from_disk() {
        let temp_dir = unique_temp_dir("soth-mitm-ca-load");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let ca_cert_path = temp_dir.join("ca-cert.pem");
        let ca_key_path = temp_dir.join("ca-key.pem");

        let config = CertificateAuthorityConfig {
            ca_cert_pem_path: Some(path_to_string(&ca_cert_path)),
            ca_key_pem_path: Some(path_to_string(&ca_key_path)),
            ..CertificateAuthorityConfig::default()
        };

        let store_first = MitmCertificateStore::new(config.clone()).expect("first store");
        let first_ca = store_first.ca_certificate_pem().expect("first ca");
        drop(store_first);

        let store_second = MitmCertificateStore::new(config).expect("second store");
        let second_ca = store_second.ca_certificate_pem().expect("second ca");
        assert_eq!(first_ca, second_ca);

        fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn cert_store_uses_persisted_ca_subject_when_config_subject_changes() {
        let temp_dir = unique_temp_dir("soth-mitm-ca-subject-drift");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let ca_cert_path = temp_dir.join("ca-cert.pem");
        let ca_key_path = temp_dir.join("ca-key.pem");

        let initial_common_name = "initial.soth-mitm-ca";
        let initial_config = CertificateAuthorityConfig {
            ca_cert_pem_path: Some(path_to_string(&ca_cert_path)),
            ca_key_pem_path: Some(path_to_string(&ca_key_path)),
            ca_common_name: initial_common_name.to_string(),
            ca_organization: "initial.soth-mitm-org".to_string(),
            ..CertificateAuthorityConfig::default()
        };
        let first_store = MitmCertificateStore::new(initial_config).expect("first store");
        let first_ca = first_store.ca_certificate_pem().expect("first ca");
        drop(first_store);

        let drifted_config = CertificateAuthorityConfig {
            ca_cert_pem_path: Some(path_to_string(&ca_cert_path)),
            ca_key_pem_path: Some(path_to_string(&ca_key_path)),
            ca_common_name: "drifted.soth-mitm-ca".to_string(),
            ca_organization: "drifted.soth-mitm-org".to_string(),
            ..CertificateAuthorityConfig::default()
        };
        let second_store = MitmCertificateStore::new(drifted_config).expect("second store");
        let second_ca = second_store.ca_certificate_pem().expect("second ca");
        assert_eq!(first_ca, second_ca);

        let leaf = second_store
            .server_config_for_host("api.example.com")
            .expect("leaf");
        assert_leaf_issuer_common_name(&leaf.leaf_cert_der, initial_common_name);

        fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn cert_store_rejects_partial_ca_path_configuration() {
        let config = CertificateAuthorityConfig {
            ca_cert_pem_path: Some("/tmp/soth-mitm-only-cert.pem".to_string()),
            ca_key_pem_path: None,
            ..CertificateAuthorityConfig::default()
        };
        let error = match MitmCertificateStore::new(config) {
            Ok(_) => panic!("partial CA path configuration unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("must either both be set or both be unset"),
            "{error}"
        );
    }

    fn assert_leaf_common_name(
        cert_der: &rustls::pki_types::CertificateDer<'static>,
        expected: &str,
    ) {
        let (_, cert) = parse_x509_certificate(cert_der.as_ref()).expect("parse x509");
        let subject = cert.subject();
        let cn = subject
            .iter_common_name()
            .next()
            .expect("commonName")
            .as_str()
            .expect("commonName as utf8");
        assert_eq!(cn, expected);
    }

    fn assert_leaf_issuer_common_name(
        cert_der: &rustls::pki_types::CertificateDer<'static>,
        expected: &str,
    ) {
        let (_, cert) = parse_x509_certificate(cert_der.as_ref()).expect("parse x509");
        let issuer = cert.issuer();
        let cn = issuer
            .iter_common_name()
            .next()
            .expect("issuer commonName")
            .as_str()
            .expect("issuer commonName as utf8");
        assert_eq!(cn, expected);
    }

    fn assert_leaf_dns_name(cert_der: &rustls::pki_types::CertificateDer<'static>, expected: &str) {
        let (_, cert) = parse_x509_certificate(cert_der.as_ref()).expect("parse x509");
        let san = cert
            .subject_alternative_name()
            .expect("san extension parse")
            .expect("san extension present");
        let found = san
            .value
            .general_names
            .iter()
            .any(|name| matches!(name, GeneralName::DNSName(value) if *value == expected));
        assert!(found, "expected SAN DNSName {expected}");
    }

    fn assert_leaf_ip(cert_der: &rustls::pki_types::CertificateDer<'static>, expected: [u8; 4]) {
        let (_, cert) = parse_x509_certificate(cert_der.as_ref()).expect("parse x509");
        let san = cert
            .subject_alternative_name()
            .expect("san extension parse")
            .expect("san extension present");
        let found = san
            .value
            .general_names
            .iter()
            .any(|name| matches!(name, GeneralName::IPAddress(value) if *value == expected));
        assert!(found, "expected SAN IPAddress {expected:?}");
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock");
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            now.as_nanos()
        ))
    }

    fn path_to_string(path: &Path) -> String {
        path.to_string_lossy().to_string()
    }
}
