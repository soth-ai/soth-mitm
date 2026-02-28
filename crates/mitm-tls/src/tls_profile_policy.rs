#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTlsProfile {
    Strict,
    Default,
    Compat,
}

impl UpstreamTlsProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Default => "default",
            Self::Compat => "compat",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTlsSniMode {
    Required,
    Auto,
    Disabled,
}

impl UpstreamTlsSniMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Auto => "auto",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamClientAuthMode {
    Never,
    IfRequested,
    Required,
}

impl UpstreamClientAuthMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::IfRequested => "if_requested",
            Self::Required => "required",
        }
    }
}

#[derive(Debug)]
pub struct UpstreamClientAuthMaterial {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownstreamCertProfile {
    Modern,
    Compat,
}

impl DownstreamCertProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Modern => "modern",
            Self::Compat => "compat",
        }
    }
}

pub fn resolve_upstream_server_name(
    target_host: &str,
    sni_mode: UpstreamTlsSniMode,
) -> Result<ServerName<'static>, TlsConfigError> {
    let _ = should_enable_sni_for_target(target_host, sni_mode)?;
    ServerName::try_from(target_host.to_string()).map_err(|_| {
        TlsConfigError::InvalidConfiguration(format!(
            "invalid upstream server name: {target_host}"
        ))
    })
}

pub fn should_enable_sni_for_target(
    target_host: &str,
    sni_mode: UpstreamTlsSniMode,
) -> Result<bool, TlsConfigError> {
    let is_ip_target = target_host.parse::<IpAddr>().is_ok();
    match sni_mode {
        UpstreamTlsSniMode::Required => {
            if is_ip_target {
                return Err(TlsConfigError::InvalidConfiguration(
                    "upstream_sni_mode=required does not allow IP targets".to_string(),
                ));
            }
            Ok(true)
        }
        UpstreamTlsSniMode::Auto => Ok(!is_ip_target),
        UpstreamTlsSniMode::Disabled => Ok(false),
    }
}

pub fn build_http_client_config_with_policy(
    insecure_skip_verify: bool,
    http2_enabled: bool,
    profile: UpstreamTlsProfile,
    sni_mode: UpstreamTlsSniMode,
    target_host: &str,
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    build_http_client_config_with_policy_and_client_auth(
        insecure_skip_verify,
        http2_enabled,
        profile,
        sni_mode,
        UpstreamClientAuthMode::Never,
        target_host,
        None,
    )
}

pub fn build_http_client_config_with_policy_and_client_auth(
    insecure_skip_verify: bool,
    http2_enabled: bool,
    profile: UpstreamTlsProfile,
    sni_mode: UpstreamTlsSniMode,
    client_auth_mode: UpstreamClientAuthMode,
    target_host: &str,
    client_auth_material: Option<UpstreamClientAuthMaterial>,
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let enable_sni = should_enable_sni_for_target(target_host, sni_mode)?;
    let mut provider = default_crypto_provider();
    provider.cipher_suites = select_cipher_suites(&provider.cipher_suites, profile);
    if provider.cipher_suites.is_empty() {
        return Err(TlsConfigError::InvalidConfiguration(format!(
            "TLS profile {} yielded zero usable cipher suites",
            profile.as_str()
        )));
    }
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(protocol_versions_for_profile(profile))
        .map_err(TlsConfigError::ConfigBuild)?;

    let mut config = if insecure_skip_verify {
        let dangerous_builder = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureSkipVerifyServerCertVerifier));
        apply_upstream_client_auth_config(
            dangerous_builder,
            client_auth_mode,
            client_auth_material,
        )?
    } else {
        let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let secure_builder = builder.with_root_certificates(root_store);
        apply_upstream_client_auth_config(secure_builder, client_auth_mode, client_auth_material)?
    };
    config.enable_sni = enable_sni;
    config.alpn_protocols = configured_http_alpn_protocols(http2_enabled);
    Ok(Arc::new(config))
}

pub fn parse_upstream_client_auth_material(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<UpstreamClientAuthMaterial, TlsConfigError> {
    let cert = CertificateDer::from_pem_slice(cert_pem).map_err(|error| {
        TlsConfigError::InvalidConfiguration(format!(
            "failed to parse upstream client certificate PEM: {error}"
        ))
    })?;
    let private_key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|error| {
        TlsConfigError::InvalidConfiguration(format!(
            "failed to parse upstream client key PEM: {error}"
        ))
    })?;
    Ok(UpstreamClientAuthMaterial {
        cert_chain: vec![cert],
        private_key,
    })
}

fn apply_upstream_client_auth_config(
    builder: rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>,
    client_auth_mode: UpstreamClientAuthMode,
    client_auth_material: Option<UpstreamClientAuthMaterial>,
) -> Result<ClientConfig, TlsConfigError> {
    match (client_auth_mode, client_auth_material) {
        (UpstreamClientAuthMode::Never, _) => Ok(builder.with_no_client_auth()),
        (UpstreamClientAuthMode::IfRequested, Some(material))
        | (UpstreamClientAuthMode::Required, Some(material)) => builder
            .with_client_auth_cert(material.cert_chain, material.private_key)
            .map_err(TlsConfigError::ConfigBuild),
        (UpstreamClientAuthMode::IfRequested, None) => Ok(builder.with_no_client_auth()),
        (UpstreamClientAuthMode::Required, None) => Err(TlsConfigError::InvalidConfiguration(
            "upstream_client_auth_mode=required but no client cert material is configured"
                .to_string(),
        )),
    }
}

fn protocol_versions_for_profile(
    profile: UpstreamTlsProfile,
) -> &'static [&'static rustls::SupportedProtocolVersion] {
    const TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    const TLS13_TLS12: &[&rustls::SupportedProtocolVersion] =
        &[&rustls::version::TLS13, &rustls::version::TLS12];
    const TLS12_TLS13: &[&rustls::SupportedProtocolVersion] =
        &[&rustls::version::TLS12, &rustls::version::TLS13];

    match profile {
        UpstreamTlsProfile::Strict => TLS13_ONLY,
        UpstreamTlsProfile::Default => TLS13_TLS12,
        UpstreamTlsProfile::Compat => TLS12_TLS13,
    }
}

fn default_crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider::get_default()
        .map(|provider| (**provider).clone())
        .unwrap_or_else(rustls::crypto::aws_lc_rs::default_provider)
}

fn select_cipher_suites(
    available: &[rustls::SupportedCipherSuite],
    profile: UpstreamTlsProfile,
) -> Vec<rustls::SupportedCipherSuite> {
    match profile {
        UpstreamTlsProfile::Strict => {
            let strict_allowlist = [
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ];
            available
                .iter()
                .copied()
                .filter(|suite| strict_allowlist.contains(&suite.suite()))
                .collect()
        }
        UpstreamTlsProfile::Default => available.to_vec(),
        UpstreamTlsProfile::Compat => {
            let mut tls12 = Vec::new();
            let mut tls13 = Vec::new();
            for suite in available.iter().copied() {
                if suite.version() == &rustls::version::TLS12 {
                    tls12.push(suite);
                } else {
                    tls13.push(suite);
                }
            }
            if tls12.is_empty() {
                return tls13;
            }
            tls12.extend(tls13);
            tls12
        }
    }
}
