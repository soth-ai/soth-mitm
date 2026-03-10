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
        self.server_config_for_host_with_http2(host, false)
    }

    pub fn server_config_for_host_with_http2(
        &self,
        host: &str,
        http2_enabled: bool,
    ) -> Result<IssuedServerConfig, TlsConfigError> {
        let normalized_host = normalize_host(host);
        let cache_key = format!(
            "{}|h2={}",
            normalized_host,
            if http2_enabled { 1 } else { 0 }
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_| TlsConfigError::LockPoisoned)?;
        self.maybe_rotate_locked(&mut state)?;

        if let Some((server_config, leaf_cert_der, leaf_identity)) =
            state.leaf_cache.get(&cache_key).map(|cached| {
                (
                    Arc::clone(&cached.server_config),
                    cached.leaf_cert_der.clone(),
                    cached.leaf_identity.clone(),
                )
            })
        {
            touch_lru(&mut state.cache_lru, &cache_key);
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(IssuedServerConfig {
                server_config,
                cache_status: LeafCacheStatus::Hit,
                leaf_cert_der,
                leaf_identity,
            });
        }

        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        let (server_config, leaf_cert_der, leaf_identity) =
            issue_leaf_server_config(
                &state.ca,
                &normalized_host,
                http2_enabled,
                self.config.downstream_cert_profile,
            )?;
        self.leaves_issued.fetch_add(1, Ordering::Relaxed);

        if self.config.leaf_cert_cache_capacity > 0 {
            if state.leaf_cache.len() >= self.config.leaf_cert_cache_capacity {
                evict_lru_entry(&mut state);
            }
            state.leaf_cache.insert(
                cache_key.clone(),
                CachedLeaf {
                    server_config: Arc::clone(&server_config),
                    leaf_cert_der: leaf_cert_der.clone(),
                    leaf_identity: leaf_identity.clone(),
                },
            );
            touch_lru(&mut state.cache_lru, &cache_key);
        }

        Ok(IssuedServerConfig {
            server_config,
            cache_status: LeafCacheStatus::Miss,
            leaf_cert_der,
            leaf_identity,
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
    validate_ca_material_with_openssl(ca_cert_path, &cert_pem, &key_pem)?;
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
    http2_enabled: bool,
    downstream_cert_profile: DownstreamCertProfile,
) -> Result<
    (
        Arc<ServerConfig>,
        CertificateDer<'static>,
        IssuedLeafIdentity,
    ),
    TlsConfigError,
> {
    let leaf_params = build_leaf_params(host)?;
    let leaf_key = generate_leaf_key_pair(downstream_cert_profile)?;
    let leaf_key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca.issuer)?;
    let leaf_cert_der = leaf_cert.der().clone();
    let leaf_cert_pem = leaf_cert.pem();
    let leaf_key_pem = leaf_key.serialize_pem();

    let chain = vec![leaf_cert_der.clone(), ca.cert_der.clone()];
    let private_key = PrivateKeyDer::from(leaf_key_der);

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, private_key)?;
    server_config.alpn_protocols = configured_http_alpn_protocols(http2_enabled);

    Ok((
        Arc::new(server_config),
        leaf_cert_der,
        IssuedLeafIdentity {
            leaf_cert_pem,
            leaf_key_pem,
            ca_cert_pem: ca.cert_pem.clone(),
        },
    ))
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

fn generate_leaf_key_pair(
    downstream_cert_profile: DownstreamCertProfile,
) -> Result<KeyPair, TlsConfigError> {
    match downstream_cert_profile {
        DownstreamCertProfile::Modern => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .or_else(|_| KeyPair::generate())
            .map_err(Into::into),
        DownstreamCertProfile::Compat => KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
            .or_else(|_| KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256))
            .or_else(|_| KeyPair::generate())
            .map_err(Into::into),
    }
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
