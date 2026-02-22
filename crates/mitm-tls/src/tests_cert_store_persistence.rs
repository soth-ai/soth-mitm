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
