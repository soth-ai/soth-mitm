    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use x509_parser::extensions::GeneralName;
    use x509_parser::parse_x509_certificate;

    use super::{
        build_http1_client_config, build_http1_server_config_for_host, build_http_client_config,
        build_http_server_config_for_host, classify_tls_error, CertStoreMetricsSnapshot,
        CertificateAuthorityConfig, LeafCacheStatus, MitmCertificateStore, TlsFailureReason,
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
    fn builds_http2_capable_tls_configs_when_enabled() {
        let server = build_http_server_config_for_host("example.com", true).expect("server config");
        assert_eq!(
            server.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );

        let client = build_http_client_config(true, true);
        assert_eq!(
            client.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn cert_store_uses_distinct_cache_entries_for_http_alpn_modes() {
        let store =
            MitmCertificateStore::new(CertificateAuthorityConfig::default()).expect("cert store");

        let http1 = store
            .server_config_for_host_with_http2("api.example.com", false)
            .expect("http1 leaf");
        let http2 = store
            .server_config_for_host_with_http2("api.example.com", true)
            .expect("http2 leaf");

        assert_eq!(http1.cache_status, LeafCacheStatus::Miss);
        assert_eq!(http2.cache_status, LeafCacheStatus::Miss);
        assert_eq!(store.metrics_snapshot().cache_misses, 2);
        assert_eq!(store.metrics_snapshot().cache_hits, 0);
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
