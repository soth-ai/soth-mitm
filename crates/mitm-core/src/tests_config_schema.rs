#[test]
fn default_config_is_valid() {
    let config = super::MitmConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn serde_round_trip_preserves_core_flags() {
    let json = r#"
        {
          "listen_addr": "0.0.0.0",
          "listen_port": 18080,
          "http2_enabled": false,
          "downstream_tls_backend": "openssl",
          "http3_passthrough": true,
          "ignore_hosts": ["example.internal"],
          "event_sink": {
            "kind": "grpc",
            "endpoint": "127.0.0.1:50051"
          }
        }
    "#;
    let parsed = serde_json::from_str::<super::MitmConfig>(json).expect("deserialize config");
    assert_eq!(parsed.listen_addr, "0.0.0.0");
    assert_eq!(parsed.listen_port, 18_080);
    assert!(!parsed.http2_enabled);
    assert_eq!(
        parsed.downstream_tls_backend,
        super::DownstreamTlsBackend::Openssl
    );
    assert!(parsed.http3_passthrough);
    assert_eq!(parsed.ignore_hosts, vec!["example.internal".to_string()]);
    assert_eq!(parsed.event_sink.kind, super::EventSinkKind::Grpc);
    assert_eq!(
        parsed.event_sink.endpoint.as_deref(),
        Some("127.0.0.1:50051")
    );
    assert!(parsed.validate().is_ok());
}

#[test]
fn serde_rejects_unknown_fields() {
    let json = r#"{ "unknown_field": true }"#;
    let err = serde_json::from_str::<super::MitmConfig>(json).expect_err("unknown field must fail");
    let message = err.to_string();
    assert!(
        message.contains("unknown field"),
        "expected unknown field error, got: {message}"
    );
}

#[test]
fn validation_rejects_partial_ca_path_pair() {
    let config = super::MitmConfig {
        ca_cert_pem_path: Some("/tmp/ca.crt".to_string()),
        ca_key_pem_path: None,
        ..super::MitmConfig::default()
    };
    let err = config.validate().expect_err("partial CA pair should fail");
    assert_eq!(err, super::MitmConfigError::InvalidCaPathPair);
}

#[test]
fn validation_rejects_decoder_budget_above_body_budget() {
    let config = super::MitmConfig {
        max_flow_body_buffer_bytes: 1024,
        max_flow_decoder_buffer_bytes: 2048,
        ..super::MitmConfig::default()
    };
    let err = config.validate().expect_err("decoder budget must be <= body budget");
    assert_eq!(err, super::MitmConfigError::DecoderBudgetExceedsBodyBudget);
}

#[test]
fn validation_rejects_invalid_event_sink_parameters() {
    let config = super::MitmConfig {
        event_sink: super::EventSinkConfig {
            kind: super::EventSinkKind::Grpc,
            endpoint: None,
            path: None,
        },
        ..super::MitmConfig::default()
    };
    let err = config.validate().expect_err("grpc sink without endpoint must fail");
    assert_eq!(err, super::MitmConfigError::MissingEventSinkEndpoint);
}
