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
          "route_mode": "upstream_http",
          "upstream_http_proxy": {
            "host": "127.0.0.1",
            "port": 3128
          },
          "tls_profile": "compat",
          "upstream_sni_mode": "disabled",
          "downstream_cert_profile": "compat",
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
    assert_eq!(parsed.route_mode, super::RouteMode::UpstreamHttp);
    assert_eq!(
        parsed.upstream_http_proxy,
        Some(super::RouteEndpointConfig {
            host: "127.0.0.1".to_string(),
            port: 3128
        })
    );
    assert_eq!(parsed.tls_profile, super::TlsProfile::Compat);
    assert_eq!(parsed.upstream_sni_mode, super::UpstreamSniMode::Disabled);
    assert_eq!(
        parsed.downstream_cert_profile,
        super::DownstreamCertProfile::Compat
    );
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

#[test]
fn strict_tls_profile_rejects_disabled_sni_mode() {
    let config = super::MitmConfig {
        tls_profile: super::TlsProfile::Strict,
        upstream_sni_mode: super::UpstreamSniMode::Disabled,
        ..super::MitmConfig::default()
    };
    let err = config
        .validate()
        .expect_err("strict profile with disabled sni must fail");
    assert_eq!(err, super::MitmConfigError::StrictTlsProfileRequiresSni);
}

#[test]
fn route_mode_requires_corresponding_endpoint() {
    let config = super::MitmConfig {
        route_mode: super::RouteMode::UpstreamSocks5,
        ..super::MitmConfig::default()
    };
    let err = config
        .validate()
        .expect_err("upstream_socks5 mode requires upstream_socks5_proxy");
    assert_eq!(
        err,
        super::MitmConfigError::MissingRouteEndpoint {
            route_mode: "upstream_socks5",
            field: "upstream_socks5_proxy",
        }
    );
}

#[test]
fn route_mode_rejects_unexpected_endpoint() {
    let config = super::MitmConfig {
        route_mode: super::RouteMode::Direct,
        upstream_http_proxy: Some(super::RouteEndpointConfig {
            host: "127.0.0.1".to_string(),
            port: 3128,
        }),
        ..super::MitmConfig::default()
    };
    let err = config
        .validate()
        .expect_err("direct mode should reject upstream_http_proxy");
    assert_eq!(
        err,
        super::MitmConfigError::UnexpectedRouteEndpoint {
            route_mode: "direct",
            field: "upstream_http_proxy",
        }
    );
}

#[test]
fn route_endpoint_rejects_empty_host() {
    let config = super::MitmConfig {
        route_mode: super::RouteMode::Reverse,
        reverse_upstream: Some(super::RouteEndpointConfig {
            host: " ".to_string(),
            port: 9443,
        }),
        ..super::MitmConfig::default()
    };
    let err = config
        .validate()
        .expect_err("reverse_upstream host must not be empty");
    assert_eq!(
        err,
        super::MitmConfigError::EmptyRouteEndpointHost {
            field: "reverse_upstream",
        }
    );
}

#[test]
fn serde_round_trip_parses_compatibility_overrides() {
    let json = r#"
        {
          "compatibility_overrides": [
            {
              "rule_id": "api-compat",
              "host_pattern": "*.api.example.com",
              "force_tunnel": true,
              "disable_h2": true,
              "strict_header_mode": true,
              "skip_upstream_verify": false
            }
          ]
        }
    "#;
    let parsed = serde_json::from_str::<super::MitmConfig>(json).expect("deserialize config");
    assert_eq!(parsed.compatibility_overrides.len(), 1);
    let rule = &parsed.compatibility_overrides[0];
    assert_eq!(rule.rule_id, "api-compat");
    assert_eq!(rule.host_pattern, "*.api.example.com");
    assert!(rule.force_tunnel);
    assert!(rule.disable_h2);
    assert!(rule.strict_header_mode);
    assert!(!rule.skip_upstream_verify);
    assert!(parsed.validate().is_ok());
}

#[test]
fn validation_rejects_noop_compatibility_override() {
    let config = super::MitmConfig {
        compatibility_overrides: vec![super::CompatibilityOverrideConfig {
            rule_id: "noop".to_string(),
            host_pattern: "example.com".to_string(),
            ..super::CompatibilityOverrideConfig::default()
        }],
        ..super::MitmConfig::default()
    };
    let err = config
        .validate()
        .expect_err("noop compatibility override must fail");
    assert_eq!(err, super::MitmConfigError::NoopCompatibilityOverride { index: 0 });
}

#[test]
fn validation_rejects_invalid_compatibility_override_host_pattern() {
    let config = super::MitmConfig {
        compatibility_overrides: vec![super::CompatibilityOverrideConfig {
            rule_id: "invalid-host-pattern".to_string(),
            host_pattern: "*.*.example.com".to_string(),
            force_tunnel: true,
            ..super::CompatibilityOverrideConfig::default()
        }],
        ..super::MitmConfig::default()
    };
    let err = config
        .validate()
        .expect_err("invalid compatibility override host pattern must fail");
    assert_eq!(
        err,
        super::MitmConfigError::InvalidCompatibilityOverrideHostPattern { index: 0 }
    );
}
