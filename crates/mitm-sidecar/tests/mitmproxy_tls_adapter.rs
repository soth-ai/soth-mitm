use mitm_core::{MitmConfig, MitmEngine};
use mitm_http::ApplicationProtocol;
use mitm_observe::{EventType, VecEventSink};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{MitmproxyTlsCallback, MitmproxyTlsHook, SidecarConfig, SidecarServer};
use mitm_tls::classify_tls_error;

fn build_engine(
    config: MitmConfig,
    sink: VecEventSink,
) -> MitmEngine<DefaultPolicyEngine, VecEventSink> {
    let policy =
        DefaultPolicyEngine::new(config.ignore_hosts.clone(), config.blocked_hosts.clone());
    MitmEngine::new(config, policy, sink)
}

fn build_sidecar(sink: VecEventSink) -> SidecarServer<DefaultPolicyEngine, VecEventSink> {
    let config = MitmConfig::default();
    let engine = build_engine(config, sink);
    SidecarServer::new(SidecarConfig::default(), engine).expect("build sidecar")
}

#[test]
fn replayed_mitmproxy_failed_callbacks_match_native_taxonomy() {
    let sink = VecEventSink::default();
    let server = build_sidecar(sink.clone());

    let fixtures = vec![
        (
            1_u64,
            MitmproxyTlsHook::TlsFailedClient,
            "127.0.0.1",
            "certificate verify failed: unknown ca",
        ),
        (
            2_u64,
            MitmproxyTlsHook::TlsFailedServer,
            "api.example.com",
            "invalid peer certificate: HostnameMismatch",
        ),
        (
            3_u64,
            MitmproxyTlsHook::TlsFailedServer,
            "api.example.com",
            "remote error: tls: handshake failure",
        ),
        (
            4_u64,
            MitmproxyTlsHook::TlsFailedServer,
            "service.local",
            "operation timed out",
        ),
        (
            5_u64,
            MitmproxyTlsHook::TlsFailedClient,
            "127.0.0.1",
            "connection reset by peer",
        ),
        (
            6_u64,
            MitmproxyTlsHook::TlsFailedServer,
            "service.local",
            "unexpected provider fault",
        ),
    ];

    for (flow_id, hook, host, detail) in &fixtures {
        let callback = MitmproxyTlsCallback {
            flow_id: *flow_id,
            client_addr: "127.0.0.1:50000".to_string(),
            server_host: (*host).to_string(),
            server_port: 443,
            protocol: ApplicationProtocol::Http1,
            hook: *hook,
            error: Some((*detail).to_string()),
            provider_error_class: Some("TlsException".to_string()),
            provider_error_code: Some(format!("ERR_{flow_id}")),
            provider_error_detail: Some((*detail).to_string()),
        };
        let adapted = server.ingest_mitmproxy_tls_callback(callback);
        let expected_reason = classify_tls_error(detail).code();
        assert_eq!(
            adapted
                .failure
                .as_ref()
                .map(|failure| failure.reason.as_str()),
            Some(expected_reason)
        );
    }

    let events = sink.snapshot();
    let failed_events = events
        .iter()
        .filter(|event| event.kind == EventType::TlsHandshakeFailed)
        .collect::<Vec<_>>();
    assert_eq!(failed_events.len(), fixtures.len());

    for event in &failed_events {
        let detail = event
            .attributes
            .get("detail")
            .expect("provider detail present");
        let expected_reason = classify_tls_error(detail).code();
        assert_eq!(
            event
                .attributes
                .get("tls_failure_reason")
                .map(String::as_str),
            Some(expected_reason)
        );
        assert_eq!(
            event.attributes.get("tls_ops_provider").map(String::as_str),
            Some("mitmproxy")
        );
        assert!(event.attributes.contains_key("tls_ops_provider_hook"));
        assert!(event
            .attributes
            .contains_key("tls_ops_provider_error_class"));
        assert!(event.attributes.contains_key("tls_ops_provider_error_code"));
        assert!(event
            .attributes
            .contains_key("tls_ops_provider_error_detail"));
    }

    let diagnostics = server.tls_diagnostics_snapshot();
    assert_eq!(diagnostics.total_failures, fixtures.len() as u64);
    assert_eq!(
        diagnostics
            .hosts
            .get("api.example.com")
            .expect("api.example.com diagnostics")
            .total_failures,
        2
    );
    assert_eq!(
        diagnostics
            .hosts
            .get("127.0.0.1")
            .expect("127.0.0.1 diagnostics")
            .total_failures,
        2
    );
    assert_eq!(
        diagnostics
            .hosts
            .get("service.local")
            .expect("service.local diagnostics")
            .total_failures,
        2
    );

    let learning = server.tls_learning_snapshot();
    assert_eq!(learning.applied_total, 0);
    assert_eq!(learning.ignored_total, fixtures.len() as u64);
    assert!(learning.hosts.is_empty());

    let audit_events = events
        .iter()
        .filter(|event| event.kind == EventType::TlsLearningAudit)
        .collect::<Vec<_>>();
    assert_eq!(audit_events.len(), fixtures.len());
    for audit in &audit_events {
        assert_eq!(
            audit
                .attributes
                .get("tls_learning_decision")
                .map(String::as_str),
            Some("ignored")
        );
        assert_eq!(
            audit
                .attributes
                .get("tls_learning_reason_code")
                .map(String::as_str),
            Some("non_authoritative_provider")
        );
        assert_eq!(
            audit.attributes.get("signal_provider").map(String::as_str),
            Some("mitmproxy")
        );
    }
}

#[test]
fn replayed_mitmproxy_started_and_succeeded_callbacks_emit_lifecycle_events() {
    let sink = VecEventSink::default();
    let server = build_sidecar(sink.clone());

    let callbacks = vec![
        MitmproxyTlsCallback {
            flow_id: 10,
            client_addr: "127.0.0.1:50001".to_string(),
            server_host: "example.com".to_string(),
            server_port: 443,
            protocol: ApplicationProtocol::Http1,
            hook: MitmproxyTlsHook::TlsHandshakeStartedClient,
            error: None,
            provider_error_class: None,
            provider_error_code: None,
            provider_error_detail: None,
        },
        MitmproxyTlsCallback {
            flow_id: 11,
            client_addr: "127.0.0.1:50002".to_string(),
            server_host: "example.com".to_string(),
            server_port: 443,
            protocol: ApplicationProtocol::Http1,
            hook: MitmproxyTlsHook::TlsHandshakeStartedServer,
            error: None,
            provider_error_class: None,
            provider_error_code: None,
            provider_error_detail: None,
        },
        MitmproxyTlsCallback {
            flow_id: 12,
            client_addr: "127.0.0.1:50003".to_string(),
            server_host: "example.com".to_string(),
            server_port: 443,
            protocol: ApplicationProtocol::Http1,
            hook: MitmproxyTlsHook::TlsHandshakeSucceededClient,
            error: None,
            provider_error_class: None,
            provider_error_code: None,
            provider_error_detail: None,
        },
        MitmproxyTlsCallback {
            flow_id: 13,
            client_addr: "127.0.0.1:50004".to_string(),
            server_host: "example.com".to_string(),
            server_port: 443,
            protocol: ApplicationProtocol::Http1,
            hook: MitmproxyTlsHook::TlsHandshakeSucceededServer,
            error: None,
            provider_error_class: None,
            provider_error_code: None,
            provider_error_detail: None,
        },
    ];

    for callback in callbacks {
        let adapted = server.ingest_mitmproxy_tls_callback(callback);
        assert!(adapted.failure.is_none());
    }

    let events = sink.snapshot();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == EventType::TlsHandshakeStarted)
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == EventType::TlsHandshakeSucceeded)
            .count(),
        2
    );

    let peers = events
        .iter()
        .filter_map(|event| event.attributes.get("peer"))
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert!(peers.contains(&"downstream"));
    assert!(peers.contains(&"upstream"));
}
