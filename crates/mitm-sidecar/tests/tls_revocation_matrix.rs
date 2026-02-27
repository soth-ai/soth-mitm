use std::collections::BTreeMap;

use mitm_core::{MitmConfig, MitmEngine};
use mitm_http::ApplicationProtocol;
use mitm_observe::{EventType, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{MitmproxyTlsCallback, MitmproxyTlsHook, SidecarConfig, SidecarServer};

fn build_engine(
    config: MitmConfig,
    sink: VecEventConsumer,
) -> MitmEngine<DefaultPolicyEngine, VecEventConsumer> {
    let policy =
        DefaultPolicyEngine::new(config.ignore_hosts.clone(), config.blocked_hosts.clone());
    MitmEngine::new(config, policy, sink)
}

fn build_sidecar(sink: VecEventConsumer) -> SidecarServer<DefaultPolicyEngine, VecEventConsumer> {
    let engine = build_engine(MitmConfig::default(), sink);
    SidecarServer::new(SidecarConfig::default(), engine).expect("build sidecar")
}

fn metadata_for_flow(events: &[mitm_observe::Event], flow_id: u64) -> BTreeMap<String, String> {
    events
        .iter()
        .find(|event| {
            event.kind == EventType::TlsHandshakeFailed && event.context.flow_id == flow_id
        })
        .expect("missing tls failed event")
        .attributes
        .clone()
}

#[test]
fn upstream_revocation_metadata_matrix_emits_stable_fields() {
    let sink = VecEventConsumer::default();
    let server = build_sidecar(sink.clone());

    let fixtures = vec![
        (
            201_u64,
            "OCSP response required but missing",
            "false",
            "missing",
            "signal_missing_staple",
        ),
        (
            202_u64,
            "upstream rejected malformed OCSP stapling parse error",
            "true",
            "invalid",
            "signal_invalid_staple",
        ),
        (
            203_u64,
            "certificate revoked by OCSP responder",
            "unknown",
            "revoked",
            "signal_revoked",
        ),
        (
            204_u64,
            "OCSP stapling status: good",
            "true",
            "present",
            "signal_present",
        ),
        (
            205_u64,
            "OCSP response expired while validating chain",
            "true",
            "invalid",
            "signal_invalid_staple",
        ),
    ];

    for (flow_id, detail, _, _, _) in &fixtures {
        server.ingest_mitmproxy_tls_callback(MitmproxyTlsCallback {
            flow_id: *flow_id,
            client_addr: "127.0.0.1:50000".to_string(),
            server_host: "api.example.com".to_string(),
            server_port: 443,
            protocol: ApplicationProtocol::Http1,
            hook: MitmproxyTlsHook::TlsFailedServer,
            error: Some((*detail).to_string()),
            provider_error_class: Some("TlsException".to_string()),
            provider_error_code: Some(format!("ERR_{flow_id}")),
            provider_error_detail: Some((*detail).to_string()),
        });
    }

    let events = sink.snapshot();
    for (flow_id, _, expected_present, expected_status, expected_decision) in fixtures {
        let attrs = metadata_for_flow(&events, flow_id);
        assert_eq!(
            attrs
                .get("upstream_ocsp_staple_present")
                .map(String::as_str),
            Some(expected_present)
        );
        assert_eq!(
            attrs.get("upstream_ocsp_staple_status").map(String::as_str),
            Some(expected_status)
        );
        assert_eq!(
            attrs.get("revocation_policy_mode").map(String::as_str),
            Some("passive_observe")
        );
        assert_eq!(
            attrs.get("revocation_decision").map(String::as_str),
            Some(expected_decision)
        );
    }
}

#[test]
fn downstream_tls_failure_marks_revocation_not_applicable() {
    let sink = VecEventConsumer::default();
    let server = build_sidecar(sink.clone());

    server.ingest_mitmproxy_tls_callback(MitmproxyTlsCallback {
        flow_id: 301,
        client_addr: "127.0.0.1:50001".to_string(),
        server_host: "api.example.com".to_string(),
        server_port: 443,
        protocol: ApplicationProtocol::Http1,
        hook: MitmproxyTlsHook::TlsFailedClient,
        error: Some("certificate verify failed: unknown ca".to_string()),
        provider_error_class: Some("TlsException".to_string()),
        provider_error_code: Some("ERR_301".to_string()),
        provider_error_detail: Some("certificate verify failed: unknown ca".to_string()),
    });

    let events = sink.snapshot();
    let attrs = metadata_for_flow(&events, 301);
    assert_eq!(
        attrs
            .get("upstream_ocsp_staple_present")
            .map(String::as_str),
        Some("not_applicable")
    );
    assert_eq!(
        attrs.get("upstream_ocsp_staple_status").map(String::as_str),
        Some("not_applicable")
    );
    assert_eq!(
        attrs.get("revocation_policy_mode").map(String::as_str),
        Some("passive_observe")
    );
    assert_eq!(
        attrs.get("revocation_decision").map(String::as_str),
        Some("not_applicable")
    );
}
