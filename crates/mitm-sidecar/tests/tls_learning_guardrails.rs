use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::{EventType, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer, TlsLearningDecision, TlsLearningSignal};

fn build_engine(
    config: MitmConfig,
    sink: VecEventConsumer,
) -> MitmEngine<DefaultPolicyEngine, VecEventConsumer> {
    let policy =
        DefaultPolicyEngine::new(config.ignore_hosts.clone(), config.blocked_hosts.clone());
    MitmEngine::new(config, policy, sink)
}

fn build_sidecar(sink: VecEventConsumer) -> SidecarServer<DefaultPolicyEngine, VecEventConsumer> {
    let config = MitmConfig::default();
    let engine = build_engine(config, sink);
    SidecarServer::new(SidecarConfig::default(), engine).expect("build sidecar")
}

#[test]
fn authoritative_signal_is_learned() {
    let sink = VecEventConsumer::default();
    let server = build_sidecar(sink.clone());

    let outcome = server.ingest_tls_learning_signal(TlsLearningSignal::new(
        "api.example.com",
        "unknown_ca",
        "upstream",
        "rustls",
        false,
    ));
    assert_eq!(outcome.decision, TlsLearningDecision::Applied);
    assert_eq!(outcome.reason_code, "authoritative");
    assert_eq!(outcome.host_applied_total, 1);

    let snapshot = server.tls_learning_snapshot();
    assert_eq!(snapshot.applied_total, 1);
    assert_eq!(snapshot.ignored_total, 0);
    let host = snapshot
        .hosts
        .get("api.example.com")
        .expect("host learning");
    assert_eq!(host.applied_total, 1);
    assert_eq!(host.by_reason.get("unknown_ca"), Some(&1));

    let audit_events = sink
        .snapshot()
        .into_iter()
        .filter(|event| event.kind == EventType::TlsLearningAudit)
        .collect::<Vec<_>>();
    assert!(
        audit_events.is_empty(),
        "authoritative learning should not emit ignored-audit events"
    );
}

#[test]
fn inferred_hudsucker_signal_is_ignored_and_audited_without_learning_mutation() {
    let sink = VecEventConsumer::default();
    let server = build_sidecar(sink.clone());

    let first = server.ingest_tls_learning_signal(TlsLearningSignal::new(
        "api.example.com",
        "unknown_ca",
        "upstream",
        "rustls",
        false,
    ));
    assert_eq!(first.decision, TlsLearningDecision::Applied);

    let second = server.ingest_tls_learning_signal(TlsLearningSignal::new(
        "api.example.com",
        "unknown_ca",
        "hudsucker_upstream",
        "hudsucker",
        true,
    ));
    assert_eq!(second.decision, TlsLearningDecision::Ignored);
    assert_eq!(second.reason_code, "inferred_hudsucker_signal");
    assert_eq!(second.host_applied_total, 1);

    let snapshot = server.tls_learning_snapshot();
    assert_eq!(snapshot.applied_total, 1);
    assert_eq!(snapshot.ignored_total, 1);
    let host = snapshot
        .hosts
        .get("api.example.com")
        .expect("host learning");
    assert_eq!(host.applied_total, 1);
    assert_eq!(host.by_reason.get("unknown_ca"), Some(&1));

    let audit_events = sink
        .snapshot()
        .into_iter()
        .filter(|event| event.kind == EventType::TlsLearningAudit)
        .collect::<Vec<_>>();
    assert_eq!(audit_events.len(), 1, "exactly one ignored audit event");
    let audit = &audit_events[0];
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
        Some("inferred_hudsucker_signal")
    );
    assert_eq!(
        audit.attributes.get("signal_source").map(String::as_str),
        Some("hudsucker_upstream")
    );
    assert_eq!(
        audit.attributes.get("signal_provider").map(String::as_str),
        Some("hudsucker")
    );
    assert_eq!(
        audit.attributes.get("signal_inferred").map(String::as_str),
        Some("true")
    );
}

#[test]
fn non_authoritative_provider_is_ignored_and_does_not_create_host_state() {
    let sink = VecEventConsumer::default();
    let server = build_sidecar(sink.clone());

    let outcome = server.ingest_tls_learning_signal(TlsLearningSignal::new(
        "service.local",
        "timeout",
        "upstream",
        "mitmproxy",
        false,
    ));
    assert_eq!(outcome.decision, TlsLearningDecision::Ignored);
    assert_eq!(outcome.reason_code, "non_authoritative_provider");
    assert_eq!(outcome.host_applied_total, 0);

    let snapshot = server.tls_learning_snapshot();
    assert_eq!(snapshot.applied_total, 0);
    assert_eq!(snapshot.ignored_total, 1);
    assert!(snapshot.hosts.is_empty());

    let audit_events = sink
        .snapshot()
        .into_iter()
        .filter(|event| event.kind == EventType::TlsLearningAudit)
        .collect::<Vec<_>>();
    assert_eq!(audit_events.len(), 1, "expected one ignored audit event");
    let audit = &audit_events[0];
    assert_eq!(
        audit
            .attributes
            .get("tls_learning_reason_code")
            .map(String::as_str),
        Some("non_authoritative_provider")
    );
}
