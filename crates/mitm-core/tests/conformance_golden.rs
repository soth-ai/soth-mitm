use std::collections::BTreeMap;
use std::fs;

use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::{EventType, VecEventConsumer, EVENT_SCHEMA_VERSION};
use mitm_policy::{DefaultPolicyEngine, FlowAction};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FixtureSuite {
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
struct FixtureCase {
    name: String,
    config: FixtureConfig,
    input: FixtureInput,
    expected_outcome: ExpectedOutcome,
    expected_events: Vec<ExpectedEvent>,
}

#[derive(Debug, Deserialize)]
struct FixtureConfig {
    ignore_hosts: Vec<String>,
    blocked_hosts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureInput {
    client_addr: String,
    server_host: String,
    server_port: u16,
}

#[derive(Debug, Deserialize)]
struct ExpectedOutcome {
    action: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedEvent {
    sequence_id: u64,
    flow_sequence_id: u64,
    kind: String,
    attributes: BTreeMap<String, String>,
}

#[test]
fn connect_decision_event_stream_matches_golden_fixture() {
    let fixture = load_fixture();

    for case in fixture.cases {
        let sink = VecEventConsumer::default();
        let config = MitmConfig {
            ignore_hosts: case.config.ignore_hosts.clone(),
            blocked_hosts: case.config.blocked_hosts.clone(),
            ..MitmConfig::default()
        };
        let policy =
            DefaultPolicyEngine::new(config.ignore_hosts.clone(), config.blocked_hosts.clone());
        let engine = MitmEngine::new(config, policy, sink.clone());

        let flow_id = engine.allocate_flow_id();
        let outcome = engine.decide_connect(
            flow_id,
            case.input.client_addr.clone(),
            case.input.server_host.clone(),
            case.input.server_port,
            None,
            None,
        );

        assert_eq!(
            action_label(outcome.action),
            case.expected_outcome.action,
            "{}",
            case.name
        );
        assert_eq!(
            outcome.reason, case.expected_outcome.reason,
            "{}",
            case.name
        );

        let actual = sink.snapshot_envelopes();
        assert_eq!(actual.len(), case.expected_events.len(), "{}", case.name);

        for (index, expected) in case.expected_events.iter().enumerate() {
            let actual_envelope = &actual[index];
            let actual_event = &actual_envelope.event;

            assert_eq!(
                actual_envelope.schema_version, EVENT_SCHEMA_VERSION,
                "{}",
                case.name
            );
            assert_eq!(
                actual_event.sequence_id, expected.sequence_id,
                "{}",
                case.name
            );
            assert_eq!(
                actual_event.flow_sequence_id, expected.flow_sequence_id,
                "{}",
                case.name
            );
            assert_eq!(
                actual_event.kind,
                event_type_from_name(&expected.kind),
                "{}",
                case.name
            );
            assert_eq!(
                actual_event.attributes, expected.attributes,
                "{}",
                case.name
            );
            assert_eq!(
                actual_event.context.server_host, case.input.server_host,
                "{}",
                case.name
            );
            assert_eq!(
                actual_event.context.server_port, case.input.server_port,
                "{}",
                case.name
            );
        }
    }
}

fn load_fixture() -> FixtureSuite {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("connect_event_conformance.json");
    let fixture_json = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    serde_json::from_str(&fixture_json)
        .unwrap_or_else(|error| panic!("failed to parse fixture {}: {error}", path.display()))
}

fn action_label(action: FlowAction) -> &'static str {
    match action {
        FlowAction::Intercept => "intercept",
        FlowAction::Tunnel => "tunnel",
        FlowAction::Block => "block",
    }
}

fn event_type_from_name(name: &str) -> EventType {
    match name {
        "ConnectReceived" => EventType::ConnectReceived,
        "ConnectDecision" => EventType::ConnectDecision,
        other => panic!("unsupported fixture event kind: {other}"),
    }
}
