use super::{MitmConfig, MitmEngine};
use mitm_http::ApplicationProtocol;
use mitm_observe::{Event, EventConsumer, EventEnvelope, EventType, FlowContext};
use mitm_policy::{DefaultPolicyEngine, FlowAction};
use std::sync::{Arc, Mutex};

#[derive(Default, Clone)]
struct CaptureConsumer {
    events: Arc<Mutex<Vec<EventEnvelope>>>,
}

impl CaptureConsumer {
    fn snapshot(&self) -> Vec<EventEnvelope> {
        self.events.lock().expect("capture lock poisoned").clone()
    }
}

impl EventConsumer for CaptureConsumer {
    fn consume(&self, envelope: EventEnvelope) {
        self.events
            .lock()
            .expect("capture lock poisoned")
            .push(envelope);
    }
}

#[test]
fn suppresses_duplicate_stream_closed_for_same_flow() {
    let sink = CaptureConsumer::default();
    let config = MitmConfig::default();
    let policy = DefaultPolicyEngine::new(vec![], vec![]);
    let engine = MitmEngine::new(config, policy, sink.clone());

    let context = FlowContext {
        flow_id: 7,
        client_addr: "127.0.0.1:10000".to_string(),
        server_host: "example.com".to_string(),
        server_port: 443,
        protocol: ApplicationProtocol::Tunnel,
    };
    let mut first = Event::new(EventType::StreamClosed, context.clone());
    first
        .attributes
        .insert("reason_code".to_string(), "relay_eof".to_string());
    engine.emit_event(first);

    let mut second = Event::new(EventType::StreamClosed, context);
    second
        .attributes
        .insert("reason_code".to_string(), "relay_error".to_string());
    engine.emit_event(second);

    let events = sink.snapshot();
    assert_eq!(events.len(), 1, "only one stream_closed should be emitted");
    assert_eq!(events[0].event.kind, EventType::StreamClosed);
    assert_eq!(
        events[0]
            .event
            .attributes
            .get("reason_code")
            .map(String::as_str),
        Some("relay_eof")
    );
}

#[test]
fn enforces_max_flow_event_backlog_by_dropping_non_close_events() {
    let sink = CaptureConsumer::default();
    let config = MitmConfig {
        max_flow_event_backlog: 2,
        ..MitmConfig::default()
    };
    let policy = DefaultPolicyEngine::new(vec![], vec![]);
    let engine = MitmEngine::new(config, policy, sink.clone());

    let context = FlowContext {
        flow_id: 11,
        client_addr: "127.0.0.1:10000".to_string(),
        server_host: "example.com".to_string(),
        server_port: 443,
        protocol: ApplicationProtocol::Tunnel,
    };
    engine.emit_event(Event::new(EventType::ConnectReceived, context.clone()));
    engine.emit_event(Event::new(EventType::ConnectDecision, context.clone()));
    engine.emit_event(Event::new(EventType::RequestHeaders, context.clone()));
    engine.emit_event(Event::new(EventType::StreamClosed, context));

    let events = sink.snapshot();
    assert_eq!(events.len(), 3, "third non-close event should be dropped");
    assert_eq!(events[0].event.kind, EventType::ConnectReceived);
    assert_eq!(events[1].event.kind, EventType::ConnectDecision);
    assert_eq!(events[2].event.kind, EventType::StreamClosed);
}

#[test]
fn known_pinning_hosts_can_be_forced_to_tunnel_via_ignore_hosts() {
    let sink = CaptureConsumer::default();
    let config = MitmConfig {
        ignore_hosts: vec![
            "api.openai.com".to_string(),
            "api.anthropic.com".to_string(),
            "gateway.ai.cloudflare.com".to_string(),
        ],
        ..MitmConfig::default()
    };
    let policy =
        DefaultPolicyEngine::new(config.ignore_hosts.clone(), config.blocked_hosts.clone());
    let engine = MitmEngine::new(config, policy, sink);

    let outcome = engine.decide_connect(
        "127.0.0.1:40400".to_string(),
        "api.openai.com".to_string(),
        443,
        None,
    );
    assert_eq!(outcome.action, FlowAction::Tunnel);
    assert_eq!(outcome.reason, "ignored_host");
}
