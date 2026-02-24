use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use mitm_http::ApplicationProtocol;

mod event_log_v2;

pub use event_log_v2::{
    deterministic_event_record_v2, DeterministicEventRecordV2, EventLogV2Config,
    EventLogV2Consumer, DETERMINISTIC_EVENT_LOG_V2_SCHEMA,
};

pub const EVENT_SCHEMA_VERSION: &str = "v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    ConnectReceived,
    ConnectParseFailed,
    ConnectDecision,
    TlsHandshakeStarted,
    TlsHandshakeSucceeded,
    TlsHandshakeFailed,
    TlsLearningAudit,
    RequestHeaders,
    RequestBodyChunk,
    ResponseHeaders,
    ResponseBodyChunk,
    GrpcRequestHeaders,
    GrpcResponseHeaders,
    GrpcResponseTrailers,
    SseEvent,
    WebSocketOpened,
    WebSocketFrame,
    WebSocketTurnStarted,
    WebSocketTurnCompleted,
    WebSocketClosed,
    Http3Passthrough,
    StreamClosed,
}

impl EventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConnectReceived => "connect_received",
            Self::ConnectParseFailed => "connect_parse_failed",
            Self::ConnectDecision => "connect_decision",
            Self::TlsHandshakeStarted => "tls_handshake_started",
            Self::TlsHandshakeSucceeded => "tls_handshake_succeeded",
            Self::TlsHandshakeFailed => "tls_handshake_failed",
            Self::TlsLearningAudit => "tls_learning_audit",
            Self::RequestHeaders => "request_headers",
            Self::RequestBodyChunk => "request_body_chunk",
            Self::ResponseHeaders => "response_headers",
            Self::ResponseBodyChunk => "response_body_chunk",
            Self::GrpcRequestHeaders => "grpc_request_headers",
            Self::GrpcResponseHeaders => "grpc_response_headers",
            Self::GrpcResponseTrailers => "grpc_response_trailers",
            Self::SseEvent => "sse_event",
            Self::WebSocketOpened => "websocket_opened",
            Self::WebSocketFrame => "websocket_frame",
            Self::WebSocketTurnStarted => "websocket_turn_started",
            Self::WebSocketTurnCompleted => "websocket_turn_completed",
            Self::WebSocketClosed => "websocket_closed",
            Self::Http3Passthrough => "http3_passthrough",
            Self::StreamClosed => "stream_closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowContext {
    pub flow_id: u64,
    pub client_addr: String,
    pub server_host: String,
    pub server_port: u16,
    pub protocol: ApplicationProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub sequence_id: u64,
    pub flow_sequence_id: u64,
    pub kind: EventType,
    pub context: FlowContext,
    pub occurred_at_monotonic_ns: u128,
    pub occurred_at_unix_ms: u128,
    pub attributes: BTreeMap<String, String>,
}

impl Event {
    pub fn new(kind: EventType, context: FlowContext) -> Self {
        Self {
            sequence_id: 0,
            flow_sequence_id: 0,
            kind,
            context,
            occurred_at_monotonic_ns: 0,
            occurred_at_unix_ms: now_unix_ms(),
            attributes: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope {
    pub schema_version: &'static str,
    pub event: Event,
}

impl EventEnvelope {
    pub fn from_event(event: Event) -> Self {
        Self {
            schema_version: EVENT_SCHEMA_VERSION,
            event,
        }
    }
}

/// Stable downstream event-consumer interface for deterministic proxy event streams.
///
/// Consumers should use `event.sequence_id` as the global ordering key.
pub trait EventConsumer: Send + Sync {
    fn consume(&self, envelope: EventEnvelope);
}

#[derive(Debug, Default)]
pub struct NoopEventConsumer;

impl EventConsumer for NoopEventConsumer {
    fn consume(&self, _envelope: EventEnvelope) {}
}

impl EventConsumer for Box<dyn EventConsumer + Send + Sync> {
    fn consume(&self, envelope: EventEnvelope) {
        (**self).consume(envelope);
    }
}

#[derive(Debug, Default, Clone)]
pub struct VecEventConsumer {
    envelopes: Arc<Mutex<Vec<EventEnvelope>>>,
}

impl VecEventConsumer {
    pub fn snapshot(&self) -> Vec<Event> {
        self.snapshot_deterministic()
            .into_iter()
            .map(|envelope| envelope.event)
            .collect()
    }

    pub fn snapshot_envelopes(&self) -> Vec<EventEnvelope> {
        self.snapshot_deterministic()
    }

    pub fn snapshot_deterministic(&self) -> Vec<EventEnvelope> {
        let mut envelopes = self.envelopes.lock().expect("lock poisoned").clone();
        envelopes.sort_by_key(|envelope| envelope.event.sequence_id);
        envelopes
    }

    pub fn snapshot_from_sequence(&self, after_sequence_id: u64) -> Vec<EventEnvelope> {
        self.snapshot_deterministic()
            .into_iter()
            .filter(|envelope| envelope.event.sequence_id > after_sequence_id)
            .collect()
    }
}

impl EventConsumer for VecEventConsumer {
    fn consume(&self, envelope: EventEnvelope) {
        self.envelopes.lock().expect("lock poisoned").push(envelope);
    }
}

fn now_unix_ms() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        ApplicationProtocol, Event, EventConsumer, EventEnvelope, EventType, FlowContext,
        NoopEventConsumer, VecEventConsumer, EVENT_SCHEMA_VERSION,
    };

    #[derive(Debug, Default, Clone)]
    struct CaptureEventConsumer {
        events: Arc<Mutex<Vec<EventEnvelope>>>,
    }

    impl CaptureEventConsumer {
        fn snapshot(&self) -> Vec<EventEnvelope> {
            self.events.lock().expect("lock poisoned").clone()
        }
    }

    impl EventConsumer for CaptureEventConsumer {
        fn consume(&self, envelope: EventEnvelope) {
            self.events.lock().expect("lock poisoned").push(envelope);
        }
    }

    fn sample_context(flow_id: u64) -> FlowContext {
        FlowContext {
            flow_id,
            client_addr: "127.0.0.1:12345".to_string(),
            server_host: "example.com".to_string(),
            server_port: 443,
            protocol: ApplicationProtocol::Tunnel,
        }
    }

    #[test]
    fn consumer_receives_v1_envelope() {
        let consumer = CaptureEventConsumer::default();
        let mut event = Event::new(EventType::ConnectReceived, sample_context(1));
        event.sequence_id = 7;
        consumer.consume(EventEnvelope::from_event(event.clone()));

        let envelopes = consumer.snapshot();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].schema_version, EVENT_SCHEMA_VERSION);
        assert_eq!(envelopes[0].event, event);
    }

    #[test]
    fn noop_consumer_is_stable() {
        let consumer = NoopEventConsumer;
        consumer.consume(EventEnvelope::from_event(Event::new(
            EventType::ConnectReceived,
            sample_context(1),
        )));
    }

    #[test]
    fn deterministic_snapshot_is_sorted_by_sequence_id() {
        let consumer = VecEventConsumer::default();
        let mut event_three = Event::new(EventType::ConnectDecision, sample_context(1));
        event_three.sequence_id = 3;
        let mut event_one = Event::new(EventType::ConnectReceived, sample_context(1));
        event_one.sequence_id = 1;
        let mut event_two = Event::new(EventType::StreamClosed, sample_context(1));
        event_two.sequence_id = 2;

        consumer.consume(EventEnvelope::from_event(event_three));
        consumer.consume(EventEnvelope::from_event(event_one));
        consumer.consume(EventEnvelope::from_event(event_two));

        let ordered = consumer.snapshot_deterministic();
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].event.sequence_id, 1);
        assert_eq!(ordered[1].event.sequence_id, 2);
        assert_eq!(ordered[2].event.sequence_id, 3);
    }

    #[test]
    fn snapshot_from_sequence_filters_using_global_sequence_id() {
        let consumer = VecEventConsumer::default();
        for sequence_id in 1..=4 {
            let mut event = Event::new(EventType::ConnectReceived, sample_context(sequence_id));
            event.sequence_id = sequence_id;
            consumer.consume(EventEnvelope::from_event(event));
        }

        let filtered = consumer.snapshot_from_sequence(2);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].event.sequence_id, 3);
        assert_eq!(filtered[1].event.sequence_id, 4);
    }
}
