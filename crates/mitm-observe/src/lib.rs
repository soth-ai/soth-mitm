use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use mitm_http::ApplicationProtocol;

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
    StreamClosed,
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
    pub kind: EventType,
    pub context: FlowContext,
    pub occurred_at_unix_ms: u128,
    pub attributes: BTreeMap<String, String>,
}

impl Event {
    pub fn new(kind: EventType, context: FlowContext) -> Self {
        Self {
            kind,
            context,
            occurred_at_unix_ms: now_unix_ms(),
            attributes: BTreeMap::new(),
        }
    }
}

pub trait EventSink: Send + Sync {
    fn emit(&self, event: Event);
}

#[derive(Debug, Default)]
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn emit(&self, _event: Event) {}
}

#[derive(Debug, Default, Clone)]
pub struct VecEventSink {
    events: Arc<Mutex<Vec<Event>>>,
}

impl VecEventSink {
    pub fn snapshot(&self) -> Vec<Event> {
        self.events.lock().expect("lock poisoned").clone()
    }
}

impl EventSink for VecEventSink {
    fn emit(&self, event: Event) {
        self.events.lock().expect("lock poisoned").push(event);
    }
}

fn now_unix_ms() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    }
}
