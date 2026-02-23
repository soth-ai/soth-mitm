use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use mitm_observe::EventType;

const MAX_TRACKED_FLOW_STATES: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowLifecycleState {
    Accepted,
    ConnectParsed,
    PolicyDecided,
    TlsStarted,
    TlsReady,
    ProtocolActive,
    StreamClosing,
    Closed,
}

#[derive(Debug)]
struct FlowTrackerEntry {
    state: FlowLifecycleState,
    next_flow_sequence_id: u64,
}

impl Default for FlowTrackerEntry {
    fn default() -> Self {
        Self {
            state: FlowLifecycleState::Accepted,
            next_flow_sequence_id: 1,
        }
    }
}

#[derive(Debug, Default)]
struct FlowStateStore {
    entries: HashMap<u64, FlowTrackerEntry>,
    order: VecDeque<u64>,
}

#[derive(Debug, Default)]
pub(crate) struct FlowStateTracker {
    store: Mutex<FlowStateStore>,
}

impl FlowStateTracker {
    pub(crate) fn on_event(&self, flow_id: u64, kind: EventType) -> u64 {
        let mut store = self.store.lock().expect("flow state lock poisoned");
        if let std::collections::hash_map::Entry::Vacant(entry) = store.entries.entry(flow_id) {
            entry.insert(FlowTrackerEntry::default());
            store.order.push_back(flow_id);
        }

        let mut close_transition = false;
        let flow_sequence_id = {
            let entry = store
                .entries
                .get_mut(&flow_id)
                .expect("flow entry must exist");
            let flow_sequence_id = entry.next_flow_sequence_id;
            entry.next_flow_sequence_id = entry.next_flow_sequence_id.saturating_add(1);

            let current_state = entry.state;
            if let Some(next_state) = next_flow_state(current_state, kind) {
                entry.state = next_state;
                close_transition = next_state == FlowLifecycleState::Closed;
            } else {
                debug_assert!(
                    false,
                    "illegal flow transition for flow_id={flow_id}: state={current_state:?}, event={kind:?}"
                );
            }
            flow_sequence_id
        };

        if close_transition {
            store.entries.remove(&flow_id);
        }

        while store.entries.len() > MAX_TRACKED_FLOW_STATES {
            let Some(evicted_flow_id) = store.order.pop_front() else {
                break;
            };
            store.entries.remove(&evicted_flow_id);
        }

        flow_sequence_id
    }
}

pub(crate) fn next_flow_state(
    current: FlowLifecycleState,
    kind: EventType,
) -> Option<FlowLifecycleState> {
    match kind {
        EventType::ConnectReceived => {
            (current == FlowLifecycleState::Accepted).then_some(FlowLifecycleState::ConnectParsed)
        }
        EventType::ConnectParseFailed => matches!(
            current,
            FlowLifecycleState::Accepted | FlowLifecycleState::ConnectParsed
        )
        .then_some(FlowLifecycleState::StreamClosing),
        EventType::ConnectDecision => (current == FlowLifecycleState::ConnectParsed)
            .then_some(FlowLifecycleState::PolicyDecided),
        EventType::TlsHandshakeStarted => matches!(
            current,
            FlowLifecycleState::Accepted
                | FlowLifecycleState::PolicyDecided
                | FlowLifecycleState::TlsStarted
                | FlowLifecycleState::TlsReady
        )
        .then_some(FlowLifecycleState::TlsStarted),
        EventType::TlsHandshakeSucceeded => matches!(
            current,
            FlowLifecycleState::Accepted
                | FlowLifecycleState::TlsStarted
                | FlowLifecycleState::TlsReady
        )
        .then_some(FlowLifecycleState::TlsReady),
        EventType::TlsHandshakeFailed => matches!(
            current,
            FlowLifecycleState::Accepted
                | FlowLifecycleState::PolicyDecided
                | FlowLifecycleState::TlsStarted
                | FlowLifecycleState::TlsReady
        )
        .then_some(FlowLifecycleState::StreamClosing),
        EventType::StreamClosed => {
            (current != FlowLifecycleState::Closed).then_some(FlowLifecycleState::Closed)
        }
        EventType::TlsLearningAudit => Some(current),
        EventType::RequestHeaders
        | EventType::RequestBodyChunk
        | EventType::ResponseHeaders
        | EventType::ResponseBodyChunk
        | EventType::GrpcRequestHeaders
        | EventType::GrpcResponseHeaders
        | EventType::GrpcResponseTrailers
        | EventType::SseEvent
        | EventType::WebSocketOpened
        | EventType::WebSocketFrame
        | EventType::WebSocketTurnStarted
        | EventType::WebSocketTurnCompleted
        | EventType::WebSocketClosed
        | EventType::Http3Passthrough => matches!(
            current,
            FlowLifecycleState::Accepted
                | FlowLifecycleState::PolicyDecided
                | FlowLifecycleState::TlsStarted
                | FlowLifecycleState::TlsReady
                | FlowLifecycleState::ProtocolActive
        )
        .then_some(FlowLifecycleState::ProtocolActive),
    }
}

#[cfg(test)]
mod tests {
    use super::{next_flow_state, FlowLifecycleState};
    use mitm_observe::EventType;

    #[test]
    fn flow_state_machine_allows_connect_to_close_lifecycle() {
        let s1 = next_flow_state(FlowLifecycleState::Accepted, EventType::ConnectReceived)
            .expect("connect_received");
        let s2 = next_flow_state(s1, EventType::ConnectDecision).expect("connect_decision");
        let s3 = next_flow_state(s2, EventType::TlsHandshakeStarted).expect("tls_started");
        let s4 = next_flow_state(s3, EventType::TlsHandshakeSucceeded).expect("tls_succeeded");
        let s5 = next_flow_state(s4, EventType::RequestHeaders).expect("protocol_active");
        let s6 = next_flow_state(s5, EventType::StreamClosed).expect("stream_closed");
        assert_eq!(s6, FlowLifecycleState::Closed);
    }

    #[test]
    fn flow_state_machine_rejects_policy_decision_before_connect_parse() {
        let invalid = next_flow_state(FlowLifecycleState::Accepted, EventType::ConnectDecision);
        assert!(
            invalid.is_none(),
            "connect_decision must require connect_received"
        );
    }
}
