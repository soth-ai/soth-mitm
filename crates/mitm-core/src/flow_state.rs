use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use mitm_http::ApplicationProtocol;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum FlowProtocolMachine {
    #[default]
    Unknown,
    Tunnel,
    Http1,
    Http2,
    StreamableHttp,
    WebSocket,
    Sse,
}

#[derive(Debug)]
struct FlowTrackerEntry {
    state: FlowLifecycleState,
    machine: FlowProtocolMachine,
    next_flow_sequence_id: u64,
    invalid_transition_count: u64,
}

impl Default for FlowTrackerEntry {
    fn default() -> Self {
        Self {
            state: FlowLifecycleState::Accepted,
            machine: FlowProtocolMachine::Unknown,
            next_flow_sequence_id: 1,
            invalid_transition_count: 0,
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
    pub(crate) fn on_event(
        &self,
        flow_id: u64,
        protocol: ApplicationProtocol,
        kind: EventType,
    ) -> u64 {
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

            entry.machine = resolve_protocol_machine(
                entry.machine,
                protocol_machine_from_event(protocol, kind),
            );

            if let Some(next_state) = next_flow_state_for_machine(entry.machine, entry.state, kind)
            {
                entry.state = next_state;
                close_transition = next_state == FlowLifecycleState::Closed;
            } else {
                entry.invalid_transition_count = entry.invalid_transition_count.saturating_add(1);
                if entry.state != FlowLifecycleState::Closed {
                    entry.state = FlowLifecycleState::StreamClosing;
                }
            }
            flow_sequence_id
        };

        if close_transition {
            store.entries.remove(&flow_id);
            remove_from_order(&mut store.order, flow_id);
        }

        while store.entries.len() > MAX_TRACKED_FLOW_STATES {
            let mut evicted = false;
            while let Some(evicted_flow_id) = store.order.pop_front() {
                if store.entries.remove(&evicted_flow_id).is_some() {
                    evicted = true;
                    break;
                }
            }
            if !evicted {
                break;
            }
        }

        flow_sequence_id
    }

    #[cfg(test)]
    fn debug_snapshot(
        &self,
        flow_id: u64,
    ) -> Option<(FlowLifecycleState, FlowProtocolMachine, u64)> {
        let store = self.store.lock().expect("flow state lock poisoned");
        store
            .entries
            .get(&flow_id)
            .map(|entry| (entry.state, entry.machine, entry.invalid_transition_count))
    }
}

fn remove_from_order(order: &mut VecDeque<u64>, flow_id: u64) {
    order.retain(|existing| *existing != flow_id);
}

fn protocol_machine_from_event(
    protocol: ApplicationProtocol,
    kind: EventType,
) -> FlowProtocolMachine {
    if kind == EventType::Http3Passthrough {
        return FlowProtocolMachine::StreamableHttp;
    }
    match protocol {
        ApplicationProtocol::Http1 => FlowProtocolMachine::Http1,
        ApplicationProtocol::Http2 => FlowProtocolMachine::Http2,
        ApplicationProtocol::WebSocket => FlowProtocolMachine::WebSocket,
        ApplicationProtocol::Sse => FlowProtocolMachine::Sse,
        ApplicationProtocol::StreamableHttp => FlowProtocolMachine::StreamableHttp,
        ApplicationProtocol::Tunnel => FlowProtocolMachine::Tunnel,
    }
}

fn resolve_protocol_machine(
    current: FlowProtocolMachine,
    event_machine: FlowProtocolMachine,
) -> FlowProtocolMachine {
    match (current, event_machine) {
        (FlowProtocolMachine::Unknown, next) => next,
        (FlowProtocolMachine::Tunnel, next)
            if next != FlowProtocolMachine::Unknown && next != FlowProtocolMachine::Tunnel =>
        {
            next
        }
        _ => current,
    }
}

pub(crate) fn next_flow_state_for_machine(
    machine: FlowProtocolMachine,
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
            FlowLifecycleState::PolicyDecided
                | FlowLifecycleState::TlsStarted
                | FlowLifecycleState::TlsReady
        )
        .then_some(FlowLifecycleState::TlsStarted),
        EventType::TlsHandshakeSucceeded => matches!(
            current,
            FlowLifecycleState::TlsStarted | FlowLifecycleState::TlsReady
        )
        .then_some(FlowLifecycleState::TlsReady),
        EventType::TlsHandshakeFailed => matches!(
            current,
            FlowLifecycleState::PolicyDecided
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
        | EventType::Http3Passthrough => next_protocol_active_state(machine, current, kind),
    }
}

fn next_protocol_active_state(
    machine: FlowProtocolMachine,
    current: FlowLifecycleState,
    kind: EventType,
) -> Option<FlowLifecycleState> {
    let protocol_phase_valid = matches!(
        current,
        FlowLifecycleState::PolicyDecided
            | FlowLifecycleState::TlsReady
            | FlowLifecycleState::ProtocolActive
    );
    if !protocol_phase_valid {
        return None;
    }

    let event_allowed = match machine {
        FlowProtocolMachine::Unknown => true,
        FlowProtocolMachine::Tunnel => kind == EventType::Http3Passthrough,
        FlowProtocolMachine::StreamableHttp => kind == EventType::Http3Passthrough,
        FlowProtocolMachine::Http1 => matches!(
            kind,
            EventType::RequestHeaders
                | EventType::RequestBodyChunk
                | EventType::ResponseHeaders
                | EventType::ResponseBodyChunk
                | EventType::SseEvent
                | EventType::WebSocketOpened
                | EventType::WebSocketFrame
                | EventType::WebSocketTurnStarted
                | EventType::WebSocketTurnCompleted
                | EventType::WebSocketClosed
        ),
        FlowProtocolMachine::Http2 => matches!(
            kind,
            EventType::RequestHeaders
                | EventType::RequestBodyChunk
                | EventType::ResponseHeaders
                | EventType::ResponseBodyChunk
                | EventType::GrpcRequestHeaders
                | EventType::GrpcResponseHeaders
                | EventType::GrpcResponseTrailers
        ),
        FlowProtocolMachine::WebSocket => matches!(
            kind,
            EventType::WebSocketOpened
                | EventType::WebSocketFrame
                | EventType::WebSocketTurnStarted
                | EventType::WebSocketTurnCompleted
                | EventType::WebSocketClosed
        ),
        FlowProtocolMachine::Sse => matches!(
            kind,
            EventType::RequestHeaders
                | EventType::RequestBodyChunk
                | EventType::ResponseHeaders
                | EventType::ResponseBodyChunk
                | EventType::SseEvent
        ),
    };
    event_allowed.then_some(FlowLifecycleState::ProtocolActive)
}

#[cfg(test)]
include!("flow_state_tests.rs");
