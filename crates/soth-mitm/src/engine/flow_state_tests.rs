fn machine_name(machine: FlowProtocolMachine) -> &'static str {
    match machine {
        FlowProtocolMachine::Unknown => "unknown",
        FlowProtocolMachine::Tunnel => "tunnel",
        FlowProtocolMachine::Http1 => "http1",
        FlowProtocolMachine::Http2 => "http2",
        FlowProtocolMachine::StreamableHttp => "streamable_http",
        FlowProtocolMachine::WebSocket => "websocket",
        FlowProtocolMachine::Sse => "sse",
    }
}

#[test]
fn flow_state_machine_allows_connect_to_close_lifecycle() {
    let s1 = next_flow_state_for_machine(
        FlowProtocolMachine::Unknown,
        FlowLifecycleState::Accepted,
        EventType::ConnectReceived,
    )
    .expect("connect");
    let s2 = next_flow_state_for_machine(FlowProtocolMachine::Unknown, s1, EventType::ConnectDecision)
        .expect("decision");
    let s3 = next_flow_state_for_machine(
        FlowProtocolMachine::Unknown,
        s2,
        EventType::TlsHandshakeStarted,
    )
    .expect("tls started");
    let s4 = next_flow_state_for_machine(
        FlowProtocolMachine::Unknown,
        s3,
        EventType::TlsHandshakeSucceeded,
    )
    .expect("tls ok");
    let s5 = next_flow_state_for_machine(
        FlowProtocolMachine::Unknown,
        s4,
        EventType::RequestHeaders,
    )
    .expect("active");
    let s6 = next_flow_state_for_machine(
        FlowProtocolMachine::Unknown,
        s5,
        EventType::StreamClosed,
    )
    .expect("closed");
    assert_eq!(s6, FlowLifecycleState::Closed);
}

#[test]
fn flow_state_machine_rejects_policy_decision_before_connect_parse() {
    let invalid = next_flow_state_for_machine(
        FlowProtocolMachine::Unknown,
        FlowLifecycleState::Accepted,
        EventType::ConnectDecision,
    );
    assert!(invalid.is_none(), "connect_decision must follow connect");
}

#[test]
fn protocol_machine_infers_from_protocol_and_h3_event() {
    assert_eq!(
        machine_name(protocol_machine_from_event(
            ApplicationProtocol::Http1,
            EventType::RequestHeaders
        )),
        "http1"
    );
    assert_eq!(
        machine_name(protocol_machine_from_event(
            ApplicationProtocol::Tunnel,
            EventType::Http3Passthrough
        )),
        "streamable_http"
    );
}

#[test]
fn protocol_machine_promotes_from_tunnel_once() {
    let promoted =
        resolve_protocol_machine(FlowProtocolMachine::Tunnel, FlowProtocolMachine::Http2);
    assert_eq!(promoted, FlowProtocolMachine::Http2);

    let sticky = resolve_protocol_machine(promoted, FlowProtocolMachine::Http1);
    assert_eq!(sticky, FlowProtocolMachine::Http2);
}

#[test]
fn http2_machine_rejects_websocket_events() {
    let next = next_flow_state_for_machine(
        FlowProtocolMachine::Http2,
        FlowLifecycleState::ProtocolActive,
        EventType::WebSocketFrame,
    );
    assert!(
        next.is_none(),
        "http2 machine should reject websocket frame events"
    );
}

#[test]
fn invalid_transition_terminalizes_without_panic_and_allows_close() {
    let tracker = FlowStateTracker::default();
    let flow_id = 91;

    assert_eq!(
        tracker.on_event(
            flow_id,
            ApplicationProtocol::Tunnel,
            EventType::ConnectReceived
        ),
        1
    );
    assert_eq!(
        tracker.on_event(flow_id, ApplicationProtocol::Http1, EventType::RequestHeaders),
        2
    );

    let snapshot = tracker
        .debug_snapshot(flow_id)
        .expect("flow entry should still exist before close");
    assert_eq!(snapshot.0, FlowLifecycleState::StreamClosing);
    assert_eq!(snapshot.1, FlowProtocolMachine::Http1);
    assert_eq!(snapshot.2, 1);

    assert_eq!(
        tracker.on_event(flow_id, ApplicationProtocol::Tunnel, EventType::StreamClosed),
        3
    );
    assert!(
        tracker.debug_snapshot(flow_id).is_none(),
        "flow entry must be evicted after close"
    );
}
