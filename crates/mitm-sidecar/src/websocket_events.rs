fn emit_websocket_opened_event<P, S>(engine: &MitmEngine<P, S>, context: FlowContext)
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::WebSocketOpened, context);
    event
        .attributes
        .insert("relay_mode".to_string(), "intercept".to_string());
    engine.emit_event(event);
}

#[allow(clippy::too_many_arguments)]
fn emit_websocket_frame_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    direction: mitm_http::WsDirection,
    frame_kind: mitm_http::WsFrameKind,
    sequence_no: u64,
    opcode: u8,
    fin: bool,
    masked: bool,
    payload_len: u64,
    frame_len: u64,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::WebSocketFrame, context);
    event.attributes.insert(
        "direction".to_string(),
        websocket_direction_label(direction).to_string(),
    );
    event.attributes.insert(
        "frame_kind".to_string(),
        websocket_frame_kind_label(frame_kind).to_string(),
    );
    event
        .attributes
        .insert("sequence_no".to_string(), sequence_no.to_string());
    event
        .attributes
        .insert("opcode".to_string(), opcode.to_string());
    event.attributes.insert(
        "opcode_label".to_string(),
        websocket_opcode_label(opcode).to_string(),
    );
    event.attributes.insert("fin".to_string(), fin.to_string());
    event
        .attributes
        .insert("masked".to_string(), masked.to_string());
    event
        .attributes
        .insert("payload_len".to_string(), payload_len.to_string());
    event
        .attributes
        .insert("frame_len".to_string(), frame_len.to_string());
    engine.emit_event(event);
}

fn emit_websocket_closed_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    close_reason: &str,
    detail: Option<String>,
    bytes_from_client: u64,
    bytes_from_server: u64,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::WebSocketClosed, context);
    event
        .attributes
        .insert("close_reason".to_string(), close_reason.to_string());
    event.attributes.insert(
        "bytes_from_client".to_string(),
        bytes_from_client.to_string(),
    );
    event.attributes.insert(
        "bytes_from_server".to_string(),
        bytes_from_server.to_string(),
    );
    if let Some(reason_detail) = detail {
        event
            .attributes
            .insert("reason_detail".to_string(), reason_detail);
    }
    engine.emit_event(event);
}

fn emit_websocket_turn_started_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    turn_id: u64,
    initiated_by: mitm_http::WsDirection,
    first_frame_sequence_no: u64,
    started_at_unix_ms: u128,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::WebSocketTurnStarted, context);
    event
        .attributes
        .insert("turn_id".to_string(), turn_id.to_string());
    event.attributes.insert(
        "initiated_by".to_string(),
        websocket_direction_label(initiated_by).to_string(),
    );
    event.attributes.insert(
        "first_frame_sequence_no".to_string(),
        first_frame_sequence_no.to_string(),
    );
    event.attributes.insert(
        "started_at_unix_ms".to_string(),
        started_at_unix_ms.to_string(),
    );
    engine.emit_event(event);
}

fn emit_websocket_turn_completed_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    turn: &mitm_http::WebSocketTurn,
    flush_reason: &str,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::WebSocketTurnCompleted, context);
    event
        .attributes
        .insert("turn_id".to_string(), turn.turn_id.to_string());
    event.attributes.insert(
        "initiated_by".to_string(),
        websocket_direction_label(turn.initiated_by).to_string(),
    );
    event.attributes.insert(
        "started_at_unix_ms".to_string(),
        turn.started_at_unix_ms.to_string(),
    );
    event.attributes.insert(
        "ended_at_unix_ms".to_string(),
        turn.ended_at_unix_ms.to_string(),
    );
    event.attributes.insert(
        "first_frame_sequence_no".to_string(),
        turn.first_frame_sequence_no.to_string(),
    );
    event.attributes.insert(
        "last_frame_sequence_no".to_string(),
        turn.last_frame_sequence_no.to_string(),
    );
    event.attributes.insert(
        "client_frame_count".to_string(),
        turn.client_frame_count.to_string(),
    );
    event.attributes.insert(
        "server_frame_count".to_string(),
        turn.server_frame_count.to_string(),
    );
    event.attributes.insert(
        "client_payload_bytes".to_string(),
        turn.client_payload_bytes.to_string(),
    );
    event.attributes.insert(
        "server_payload_bytes".to_string(),
        turn.server_payload_bytes.to_string(),
    );
    event
        .attributes
        .insert("flush_reason".to_string(), flush_reason.to_string());
    engine.emit_event(event);
}

fn websocket_direction_label(direction: mitm_http::WsDirection) -> &'static str {
    match direction {
        mitm_http::WsDirection::ClientToServer => "client_to_server",
        mitm_http::WsDirection::ServerToClient => "server_to_client",
    }
}

fn websocket_frame_kind_label(kind: mitm_http::WsFrameKind) -> &'static str {
    match kind {
        mitm_http::WsFrameKind::Data => "data",
        mitm_http::WsFrameKind::Control => "control",
    }
}

fn websocket_opcode_label(opcode: u8) -> &'static str {
    match opcode {
        0x0 => "continuation",
        0x1 => "text",
        0x2 => "binary",
        0x8 => "close",
        0x9 => "ping",
        0xA => "pong",
        _ => "other",
    }
}
