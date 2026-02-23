fn emit_sse_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    sequence_no: u64,
    event: &mitm_http::SseEvent,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut emitted = Event::new(EventType::SseEvent, context);
    emitted
        .attributes
        .insert("sequence_no".to_string(), sequence_no.to_string());
    emitted.attributes.insert(
        "data_line_count".to_string(),
        event.data_line_count.to_string(),
    );
    emitted
        .attributes
        .insert("data_len".to_string(), event.data.len().to_string());
    emitted
        .attributes
        .insert("data".to_string(), event.data.clone());
    if let Some(name) = &event.event {
        emitted.attributes.insert("event".to_string(), name.clone());
    }
    if let Some(id) = &event.id {
        emitted.attributes.insert("id".to_string(), id.clone());
    }
    if let Some(retry_ms) = event.retry_ms {
        emitted
            .attributes
            .insert("retry_ms".to_string(), retry_ms.to_string());
    }
    engine.emit_event(emitted);
}

fn emit_http3_passthrough_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    requested_by: &str,
    policy_action: &str,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::Http3Passthrough, context);
    event
        .attributes
        .insert("passthrough_protocol".to_string(), "http3".to_string());
    event
        .attributes
        .insert("passthrough_mode".to_string(), "tunnel".to_string());
    event
        .attributes
        .insert("requested_by".to_string(), requested_by.to_string());
    event
        .attributes
        .insert("policy_action".to_string(), policy_action.to_string());
    engine.emit_event(event);
}
