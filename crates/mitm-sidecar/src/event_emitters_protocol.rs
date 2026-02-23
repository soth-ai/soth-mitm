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

fn emit_grpc_request_headers_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    observation: &GrpcRequestObservation,
    headers: &http::HeaderMap,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::GrpcRequestHeaders, context);
    insert_grpc_common_attrs(&mut event, observation);
    event
        .attributes
        .insert("grpc_event_sequence".to_string(), "1".to_string());
    event
        .attributes
        .insert("header_count".to_string(), headers.len().to_string());
    if let Some(te) = header_value(headers, "te") {
        event.attributes.insert("te".to_string(), te);
    }
    if let Some(user_agent) = header_value(headers, "user-agent") {
        event.attributes.insert("user_agent".to_string(), user_agent);
    }
    engine.emit_event(event);
}

fn emit_grpc_response_headers_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    observation: &GrpcRequestObservation,
    response: &http::response::Parts,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::GrpcResponseHeaders, context);
    insert_grpc_common_attrs(&mut event, observation);
    event
        .attributes
        .insert("grpc_event_sequence".to_string(), "2".to_string());
    event.attributes.insert(
        "status_code".to_string(),
        response.status.as_u16().to_string(),
    );
    event.attributes.insert(
        "header_count".to_string(),
        response.headers.len().to_string(),
    );
    if let Some(content_type) = header_value(&response.headers, "content-type") {
        event
            .attributes
            .insert("grpc_response_content_type".to_string(), content_type);
    }
    engine.emit_event(event);
}

fn emit_grpc_response_trailers_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    observation: &GrpcRequestObservation,
    trailers: &http::HeaderMap,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::GrpcResponseTrailers, context);
    insert_grpc_common_attrs(&mut event, observation);
    event
        .attributes
        .insert("grpc_event_sequence".to_string(), "3".to_string());
    event.attributes.insert(
        "trailer_count".to_string(),
        trailers.len().to_string(),
    );
    if let Some(grpc_status) = header_value(trailers, "grpc-status") {
        event
            .attributes
            .insert("grpc_status".to_string(), grpc_status);
    }
    if let Some(grpc_message) = header_value(trailers, "grpc-message") {
        event
            .attributes
            .insert("grpc_message".to_string(), grpc_message);
    }
    engine.emit_event(event);
}

fn insert_grpc_common_attrs(event: &mut Event, observation: &GrpcRequestObservation) {
    event
        .attributes
        .insert("grpc_path".to_string(), observation.path.clone());
    event.attributes.insert(
        "grpc_detection_mode".to_string(),
        observation.detection_mode.to_string(),
    );
    if let Some(service) = &observation.service {
        event
            .attributes
            .insert("grpc_service".to_string(), service.clone());
    }
    if let Some(method) = &observation.method {
        event
            .attributes
            .insert("grpc_method".to_string(), method.clone());
    }
    if let Some(content_type) = &observation.content_type {
        event
            .attributes
            .insert("grpc_request_content_type".to_string(), content_type.clone());
    }
}

fn header_value(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}
