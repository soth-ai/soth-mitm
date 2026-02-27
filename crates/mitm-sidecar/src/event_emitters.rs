fn emit_request_headers_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: &FlowContext,
    request: &HttpRequestHead,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::RequestHeaders, context.clone());
    event
        .attributes
        .insert("method".to_string(), request.method.clone());
    event
        .attributes
        .insert("target".to_string(), request.target.clone());
    event
        .attributes
        .insert("version".to_string(), request.version.as_str().to_string());
    event.attributes.insert(
        "header_count".to_string(),
        request.headers.len().to_string(),
    );
    engine.emit_event(event);
}

fn emit_response_headers_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: &FlowContext,
    response: &HttpResponseHead,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::ResponseHeaders, context.clone());
    event
        .attributes
        .insert("status_code".to_string(), response.status_code.to_string());
    event
        .attributes
        .insert("reason_phrase".to_string(), response.reason_phrase.clone());
    event
        .attributes
        .insert("version".to_string(), response.version.as_str().to_string());
    event.attributes.insert(
        "header_count".to_string(),
        response.headers.len().to_string(),
    );
    engine.emit_event(event);
}

fn emit_body_chunk_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    kind: EventType,
    bytes: u64,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    if bytes == 0 {
        return;
    }
    let mut event = Event::new(kind, context);
    event
        .attributes
        .insert("bytes".to_string(), bytes.to_string());
    engine.emit_event(event);
}

fn emit_tls_event<P, S>(
    engine: &MitmEngine<P, S>,
    kind: EventType,
    context: FlowContext,
    peer: &str,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut event = Event::new(kind, context);
    event
        .attributes
        .insert("peer".to_string(), peer.to_string());
    engine.emit_event(event);
}

fn emit_tls_event_with_negotiated_alpn<P, S>(
    engine: &MitmEngine<P, S>,
    kind: EventType,
    context: FlowContext,
    peer: &str,
    negotiated_alpn: Option<&[u8]>,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut event = Event::new(kind, context);
    event
        .attributes
        .insert("peer".to_string(), peer.to_string());
    if let Some(label) = negotiated_alpn_label(negotiated_alpn) {
        event
            .attributes
            .insert("negotiated_alpn".to_string(), label.to_string());
    }
    engine.emit_event(event);
}

fn emit_tls_event_with_cache<P, S>(
    engine: &MitmEngine<P, S>,
    kind: EventType,
    context: FlowContext,
    peer: &str,
    cert_cache_status: &str,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut event = Event::new(kind, context);
    event
        .attributes
        .insert("peer".to_string(), peer.to_string());
    event.attributes.insert(
        "cert_cache_status".to_string(),
        cert_cache_status.to_string(),
    );
    engine.emit_event(event);
}

fn emit_tls_event_with_detail<P, S>(
    engine: &MitmEngine<P, S>,
    tls_diagnostics: &TlsDiagnostics,
    tls_learning: &TlsLearningGuardrails,
    kind: EventType,
    context: FlowContext,
    peer: &str,
    detail: String,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let failure_metadata = if kind == EventType::TlsHandshakeFailed {
        let reason = classify_tls_error(&detail).code().to_string();
        let source = peer.to_string();
        let provider = TLS_OPS_PROVIDER.to_string();
        let counters = tls_diagnostics.record_failure(&context.server_host, &source, &reason);
        let learning_signal = TlsLearningSignal::new(
            context.server_host.clone(),
            reason.clone(),
            source.clone(),
            provider.clone(),
            false,
        );
        let learning_outcome = ingest_tls_learning_signal_with_audit(
            engine,
            tls_learning,
            context.clone(),
            learning_signal,
        );
        Some((reason, source, provider, counters, learning_outcome))
    } else {
        None
    };

    let mut event = Event::new(kind, context);
    event
        .attributes
        .insert("peer".to_string(), peer.to_string());
    event.attributes.insert("detail".to_string(), detail.clone());
    if let Some((reason, source, provider, counters, learning_outcome)) = failure_metadata {
        event
            .attributes
            .insert("tls_failure_reason".to_string(), reason);
        event
            .attributes
            .insert("tls_failure_source".to_string(), source);
        event
            .attributes
            .insert("tls_ops_provider".to_string(), provider);
        event.attributes.insert(
            "normalized_reason".to_string(),
            event
                .attributes
                .get("tls_failure_reason")
                .cloned()
                .unwrap_or_else(|| "other".to_string()),
        );
        event
            .attributes
            .insert("raw_provider_error".to_string(), detail.clone());
        insert_tls_revocation_metadata(&mut event.attributes, &detail, peer);
        event.attributes.insert(
            "provider_identity".to_string(),
            event
                .attributes
                .get("tls_ops_provider")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
        );
        event.attributes.insert(
            "source_confidence".to_string(),
            tls_source_confidence(
                event
                    .attributes
                    .get("tls_failure_source")
                    .map(String::as_str)
                    .unwrap_or("unknown"),
                event
                    .attributes
                    .get("tls_ops_provider")
                    .map(String::as_str)
                    .unwrap_or("unknown"),
            )
            .to_string(),
        );
        event.attributes.insert(
            "tls_failure_host_count".to_string(),
            counters.host_total_failures.to_string(),
        );
        event.attributes.insert(
            "tls_failure_host_rolling_count".to_string(),
            counters.host_rolling_failures.to_string(),
        );
        event.attributes.insert(
            "tls_failure_source_count".to_string(),
            counters.source_total_failures.to_string(),
        );
        event.attributes.insert(
            "tls_failure_reason_count".to_string(),
            counters.reason_total_failures.to_string(),
        );
        event.attributes.insert(
            "tls_failure_global_count".to_string(),
            counters.global_total_failures.to_string(),
        );
        event.attributes.insert(
            "tls_learning_decision".to_string(),
            learning_outcome.decision.as_str().to_string(),
        );
        event.attributes.insert(
            "tls_learning_reason_code".to_string(),
            learning_outcome.reason_code.to_string(),
        );
        event.attributes.insert(
            "tls_learning_host_count".to_string(),
            learning_outcome.host_applied_total.to_string(),
        );
        event.attributes.insert(
            "tls_learning_global_applied".to_string(),
            learning_outcome.global_applied_total.to_string(),
        );
        event.attributes.insert(
            "tls_learning_global_ignored".to_string(),
            learning_outcome.global_ignored_total.to_string(),
        );
    }
    engine.emit_event(event);
}

fn ingest_tls_learning_signal_with_audit<P, S>(
    engine: &MitmEngine<P, S>,
    tls_learning: &TlsLearningGuardrails,
    context: FlowContext,
    signal: TlsLearningSignal,
) -> TlsLearningOutcome
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let outcome = tls_learning.ingest(signal.clone());
    if outcome.decision == TlsLearningDecision::Ignored {
        emit_tls_learning_audit_event(engine, context, signal, outcome);
    }
    outcome
}

fn emit_tls_learning_audit_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    signal: TlsLearningSignal,
    outcome: TlsLearningOutcome,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::TlsLearningAudit, context);
    event.attributes.insert(
        "tls_learning_decision".to_string(),
        outcome.decision.as_str().to_string(),
    );
    event.attributes.insert(
        "tls_learning_reason_code".to_string(),
        outcome.reason_code.to_string(),
    );
    event.attributes.insert(
        "tls_learning_global_applied".to_string(),
        outcome.global_applied_total.to_string(),
    );
    event.attributes.insert(
        "tls_learning_global_ignored".to_string(),
        outcome.global_ignored_total.to_string(),
    );
    event
        .attributes
        .insert("signal_host".to_string(), signal.host);
    event
        .attributes
        .insert("signal_reason".to_string(), signal.failure_reason);
    event
        .attributes
        .insert("signal_source".to_string(), signal.failure_source);
    event
        .attributes
        .insert("signal_provider".to_string(), signal.provider);
    event
        .attributes
        .insert("signal_inferred".to_string(), signal.inferred.to_string());
    engine.emit_event(event);
}

fn emit_stream_closed<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    reason_code: CloseReasonCode,
    reason_detail: Option<String>,
    bytes_from_client: Option<u64>,
    bytes_from_server: Option<u64>,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::StreamClosed, context);
    event
        .attributes
        .insert("reason_code".to_string(), reason_code.as_str().to_string());
    if let Some(detail) = reason_detail {
        event.attributes.insert("reason_detail".to_string(), detail);
    }

    if let Some(value) = bytes_from_client {
        event
            .attributes
            .insert("bytes_from_client".to_string(), value.to_string());
    }
    if let Some(value) = bytes_from_server {
        event
            .attributes
            .insert("bytes_from_server".to_string(), value.to_string());
    }
    engine.emit_event(event);
}

fn emit_connect_parse_failed<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    parse_failure: ParseFailureCode,
    parse_detail: Option<String>,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    runtime_governor::mark_decoder_failure_global();
    let mut event = Event::new(EventType::ConnectParseFailed, context);
    event.attributes.insert(
        "parse_error_code".to_string(),
        parse_failure.as_str().to_string(),
    );
    if let Some(detail) = parse_detail {
        event
            .attributes
            .insert("parse_error_detail".to_string(), detail);
    }
    engine.emit_event(event);
}

fn unknown_context(flow_id: u64, client_addr: String) -> FlowContext {
    FlowContext {
        flow_id,
        client_addr,
        server_host: "<unknown>".to_string(),
        server_port: 0,
        protocol: ApplicationProtocol::Tunnel,
    }
}

fn tls_error_to_io_invalid_input(error: TlsConfigError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

fn tls_source_confidence(source: &str, provider: &str) -> &'static str {
    let source_lower = source.to_ascii_lowercase();
    let provider_lower = provider.to_ascii_lowercase();
    if source_lower.contains("hudsucker") || provider_lower.contains("hudsucker") {
        return "inferred";
    }
    if source_lower.contains("mitmproxy") || provider_lower.contains("mitmproxy") {
        return "authoritative";
    }
    "authoritative"
}
