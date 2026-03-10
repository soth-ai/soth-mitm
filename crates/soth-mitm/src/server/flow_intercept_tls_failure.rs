async fn fail_tls_and_close<P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    flow_hooks: &Arc<dyn FlowHooks>,
    tls_diagnostics: &Arc<TlsDiagnostics>,
    tls_learning: &Arc<TlsLearningGuardrails>,
    failure_context: FlowContext,
    tunnel_context: FlowContext,
    peer: &'static str,
    detail: String,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    flow_hooks
        .on_tls_failure(failure_context.clone(), detail.clone())
        .await;
    emit_tls_event_with_detail(
        engine,
        tls_diagnostics,
        tls_learning,
        EventType::TlsHandshakeFailed,
        failure_context,
        peer,
        detail.clone(),
    );
    emit_stream_closed(
        engine,
        tunnel_context,
        CloseReasonCode::TlsHandshakeFailed,
        Some(detail),
        None,
        None,
    );
    Ok(())
}
