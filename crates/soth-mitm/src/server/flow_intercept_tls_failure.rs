use super::close_codes::CloseReasonCode;
use super::event_emitters::{emit_stream_closed, emit_tls_event_with_detail};
use super::flow_hooks::FlowHooks;
use super::tls_diagnostics::TlsDiagnostics;
use super::tls_learning::TlsLearningGuardrails;
use crate::engine::MitmEngine;
use crate::observe::{EventConsumer, EventType, FlowContext};
use crate::policy::PolicyEngine;
use std::io;
use std::sync::Arc;

pub(crate) async fn fail_tls_and_close<P, S>(
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
