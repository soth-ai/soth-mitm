use crate::config::MitmConfig;
use crate::handler::InterceptHandler;
use crate::metrics::ProxyMetricsStore;
use crate::process::{PlatformProcessAttributor, ProcessLookupService};
use crate::runtime::connection_meta::{
    connection_meta_from_accept_context, lookup_connection_info_from_flow_context,
    policy_process_info_from_runtime, process_info_from_unix_client_addr,
    runtime_process_info_from_policy,
};
use crate::runtime::handler_guard::HandlerCallbackGuard;
use crate::types::{ConnectionMeta, FrameKind, RawRequest, RawResponse, StreamChunk};
use crate::HandlerDecision;
use bytes::Bytes;
use mitm_observe::FlowContext;
use mitm_sidecar::{
    FlowHooks, RawRequest as SidecarRawRequest, RawResponse as SidecarRawResponse, RequestDecision,
    StreamChunk as SidecarStreamChunk, StreamFrameKind,
};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;
#[derive(Debug)]
struct HandlerFlowHooks<H: InterceptHandler> {
    handler: Arc<H>,
    metrics_store: Arc<ProxyMetricsStore>,
    callback_guard: Arc<HandlerCallbackGuard>,
    process_lookup: Option<Arc<ProcessLookupService<PlatformProcessAttributor>>>,
    stream_sequences: Arc<Mutex<HashMap<u64, u64>>>,
    connection_meta_by_flow: Arc<Mutex<HashMap<u64, ConnectionMeta>>>,
}
impl<H: InterceptHandler> HandlerFlowHooks<H> {
    fn new(
        handler: Arc<H>,
        metrics_store: Arc<ProxyMetricsStore>,
        callback_guard: Arc<HandlerCallbackGuard>,
        process_lookup: Option<Arc<ProcessLookupService<PlatformProcessAttributor>>>,
    ) -> Self {
        Self {
            handler,
            metrics_store,
            callback_guard,
            process_lookup,
            stream_sequences: Arc::new(Mutex::new(HashMap::new())),
            connection_meta_by_flow: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
impl<H: InterceptHandler> FlowHooks for HandlerFlowHooks<H> {
    fn resolve_process_info(
        &self,
        context: FlowContext,
    ) -> Pin<Box<dyn Future<Output = Option<mitm_policy::ProcessInfo>> + Send>> {
        let process_lookup = self.process_lookup.clone();
        let metrics_store = Arc::clone(&self.metrics_store);
        Box::pin(async move {
            let Some(lookup) = process_lookup.as_ref() else {
                return None;
            };
            if let Some(uds_process_info) = process_info_from_unix_client_addr(&context.client_addr)
            {
                return Some(policy_process_info_from_runtime(&uds_process_info));
            }
            let result = lookup
                .resolve_with_status(&lookup_connection_info_from_flow_context(&context))
                .await;
            if result.timed_out {
                metrics_store.record_process_attribution_timeout();
                return None;
            }
            let Some(process_info) = result.process_info.as_ref() else {
                metrics_store.record_process_attribution_failure();
                return None;
            };
            Some(policy_process_info_from_runtime(process_info))
        })
    }
    fn on_connection_open(
        &self,
        context: FlowContext,
        process_info: Option<mitm_policy::ProcessInfo>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = Arc::clone(&self.handler);
        let callback_guard = Arc::clone(&self.callback_guard);
        let connection_meta_by_flow = Arc::clone(&self.connection_meta_by_flow);
        Box::pin(async move {
            let connection_meta = connection_meta_from_accept_context(
                &context,
                process_info.map(runtime_process_info_from_policy),
            );
            let mut guard = connection_meta_by_flow.lock().await;
            guard.insert(context.flow_id, connection_meta.clone());
            drop(guard);
            callback_guard.run_sync(Duration::ZERO, (), || {
                handler.on_connection_open(&connection_meta)
            });
        })
    }
    fn should_intercept_tls(
        &self,
        context: FlowContext,
        process_info: Option<mitm_policy::ProcessInfo>,
    ) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        let handler = Arc::clone(&self.handler);
        let callback_guard = Arc::clone(&self.callback_guard);
        Box::pin(async move {
            let process_info = process_info.map(runtime_process_info_from_policy);
            callback_guard.run_sync(Duration::ZERO, false, || {
                handler.should_intercept_tls(&context.server_host, process_info.as_ref())
            })
        })
    }
    fn on_tls_failure(
        &self,
        context: FlowContext,
        error: String,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = Arc::clone(&self.handler);
        let callback_guard = Arc::clone(&self.callback_guard);
        Box::pin(async move {
            callback_guard.run_sync(Duration::ZERO, (), || {
                handler.on_tls_failure(&context.server_host, &error)
            })
        })
    }
    fn on_request(
        &self,
        context: FlowContext,
        request: SidecarRawRequest,
    ) -> Pin<Box<dyn Future<Output = RequestDecision> + Send>> {
        let handler = Arc::clone(&self.handler);
        let callback_guard = Arc::clone(&self.callback_guard);
        let connection_meta_by_flow = Arc::clone(&self.connection_meta_by_flow);
        Box::pin(async move {
            let Some(connection_meta) =
                connection_meta_for_context(&context, &connection_meta_by_flow).await
            else {
                return RequestDecision::Block {
                    status: 500,
                    body: Bytes::from_static(b"missing ConnectionMeta"),
                };
            };
            let raw_request = RawRequest {
                method: request.method,
                path: request.path,
                headers: request.headers,
                body: request.body,
                connection_meta,
            };
            let decision = callback_guard
                .run_request(HandlerDecision::Allow, handler.on_request(&raw_request))
                .await;
            match decision {
                HandlerDecision::Allow => RequestDecision::Allow,
                HandlerDecision::Block { status, body } => RequestDecision::Block { status, body },
            }
        })
    }
    fn on_response(
        &self,
        context: FlowContext,
        response: SidecarRawResponse,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = Arc::clone(&self.handler);
        let callback_guard = Arc::clone(&self.callback_guard);
        let connection_meta_by_flow = Arc::clone(&self.connection_meta_by_flow);
        Box::pin(async move {
            let Some(connection_meta) =
                connection_meta_for_context(&context, &connection_meta_by_flow).await
            else {
                return;
            };
            let raw_response = RawResponse {
                status: response.status,
                headers: response.headers,
                body: response.body,
                connection_meta,
            };
            let handler = Arc::clone(&handler);
            let callback_guard = Arc::clone(&callback_guard);
            tokio::spawn(async move {
                callback_guard
                    .run_response((), handler.on_response(&raw_response))
                    .await;
            });
        })
    }
    fn on_stream_chunk(
        &self,
        context: FlowContext,
        chunk: SidecarStreamChunk,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = Arc::clone(&self.handler);
        let callback_guard = Arc::clone(&self.callback_guard);
        let stream_sequences = Arc::clone(&self.stream_sequences);
        Box::pin(async move {
            let Some(frame_kind) = map_stream_frame_kind(chunk.frame_kind) else {
                return;
            };
            let sequence = {
                let mut guard = stream_sequences.lock().await;
                let next = guard.entry(context.flow_id).or_insert(0);
                let value = *next;
                *next += 1;
                value
            };
            let translated = StreamChunk {
                connection_id: Uuid::from_u128(context.flow_id as u128),
                payload: chunk.payload,
                sequence,
                frame_kind,
            };
            let handler = Arc::clone(&handler);
            let callback_guard = Arc::clone(&callback_guard);
            tokio::spawn(async move {
                callback_guard
                    .run_response((), handler.on_stream_chunk(&translated))
                    .await;
            });
        })
    }
    fn on_stream_end(&self, context: FlowContext) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = Arc::clone(&self.handler);
        let callback_guard = Arc::clone(&self.callback_guard);
        let stream_sequences = Arc::clone(&self.stream_sequences);
        let connection_meta_by_flow = Arc::clone(&self.connection_meta_by_flow);
        let process_lookup = self.process_lookup.clone();
        Box::pin(async move {
            let mut guard = stream_sequences.lock().await;
            guard.remove(&context.flow_id);
            drop(guard);
            let mut connection_guard = connection_meta_by_flow.lock().await;
            connection_guard.remove(&context.flow_id);
            drop(connection_guard);
            if let Some(lookup) = process_lookup.as_ref() {
                lookup
                    .remove_connection(Uuid::from_u128(context.flow_id as u128))
                    .await;
            }
            let connection_id = Uuid::from_u128(context.flow_id as u128);
            callback_guard
                .run_response((), handler.on_stream_end(connection_id))
                .await;
            callback_guard.run_sync(Duration::ZERO, (), || {
                handler.on_connection_close(connection_id)
            });
        })
    }
}
pub(crate) fn build_handler_flow_hooks<H: InterceptHandler>(
    config: &MitmConfig,
    handler: Arc<H>,
    metrics_store: Arc<ProxyMetricsStore>,
) -> Arc<dyn FlowHooks> {
    let callback_guard = Arc::new(HandlerCallbackGuard::new(
        Duration::from_millis(config.handler.request_timeout_ms.max(1)),
        Duration::from_millis(config.handler.response_timeout_ms.max(1)),
        config.handler.recover_from_panics,
        Arc::clone(&metrics_store),
    ));
    let process_lookup = if config.process_attribution.enabled {
        Some(Arc::new(ProcessLookupService::new(
            Arc::new(PlatformProcessAttributor),
            Duration::from_millis(config.process_attribution.lookup_timeout_ms.max(1)),
        )))
    } else {
        None
    };
    Arc::new(HandlerFlowHooks::new(
        handler,
        metrics_store,
        callback_guard,
        process_lookup,
    ))
}
fn map_stream_frame_kind(kind: StreamFrameKind) -> Option<FrameKind> {
    match kind {
        StreamFrameKind::SseData => Some(FrameKind::SseData),
        StreamFrameKind::NdjsonLine => Some(FrameKind::NdjsonLine),
        StreamFrameKind::GrpcMessage => Some(FrameKind::GrpcMessage),
        StreamFrameKind::WebSocketText => Some(FrameKind::WebSocketText),
        StreamFrameKind::WebSocketBinary => Some(FrameKind::WebSocketBinary),
        StreamFrameKind::WebSocketClose => Some(FrameKind::WebSocketClose),
    }
}

async fn connection_meta_for_context(
    context: &FlowContext,
    connection_meta_by_flow: &Arc<Mutex<HashMap<u64, ConnectionMeta>>>,
) -> Option<ConnectionMeta> {
    let guard = connection_meta_by_flow.lock().await;
    let Some(connection_meta) = guard.get(&context.flow_id).cloned() else {
        debug_assert!(
            false,
            "connection {} missing ConnectionMeta in flow map",
            context.flow_id
        );
        eprintln!(
            "missing ConnectionMeta for flow_id={} host={} port={}",
            context.flow_id, context.server_host, context.server_port
        );
        return None;
    };
    Some(connection_meta)
}

#[cfg(test)]
#[path = "flow_hooks_tests.rs"]
mod tests;
