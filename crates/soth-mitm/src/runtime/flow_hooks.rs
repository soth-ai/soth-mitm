use crate::config::MitmConfig;
use crate::handler::InterceptHandler;
use crate::metrics::ProxyMetricsStore;
use crate::process::{PlatformProcessAttributor, ProcessLookupService};
use crate::runtime::connection_id::connection_id_for_flow_id;
use crate::runtime::connection_meta::{
    connection_meta_from_accept_context, lookup_connection_info_from_flow_context,
    policy_process_info_from_runtime, process_info_from_unix_client_addr,
    runtime_process_info_from_policy, tls_info_from_flow_context,
};
use crate::runtime::flow_dispatch::FlowDispatchers;
use crate::runtime::handler_guard::HandlerCallbackGuard;
use crate::types::{ConnectionMeta, FrameKind, RawRequest, RawResponse, StreamChunk};
use crate::HandlerDecision;
use bytes::Bytes;
use dashmap::DashMap;
use lru::LruCache;
use mitm_observe::FlowContext;
use mitm_sidecar::{
    FlowHooks, RawRequest as SidecarRawRequest, RawResponse as SidecarRawResponse, RequestDecision,
    StreamChunk as SidecarStreamChunk, StreamFrameKind,
};
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
#[derive(Debug)]
struct HandlerFlowHooks<H: InterceptHandler> {
    handler: Arc<H>,
    metrics_store: Arc<ProxyMetricsStore>,
    callback_guard: Arc<HandlerCallbackGuard>,
    process_lookup: Option<Arc<ProcessLookupService<PlatformProcessAttributor>>>,
    flow_dispatchers: Arc<FlowDispatchers<H>>,
    stream_sequences: Arc<DashMap<u64, u64>>,
    connection_meta_by_flow: Arc<DashMap<u64, ConnectionMeta>>,
    closed_flow_ids: Arc<Mutex<LruCache<u64, ()>>>,
}
impl<H: InterceptHandler> HandlerFlowHooks<H> {
    fn new(
        handler: Arc<H>,
        metrics_store: Arc<ProxyMetricsStore>,
        callback_guard: Arc<HandlerCallbackGuard>,
        process_lookup: Option<Arc<ProcessLookupService<PlatformProcessAttributor>>>,
    ) -> Self {
        let flow_dispatchers = Arc::new(FlowDispatchers::new(
            Arc::clone(&handler),
            Arc::clone(&callback_guard),
            256,
        ));
        Self {
            handler,
            metrics_store,
            callback_guard,
            process_lookup,
            flow_dispatchers,
            stream_sequences: Arc::new(DashMap::new()),
            connection_meta_by_flow: Arc::new(DashMap::new()),
            closed_flow_ids: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(16_384).expect("closed flow cache capacity must be non-zero"),
            ))),
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
        let closed_flow_ids = Arc::clone(&self.closed_flow_ids);
        Box::pin(async move {
            {
                let mut closed = closed_flow_ids.lock().await;
                let _ = closed.pop(&context.flow_id);
            }
            let connection_meta = connection_meta_from_accept_context(
                &context,
                process_info.map(runtime_process_info_from_policy),
            );
            connection_meta_by_flow.insert(context.flow_id, connection_meta.clone());
            callback_guard.run_sync((), || handler.on_connection_open(&connection_meta));
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
            callback_guard.run_sync(false, || {
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
            callback_guard.run_sync((), || handler.on_tls_failure(&context.server_host, &error))
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
            let handler = Arc::clone(&handler);
            let decision = callback_guard
                .run_request(HandlerDecision::Allow, async move {
                    handler.on_request(&raw_request).await
                })
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
        let connection_meta_by_flow = Arc::clone(&self.connection_meta_by_flow);
        let flow_dispatchers = Arc::clone(&self.flow_dispatchers);
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
            flow_dispatchers
                .enqueue_response(context.flow_id, raw_response)
                .await;
        })
    }
    fn on_stream_chunk(
        &self,
        context: FlowContext,
        chunk: SidecarStreamChunk,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let flow_dispatchers = Arc::clone(&self.flow_dispatchers);
        let stream_sequences = Arc::clone(&self.stream_sequences);
        Box::pin(async move {
            let Some(frame_kind) = map_stream_frame_kind(chunk.frame_kind) else {
                return;
            };
            let sequence = {
                let mut next = stream_sequences.entry(context.flow_id).or_insert(0);
                let value = *next;
                *next += 1;
                value
            };
            let translated = StreamChunk {
                connection_id: connection_id_for_flow_id(context.flow_id),
                payload: chunk.payload,
                sequence,
                frame_kind,
            };
            flow_dispatchers
                .enqueue_stream_chunk(context.flow_id, translated)
                .await;
        })
    }
    fn on_stream_end(&self, context: FlowContext) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = Arc::clone(&self.handler);
        let callback_guard = Arc::clone(&self.callback_guard);
        let flow_dispatchers = Arc::clone(&self.flow_dispatchers);
        let stream_sequences = Arc::clone(&self.stream_sequences);
        let connection_meta_by_flow = Arc::clone(&self.connection_meta_by_flow);
        let closed_flow_ids = Arc::clone(&self.closed_flow_ids);
        let process_lookup = self.process_lookup.clone();
        Box::pin(async move {
            let should_finalize = {
                let mut closed = closed_flow_ids.lock().await;
                if closed.get(&context.flow_id).is_some() {
                    false
                } else {
                    closed.put(context.flow_id, ());
                    true
                }
            };
            if !should_finalize {
                return;
            }

            flow_dispatchers.close_and_drain(context.flow_id).await;

            stream_sequences.remove(&context.flow_id);
            connection_meta_by_flow.remove(&context.flow_id);
            if let Some(lookup) = process_lookup.as_ref() {
                lookup
                    .remove_connection(connection_id_for_flow_id(context.flow_id))
                    .await;
            }
            let connection_id = connection_id_for_flow_id(context.flow_id);
            let handler_for_end = Arc::clone(&handler);
            callback_guard
                .run_response((), async move {
                    handler_for_end.on_stream_end(connection_id).await
                })
                .await;
            let handler_for_close = Arc::clone(&handler);
            callback_guard.run_sync((), || handler_for_close.on_connection_close(connection_id));
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
    connection_meta_by_flow: &Arc<DashMap<u64, ConnectionMeta>>,
) -> Option<ConnectionMeta> {
    let Some(connection_meta) = connection_meta_by_flow
        .get(&context.flow_id)
        .map(|value| value.clone())
    else {
        debug_assert!(
            false,
            "connection {} missing ConnectionMeta in flow map",
            context.flow_id
        );
        tracing::error!(
            flow_id = context.flow_id,
            host = %context.server_host,
            port = context.server_port,
            "missing ConnectionMeta in flow map"
        );
        return None;
    };
    let mut enriched = connection_meta;
    if enriched.tls_info.is_none() {
        enriched.tls_info = tls_info_from_flow_context(context);
    }
    Some(enriched)
}

#[cfg(test)]
#[path = "flow_hooks_tests.rs"]
mod tests;
