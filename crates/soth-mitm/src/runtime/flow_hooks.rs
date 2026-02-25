use crate::config::MitmConfig;
use crate::handler::InterceptHandler;
use crate::metrics::ProxyMetricsStore;
use crate::process::{PlatformProcessAttributor, ProcessCachePath, ProcessLookupService};
use crate::runtime::connection_id::connection_id_for_flow_id;
use crate::runtime::connection_meta::{
    connection_meta_from_accept_context, lookup_connection_info_from_flow_context,
    policy_process_info_from_runtime, process_info_from_unix_client_addr,
    runtime_process_info_from_policy,
};
use crate::runtime::flow_dispatch::FlowDispatchers;
use crate::runtime::flow_lifecycle::{finalize_flow, schedule_stale_flow_reap, FlowStateContext};
use crate::runtime::handler_guard::HandlerCallbackGuard;
use crate::types::{RawRequest, RawResponse, StreamChunk};
use crate::HandlerDecision;
use bytes::Bytes;
use dashmap::{DashMap, DashSet};
use lru::LruCache;
use mitm_observe::FlowContext;
use mitm_sidecar::{
    FlowHooks, RawRequest as SidecarRawRequest, RawResponse as SidecarRawResponse, RequestDecision,
    StreamChunk as SidecarStreamChunk,
};
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

mod translate;
use self::translate::{connection_meta_for_context, map_stream_frame_kind};

#[derive(Debug)]
struct HandlerFlowHooks<H: InterceptHandler> {
    flow_state: Arc<FlowStateContext<H>>,
    stale_flow_ttl: Duration,
    stale_reap_interval: Duration,
    stale_reap_max_batch: usize,
    last_stale_reap_at: Arc<Mutex<Instant>>,
}

impl<H: InterceptHandler> HandlerFlowHooks<H> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        handler: Arc<H>,
        metrics_store: Arc<ProxyMetricsStore>,
        callback_guard: Arc<HandlerCallbackGuard>,
        process_lookup: Option<Arc<ProcessLookupService<PlatformProcessAttributor>>>,
        flow_dispatch_queue_capacity: usize,
        closed_flow_lru_capacity: usize,
        stale_flow_ttl: Duration,
        stale_reap_max_batch: usize,
        dispatch_queue_send_timeout: Duration,
        dispatch_close_join_timeout: Duration,
    ) -> Self {
        let closed_flow_ids = Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(closed_flow_lru_capacity.max(1))
                .expect("closed flow cache capacity must be non-zero"),
        )));
        let closed_flow_live = Arc::new(DashSet::new());
        let flow_dispatchers = Arc::new(FlowDispatchers::new(
            Arc::clone(&handler),
            Arc::clone(&callback_guard),
            Arc::clone(&metrics_store),
            Arc::clone(&closed_flow_live),
            flow_dispatch_queue_capacity,
            dispatch_queue_send_timeout,
            dispatch_close_join_timeout,
        ));
        let flow_state = Arc::new(FlowStateContext {
            metrics_store,
            closed_flow_ids,
            closed_flow_live,
            flow_dispatchers,
            stream_sequences: Arc::new(DashMap::new()),
            connection_meta_by_flow: Arc::new(DashMap::new()),
            flow_last_touched: Arc::new(DashMap::new()),
            tls_intercepted_flow_ids: Arc::new(DashMap::new()),
            process_lookup,
            handler,
            callback_guard,
        });
        let stale_reap_interval = (stale_flow_ttl / 4).max(Duration::from_secs(15));
        Self {
            flow_state,
            stale_flow_ttl,
            stale_reap_interval,
            stale_reap_max_batch: stale_reap_max_batch.max(1),
            last_stale_reap_at: Arc::new(Mutex::new(Instant::now())),
        }
    }
}

impl<H: InterceptHandler> FlowHooks for HandlerFlowHooks<H> {
    fn resolve_process_info(
        &self,
        context: FlowContext,
    ) -> Pin<Box<dyn Future<Output = Option<mitm_policy::ProcessInfo>> + Send>> {
        let process_lookup = self.flow_state.process_lookup.clone();
        let metrics_store = Arc::clone(&self.flow_state.metrics_store);
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
            match result.cache_path {
                ProcessCachePath::ConnectionHit => {
                    metrics_store.record_process_cache_connection_hit()
                }
                ProcessCachePath::IdentityHit => metrics_store.record_process_cache_identity_hit(),
                ProcessCachePath::Miss => metrics_store.record_process_cache_miss(),
            }
            if result.pid_reuse_detected {
                metrics_store.record_process_pid_reuse_detected();
            }
            for _ in 0..result.cache_evictions {
                metrics_store.record_process_cache_eviction();
            }
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
        let flow_state = Arc::clone(&self.flow_state);
        let stale_flow_ttl = self.stale_flow_ttl;
        let stale_reap_interval = self.stale_reap_interval;
        let stale_reap_max_batch = self.stale_reap_max_batch;
        let last_stale_reap_at = Arc::clone(&self.last_stale_reap_at);
        Box::pin(async move {
            {
                let mut closed = flow_state.closed_flow_ids.lock().await;
                let _ = closed.pop(&context.flow_id);
            }
            flow_state.closed_flow_live.remove(&context.flow_id);
            flow_state.tls_intercepted_flow_ids.remove(&context.flow_id);

            let connection_meta = connection_meta_from_accept_context(
                &context,
                process_info.map(runtime_process_info_from_policy),
            );
            let connection_meta = Arc::new(connection_meta);
            flow_state
                .connection_meta_by_flow
                .insert(context.flow_id, Arc::clone(&connection_meta));
            flow_state
                .flow_last_touched
                .insert(context.flow_id, Instant::now());

            schedule_stale_flow_reap(
                Arc::clone(&flow_state),
                stale_flow_ttl,
                stale_reap_interval,
                stale_reap_max_batch,
                Arc::clone(&last_stale_reap_at),
            )
            .await;

            let handler = Arc::clone(&flow_state.handler);
            flow_state
                .callback_guard
                .run_lifecycle((), move || handler.on_connection_open(&connection_meta))
                .await;
        })
    }

    fn should_intercept_tls(
        &self,
        context: FlowContext,
        process_info: Option<mitm_policy::ProcessInfo>,
    ) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        let flow_state = Arc::clone(&self.flow_state);
        Box::pin(async move {
            let process_info = process_info.map(runtime_process_info_from_policy);
            let handler = Arc::clone(&flow_state.handler);
            let should_intercept = flow_state
                .callback_guard
                .run_sync(false, move || {
                    handler.should_intercept_tls(&context.server_host, process_info.as_ref())
                })
                .await;
            if should_intercept {
                flow_state
                    .tls_intercepted_flow_ids
                    .insert(context.flow_id, ());
            } else {
                flow_state.tls_intercepted_flow_ids.remove(&context.flow_id);
            }
            should_intercept
        })
    }

    fn on_tls_failure(
        &self,
        context: FlowContext,
        error: String,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let flow_state = Arc::clone(&self.flow_state);
        Box::pin(async move {
            let handler = Arc::clone(&flow_state.handler);
            flow_state
                .callback_guard
                .run_sync((), move || {
                    handler.on_tls_failure(&context.server_host, &error)
                })
                .await
        })
    }

    fn on_request(
        &self,
        context: FlowContext,
        request: SidecarRawRequest,
    ) -> Pin<Box<dyn Future<Output = RequestDecision> + Send>> {
        let flow_state = Arc::clone(&self.flow_state);
        Box::pin(async move {
            flow_state
                .flow_last_touched
                .insert(context.flow_id, Instant::now());
            let Some(connection_meta) = connection_meta_for_context(
                &context,
                &flow_state.connection_meta_by_flow,
                &flow_state.closed_flow_live,
                &flow_state.tls_intercepted_flow_ids,
            )
            .await
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
                connection_meta: Arc::clone(&connection_meta),
            };
            let handler = Arc::clone(&flow_state.handler);
            let decision = flow_state
                .callback_guard
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
        let flow_state = Arc::clone(&self.flow_state);
        Box::pin(async move {
            flow_state
                .flow_last_touched
                .insert(context.flow_id, Instant::now());
            let Some(connection_meta) = connection_meta_for_context(
                &context,
                &flow_state.connection_meta_by_flow,
                &flow_state.closed_flow_live,
                &flow_state.tls_intercepted_flow_ids,
            )
            .await
            else {
                return;
            };
            let raw_response = RawResponse {
                status: response.status,
                headers: response.headers,
                body: response.body,
                connection_meta,
            };
            flow_state
                .flow_dispatchers
                .enqueue_response(context.flow_id, raw_response)
                .await;
        })
    }

    fn on_stream_chunk(
        &self,
        context: FlowContext,
        chunk: SidecarStreamChunk,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let flow_state = Arc::clone(&self.flow_state);
        Box::pin(async move {
            flow_state
                .flow_last_touched
                .insert(context.flow_id, Instant::now());
            let Some(frame_kind) = map_stream_frame_kind(chunk.frame_kind) else {
                return;
            };
            let sequence = {
                let mut next = flow_state
                    .stream_sequences
                    .entry(context.flow_id)
                    .or_insert(0);
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
            flow_state
                .flow_dispatchers
                .enqueue_stream_chunk(context.flow_id, translated)
                .await;
        })
    }

    fn on_stream_end(&self, context: FlowContext) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let flow_state = Arc::clone(&self.flow_state);
        Box::pin(async move {
            finalize_flow(context.flow_id, Arc::clone(&flow_state)).await;
        })
    }
}

pub(crate) fn build_handler_flow_hooks<H: InterceptHandler>(
    config: &MitmConfig,
    handler: Arc<H>,
    metrics_store: Arc<ProxyMetricsStore>,
) -> Arc<dyn FlowHooks> {
    let expected_live_flows = (config.connection_pool.max_connections_per_host as usize)
        .saturating_mul(config.interception.destinations.len().max(1));
    let flow_dispatch_queue_capacity = expected_live_flows.clamp(128, 1024);
    let closed_flow_lru_capacity = expected_live_flows.saturating_mul(8).clamp(4096, 65_536);
    let stale_flow_ttl = Duration::from_millis(
        config
            .connection_pool
            .idle_timeout_ms
            .saturating_mul(3)
            .max(30_000),
    );
    let stale_reap_max_batch = expected_live_flows.clamp(16, 256);
    let request_timeout = Duration::from_millis(config.handler.request_timeout_ms.max(1));
    let response_timeout = Duration::from_millis(config.handler.response_timeout_ms.max(1));
    let callback_guard = Arc::new(HandlerCallbackGuard::new(
        request_timeout,
        response_timeout,
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
        flow_dispatch_queue_capacity,
        closed_flow_lru_capacity,
        stale_flow_ttl,
        stale_reap_max_batch,
        response_timeout,
        response_timeout.saturating_mul(2),
    ))
}

#[cfg(test)]
mod tests;
