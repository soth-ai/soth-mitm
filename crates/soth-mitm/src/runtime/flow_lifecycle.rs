use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use lru::LruCache;
use tokio::sync::Mutex;

use crate::handler::InterceptHandler;
use crate::metrics::ProxyMetricsStore;
use crate::process::{PlatformProcessAttributor, ProcessLookupService};
use crate::runtime::connection_id::connection_id_for_flow_id;
use crate::runtime::flow_dispatch::FlowDispatchers;
use crate::runtime::handler_guard::HandlerCallbackGuard;
use crate::types::ConnectionMeta;

#[derive(Debug)]
pub(super) struct FlowStateContext<H: InterceptHandler> {
    pub(super) metrics_store: Arc<ProxyMetricsStore>,
    pub(super) closed_flow_ids: Arc<Mutex<LruCache<u64, ()>>>,
    pub(super) flow_dispatchers: Arc<FlowDispatchers<H>>,
    pub(super) stream_sequences: Arc<DashMap<u64, u64>>,
    pub(super) connection_meta_by_flow: Arc<DashMap<u64, Arc<ConnectionMeta>>>,
    pub(super) flow_last_touched: Arc<DashMap<u64, Instant>>,
    pub(super) tls_intercepted_flow_ids: Arc<DashMap<u64, ()>>,
    pub(super) process_lookup: Option<Arc<ProcessLookupService<PlatformProcessAttributor>>>,
    pub(super) handler: Arc<H>,
    pub(super) callback_guard: Arc<HandlerCallbackGuard>,
}

pub(super) async fn schedule_stale_flow_reap<H: InterceptHandler>(
    flow_state: Arc<FlowStateContext<H>>,
    stale_flow_ttl: Duration,
    stale_reap_interval: Duration,
    stale_reap_max_batch: usize,
    last_stale_reap_at: Arc<Mutex<Instant>>,
) {
    let now = Instant::now();
    let should_reap = {
        let mut last = last_stale_reap_at.lock().await;
        if now.duration_since(*last) < stale_reap_interval {
            false
        } else {
            *last = now;
            true
        }
    };
    if !should_reap {
        return;
    }

    tokio::spawn(async move {
        reap_stale_flows(flow_state, stale_flow_ttl, stale_reap_max_batch).await;
    });
}

async fn reap_stale_flows<H: InterceptHandler>(
    flow_state: Arc<FlowStateContext<H>>,
    stale_flow_ttl: Duration,
    stale_reap_max_batch: usize,
) {
    let now = Instant::now();
    let stale_flow_ids: Vec<u64> = flow_state
        .flow_last_touched
        .iter()
        .filter_map(|entry| {
            if now.duration_since(*entry.value()) >= stale_flow_ttl {
                Some(*entry.key())
            } else {
                None
            }
        })
        .take(stale_reap_max_batch.max(1))
        .collect();

    for flow_id in stale_flow_ids {
        tracing::warn!(
            flow_id,
            "reaping stale flow state without explicit stream_end"
        );
        flow_state.metrics_store.record_stale_flow_reap();
        finalize_flow(flow_id, Arc::clone(&flow_state)).await;
    }
}

pub(super) async fn finalize_flow<H: InterceptHandler>(
    flow_id: u64,
    flow_state: Arc<FlowStateContext<H>>,
) {
    let should_finalize = {
        let mut closed = flow_state.closed_flow_ids.lock().await;
        if closed.get(&flow_id).is_some() {
            false
        } else {
            if let Some((evicted_flow_id, _)) = closed.push(flow_id, ()) {
                flow_state.metrics_store.record_closed_flow_id_eviction();
                tracing::debug!(
                    flow_id,
                    evicted_flow_id,
                    "closed-flow LRU evicted tombstone entry"
                );
            }
            true
        }
    };
    if !should_finalize {
        return;
    }

    flow_state.flow_dispatchers.close_and_drain(flow_id).await;
    flow_state.stream_sequences.remove(&flow_id);
    flow_state.connection_meta_by_flow.remove(&flow_id);
    flow_state.flow_last_touched.remove(&flow_id);
    flow_state.tls_intercepted_flow_ids.remove(&flow_id);

    let connection_id = connection_id_for_flow_id(flow_id);
    if let Some(lookup) = flow_state.process_lookup.as_ref() {
        lookup.remove_connection(connection_id).await;
    }

    let handler_for_end = Arc::clone(&flow_state.handler);
    flow_state
        .callback_guard
        .run_response((), async move {
            handler_for_end.on_stream_end(connection_id).await
        })
        .await;
    let handler_for_close = Arc::clone(&flow_state.handler);
    flow_state
        .callback_guard
        .run_lifecycle((), move || {
            handler_for_close.on_connection_close(connection_id)
        })
        .await;
}
