use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use lru::LruCache;
use tokio::sync::Mutex;

use crate::handler::InterceptHandler;
use crate::process::{PlatformProcessAttributor, ProcessLookupService};
use crate::runtime::connection_id::connection_id_for_flow_id;
use crate::runtime::flow_dispatch::FlowDispatchers;
use crate::runtime::handler_guard::HandlerCallbackGuard;
use crate::types::ConnectionMeta;

pub(super) async fn reap_stale_flows<H: InterceptHandler>(
    stale_flow_ttl: Duration,
    stale_reap_interval: Duration,
    last_stale_reap_at: Arc<Mutex<Instant>>,
    flow_last_touched: Arc<DashMap<u64, Instant>>,
    closed_flow_ids: Arc<Mutex<LruCache<u64, ()>>>,
    flow_dispatchers: Arc<FlowDispatchers<H>>,
    stream_sequences: Arc<DashMap<u64, u64>>,
    connection_meta_by_flow: Arc<DashMap<u64, Arc<ConnectionMeta>>>,
    process_lookup: Option<Arc<ProcessLookupService<PlatformProcessAttributor>>>,
    handler: Arc<H>,
    callback_guard: Arc<HandlerCallbackGuard>,
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

    let stale_flow_ids: Vec<u64> = flow_last_touched
        .iter()
        .filter_map(|entry| {
            if now.duration_since(*entry.value()) >= stale_flow_ttl {
                Some(*entry.key())
            } else {
                None
            }
        })
        .collect();

    for flow_id in stale_flow_ids {
        tracing::warn!(
            flow_id,
            "reaping stale flow state without explicit stream_end"
        );
        finalize_flow(
            flow_id,
            Arc::clone(&closed_flow_ids),
            Arc::clone(&flow_dispatchers),
            Arc::clone(&stream_sequences),
            Arc::clone(&connection_meta_by_flow),
            Arc::clone(&flow_last_touched),
            process_lookup.clone(),
            Arc::clone(&handler),
            Arc::clone(&callback_guard),
        )
        .await;
    }
}

pub(super) async fn finalize_flow<H: InterceptHandler>(
    flow_id: u64,
    closed_flow_ids: Arc<Mutex<LruCache<u64, ()>>>,
    flow_dispatchers: Arc<FlowDispatchers<H>>,
    stream_sequences: Arc<DashMap<u64, u64>>,
    connection_meta_by_flow: Arc<DashMap<u64, Arc<ConnectionMeta>>>,
    flow_last_touched: Arc<DashMap<u64, Instant>>,
    process_lookup: Option<Arc<ProcessLookupService<PlatformProcessAttributor>>>,
    handler: Arc<H>,
    callback_guard: Arc<HandlerCallbackGuard>,
) {
    let should_finalize = {
        let mut closed = closed_flow_ids.lock().await;
        if closed.get(&flow_id).is_some() {
            false
        } else {
            closed.put(flow_id, ());
            true
        }
    };
    if !should_finalize {
        return;
    }

    flow_dispatchers.close_and_drain(flow_id).await;
    stream_sequences.remove(&flow_id);
    connection_meta_by_flow.remove(&flow_id);
    flow_last_touched.remove(&flow_id);
    if let Some(lookup) = process_lookup.as_ref() {
        lookup
            .remove_connection(connection_id_for_flow_id(flow_id))
            .await;
    }

    let connection_id = connection_id_for_flow_id(flow_id);
    let handler_for_end = Arc::clone(&handler);
    callback_guard
        .run_response((), async move {
            handler_for_end.on_stream_end(connection_id).await
        })
        .await;
    let handler_for_close = Arc::clone(&handler);
    callback_guard
        .run_sync((), move || {
            handler_for_close.on_connection_close(connection_id)
        })
        .await;
}
