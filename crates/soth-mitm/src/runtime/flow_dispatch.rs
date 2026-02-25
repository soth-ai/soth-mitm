use std::sync::Arc;
use std::time::Duration;

use dashmap::{mapref::entry::Entry, DashMap};
use lru::LruCache;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::handler::InterceptHandler;
use crate::metrics::ProxyMetricsStore;
use crate::runtime::handler_guard::HandlerCallbackGuard;
use crate::types::{RawResponse, StreamChunk};

#[derive(Debug)]
enum DispatchWork {
    Response(RawResponse),
    StreamChunk(StreamChunk),
}

#[derive(Debug)]
struct FlowDispatcher {
    sender: mpsc::Sender<DispatchWork>,
    worker: JoinHandle<()>,
}

#[derive(Debug)]
pub(crate) struct FlowDispatchers<H: InterceptHandler> {
    handler: Arc<H>,
    callback_guard: Arc<HandlerCallbackGuard>,
    metrics_store: Arc<ProxyMetricsStore>,
    closed_flow_ids: Arc<Mutex<LruCache<u64, ()>>>,
    per_flow: DashMap<u64, FlowDispatcher>,
    queue_capacity: usize,
    queue_send_timeout: Duration,
    close_join_timeout: Duration,
}

impl<H: InterceptHandler> FlowDispatchers<H> {
    pub(crate) fn new(
        handler: Arc<H>,
        callback_guard: Arc<HandlerCallbackGuard>,
        metrics_store: Arc<ProxyMetricsStore>,
        closed_flow_ids: Arc<Mutex<LruCache<u64, ()>>>,
        queue_capacity: usize,
        queue_send_timeout: Duration,
        close_join_timeout: Duration,
    ) -> Self {
        Self {
            handler,
            callback_guard,
            metrics_store,
            closed_flow_ids,
            per_flow: DashMap::new(),
            queue_capacity: queue_capacity.max(1),
            queue_send_timeout: queue_send_timeout.max(Duration::from_millis(1)),
            close_join_timeout: close_join_timeout.max(Duration::from_millis(1)),
        }
    }

    pub(crate) async fn enqueue_response(&self, flow_id: u64, response: RawResponse) {
        self.enqueue(flow_id, DispatchWork::Response(response))
            .await;
    }

    pub(crate) async fn enqueue_stream_chunk(&self, flow_id: u64, chunk: StreamChunk) {
        self.enqueue(flow_id, DispatchWork::StreamChunk(chunk))
            .await;
    }

    pub(crate) async fn close_and_drain(&self, flow_id: u64) {
        let Some((_, mut dispatcher)) = self.per_flow.remove(&flow_id) else {
            return;
        };
        drop(dispatcher.sender);
        match tokio::time::timeout(self.close_join_timeout, &mut dispatcher.worker).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.metrics_store.record_dispatch_drop();
                tracing::warn!(flow_id, error = %error, "flow dispatcher worker join failed");
            }
            Err(_) => {
                dispatcher.worker.abort();
                let _ =
                    tokio::time::timeout(Duration::from_millis(100), &mut dispatcher.worker).await;
                self.metrics_store.record_dispatch_drop();
                tracing::warn!(
                    flow_id,
                    timeout_ms = self.close_join_timeout.as_millis(),
                    "flow dispatcher worker join timed out; worker aborted"
                );
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn shutdown_all(&self) {
        let flow_ids: Vec<u64> = self.per_flow.iter().map(|entry| *entry.key()).collect();
        for flow_id in flow_ids {
            self.close_and_drain(flow_id).await;
        }
    }

    pub(crate) fn abort_all_now(&self) {
        let flow_ids: Vec<u64> = self.per_flow.iter().map(|entry| *entry.key()).collect();
        for flow_id in flow_ids {
            if let Some((_, dispatcher)) = self.per_flow.remove(&flow_id) {
                dispatcher.worker.abort();
            }
        }
    }

    async fn enqueue(&self, flow_id: u64, work: DispatchWork) {
        let Some(sender) = self.sender_for_flow(flow_id).await else {
            self.metrics_store.record_dispatch_drop();
            tracing::warn!(flow_id, "dropped dispatch work for finalized flow");
            return;
        };
        match tokio::time::timeout(self.queue_send_timeout, sender.send(work)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                self.metrics_store.record_dispatch_drop();
                tracing::warn!(flow_id, "dropped dispatch work; flow worker closed");
            }
            Err(_) => {
                self.metrics_store.record_dispatch_drop();
                tracing::warn!(
                    flow_id,
                    timeout_ms = self.queue_send_timeout.as_millis(),
                    "dispatch queue send timed out; dropping work item"
                );
            }
        }
    }

    async fn sender_for_flow(&self, flow_id: u64) -> Option<mpsc::Sender<DispatchWork>> {
        let mut closed = self.closed_flow_ids.lock().await;
        if closed.get(&flow_id).is_some() {
            return None;
        }

        if let Some(existing) = self.per_flow.get(&flow_id) {
            return Some(existing.sender.clone());
        }

        let (sender, receiver) = mpsc::channel(self.queue_capacity);
        let worker = spawn_flow_dispatch_worker(
            Arc::clone(&self.handler),
            Arc::clone(&self.callback_guard),
            receiver,
        );
        match self.per_flow.entry(flow_id) {
            Entry::Occupied(existing) => {
                worker.abort();
                Some(existing.get().sender.clone())
            }
            Entry::Vacant(vacant) => {
                vacant.insert(FlowDispatcher {
                    sender: sender.clone(),
                    worker,
                });
                Some(sender)
            }
        }
    }
}

impl<H: InterceptHandler> Drop for FlowDispatchers<H> {
    fn drop(&mut self) {
        self.abort_all_now();
    }
}

fn spawn_flow_dispatch_worker<H: InterceptHandler>(
    handler: Arc<H>,
    callback_guard: Arc<HandlerCallbackGuard>,
    mut receiver: mpsc::Receiver<DispatchWork>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(work) = receiver.recv().await {
            match work {
                DispatchWork::Response(response) => {
                    let handler = Arc::clone(&handler);
                    callback_guard
                        .run_response((), async move { handler.on_response(&response).await })
                        .await;
                }
                DispatchWork::StreamChunk(chunk) => {
                    let handler = Arc::clone(&handler);
                    callback_guard
                        .run_response((), async move { handler.on_stream_chunk(&chunk).await })
                        .await;
                }
            }
        }
    })
}
