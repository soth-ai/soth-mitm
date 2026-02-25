use std::sync::Arc;

use dashmap::{mapref::entry::Entry, DashMap};
use tokio::sync::mpsc;
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
    per_flow: DashMap<u64, FlowDispatcher>,
    queue_capacity: usize,
}

impl<H: InterceptHandler> FlowDispatchers<H> {
    pub(crate) fn new(
        handler: Arc<H>,
        callback_guard: Arc<HandlerCallbackGuard>,
        metrics_store: Arc<ProxyMetricsStore>,
        queue_capacity: usize,
    ) -> Self {
        Self {
            handler,
            callback_guard,
            metrics_store,
            per_flow: DashMap::new(),
            queue_capacity: queue_capacity.max(1),
        }
    }

    pub(crate) async fn enqueue_response(&self, flow_id: u64, response: RawResponse) {
        let sender = self.sender_for_flow(flow_id);
        if sender.send(DispatchWork::Response(response)).await.is_err() {
            self.metrics_store.record_dispatch_drop();
            tracing::warn!(
                flow_id,
                "dropped response dispatch work; flow worker closed"
            );
        }
    }

    pub(crate) async fn enqueue_stream_chunk(&self, flow_id: u64, chunk: StreamChunk) {
        let sender = self.sender_for_flow(flow_id);
        if sender.send(DispatchWork::StreamChunk(chunk)).await.is_err() {
            self.metrics_store.record_dispatch_drop();
            tracing::warn!(
                flow_id,
                "dropped stream-chunk dispatch work; flow worker closed"
            );
        }
    }

    pub(crate) async fn close_and_drain(&self, flow_id: u64) {
        let Some((_, dispatcher)) = self.per_flow.remove(&flow_id) else {
            return;
        };
        drop(dispatcher.sender);
        if let Err(error) = dispatcher.worker.await {
            self.metrics_store.record_dispatch_drop();
            tracing::warn!(flow_id, error = %error, "flow dispatcher worker join failed");
        }
    }

    fn sender_for_flow(&self, flow_id: u64) -> mpsc::Sender<DispatchWork> {
        match self.per_flow.entry(flow_id) {
            Entry::Occupied(existing) => existing.get().sender.clone(),
            Entry::Vacant(vacant) => {
                let (sender, receiver) = mpsc::channel(self.queue_capacity);
                let worker = spawn_flow_dispatch_worker(
                    Arc::clone(&self.handler),
                    Arc::clone(&self.callback_guard),
                    receiver,
                );
                vacant.insert(FlowDispatcher {
                    sender: sender.clone(),
                    worker,
                });
                sender
            }
        }
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
