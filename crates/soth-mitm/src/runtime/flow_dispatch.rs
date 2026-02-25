use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::handler::InterceptHandler;
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
    per_flow: Mutex<HashMap<u64, FlowDispatcher>>,
    queue_capacity: usize,
}

impl<H: InterceptHandler> FlowDispatchers<H> {
    pub(crate) fn new(
        handler: Arc<H>,
        callback_guard: Arc<HandlerCallbackGuard>,
        queue_capacity: usize,
    ) -> Self {
        Self {
            handler,
            callback_guard,
            per_flow: Mutex::new(HashMap::new()),
            queue_capacity: queue_capacity.max(1),
        }
    }

    pub(crate) async fn enqueue_response(&self, flow_id: u64, response: RawResponse) {
        let sender = self.sender_for_flow(flow_id).await;
        let _ = sender.send(DispatchWork::Response(response)).await;
    }

    pub(crate) async fn enqueue_stream_chunk(&self, flow_id: u64, chunk: StreamChunk) {
        let sender = self.sender_for_flow(flow_id).await;
        let _ = sender.send(DispatchWork::StreamChunk(chunk)).await;
    }

    pub(crate) async fn close_and_drain(&self, flow_id: u64) {
        let dispatcher = {
            let mut guard = self.per_flow.lock().await;
            guard.remove(&flow_id)
        };
        let Some(dispatcher) = dispatcher else {
            return;
        };
        drop(dispatcher.sender);
        let _ = dispatcher.worker.await;
    }

    async fn sender_for_flow(&self, flow_id: u64) -> mpsc::Sender<DispatchWork> {
        let mut guard = self.per_flow.lock().await;
        if let Some(existing) = guard.get(&flow_id) {
            return existing.sender.clone();
        }

        let (sender, receiver) = mpsc::channel(self.queue_capacity);
        let worker = spawn_flow_dispatch_worker(
            Arc::clone(&self.handler),
            Arc::clone(&self.callback_guard),
            receiver,
        );
        guard.insert(
            flow_id,
            FlowDispatcher {
                sender: sender.clone(),
                worker,
            },
        );
        sender
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
                    callback_guard
                        .run_response((), handler.on_response(&response))
                        .await;
                }
                DispatchWork::StreamChunk(chunk) => {
                    callback_guard
                        .run_response((), handler.on_stream_chunk(&chunk))
                        .await;
                }
            }
        }
    })
}
