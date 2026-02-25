use std::future::Future;

use crate::{HandlerDecision, ProcessInfo, RawRequest, RawResponse, StreamChunk};
use uuid::Uuid;

pub trait InterceptHandler: Send + Sync + 'static {
    fn should_intercept_tls(&self, _host: &str, _process_info: Option<&ProcessInfo>) -> bool {
        true
    }

    fn on_tls_failure(&self, _host: &str, _error: &str) {}

    fn on_request(&self, _request: &RawRequest) -> impl Future<Output = HandlerDecision> + Send {
        async { HandlerDecision::Allow }
    }

    fn on_stream_chunk(&self, _chunk: &StreamChunk) -> impl Future<Output = ()> + Send {
        async {}
    }

    fn on_stream_end(&self, _connection_id: Uuid) -> impl Future<Output = ()> + Send {
        async {}
    }

    fn on_response(&self, _response: &RawResponse) -> impl Future<Output = ()> + Send {
        async {}
    }

    #[allow(dead_code)]
    fn on_connection_open(&self, _meta: &crate::ConnectionMeta) {}

    #[allow(dead_code)]
    fn on_connection_close(&self, _connection_id: Uuid) {}
}
