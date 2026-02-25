use crate::{HandlerDecision, RawRequest, RawResponse, StreamChunk};
use uuid::Uuid;

pub trait InterceptHandler: Send + Sync + 'static {
    fn should_intercept_tls(&self, _host: &str) -> bool {
        true
    }

    fn on_tls_failure(&self, _host: &str, _error: &str) {}

    fn on_request(&self, _request: &RawRequest) -> HandlerDecision {
        HandlerDecision::Allow
    }

    fn on_stream_chunk(&self, _chunk: &StreamChunk) {}

    fn on_stream_end(&self, _connection_id: Uuid) {}

    fn on_response(&self, _response: &RawResponse) {}

    #[allow(dead_code)]
    fn on_connection_open(&self, _connection_id: Uuid) {}

    #[allow(dead_code)]
    fn on_connection_close(&self, _connection_id: Uuid) {}
}
