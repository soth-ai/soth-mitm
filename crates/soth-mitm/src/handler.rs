use std::future::Future;

use crate::{HandlerDecision, ProcessInfo, RawRequest, RawResponse, StreamChunk};
use uuid::Uuid;

/// Trait for intercepting and inspecting proxy traffic.
///
/// Implement this trait to receive callbacks for requests, responses,
/// streaming frames, and connection lifecycle events. All methods have
/// default no-op implementations so you only override what you need.
pub trait InterceptHandler: Send + Sync + 'static {
    fn should_intercept_tls(&self, _host: &str, _process_info: Option<&ProcessInfo>) -> bool {
        true
    }

    fn on_tls_failure(&self, _host: &str, _error: &str) {}

    fn on_request(&self, _request: &RawRequest) -> impl Future<Output = HandlerDecision> + Send {
        async { HandlerDecision::Allow }
    }

    fn handles_local_requests(&self) -> bool {
        false
    }

    /// Called for HTTP/1 forward-proxy requests whose target matches the proxy listener itself.
    ///
    /// Return `Some(response)` to serve the request locally. Return `None` to keep
    /// the proxy's default self-target loop handling.
    fn on_local_request(
        &self,
        _request: &RawRequest,
    ) -> impl Future<Output = Option<RawResponse>> + Send {
        async { None }
    }

    /// Called when a WebSocket upgrade completes (server sent 101).
    ///
    /// The `response` carries the 101 status and upgrade headers (empty body).
    /// Fires after `on_request` and before the first `on_stream_chunk`.
    /// Ordering is guaranteed by the per-flow dispatch queue.
    fn on_websocket_start(&self, _response: &RawResponse) -> impl Future<Output = ()> + Send {
        async {}
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

    /// Called exactly once when the underlying connection is torn down.
    ///
    /// This fires *after* `on_stream_end` and is the correct place for
    /// connection-scoped cleanup (session unbinding, pending state removal).
    /// For HTTP/2 multiplexed connections, `on_stream_end` fires per-stream
    /// while `on_connection_close` fires once for the connection.
    fn on_connection_close(&self, _connection_id: Uuid) {}
}
