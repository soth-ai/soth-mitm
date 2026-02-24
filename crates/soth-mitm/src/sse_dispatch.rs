use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use tokio::time::Instant;

use crate::handler::InterceptHandler;
use crate::types::{ConnectionInfo, InterceptedResponse};
use crate::ResponseAction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResponseDispatchOutcome {
    pub used_stream_chunks: bool,
    pub response_action: Option<ResponseAction>,
    pub chunk_outputs: Vec<Bytes>,
    pub first_chunk_delta: Option<Duration>,
}

pub(crate) async fn dispatch_response_with_streaming_policy<H, I>(
    handler: &H,
    response: &InterceptedResponse,
    connection: &ConnectionInfo,
    chunks: I,
) -> ResponseDispatchOutcome
where
    H: InterceptHandler,
    I: IntoIterator<Item = Bytes>,
{
    if is_sse_streaming_response(response) {
        let mut first_chunk_delta = None;
        let mut chunk_outputs = Vec::new();
        for chunk in chunks {
            let started = Instant::now();
            let transformed = handler.on_stream_chunk(&chunk, connection).await;
            if first_chunk_delta.is_none() {
                first_chunk_delta = Some(started.elapsed());
            }
            chunk_outputs.push(transformed);
        }
        return ResponseDispatchOutcome {
            used_stream_chunks: true,
            response_action: None,
            chunk_outputs,
            first_chunk_delta,
        };
    }

    let action = handler.on_response(response, connection).await;
    ResponseDispatchOutcome {
        used_stream_chunks: false,
        response_action: Some(action),
        chunk_outputs: Vec::new(),
        first_chunk_delta: None,
    }
}

fn is_sse_streaming_response(response: &InterceptedResponse) -> bool {
    response.is_streaming && has_sse_content_type(&response.headers)
}

fn has_sse_content_type(headers: &http::HeaderMap) -> bool {
    let Some(value) = headers.get(CONTENT_TYPE) else {
        return false;
    };
    let Ok(content_type) = value.to_str() else {
        return false;
    };
    content_type
        .split(';')
        .next()
        .map(str::trim)
        .map(|base| base.eq_ignore_ascii_case("text/event-stream"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue};
    use uuid::Uuid;

    use super::dispatch_response_with_streaming_policy;
    use crate::actions::{HandlerAction, ResponseAction};
    use crate::handler::InterceptHandler;
    use crate::types::{
        ConnectionInfo, ConnectionStats, InterceptedRequest, InterceptedResponse, ProcessInfo,
    };

    #[derive(Default)]
    struct CountingHandler {
        on_response_calls: AtomicU64,
        on_stream_chunk_calls: AtomicU64,
    }

    impl CountingHandler {
        fn on_response_calls(&self) -> u64 {
            self.on_response_calls.load(Ordering::Relaxed)
        }

        fn on_stream_chunk_calls(&self) -> u64 {
            self.on_stream_chunk_calls.load(Ordering::Relaxed)
        }
    }

    impl InterceptHandler for CountingHandler {
        async fn on_request(
            &self,
            _request: &InterceptedRequest,
            _connection: &ConnectionInfo,
        ) -> HandlerAction {
            HandlerAction::Forward
        }

        async fn on_response(
            &self,
            _response: &InterceptedResponse,
            _connection: &ConnectionInfo,
        ) -> ResponseAction {
            self.on_response_calls.fetch_add(1, Ordering::Relaxed);
            ResponseAction::Forward
        }

        async fn on_stream_chunk(&self, chunk: &Bytes, _connection: &ConnectionInfo) -> Bytes {
            self.on_stream_chunk_calls.fetch_add(1, Ordering::Relaxed);
            let mut out = chunk.to_vec();
            out.extend_from_slice(b"#");
            Bytes::from(out)
        }

        async fn on_connection_close(
            &self,
            _connection: &ConnectionInfo,
            _stats: &ConnectionStats,
        ) {
        }
    }

    #[tokio::test]
    async fn sse_skips_on_response_and_calls_on_stream_chunk() {
        let handler = Arc::new(CountingHandler::default());
        let response = sse_response();
        let connection = sample_connection();

        let outcome = dispatch_response_with_streaming_policy(
            handler.as_ref(),
            &response,
            &connection,
            vec![
                Bytes::from_static(b"data: hello\n\n"),
                Bytes::from_static(b"data: world\n\n"),
            ],
        )
        .await;

        assert!(outcome.used_stream_chunks);
        assert!(outcome.response_action.is_none());
        assert_eq!(outcome.chunk_outputs.len(), 2);
        assert_eq!(
            outcome.chunk_outputs[0],
            Bytes::from_static(b"data: hello\n\n#")
        );
        assert_eq!(handler.on_response_calls(), 0);
        assert_eq!(handler.on_stream_chunk_calls(), 2);
    }

    #[tokio::test]
    async fn sse_first_chunk_delta_budget() {
        let handler = Arc::new(CountingHandler::default());
        let response = sse_response();
        let connection = sample_connection();

        let outcome = dispatch_response_with_streaming_policy(
            handler.as_ref(),
            &response,
            &connection,
            vec![Bytes::from_static(b"data: hello\n\n")],
        )
        .await;

        let first_delta = outcome
            .first_chunk_delta
            .expect("expected first chunk delta");
        assert!(
            first_delta <= Duration::from_millis(50),
            "first SSE chunk callback exceeded budget: {first_delta:?}"
        );
    }

    fn sse_response() -> InterceptedResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("text/event-stream; charset=utf-8"),
        );
        InterceptedResponse {
            status: 200,
            headers,
            body: Bytes::new(),
            is_streaming: true,
        }
    }

    fn sample_connection() -> ConnectionInfo {
        ConnectionInfo {
            connection_id: Uuid::new_v4(),
            source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            source_port: 42000,
            destination_host: "api.example.com".to_string(),
            destination_port: 443,
            tls_fingerprint: None,
            alpn_protocol: Some("h2".to_string()),
            is_http2: true,
            process_info: Some(ProcessInfo {
                pid: 4242,
                process_name: "curl".to_string(),
                process_path: PathBuf::from("/usr/bin/curl"),
                bundle_id: None,
                code_signature: None,
                parent_pid: None,
                parent_name: None,
            }),
            connected_at: SystemTime::now(),
            request_count: 1,
        }
    }
}
