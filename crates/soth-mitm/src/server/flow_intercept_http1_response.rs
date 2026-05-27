use super::flow_hook_http_helpers::{
    build_handler_header_map, is_grpc_response, is_ndjson_response, mark_body_truncated,
    normalize_response_body_for_handler, relay_http_body_with_capture,
};
use super::flow_hooks::{FlowHooks, RawResponse};
use super::flow_intercept_http1::emit_http1_relay_error_close;
use super::grpc_stream_observer::GrpcStreamObserver;
use super::http2_stream_hook_dispatch::{
    dispatch_grpc_chunks_from_buffer, dispatch_ndjson_chunks_from_buffer,
    dispatch_sse_chunks_from_buffer,
};
use super::http_body_relay::{relay_http_body, HttpBodyObserver};
use super::http_head_parser::is_sse_response;
use super::ndjson_stream_observer::NdjsonStreamObserver;
use super::runtime_governor;
use super::sse_stream_observer::SseStreamObserver;
use super::stream_content_decoder::StreamingContentDecoder;
use super::{BufferedConn, HttpResponseHead};
use crate::engine::MitmEngine;
use crate::observe::{EventConsumer, EventType, FlowContext};
use crate::policy::PolicyEngine;
use crate::protocol::ApplicationProtocol;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Http1StreamingKind {
    Sse,
    Ndjson,
    Grpc,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_http1_response_with_hooks<P, S, D, U>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    tunnel_context: &FlowContext,
    http_context: &FlowContext,
    response: &HttpResponseHead,
    upstream_conn: &mut BufferedConn<U>,
    downstream_stream: &mut D,
    max_http_head_bytes: usize,
    bytes_from_client: u64,
    bytes_from_server: u64,
) -> Result<u64, ()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let max_handler_body = engine.config.max_flow_body_buffer_bytes.max(1);
    if is_sse_response(response) {
        let sse_context = FlowContext {
            protocol: ApplicationProtocol::Sse,
            ..tunnel_context.clone()
        };
        if let Some(encoding) = response_content_encoding(response) {
            if let Ok(Some(decoder)) = StreamingContentDecoder::from_header_value(
                encoding,
                engine.config.max_flow_decoder_buffer_bytes,
            ) {
                let sse_observer = SseStreamObserver::new(
                    Arc::clone(&engine),
                    sse_context.clone(),
                    Arc::clone(&runtime_governor),
                    Arc::clone(&flow_hooks),
                    engine.config.max_flow_decoder_buffer_bytes,
                );
                let mut decoded_observer = DecodedSseStreamObserver::new(
                    decoder,
                    Arc::clone(&runtime_governor),
                    sse_observer,
                );
                let response_body_result = relay_http_body(
                    &engine,
                    http_context,
                    EventType::ResponseBodyChunk,
                    upstream_conn,
                    downstream_stream,
                    response.body_mode,
                    max_http_head_bytes,
                    &runtime_governor,
                    &mut decoded_observer,
                )
                .await;
                return match response_body_result {
                    Ok(bytes) => Ok(bytes),
                    Err(error) => {
                        emit_http1_relay_error_close(
                            &engine,
                            http_context,
                            "encoded SSE response body relay failed",
                            &error,
                            bytes_from_client,
                            bytes_from_server,
                        );
                        Err(())
                    }
                };
            }
            return relay_encoded_streaming_http1_response_with_hooks(
                Arc::clone(&engine),
                Arc::clone(&runtime_governor),
                Arc::clone(&flow_hooks),
                http_context,
                response,
                upstream_conn,
                downstream_stream,
                max_http_head_bytes,
                max_handler_body,
                bytes_from_client,
                bytes_from_server,
                sse_context,
                Http1StreamingKind::Sse,
            )
            .await;
        }
        let mut sse_observer = SseStreamObserver::new(
            Arc::clone(&engine),
            sse_context,
            Arc::clone(&runtime_governor),
            Arc::clone(&flow_hooks),
            engine.config.max_flow_decoder_buffer_bytes,
        );
        let response_body_result = relay_http_body(
            &engine,
            http_context,
            EventType::ResponseBodyChunk,
            upstream_conn,
            downstream_stream,
            response.body_mode,
            max_http_head_bytes,
            &runtime_governor,
            &mut sse_observer,
        )
        .await;
        return match response_body_result {
            Ok(bytes) => Ok(bytes),
            Err(error) => {
                emit_http1_relay_error_close(
                    &engine,
                    http_context,
                    "response body relay failed",
                    &error,
                    bytes_from_client,
                    bytes_from_server,
                );
                Err(())
            }
        };
    }

    if is_ndjson_response(response) {
        let ndjson_context = FlowContext {
            protocol: ApplicationProtocol::Http1,
            ..tunnel_context.clone()
        };
        if response_has_content_encoding(response) {
            return relay_encoded_streaming_http1_response_with_hooks(
                Arc::clone(&engine),
                Arc::clone(&runtime_governor),
                Arc::clone(&flow_hooks),
                http_context,
                response,
                upstream_conn,
                downstream_stream,
                max_http_head_bytes,
                max_handler_body,
                bytes_from_client,
                bytes_from_server,
                ndjson_context,
                Http1StreamingKind::Ndjson,
            )
            .await;
        }
        let mut ndjson_observer = NdjsonStreamObserver::<P, S>::new(
            ndjson_context,
            Arc::clone(&runtime_governor),
            Arc::clone(&flow_hooks),
            engine.config.max_flow_decoder_buffer_bytes,
        );
        let response_body_result = relay_http_body(
            &engine,
            http_context,
            EventType::ResponseBodyChunk,
            upstream_conn,
            downstream_stream,
            response.body_mode,
            max_http_head_bytes,
            &runtime_governor,
            &mut ndjson_observer,
        )
        .await;
        return match response_body_result {
            Ok(bytes) => Ok(bytes),
            Err(error) => {
                emit_http1_relay_error_close(
                    &engine,
                    http_context,
                    "response body relay failed",
                    &error,
                    bytes_from_client,
                    bytes_from_server,
                );
                Err(())
            }
        };
    }

    if is_grpc_response(response) {
        let grpc_context = FlowContext {
            protocol: ApplicationProtocol::Http1,
            ..tunnel_context.clone()
        };
        if response_has_content_encoding(response) {
            return relay_encoded_streaming_http1_response_with_hooks(
                Arc::clone(&engine),
                Arc::clone(&runtime_governor),
                Arc::clone(&flow_hooks),
                http_context,
                response,
                upstream_conn,
                downstream_stream,
                max_http_head_bytes,
                max_handler_body,
                bytes_from_client,
                bytes_from_server,
                grpc_context,
                Http1StreamingKind::Grpc,
            )
            .await;
        }
        let mut grpc_observer = GrpcStreamObserver::<P, S>::new(
            grpc_context,
            Arc::clone(&runtime_governor),
            Arc::clone(&flow_hooks),
            engine.config.max_flow_decoder_buffer_bytes,
        );
        let response_body_result = relay_http_body(
            &engine,
            http_context,
            EventType::ResponseBodyChunk,
            upstream_conn,
            downstream_stream,
            response.body_mode,
            max_http_head_bytes,
            &runtime_governor,
            &mut grpc_observer,
        )
        .await;
        return match response_body_result {
            Ok(bytes) => Ok(bytes),
            Err(error) => {
                emit_http1_relay_error_close(
                    &engine,
                    http_context,
                    "response body relay failed",
                    &error,
                    bytes_from_client,
                    bytes_from_server,
                );
                Err(())
            }
        };
    }

    let (response_body_bytes, response_body, response_body_truncated) =
        match relay_http_body_with_capture(
            &engine,
            http_context,
            EventType::ResponseBodyChunk,
            upstream_conn,
            downstream_stream,
            response.body_mode,
            max_http_head_bytes,
            &runtime_governor,
            max_handler_body,
        )
        .await
        {
            Ok(result) => result,
            Err(error) => {
                emit_http1_relay_error_close(
                    &engine,
                    http_context,
                    "response body relay failed",
                    &error,
                    bytes_from_client,
                    bytes_from_server,
                );
                return Err(());
            }
        };

    let mut handler_response_headers = build_handler_header_map(&response.headers);
    if response_body_truncated {
        mark_body_truncated(&mut handler_response_headers);
    }
    let handler_body = if response_body_truncated {
        response_body.slice(..max_handler_body.min(response_body.len()))
    } else {
        response_body
    };
    let normalized_body =
        normalize_response_body_for_handler(&mut handler_response_headers, handler_body);
    flow_hooks
        .on_response(
            http_context.clone(),
            RawResponse {
                status: response.status_code,
                headers: handler_response_headers,
                body: normalized_body,
            },
        )
        .await;
    Ok(response_body_bytes)
}

pub(crate) fn response_has_content_encoding(response: &HttpResponseHead) -> bool {
    response_content_encoding(response).is_some()
}

pub(crate) fn response_content_encoding(response: &HttpResponseHead) -> Option<&str> {
    response
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-encoding"))
        .map(|header| header.value.as_str())
}

struct DecodedSseStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    decoder: StreamingContentDecoder,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    sse_observer: SseStreamObserver<P, S>,
    // Once the decoder errors (corrupt gzip/br/zstd from upstream, or the
    // per-chunk budget is exceeded) we stop attempting further decode but
    // MUST keep returning Ok so the relay continues forwarding the encoded
    // bytes to the client. The encoded body has already been written to the
    // wire before on_chunk runs; failing here would tear down the response
    // mid-flight on attacker-controlled input.
    decoder_failed: bool,
}

impl<P, S> DecodedSseStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    fn new(
        decoder: StreamingContentDecoder,
        runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
        sse_observer: SseStreamObserver<P, S>,
    ) -> Self {
        Self {
            decoder,
            runtime_governor,
            sse_observer,
            decoder_failed: false,
        }
    }
}

impl<P, S> HttpBodyObserver for DecodedSseStreamObserver<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    fn on_chunk<'a>(
        &'a mut self,
        chunk: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if self.decoder_failed {
                return Ok(());
            }
            let decoded = match self.decoder.decode_chunk(chunk) {
                Ok(decoded) => decoded,
                Err(error) => {
                    self.runtime_governor.mark_decoder_failure();
                    tracing::debug!(error = %error, "encoded SSE response decode failed; observation disabled, forwarding unchanged");
                    self.decoder_failed = true;
                    return Ok(());
                }
            };
            if !decoded.is_empty() {
                if let Err(error) = self.sse_observer.on_chunk(&decoded).await {
                    tracing::debug!(error = %error, "encoded SSE observer dispatch failed; observation disabled, forwarding unchanged");
                    self.decoder_failed = true;
                }
            }
            Ok(())
        })
    }

    fn on_complete<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if self.decoder_failed {
                return Ok(());
            }
            let decoded = match self.decoder.finish() {
                Ok(decoded) => decoded,
                Err(error) => {
                    self.runtime_governor.mark_decoder_failure();
                    tracing::debug!(error = %error, "encoded SSE response decoder finish failed; observation disabled");
                    return Ok(());
                }
            };
            if !decoded.is_empty() {
                if let Err(error) = self.sse_observer.on_chunk(&decoded).await {
                    tracing::debug!(error = %error, "encoded SSE observer final dispatch failed; observation disabled");
                    return Ok(());
                }
            }
            if let Err(error) = self.sse_observer.on_complete().await {
                tracing::debug!(error = %error, "encoded SSE observer on_complete failed; ignored to preserve forwarding");
            }
            Ok(())
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_encoded_streaming_http1_response_with_hooks<P, S, D, U>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    http_context: &FlowContext,
    response: &HttpResponseHead,
    upstream_conn: &mut BufferedConn<U>,
    downstream_stream: &mut D,
    max_http_head_bytes: usize,
    max_handler_body: usize,
    bytes_from_client: u64,
    bytes_from_server: u64,
    stream_context: FlowContext,
    stream_kind: Http1StreamingKind,
) -> Result<u64, ()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (response_body_bytes, response_body, response_body_truncated) =
        match relay_http_body_with_capture(
            &engine,
            http_context,
            EventType::ResponseBodyChunk,
            upstream_conn,
            downstream_stream,
            response.body_mode,
            max_http_head_bytes,
            &runtime_governor,
            max_handler_body,
        )
        .await
        {
            Ok(result) => result,
            Err(error) => {
                emit_http1_relay_error_close(
                    &engine,
                    http_context,
                    "response body relay failed",
                    &error,
                    bytes_from_client,
                    bytes_from_server,
                );
                return Err(());
            }
        };

    let mut handler_response_headers = build_handler_header_map(&response.headers);
    if response_body_truncated {
        mark_body_truncated(&mut handler_response_headers);
    }
    let handler_body = if response_body_truncated {
        response_body.slice(..max_handler_body.min(response_body.len()))
    } else {
        response_body
    };
    let normalized_body =
        normalize_response_body_for_handler(&mut handler_response_headers, handler_body);
    if handler_response_headers.contains_key("x-soth-encoding-error") {
        flow_hooks
            .on_response(
                http_context.clone(),
                RawResponse {
                    status: response.status_code,
                    headers: handler_response_headers,
                    body: normalized_body,
                },
            )
            .await;
        return Ok(response_body_bytes);
    }

    match stream_kind {
        Http1StreamingKind::Sse => {
            dispatch_sse_chunks_from_buffer(&flow_hooks, stream_context, normalized_body).await;
        }
        Http1StreamingKind::Ndjson => {
            dispatch_ndjson_chunks_from_buffer(&flow_hooks, stream_context, normalized_body).await;
        }
        Http1StreamingKind::Grpc => {
            dispatch_grpc_chunks_from_buffer(&flow_hooks, stream_context, normalized_body).await;
        }
    }
    Ok(response_body_bytes)
}
