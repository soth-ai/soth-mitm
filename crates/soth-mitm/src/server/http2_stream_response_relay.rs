use super::flow_hook_http_helpers::strip_trailer_forbidden_and_transport_headers;
use super::flow_hooks::{FlowHooks, StreamChunk};
use super::http2_relay_support::h2_error_to_io;
use super::http2_stream_hook_dispatch::{
    is_grpc_h2_response, is_ndjson_h2_response, is_sse_h2_response, H2CapturedBody,
};
use super::http2_stream_relay_body::send_h2_data_with_backpressure;
use super::io_timeouts::with_h2_body_idle_timeout;
use super::runtime_governor;
use super::stream_content_decoder::StreamingContentDecoder;
use crate::observe::FlowContext;
use crate::types::FrameKind;
use std::io;
use std::sync::Arc;

pub(crate) enum H2ResponseStreamHookDispatcher {
    Sse(H2SseDispatchState),
    EncodedSse {
        decoder: StreamingContentDecoder,
        state: H2SseDispatchState,
    },
    Ndjson {
        pending: Vec<u8>,
        sequence: u64,
        stream_ended: bool,
    },
    Grpc {
        pending: Vec<u8>,
        sequence: u64,
        stream_ended: bool,
    },
}

pub(crate) struct H2SseDispatchState {
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    parser: crate::protocol::SseParser,
    max_event_bytes: Option<usize>,
    sequence: u64,
    stream_ended: bool,
}

impl H2SseDispatchState {
    fn unbounded(runtime_governor: Arc<runtime_governor::RuntimeGovernor>) -> Self {
        Self {
            runtime_governor,
            parser: crate::protocol::SseParser::new(),
            max_event_bytes: None,
            sequence: 0,
            stream_ended: false,
        }
    }

    fn bounded(
        runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
        max_event_bytes: usize,
    ) -> Self {
        Self {
            runtime_governor,
            parser: crate::protocol::SseParser::new(),
            max_event_bytes: Some(max_event_bytes),
            sequence: 0,
            stream_ended: false,
        }
    }

    async fn on_chunk(
        &mut self,
        flow_hooks: &Arc<dyn FlowHooks>,
        stream_context: &FlowContext,
        chunk: &[u8],
    ) -> io::Result<()> {
        if self.stream_ended {
            return Ok(());
        }
        if let Some(max_event_bytes) = self.max_event_bytes {
            if chunk.len() > max_event_bytes {
                self.runtime_governor.mark_decoder_failure();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "SSE chunk exceeded decoder budget (len={}, limit={})",
                        chunk.len(),
                        max_event_bytes
                    ),
                ));
            }
        }
        let events = self.parser.push_bytes(chunk);
        for event in events {
            self.emit_event(flow_hooks, stream_context, event).await?;
            if self.stream_ended {
                break;
            }
        }
        Ok(())
    }

    async fn finish(
        &mut self,
        flow_hooks: &Arc<dyn FlowHooks>,
        stream_context: &FlowContext,
    ) -> io::Result<()> {
        if self.stream_ended {
            return Ok(());
        }
        if let Some(event) = self.parser.finish() {
            self.emit_event(flow_hooks, stream_context, event).await?;
            if self.stream_ended {
                return Ok(());
            }
        }
        flow_hooks.on_stream_end(stream_context.clone()).await;
        self.stream_ended = true;
        Ok(())
    }

    async fn emit_event(
        &mut self,
        flow_hooks: &Arc<dyn FlowHooks>,
        stream_context: &FlowContext,
        event: crate::protocol::SseEvent,
    ) -> io::Result<()> {
        if let Some(max_event_bytes) = self.max_event_bytes {
            if event.data.len() > max_event_bytes {
                self.runtime_governor.mark_decoder_failure();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "SSE event exceeded decoder budget (len={}, limit={})",
                        event.data.len(),
                        max_event_bytes
                    ),
                ));
            }
        }
        let done = event.data == "[DONE]";
        flow_hooks
            .on_stream_chunk(
                stream_context.clone(),
                StreamChunk {
                    payload: bytes::Bytes::from(event.data),
                    sequence: self.sequence,
                    frame_kind: FrameKind::SseData,
                    direction: None,
                },
            )
            .await;
        self.sequence += 1;
        if done {
            flow_hooks.on_stream_end(stream_context.clone()).await;
            self.stream_ended = true;
        }
        Ok(())
    }
}

impl H2ResponseStreamHookDispatcher {
    pub(crate) async fn on_chunk(
        &mut self,
        flow_hooks: &Arc<dyn FlowHooks>,
        stream_context: &FlowContext,
        chunk: &[u8],
    ) -> io::Result<()> {
        match self {
            Self::Sse(state) => {
                state.on_chunk(flow_hooks, stream_context, chunk).await?;
            }
            Self::EncodedSse { decoder, state } => {
                if state.stream_ended {
                    return Ok(());
                }
                // Encoded-SSE observation runs AFTER the response data has been
                // sent downstream (see relay_h2_response_body_with_incremental_forwarding).
                // Decoder errors or budget-exceeded conditions originate in
                // attacker-controlled upstream bytes; propagating them would
                // reset the HTTP/2 stream mid-response. Swallow them, mark the
                // governor, and disable further observation on this stream.
                match decoder.decode_chunk(chunk) {
                    Ok(decoded) if !decoded.is_empty() => {
                        if let Err(error) =
                            state.on_chunk(flow_hooks, stream_context, &decoded).await
                        {
                            tracing::debug!(error = %error, "HTTP/2 encoded SSE state dispatch failed; observation disabled, forwarding unchanged");
                            state.stream_ended = true;
                        }
                    }
                    Ok(_) => {}
                    Err(error) => {
                        state.runtime_governor.mark_decoder_failure();
                        tracing::debug!(error = %error, "HTTP/2 encoded SSE response decode failed; observation disabled, forwarding unchanged");
                        state.stream_ended = true;
                    }
                }
            }
            Self::Ndjson {
                pending,
                sequence,
                stream_ended,
            } => {
                if *stream_ended {
                    return Ok(());
                }
                pending.extend_from_slice(chunk);
                while let Some(index) = pending.iter().position(|byte| *byte == b'\n') {
                    let mut line = pending.drain(..=index).collect::<Vec<u8>>();
                    let _ = line.pop();
                    if line.is_empty() {
                        continue;
                    }
                    let payload = if line.last() == Some(&b'\r') {
                        bytes::Bytes::copy_from_slice(&line[..line.len() - 1])
                    } else {
                        bytes::Bytes::copy_from_slice(&line)
                    };
                    flow_hooks
                        .on_stream_chunk(
                            stream_context.clone(),
                            StreamChunk {
                                payload,
                                sequence: *sequence,
                                frame_kind: FrameKind::NdjsonLine,
                                direction: None,
                            },
                        )
                        .await;
                    *sequence += 1;
                }
            }
            Self::Grpc {
                pending,
                sequence,
                stream_ended,
            } => {
                if *stream_ended {
                    return Ok(());
                }
                pending.extend_from_slice(chunk);
                while pending.len() >= 5 {
                    let frame_len =
                        u32::from_be_bytes([pending[1], pending[2], pending[3], pending[4]])
                            as usize;
                    if pending.len() < 5 + frame_len {
                        break;
                    }
                    let payload = bytes::Bytes::copy_from_slice(&pending[5..5 + frame_len]);
                    pending.drain(..5 + frame_len);
                    flow_hooks
                        .on_stream_chunk(
                            stream_context.clone(),
                            StreamChunk {
                                payload,
                                sequence: *sequence,
                                frame_kind: FrameKind::GrpcMessage,
                                direction: None,
                            },
                        )
                        .await;
                    *sequence += 1;
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn finish(
        &mut self,
        flow_hooks: &Arc<dyn FlowHooks>,
        stream_context: &FlowContext,
    ) -> io::Result<()> {
        match self {
            Self::Sse(state) => {
                state.finish(flow_hooks, stream_context).await?;
            }
            Self::EncodedSse { decoder, state } => {
                if state.stream_ended {
                    return Ok(());
                }
                // Same rationale as on_chunk: end-of-stream decode errors must
                // not propagate; the response is already fully forwarded.
                match decoder.finish() {
                    Ok(decoded) if !decoded.is_empty() => {
                        if let Err(error) =
                            state.on_chunk(flow_hooks, stream_context, &decoded).await
                        {
                            tracing::debug!(error = %error, "HTTP/2 encoded SSE final state dispatch failed; observation disabled");
                            state.stream_ended = true;
                            return Ok(());
                        }
                    }
                    Ok(_) => {}
                    Err(error) => {
                        state.runtime_governor.mark_decoder_failure();
                        tracing::debug!(error = %error, "HTTP/2 encoded SSE response decoder finish failed; observation disabled");
                        state.stream_ended = true;
                        return Ok(());
                    }
                }
                if let Err(error) = state.finish(flow_hooks, stream_context).await {
                    tracing::debug!(error = %error, "HTTP/2 encoded SSE state.finish failed; observation disabled");
                    state.stream_ended = true;
                }
            }
            Self::Ndjson {
                pending,
                sequence,
                stream_ended,
            } => {
                if *stream_ended {
                    return Ok(());
                }
                if !pending.is_empty() {
                    let line = std::mem::take(pending);
                    let payload = if line.last() == Some(&b'\r') {
                        bytes::Bytes::copy_from_slice(&line[..line.len() - 1])
                    } else {
                        bytes::Bytes::copy_from_slice(&line)
                    };
                    flow_hooks
                        .on_stream_chunk(
                            stream_context.clone(),
                            StreamChunk {
                                payload,
                                sequence: *sequence,
                                frame_kind: FrameKind::NdjsonLine,
                                direction: None,
                            },
                        )
                        .await;
                }
                flow_hooks.on_stream_end(stream_context.clone()).await;
                *stream_ended = true;
            }
            Self::Grpc { stream_ended, .. } => {
                if *stream_ended {
                    return Ok(());
                }
                flow_hooks.on_stream_end(stream_context.clone()).await;
                *stream_ended = true;
            }
        }
        Ok(())
    }
}

pub(crate) fn h2_response_stream_hook_dispatcher(
    response_parts: &http::response::Parts,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    max_decoder_buffer_bytes: usize,
) -> Option<H2ResponseStreamHookDispatcher> {
    if is_sse_h2_response(response_parts) {
        if let Some(encoding) = h2_response_content_encoding(response_parts) {
            match StreamingContentDecoder::from_header_value(encoding, max_decoder_buffer_bytes) {
                Ok(Some(decoder)) => {
                    return Some(H2ResponseStreamHookDispatcher::EncodedSse {
                        decoder,
                        state: H2SseDispatchState::bounded(
                            runtime_governor,
                            max_decoder_buffer_bytes,
                        ),
                    });
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::debug!(
                        error = %error,
                        encoding,
                        "falling back to plain HTTP/2 SSE observation after decoder setup failed"
                    );
                }
            }
        }
        return Some(H2ResponseStreamHookDispatcher::Sse(
            H2SseDispatchState::unbounded(runtime_governor),
        ));
    }
    if is_ndjson_h2_response(response_parts) {
        return Some(H2ResponseStreamHookDispatcher::Ndjson {
            pending: Vec::new(),
            sequence: 0,
            stream_ended: false,
        });
    }
    if is_grpc_h2_response(response_parts) {
        return Some(H2ResponseStreamHookDispatcher::Grpc {
            pending: Vec::new(),
            sequence: 0,
            stream_ended: false,
        });
    }
    None
}

fn h2_response_content_encoding(response_parts: &http::response::Parts) -> Option<&str> {
    response_parts
        .headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
}

pub(crate) struct H2ResponseStreamRelayOutcome {
    pub(crate) captured: H2CapturedBody,
    pub(crate) observed_trailers: Option<http::HeaderMap>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_h2_response_body_with_incremental_forwarding(
    upstream_response_body: &mut h2::RecvStream,
    downstream_response_stream: &mut h2::SendStream<bytes::Bytes>,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: &FlowContext,
    stream_dispatcher: &mut Option<H2ResponseStreamHookDispatcher>,
    max_handler_body: usize,
    h2_response_overflow_strict: bool,
) -> io::Result<H2ResponseStreamRelayOutcome> {
    let mut total_forwarded = 0_u64;
    let mut captured = Vec::new();
    let mut body_truncated = false;

    while let Some(next_data) = with_h2_body_idle_timeout("http2_response_body_next_frame", async {
        Ok(upstream_response_body.data().await)
    })
    .await?
    {
        let data =
            next_data.map_err(|error| h2_error_to_io("reading HTTP/2 body frame failed", error))?;
        let frame_len = data.len();
        if frame_len == 0 {
            if upstream_response_body.is_end_stream() {
                break;
            }
            continue;
        }
        total_forwarded += frame_len as u64;
        let mut truncated_now = false;
        if !body_truncated {
            let remaining = max_handler_body.saturating_sub(captured.len());
            if remaining >= frame_len {
                captured.extend_from_slice(data.as_ref());
            } else {
                if remaining > 0 {
                    captured.extend_from_slice(&data.as_ref()[..remaining]);
                }
                body_truncated = true;
                truncated_now = true;
            }
        }
        if truncated_now && h2_response_overflow_strict {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream response body exceeded flow body budget (strict overflow mode)",
            ));
        }

        let hook_chunk = stream_dispatcher.as_ref().map(|_| data.clone());
        // Release upstream receive capacity immediately so the next frame can arrive
        // while we forward the current one downstream (pipelining instead of stop-and-wait).
        upstream_response_body
            .flow_control()
            .release_capacity(frame_len)
            .map_err(|error| h2_error_to_io("releasing HTTP/2 receive capacity failed", error))?;
        send_h2_data_with_backpressure(downstream_response_stream, runtime_governor, data, false)
            .await?;
        if let (Some(dispatcher), Some(chunk)) = (stream_dispatcher.as_mut(), hook_chunk.as_ref()) {
            dispatcher
                .on_chunk(flow_hooks, stream_context, chunk.as_ref())
                .await?;
        }
        if upstream_response_body.is_end_stream() {
            break;
        }
    }

    let mut trailers = if upstream_response_body.is_end_stream() {
        None
    } else {
        with_h2_body_idle_timeout("http2_response_body_trailers_wait", async {
            upstream_response_body
                .trailers()
                .await
                .map_err(|error| h2_error_to_io("reading HTTP/2 trailers failed", error))
        })
        .await?
    };

    if let Some(candidate) = trailers.as_mut() {
        strip_trailer_forbidden_and_transport_headers(candidate);
        if candidate.is_empty() {
            trailers = None;
        }
    }

    let observed_trailers = if let Some(trailers_to_send) = trailers.clone() {
        downstream_response_stream
            .send_trailers(trailers_to_send.clone())
            .map_err(|error| h2_error_to_io("sending HTTP/2 trailers failed", error))?;
        Some(trailers_to_send)
    } else {
        send_h2_data_with_backpressure(
            downstream_response_stream,
            runtime_governor,
            bytes::Bytes::new(),
            true,
        )
        .await?;
        None
    };

    if let Some(dispatcher) = stream_dispatcher.as_mut() {
        dispatcher.finish(flow_hooks, stream_context).await?;
    }

    Ok(H2ResponseStreamRelayOutcome {
        captured: H2CapturedBody {
            bytes: bytes::Bytes::from(captured),
            bytes_forwarded: total_forwarded,
            trailers,
            body_truncated,
        },
        observed_trailers,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        h2_response_stream_hook_dispatcher, runtime_governor, H2ResponseStreamHookDispatcher,
    };
    use std::sync::Arc;

    fn runtime_governor() -> Arc<runtime_governor::RuntimeGovernor> {
        Arc::new(runtime_governor::RuntimeGovernor::new(
            runtime_governor::RuntimeBudgetConfig::default(),
        ))
    }

    fn sse_response_parts(content_encoding: Option<&str>) -> http::response::Parts {
        let mut builder = http::Response::builder()
            .status(200)
            .header("content-type", "text/event-stream");
        if let Some(content_encoding) = content_encoding {
            builder = builder.header("content-encoding", content_encoding);
        }
        builder.body(()).unwrap().into_parts().0
    }

    #[test]
    fn h2_sse_unsupported_encoding_falls_back_to_plain_dispatcher() {
        let dispatcher = h2_response_stream_hook_dispatcher(
            &sse_response_parts(Some("gzip, br")),
            runtime_governor(),
            1024,
        )
        .expect("SSE response should still be observed");

        assert!(matches!(dispatcher, H2ResponseStreamHookDispatcher::Sse(_)));
    }

    #[test]
    fn h2_sse_supported_encoding_uses_encoded_dispatcher() {
        let dispatcher = h2_response_stream_hook_dispatcher(
            &sse_response_parts(Some("gzip")),
            runtime_governor(),
            1024,
        )
        .expect("encoded SSE response should be observed");

        assert!(matches!(
            dispatcher,
            H2ResponseStreamHookDispatcher::EncodedSse { .. }
        ));
    }
}
