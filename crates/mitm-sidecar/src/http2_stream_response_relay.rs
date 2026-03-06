enum H2ResponseStreamHookDispatcher {
    Sse {
        parser: mitm_http::SseParser,
        sequence: u64,
        stream_ended: bool,
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

impl H2ResponseStreamHookDispatcher {
    async fn on_chunk(
        &mut self,
        flow_hooks: &Arc<dyn FlowHooks>,
        stream_context: &FlowContext,
        chunk: &[u8],
    ) {
        match self {
            Self::Sse {
                parser,
                sequence,
                stream_ended,
            } => {
                if *stream_ended {
                    return;
                }
                for event in parser.push_bytes(chunk) {
                    let done = event.data == "[DONE]";
                    flow_hooks
                        .on_stream_chunk(
                            stream_context.clone(),
                            StreamChunk {
                                payload: bytes::Bytes::from(event.data),
                                sequence: *sequence,
                                frame_kind: StreamFrameKind::SseData,
                            },
                        )
                        .await;
                    *sequence += 1;
                    if done {
                        flow_hooks.on_stream_end(stream_context.clone()).await;
                        *stream_ended = true;
                        break;
                    }
                }
            }
            Self::Ndjson {
                pending,
                sequence,
                stream_ended,
            } => {
                if *stream_ended {
                    return;
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
                                frame_kind: StreamFrameKind::NdjsonLine,
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
                    return;
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
                                frame_kind: StreamFrameKind::GrpcMessage,
                            },
                        )
                        .await;
                    *sequence += 1;
                }
            }
        }
    }

    async fn finish(&mut self, flow_hooks: &Arc<dyn FlowHooks>, stream_context: &FlowContext) {
        match self {
            Self::Sse {
                parser,
                sequence,
                stream_ended,
            } => {
                if *stream_ended {
                    return;
                }
                if let Some(event) = parser.finish() {
                    let done = event.data == "[DONE]";
                    flow_hooks
                        .on_stream_chunk(
                            stream_context.clone(),
                            StreamChunk {
                                payload: bytes::Bytes::from(event.data),
                                sequence: *sequence,
                                frame_kind: StreamFrameKind::SseData,
                            },
                        )
                        .await;
                    if done {
                        flow_hooks.on_stream_end(stream_context.clone()).await;
                        *stream_ended = true;
                        return;
                    }
                }
                flow_hooks.on_stream_end(stream_context.clone()).await;
                *stream_ended = true;
            }
            Self::Ndjson {
                pending,
                sequence,
                stream_ended,
            } => {
                if *stream_ended {
                    return;
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
                                frame_kind: StreamFrameKind::NdjsonLine,
                            },
                        )
                        .await;
                }
                flow_hooks.on_stream_end(stream_context.clone()).await;
                *stream_ended = true;
            }
            Self::Grpc { stream_ended, .. } => {
                if *stream_ended {
                    return;
                }
                flow_hooks.on_stream_end(stream_context.clone()).await;
                *stream_ended = true;
            }
        }
    }
}

fn h2_response_stream_hook_dispatcher(
    response_parts: &http::response::Parts,
) -> Option<H2ResponseStreamHookDispatcher> {
    if is_sse_h2_response(response_parts) {
        return Some(H2ResponseStreamHookDispatcher::Sse {
            parser: mitm_http::SseParser::new(),
            sequence: 0,
            stream_ended: false,
        });
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

struct H2ResponseStreamRelayOutcome {
    captured: H2CapturedBody,
    observed_trailers: Option<http::HeaderMap>,
}

#[allow(clippy::too_many_arguments)]
async fn relay_h2_response_body_with_incremental_forwarding(
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
        let data = next_data.map_err(|error| h2_error_to_io("reading HTTP/2 body frame failed", error))?;
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
        send_h2_data_with_backpressure(downstream_response_stream, runtime_governor, data, false).await?;
        if let (Some(dispatcher), Some(chunk)) = (stream_dispatcher.as_mut(), hook_chunk.as_ref()) {
            dispatcher
                .on_chunk(flow_hooks, stream_context, chunk.as_ref())
                .await;
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
        dispatcher.finish(flow_hooks, stream_context).await;
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
