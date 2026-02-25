struct H2CapturedBody {
    bytes: bytes::Bytes,
    bytes_forwarded: u64,
    trailers: Option<http::HeaderMap>,
    body_truncated: bool,
}

async fn capture_h2_body(
    source: &mut h2::RecvStream,
    max_handler_body: usize,
) -> io::Result<H2CapturedBody> {
    let mut total = 0_u64;
    let mut body = Vec::new();
    let mut body_truncated = false;

    while let Some(next_data) = source.data().await {
        let data =
            next_data.map_err(|error| h2_error_to_io("reading HTTP/2 body frame failed", error))?;
        let frame_len = data.len();
        if frame_len == 0 {
            if source.is_end_stream() {
                break;
            }
            continue;
        }
        if !body_truncated {
            let remaining = max_handler_body.saturating_sub(body.len());
            if remaining >= frame_len {
                body.extend_from_slice(data.as_ref());
            } else {
                if remaining > 0 {
                    body.extend_from_slice(&data.as_ref()[..remaining]);
                }
                body_truncated = true;
            }
        }
        total += frame_len as u64;
        source
            .flow_control()
            .release_capacity(frame_len)
            .map_err(|error| h2_error_to_io("releasing HTTP/2 receive capacity failed", error))?;
        if source.is_end_stream() {
            break;
        }
    }

    let trailers = match tokio::time::timeout(H2_TRAILERS_WAIT_TIMEOUT, source.trailers()).await {
        Ok(result) => {
            result.map_err(|error| h2_error_to_io("reading HTTP/2 trailers failed", error))?
        }
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for HTTP/2 trailers",
            ));
        }
    };

    Ok(H2CapturedBody {
        bytes: bytes::Bytes::from(body),
        bytes_forwarded: total,
        trailers,
        body_truncated,
    })
}

async fn send_h2_captured_body(
    sink: &mut h2::SendStream<bytes::Bytes>,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    captured: H2CapturedBody,
) -> io::Result<Option<http::HeaderMap>> {
    if !captured.bytes.is_empty() {
        send_h2_data_with_backpressure(
            sink,
            runtime_governor,
            captured.bytes,
            captured.trailers.is_none(),
        )
        .await?;
    } else if captured.trailers.is_none() {
        send_h2_data_with_backpressure(sink, runtime_governor, bytes::Bytes::new(), true).await?;
    }

    if let Some(trailers) = captured.trailers {
        sink.send_trailers(trailers.clone())
            .map_err(|error| h2_error_to_io("sending HTTP/2 trailers failed", error))?;
        return Ok(Some(trailers));
    }
    Ok(None)
}

async fn dispatch_h2_response_hooks(
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: FlowContext,
    response_parts: &http::response::Parts,
    captured: &H2CapturedBody,
    max_handler_body: usize,
) {
    let mut headers = build_handler_header_map_from_h2(&response_parts.headers);
    if captured.body_truncated {
        mark_body_truncated(&mut headers);
    }
    let handler_body = if captured.body_truncated {
        captured
            .bytes
            .slice(..max_handler_body.min(captured.bytes.len()))
    } else {
        captured.bytes.clone()
    };
    let normalized_body = normalize_response_body_for_handler(&mut headers, handler_body);
    if headers.contains_key("x-soth-encoding-error") {
        flow_hooks
            .on_response(
                stream_context.clone(),
                RawResponse {
                    status: response_parts.status.as_u16(),
                    headers,
                    body: normalized_body,
                },
            )
            .await;
        flow_hooks.on_stream_end(stream_context).await;
        return;
    }

    if is_sse_h2_response(response_parts) {
        dispatch_sse_chunks_from_buffer(flow_hooks, stream_context, normalized_body).await;
        return;
    }
    if is_ndjson_h2_response(response_parts) {
        dispatch_ndjson_chunks_from_buffer(flow_hooks, stream_context, normalized_body).await;
        return;
    }
    if is_grpc_h2_response(response_parts) {
        dispatch_grpc_chunks_from_buffer(flow_hooks, stream_context, normalized_body).await;
        return;
    }

    flow_hooks
        .on_response(
            stream_context.clone(),
            RawResponse {
                status: response_parts.status.as_u16(),
                headers,
                body: normalized_body,
            },
        )
        .await;
    flow_hooks.on_stream_end(stream_context).await;
}

async fn dispatch_sse_chunks_from_buffer(
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: FlowContext,
    body: bytes::Bytes,
) {
    let mut parser = mitm_http::SseParser::new();
    let mut sequence = 0_u64;
    for event in parser.push_bytes(body.as_ref()) {
        let done = event.data == "[DONE]";
        flow_hooks
            .on_stream_chunk(
                stream_context.clone(),
                StreamChunk {
                    payload: bytes::Bytes::from(event.data),
                    sequence,
                    frame_kind: StreamFrameKind::SseData,
                },
            )
            .await;
        sequence += 1;
        if done {
            flow_hooks.on_stream_end(stream_context.clone()).await;
            return;
        }
    }
    if let Some(event) = parser.finish() {
        let done = event.data == "[DONE]";
        flow_hooks
            .on_stream_chunk(
                stream_context.clone(),
                StreamChunk {
                    payload: bytes::Bytes::from(event.data),
                    sequence,
                    frame_kind: StreamFrameKind::SseData,
                },
            )
            .await;
        if done {
            flow_hooks.on_stream_end(stream_context).await;
            return;
        }
    }
    flow_hooks.on_stream_end(stream_context).await;
}

async fn dispatch_ndjson_chunks_from_buffer(
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: FlowContext,
    body: bytes::Bytes,
) {
    let mut sequence = 0_u64;
    for line in body.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let payload = if line.last() == Some(&b'\r') {
            bytes::Bytes::copy_from_slice(&line[..line.len() - 1])
        } else {
            bytes::Bytes::copy_from_slice(line)
        };
        flow_hooks
            .on_stream_chunk(
                stream_context.clone(),
                StreamChunk {
                    payload,
                    sequence,
                    frame_kind: StreamFrameKind::NdjsonLine,
                },
            )
            .await;
        sequence += 1;
    }
    flow_hooks.on_stream_end(stream_context).await;
}

async fn dispatch_grpc_chunks_from_buffer(
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: FlowContext,
    body: bytes::Bytes,
) {
    let mut cursor = 0_usize;
    let mut sequence = 0_u64;
    while cursor + 5 <= body.len() {
        let frame_len = u32::from_be_bytes([
            body[cursor + 1],
            body[cursor + 2],
            body[cursor + 3],
            body[cursor + 4],
        ]) as usize;
        if cursor + 5 + frame_len > body.len() {
            break;
        }
        let payload = bytes::Bytes::copy_from_slice(&body[cursor + 5..cursor + 5 + frame_len]);
        flow_hooks
            .on_stream_chunk(
                stream_context.clone(),
                StreamChunk {
                    payload,
                    sequence,
                    frame_kind: StreamFrameKind::GrpcMessage,
                },
            )
            .await;
        sequence += 1;
        cursor += 5 + frame_len;
    }
    flow_hooks.on_stream_end(stream_context).await;
}

fn is_sse_h2_response(parts: &http::response::Parts) -> bool {
    parts
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or("").trim())
        .map(|value| value.eq_ignore_ascii_case("text/event-stream"))
        .unwrap_or(false)
}

fn is_ndjson_h2_response(parts: &http::response::Parts) -> bool {
    parts
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or("").trim())
        .map(|value| {
            value.eq_ignore_ascii_case("application/x-ndjson")
                || value.eq_ignore_ascii_case("application/jsonl")
        })
        .unwrap_or(false)
}

fn is_grpc_h2_response(parts: &http::response::Parts) -> bool {
    parts
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(is_grpc_content_type_value)
        .unwrap_or(false)
}
