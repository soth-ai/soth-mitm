#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Http1StreamingKind {
    Sse,
    Ndjson,
    Grpc,
}

#[allow(clippy::too_many_arguments)]
async fn relay_http1_response_with_hooks<P, S, D, U>(
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

fn response_has_content_encoding(response: &HttpResponseHead) -> bool {
    response
        .headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("content-encoding"))
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
