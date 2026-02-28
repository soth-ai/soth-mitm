async fn relay_http2_stream<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    stream_context: FlowContext,
    upstream_sender: h2::client::SendRequest<bytes::Bytes>,
    downstream_request: http::Request<h2::RecvStream>,
    mut downstream_respond: h2::server::SendResponse<bytes::Bytes>,
    max_header_list_size: u32,
    byte_counters: H2ByteCounters,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let (mut request_parts, mut downstream_request_body) = downstream_request.into_parts();
    if let Err(error) = enforce_h2_request_header_limit(&request_parts, max_header_list_size) {
        h2_relay_debug(format!(
            "[h2-relay:request] request header limit exceeded; resetting stream: {error}"
        ));
        downstream_respond.send_reset(h2::Reason::PROTOCOL_ERROR);
        flow_hooks.on_stream_end(stream_context).await;
        return Ok(());
    }

    let grpc_observation = detect_grpc_request(&request_parts);
    if let Some(observation) = grpc_observation.as_ref() {
        emit_grpc_request_headers_event(
            &engine,
            stream_context.clone(),
            observation,
            &request_parts.headers,
        );
    }

    let max_handler_body = engine.config.max_flow_body_buffer_bytes.max(1);
    let request_captured = if downstream_request_body.is_end_stream() {
        H2CapturedBody {
            bytes: bytes::Bytes::new(),
            bytes_forwarded: 0,
            trailers: None,
            body_truncated: false,
        }
    } else {
        with_stream_stage_timeout(
            "http2_request_body_capture",
            capture_h2_body(&mut downstream_request_body, max_handler_body),
        )
        .await?
    };
    byte_counters
        .request_bytes
        .fetch_add(request_captured.bytes_forwarded, Ordering::Relaxed);
    if request_captured.body_truncated {
        let body = bytes::Bytes::from_static(b"request body exceeded flow body budget");
        let mut builder = http::Response::builder().status(413);
        builder = builder.header("content-type", "text/plain");
        builder = builder.header("content-length", body.len().to_string());
        let response = builder
            .body(())
            .map_err(|error| io::Error::other(format!("build oversized HTTP/2 response: {error}")))?;
        let mut stream = downstream_respond
            .send_response(response, body.is_empty())
            .map_err(|error| h2_error_to_io("sending oversized HTTP/2 response failed", error))?;
        if !body.is_empty() {
            send_h2_data_with_backpressure(&mut stream, &runtime_governor, body, true).await?;
        }
        flow_hooks.on_stream_end(stream_context).await;
        return Ok(());
    }

    let mut handler_request_headers = build_handler_header_map_from_h2(&request_parts.headers);
    ensure_handler_host_header_from_uri(
        &mut handler_request_headers,
        &stream_context,
        &request_parts.uri,
    );
    if request_captured.body_truncated {
        mark_body_truncated(&mut handler_request_headers);
    }
    let mut handler_request_body = if request_captured.body_truncated {
        request_captured
            .bytes
            .slice(..max_handler_body.min(request_captured.bytes.len()))
    } else {
        request_captured.bytes.clone()
    };
    handler_request_body =
        normalize_request_body_for_handler(&mut handler_request_headers, handler_request_body);
    if grpc_observation.is_some() {
        handler_request_body = normalize_grpc_request_body_for_handler(
            &mut handler_request_headers,
            handler_request_body,
        );
    }

    let request_decision = flow_hooks
        .on_request(
            stream_context.clone(),
            RawRequest {
                method: request_parts.method.to_string(),
                path: normalize_h2_path_for_handler(&request_parts.uri),
                headers: handler_request_headers,
                body: handler_request_body,
            },
        )
        .await;
    if let RequestDecision::Block { status, body } = request_decision {
        let status = sanitize_block_status(status);
        let mut builder = http::Response::builder().status(status);
        builder = builder.header("content-type", "text/plain");
        builder = builder.header("content-length", body.len().to_string());
        let block_response = builder
            .body(())
            .map_err(|error| io::Error::other(format!("build blocked HTTP/2 response: {error}")))?;
        let mut stream = downstream_respond
            .send_response(block_response, body.is_empty())
            .map_err(|error| h2_error_to_io("sending blocked HTTP/2 response failed", error))?;
        if !body.is_empty() {
            send_h2_data_with_backpressure(&mut stream, &runtime_governor, body, true).await?;
        }
        flow_hooks.on_stream_end(stream_context).await;
        return Ok(());
    }

    request_parts.version = http::Version::HTTP_2;
    let upstream_request = http::Request::from_parts(request_parts, ());
    let request_end_stream =
        request_captured.bytes.is_empty() && request_captured.trailers.as_ref().is_none();

    let mut ready_upstream_sender = match upstream_sender.ready().await {
        Ok(sender) => sender,
        Err(error) => {
            if is_h2_nonfatal_stream_error(&error) {
                downstream_respond.send_reset(h2_reason_for_downstream_reset(&error));
                flow_hooks.on_stream_end(stream_context).await;
                return Ok(());
            }
            return Err(h2_error_to_io("upstream HTTP/2 sender not ready", error));
        }
    };
    let (upstream_response_future, mut upstream_request_stream) =
        match ready_upstream_sender.send_request(upstream_request, request_end_stream) {
            Ok(parts) => parts,
            Err(error) => {
                if is_h2_nonfatal_stream_error(&error) {
                    downstream_respond.send_reset(h2_reason_for_downstream_reset(&error));
                    flow_hooks.on_stream_end(stream_context).await;
                    return Ok(());
                }
                return Err(h2_error_to_io("forwarding HTTP/2 request failed", error));
            }
        };
    if !request_end_stream {
        let _ = send_h2_captured_body(
            &mut upstream_request_stream,
            &runtime_governor,
            request_captured,
        )
        .await?;
    }

    let upstream_response_result =
        with_stream_stage_timeout("http2_upstream_response_headers", async {
            Ok(upstream_response_future.await)
        })
        .await?;
    let upstream_response = match upstream_response_result {
        Ok(response) => response,
        Err(error) => {
            if is_h2_nonfatal_stream_error(&error) {
                downstream_respond.send_reset(h2_reason_for_downstream_reset(&error));
                flow_hooks.on_stream_end(stream_context).await;
                return Ok(());
            }
            return Err(h2_error_to_io(
                "awaiting upstream HTTP/2 response failed",
                error,
            ));
        }
    };
    let (response_parts, mut upstream_response_body) = upstream_response.into_parts();
    if enforce_h2_response_header_limit(&response_parts, max_header_list_size).is_err() {
        h2_relay_debug("[h2-relay:response] response header limit exceeded; resetting stream");
        downstream_respond.send_reset(h2::Reason::PROTOCOL_ERROR);
        flow_hooks.on_stream_end(stream_context).await;
        return Ok(());
    }

    if let Some(observation) = grpc_observation.as_ref() {
        emit_grpc_response_headers_event(
            &engine,
            stream_context.clone(),
            observation,
            &response_parts,
        );
    }

    let response_captured = if upstream_response_body.is_end_stream() {
        H2CapturedBody {
            bytes: bytes::Bytes::new(),
            bytes_forwarded: 0,
            trailers: None,
            body_truncated: false,
        }
    } else {
        with_stream_stage_timeout(
            "http2_response_body_capture",
            capture_h2_body(&mut upstream_response_body, max_handler_body),
        )
        .await?
    };
    byte_counters
        .response_bytes
        .fetch_add(response_captured.bytes_forwarded, Ordering::Relaxed);
    if response_captured.body_truncated {
        let body = bytes::Bytes::from_static(b"upstream response body exceeded flow body budget");
        let mut builder = http::Response::builder().status(502);
        builder = builder.header("content-type", "text/plain");
        builder = builder.header("content-length", body.len().to_string());
        let response = builder
            .body(())
            .map_err(|error| io::Error::other(format!("build oversized HTTP/2 response: {error}")))?;
        let mut stream = downstream_respond
            .send_response(response, body.is_empty())
            .map_err(|error| h2_error_to_io("sending oversized HTTP/2 response failed", error))?;
        if !body.is_empty() {
            send_h2_data_with_backpressure(&mut stream, &runtime_governor, body, true).await?;
        }
        flow_hooks.on_stream_end(stream_context).await;
        return Ok(());
    }

    let response_end_stream =
        response_captured.bytes.is_empty() && response_captured.trailers.as_ref().is_none();
    let downstream_response = http::Response::from_parts(response_parts.clone(), ());
    let mut downstream_response_stream =
        match downstream_respond.send_response(downstream_response, response_end_stream) {
            Ok(stream) => stream,
            Err(error) => {
                if is_h2_nonfatal_stream_error(&error) {
                    flow_hooks.on_stream_end(stream_context).await;
                    return Ok(());
                }
                return Err(h2_error_to_io(
                    "sending downstream HTTP/2 response headers failed",
                    error,
                ));
            }
        };
    if !response_end_stream {
        let observed_trailers = send_h2_captured_body(
            &mut downstream_response_stream,
            &runtime_governor,
            H2CapturedBody {
                bytes: response_captured.bytes.clone(),
                bytes_forwarded: response_captured.bytes_forwarded,
                trailers: response_captured.trailers.clone(),
                body_truncated: response_captured.body_truncated,
            },
        )
        .await?;
        if let (Some(observation), Some(trailers)) =
            (grpc_observation.as_ref(), observed_trailers.as_ref())
        {
            emit_grpc_response_trailers_event(
                &engine,
                stream_context.clone(),
                observation,
                trailers,
            );
        }
    }

    dispatch_h2_response_hooks(
        &flow_hooks,
        stream_context,
        &response_parts,
        &response_captured,
        max_handler_body,
    )
    .await;
    Ok(())
}
