#[allow(clippy::too_many_arguments)]
async fn relay_http2_stream_to_http1_upstream<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    stream_context: FlowContext,
    upstream_factory: H2ToH1UpstreamFactory,
    downstream_request: http::Request<h2::RecvStream>,
    mut downstream_respond: h2::server::SendResponse<bytes::Bytes>,
    max_http_head_bytes: usize,
    max_header_list_size: u32,
    strict_header_mode: bool,
    byte_counters: H2ByteCounters,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let (request_parts, mut downstream_request_body) = downstream_request.into_parts();
    if let Err(error) = enforce_h2_request_header_limit(&request_parts, max_header_list_size) {
        h2_relay_debug(format!(
            "[h2-h1:request] request header limit exceeded; resetting stream: {error}"
        ));
        downstream_respond.send_reset(h2::Reason::PROTOCOL_ERROR);
        flow_hooks.on_stream_end(stream_context).await;
        return Ok(());
    }

    if request_parts.method == http::Method::CONNECT {
        respond_h2_error_and_end(
            &flow_hooks,
            stream_context,
            &mut downstream_respond,
            &runtime_governor,
            501,
            "HTTP/2 CONNECT translation is not supported",
        )
        .await?;
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

    let max_flow_body_bytes = engine.config.max_flow_body_buffer_bytes.max(1);
    let request_captured = if downstream_request_body.is_end_stream() {
        H2CapturedBody {
            bytes: bytes::Bytes::new(),
            bytes_forwarded: 0,
            trailers: None,
            body_truncated: false,
        }
    } else {
        with_stream_stage_timeout(
            "http2_to_http1_request_body_capture",
            capture_h2_body(&mut downstream_request_body, max_flow_body_bytes),
        )
        .await?
    };
    byte_counters.request_bytes.fetch_add(
        request_captured.bytes_forwarded,
        std::sync::atomic::Ordering::Relaxed,
    );
    if request_captured.bytes_forwarded > max_flow_body_bytes as u64 {
        respond_h2_error_and_end(
            &flow_hooks,
            stream_context,
            &mut downstream_respond,
            &runtime_governor,
            413,
            "request body exceeded flow body budget",
        )
        .await?;
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
    let mut handler_request_body = request_captured.bytes.clone();
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
        let _ = send_h2_text_response(
            &mut downstream_respond,
            &runtime_governor,
            sanitize_block_status(status),
            body,
        )
        .await;
        flow_hooks.on_stream_end(stream_context).await;
        return Ok(());
    }

    let upstream_stream = match acquire_h2_h1_upstream_stream(&upstream_factory).await {
        Ok(stream) => stream,
        Err(error) => {
            h2_relay_debug(format!("[h2-h1:upstream] connect failed: {error}"));
            respond_h2_error_and_end(
                &flow_hooks,
                stream_context,
                &mut downstream_respond,
                &runtime_governor,
                502,
                "upstream connect failed",
            )
            .await?;
            return Ok(());
        }
    };
    let mut upstream_conn = BufferedConn::new(upstream_stream);

    let upstream_request_head =
        match build_http1_request_head_from_h2(&request_parts, &stream_context, &request_captured)
        {
            Ok(value) => value,
            Err(error) => {
                h2_relay_debug(format!("[h2-h1:request] request head build failed: {error}"));
                respond_h2_error_and_end(
                    &flow_hooks,
                    stream_context,
                    &mut downstream_respond,
                    &runtime_governor,
                    400,
                    "downstream request could not be translated",
                )
                .await?;
                return Ok(());
            }
        };
    if let Err(error) = write_all_with_idle_timeout(
        &mut upstream_conn.stream,
        &upstream_request_head,
        "http2_to_http1_request_head_write",
    )
    .await
    {
        h2_relay_debug(format!("[h2-h1:upstream] request head write failed: {error}"));
        respond_h2_error_and_end(
            &flow_hooks,
            stream_context,
            &mut downstream_respond,
            &runtime_governor,
            502,
            "upstream request write failed",
        )
        .await?;
        return Ok(());
    }
    if let Err(error) = with_stream_stage_timeout("http2_to_http1_request_body_forward", async {
        write_http1_request_body_from_h2_capture(
            &mut upstream_conn.stream,
            &runtime_governor,
            &request_captured,
        )
        .await?;
        flush_with_idle_timeout(&mut upstream_conn.stream, "http2_to_http1_request_flush").await
    })
    .await
    {
        h2_relay_debug(format!("[h2-h1:upstream] request body forward failed: {error}"));
        respond_h2_error_and_end(
            &flow_hooks,
            stream_context,
            &mut downstream_respond,
            &runtime_governor,
            502,
            "upstream request forwarding failed",
        )
        .await?;
        return Ok(());
    }

    let response_raw = match read_until_pattern(
        &mut upstream_conn,
        b"\r\n\r\n",
        max_http_head_bytes,
        &runtime_governor,
    )
    .await
    {
        Err(error) => {
            h2_relay_debug(format!("[h2-h1:response] response head read failed: {error}"));
            respond_h2_error_and_end(
                &flow_hooks,
                stream_context,
                &mut downstream_respond,
                &runtime_governor,
                502,
                "upstream response header read failed",
            )
            .await?;
            return Ok(());
        }
        Ok(Some(value)) => value,
        Ok(None) => {
            respond_h2_error_and_end(
                &flow_hooks,
                stream_context,
                &mut downstream_respond,
                &runtime_governor,
                502,
                "upstream closed before response headers",
            )
            .await?;
            return Ok(());
        }
    };
    let upstream_response = match parse_http_response_head_with_mode(
        &response_raw,
        request_parts.method.as_str(),
        strict_header_mode,
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            let detail = format!("response parse error (strict_header_mode={strict_header_mode}): {error}");
            h2_relay_debug(format!("[h2-h1:response] {detail}"));
            respond_h2_error_and_end(
                &flow_hooks,
                stream_context,
                &mut downstream_respond,
                &runtime_governor,
                502,
                "upstream response parse failed",
            )
            .await?;
            return Ok(());
        }
    };
    if upstream_response.status_code == 101 {
        respond_h2_error_and_end(
            &flow_hooks,
            stream_context,
            &mut downstream_respond,
            &runtime_governor,
            502,
            "HTTP/1.1 upgrade response is not translatable to HTTP/2",
        )
        .await?;
        return Ok(());
    }

    let response_captured = match with_stream_stage_timeout(
        "http2_to_http1_response_body_capture",
        read_http1_response_body_for_h2(
            &mut upstream_conn,
            upstream_response.body_mode,
            max_http_head_bytes,
            &runtime_governor,
            max_flow_body_bytes,
        ),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            h2_relay_debug(format!("[h2-h1:response] response body read failed: {error}"));
            respond_h2_error_and_end(
                &flow_hooks,
                stream_context,
                &mut downstream_respond,
                &runtime_governor,
                502,
                "upstream response body read failed",
            )
            .await?;
            return Ok(());
        }
    };
    byte_counters.response_bytes.fetch_add(
        response_captured.bytes_forwarded,
        std::sync::atomic::Ordering::Relaxed,
    );
    let response_parts = match build_h2_response_parts_from_http1(&upstream_response) {
        Ok(parts) => parts,
        Err(error) => {
            h2_relay_debug(format!("[h2-h1:response] response head translate failed: {error}"));
            respond_h2_error_and_end(
                &flow_hooks,
                stream_context,
                &mut downstream_respond,
                &runtime_governor,
                502,
                "upstream response headers were invalid",
            )
            .await?;
            return Ok(());
        }
    };
    if let Err(error) = enforce_h2_response_header_limit(&response_parts, max_header_list_size) {
        h2_relay_debug(format!(
            "[h2-h1:response] response header limit exceeded; resetting stream: {error}"
        ));
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
        let observed_trailers = with_stream_stage_timeout("http2_to_http1_response_body_forward", async {
            send_h2_captured_body(
                &mut downstream_response_stream,
                &runtime_governor,
                H2CapturedBody {
                    bytes: response_captured.bytes.clone(),
                    bytes_forwarded: response_captured.bytes_forwarded,
                    trailers: response_captured.trailers.clone(),
                    body_truncated: response_captured.body_truncated,
                },
            )
            .await
        })
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
        max_flow_body_bytes,
    )
    .await;
    Ok(())
}

include!("http2_stream_relay_http1_body.rs");
