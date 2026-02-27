#[allow(clippy::too_many_arguments)]
async fn relay_http1_mitm_loop<P, S, D, U>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    tunnel_context: FlowContext,
    upstream_target_mode: UpstreamRequestTargetMode,
    mut downstream_conn: BufferedConn<D>,
    mut upstream_conn: BufferedConn<U>,
    max_http_head_bytes: usize,
    strict_header_mode: bool,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let http_context = FlowContext {
        protocol: ApplicationProtocol::Http1,
        ..tunnel_context.clone()
    };
    let mut bytes_from_client = 0_u64;
    let mut bytes_from_server = 0_u64;

    loop {
        let request_raw = match read_until_pattern(
            &mut downstream_conn,
            b"\r\n\r\n",
            max_http_head_bytes,
            &runtime_governor,
        )
        .await?
        {
            Some(value) => value,
            None => {
                emit_stream_closed(
                    &engine,
                    http_context.clone(),
                    CloseReasonCode::MitmHttpCompleted,
                    None,
                    Some(bytes_from_client),
                    Some(bytes_from_server),
                );
                return Ok(());
            }
        };

        let request = match parse_http_request_head(&request_raw) {
            Ok(parsed) => parsed,
            Err(error) => {
                emit_stream_closed(
                    &engine,
                    http_context.clone(),
                    CloseReasonCode::MitmHttpError,
                    Some(format!(
                        "request parse error (strict_header_mode={strict_header_mode}): {error}"
                    )),
                    Some(bytes_from_client),
                    Some(bytes_from_server),
                );
                return Ok(());
            }
        };
        let upstream_request_head =
            match build_upstream_http1_request_head(&request, upstream_target_mode) {
                Ok(value) => value,
                Err(error) => {
                    emit_stream_closed(
                        &engine,
                        http_context.clone(),
                        CloseReasonCode::MitmHttpError,
                        Some(format!("request target normalization failed: {error}")),
                        Some(bytes_from_client),
                        Some(bytes_from_server),
                    );
                    return Ok(());
                }
            };

        let max_handler_body = engine.config.max_flow_body_buffer_bytes.max(1);
        let mut request_sink = tokio::io::sink();
        let (request_body_bytes, request_body, request_body_truncated) =
            match relay_http_body_with_capture(
                &engine,
                &http_context,
                EventType::RequestBodyChunk,
                &mut downstream_conn,
                &mut request_sink,
                request.body_mode,
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
                        &http_context,
                        "request body relay failed",
                        &error,
                        bytes_from_client,
                        bytes_from_server,
                    );
                    return Ok(());
                }
            };
        bytes_from_client += request_body_bytes;
        if flow_body_budget_exceeded(
            &engine,
            &http_context,
            "client",
            bytes_from_client,
            bytes_from_server,
        ) {
            return Ok(());
        }

        let mut handler_request_headers = build_handler_header_map(&request.headers);
        ensure_handler_host_header_from_target(
            &mut handler_request_headers,
            &http_context,
            &request.target,
        );
        if request_body_truncated {
            mark_body_truncated(&mut handler_request_headers);
        }
        let request_is_grpc = is_grpc_request(&request.headers);
        let mut handler_body = if request_body_truncated {
            request_body.slice(..max_handler_body.min(request_body.len()))
        } else {
            request_body.clone()
        };
        handler_body =
            normalize_request_body_for_handler(&mut handler_request_headers, handler_body);
        if request_is_grpc {
            handler_body =
                normalize_grpc_request_body_for_handler(&mut handler_request_headers, handler_body);
        }
        let request_decision = flow_hooks
            .on_request(
                http_context.clone(),
                RawRequest {
                    method: request.method.clone(),
                    path: normalize_request_path_for_handler(&request.target),
                    headers: handler_request_headers,
                    body: handler_body,
                },
            )
            .await;
        if let RequestDecision::Block { status, body } = request_decision {
            let status = sanitize_block_status(status);
            let status_line = format!("{status} Blocked");
            let response_head = format!(
                "HTTP/1.1 {status_line}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = write_all_with_idle_timeout(
                &mut downstream_conn.stream,
                response_head.as_bytes(),
                "http1_block_response_head_write",
            )
            .await;
            if !body.is_empty() {
                let _ = write_all_with_idle_timeout(
                    &mut downstream_conn.stream,
                    &body,
                    "http1_block_response_body_write",
                )
                .await;
            }
            emit_stream_closed(
                &engine,
                http_context,
                CloseReasonCode::Blocked,
                Some("blocked_by_handler".to_string()),
                Some(bytes_from_client),
                Some(bytes_from_server),
            );
            return Ok(());
        }

        emit_request_headers_event(&engine, &http_context, &request);
        if let Err(error) = write_all_with_idle_timeout(
            &mut upstream_conn.stream,
            &upstream_request_head,
            "http1_request_head_write_upstream",
        )
        .await
        {
            emit_http1_relay_error_close(
                &engine,
                &http_context,
                "upstream write request failed",
                &error,
                bytes_from_client,
                bytes_from_server,
            );
            return Ok(());
        }
        if !request_body.is_empty() {
            if let Err(error) = write_all_with_idle_timeout(
                &mut upstream_conn.stream,
                &request_body,
                "http1_request_body_write_upstream",
            )
            .await
            {
                emit_http1_relay_error_close(
                    &engine,
                    &http_context,
                    "upstream write request body failed",
                    &error,
                    bytes_from_client,
                    bytes_from_server,
                );
                return Ok(());
            }
        }

        let response_raw = match read_until_pattern(
            &mut upstream_conn,
            b"\r\n\r\n",
            max_http_head_bytes,
            &runtime_governor,
        )
        .await?
        {
            Some(value) => value,
            None => {
                emit_stream_closed(
                    &engine,
                    http_context.clone(),
                    CloseReasonCode::MitmHttpError,
                    Some("upstream closed before response headers".to_string()),
                    Some(bytes_from_client),
                    Some(bytes_from_server),
                );
                return Ok(());
            }
        };

        let response = match parse_http_response_head(&response_raw, &request.method) {
            Ok(parsed) => parsed,
            Err(error) => {
                emit_stream_closed(
                    &engine,
                    http_context.clone(),
                    CloseReasonCode::MitmHttpError,
                    Some(format!(
                        "response parse error (strict_header_mode={strict_header_mode}): {error}"
                    )),
                    Some(bytes_from_client),
                    Some(bytes_from_server),
                );
                return Ok(());
            }
        };

        let websocket_upgrade =
            is_websocket_upgrade_request(&request) && is_websocket_upgrade_response(&response);

        emit_response_headers_event(&engine, &http_context, &response);
        if let Err(error) = write_all_with_idle_timeout(
            &mut downstream_conn.stream,
            &response.raw,
            "http1_response_head_write_downstream",
        )
        .await
        {
            emit_http1_relay_error_close(
                &engine,
                &http_context,
                "downstream write response failed",
                &error,
                bytes_from_client,
                bytes_from_server,
            );
            return Ok(());
        }

        if websocket_upgrade {
            return finalize_websocket_upgrade(
                Arc::clone(&engine),
                Arc::clone(&runtime_governor),
                flow_hooks,
                &tunnel_context,
                downstream_conn,
                upstream_conn,
                bytes_from_client,
                bytes_from_server,
            )
            .await;
        }

        let response_body_bytes = match relay_http1_response_with_hooks(
            Arc::clone(&engine),
            Arc::clone(&runtime_governor),
            Arc::clone(&flow_hooks),
            &tunnel_context,
            &http_context,
            &response,
            &mut upstream_conn,
            &mut downstream_conn.stream,
            max_http_head_bytes,
            bytes_from_client,
            bytes_from_server,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(()) => return Ok(()),
        };
        bytes_from_server += response_body_bytes;
        if flow_body_budget_exceeded(
            &engine,
            &http_context,
            "server",
            bytes_from_server,
            bytes_from_client,
        ) {
            return Ok(());
        }
        if request.connection_close
            || response.connection_close
            || response.body_mode == HttpBodyMode::CloseDelimited
        {
            emit_stream_closed(
                &engine,
                http_context,
                CloseReasonCode::MitmHttpCompleted,
                None,
                Some(bytes_from_client),
                Some(bytes_from_server),
            );
            return Ok(());
        }
    }
}
fn flow_body_budget_exceeded<P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    direction: &str,
    bytes: u64,
    counterpart_bytes: u64,
) -> bool
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let budget = engine.config.max_flow_body_buffer_bytes as u64;
    if bytes <= budget {
        return false;
    }

    emit_stream_closed(
        engine,
        context.clone(),
        CloseReasonCode::MitmHttpError,
        Some(format!(
            "flow body budget exceeded (limit={budget}, {direction}_bytes={bytes})"
        )),
        Some(if direction == "client" {
            bytes
        } else {
            counterpart_bytes
        }),
        Some(if direction == "server" {
            bytes
        } else {
            counterpart_bytes
        }),
    );
    true
}

fn emit_http1_relay_error_close<P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    stage: &str,
    error: &io::Error,
    bytes_from_client: u64,
    bytes_from_server: u64,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let reason = if is_idle_watchdog_timeout(error) {
        CloseReasonCode::IdleWatchdogTimeout
    } else if is_stream_stage_timeout(error) {
        CloseReasonCode::StreamStageTimeout
    } else {
        CloseReasonCode::MitmHttpError
    };
    emit_stream_closed(
        engine,
        context.clone(),
        reason,
        Some(format!("{stage}: {error}")),
        Some(bytes_from_client),
        Some(bytes_from_server),
    );
}
