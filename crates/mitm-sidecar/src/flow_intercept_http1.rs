#[allow(clippy::too_many_arguments)]
async fn relay_http1_mitm_loop<P, S, D, U>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    tunnel_context: FlowContext,
    mut downstream_conn: BufferedConn<D>,
    mut upstream_conn: BufferedConn<U>,
    max_http_head_bytes: usize,
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
                    Some(format!("request parse error: {error}")),
                    Some(bytes_from_client),
                    Some(bytes_from_server),
                );
                return Ok(());
            }
        };
        let upstream_request_head = match build_upstream_http1_request_head(&request) {
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

        emit_request_headers_event(&engine, &http_context, &request);
        if let Err(error) = upstream_conn.stream.write_all(&upstream_request_head).await {
            emit_http1_relay_error_close(
                &engine,
                &http_context,
                format!("upstream write request failed: {error}"),
                bytes_from_client,
                bytes_from_server,
            );
            return Ok(());
        }

        let mut request_observer = NoopHttpBodyObserver;
        let request_body_result = relay_http_body(
            &engine,
            &http_context,
            EventType::RequestBodyChunk,
            &mut downstream_conn,
            &mut upstream_conn.stream,
            request.body_mode,
            max_http_head_bytes,
            &runtime_governor,
            &mut request_observer,
        )
        .await;
        let request_body_bytes = match request_body_result {
            Ok(bytes) => bytes,
            Err(error) => {
                emit_http1_relay_error_close(
                    &engine,
                    &http_context,
                    format!("request body relay failed: {error}"),
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
                    Some(format!("response parse error: {error}")),
                    Some(bytes_from_client),
                    Some(bytes_from_server),
                );
                return Ok(());
            }
        };

        let websocket_upgrade =
            is_websocket_upgrade_request(&request) && is_websocket_upgrade_response(&response);

        emit_response_headers_event(&engine, &http_context, &response);
        if let Err(error) = downstream_conn.stream.write_all(&response.raw).await {
            emit_http1_relay_error_close(
                &engine,
                &http_context,
                format!("downstream write response failed: {error}"),
                bytes_from_client,
                bytes_from_server,
            );
            return Ok(());
        }

        if websocket_upgrade {
            return finalize_websocket_upgrade(
                Arc::clone(&engine),
                &tunnel_context,
                downstream_conn,
                upstream_conn,
                bytes_from_client,
                bytes_from_server,
            )
            .await;
        }

        if is_sse_response(&response) {
            let sse_context = FlowContext {
                protocol: ApplicationProtocol::Sse,
                ..tunnel_context.clone()
            };
            let mut sse_observer = SseStreamObserver::new(
                Arc::clone(&engine),
                sse_context,
                Arc::clone(&runtime_governor),
                engine.config.max_flow_decoder_buffer_bytes,
            );
            let response_body_result = relay_http_body(
                &engine,
                &http_context,
                EventType::ResponseBodyChunk,
                &mut upstream_conn,
                &mut downstream_conn.stream,
                response.body_mode,
                max_http_head_bytes,
                &runtime_governor,
                &mut sse_observer,
            )
            .await;
            let response_body_bytes = match response_body_result {
                Ok(bytes) => bytes,
                Err(error) => {
                    emit_http1_relay_error_close(
                        &engine,
                        &http_context,
                        format!("response body relay failed: {error}"),
                        bytes_from_client,
                        bytes_from_server,
                    );
                    return Ok(());
                }
            };
            bytes_from_server += response_body_bytes;
        } else {
            let mut response_observer = NoopHttpBodyObserver;
            let response_body_result = relay_http_body(
                &engine,
                &http_context,
                EventType::ResponseBodyChunk,
                &mut upstream_conn,
                &mut downstream_conn.stream,
                response.body_mode,
                max_http_head_bytes,
                &runtime_governor,
                &mut response_observer,
            )
            .await;
            let response_body_bytes = match response_body_result {
                Ok(bytes) => bytes,
                Err(error) => {
                    emit_http1_relay_error_close(
                        &engine,
                        &http_context,
                        format!("response body relay failed: {error}"),
                        bytes_from_client,
                        bytes_from_server,
                    );
                    return Ok(());
                }
            };
            bytes_from_server += response_body_bytes;
        }
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
    detail: String,
    bytes_from_client: u64,
    bytes_from_server: u64,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    emit_stream_closed(
        engine,
        context.clone(),
        CloseReasonCode::MitmHttpError,
        Some(detail),
        Some(bytes_from_client),
        Some(bytes_from_server),
    );
}
