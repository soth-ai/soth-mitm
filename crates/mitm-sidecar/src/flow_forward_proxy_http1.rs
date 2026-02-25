include!("flow_forward_proxy_http1_helpers.rs");

#[allow(clippy::too_many_arguments)]
async fn handle_forward_http1_proxy_request<P, S, D>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    downstream: D,
    client_addr: String,
    flow_id: u64,
    process_info: Option<mitm_policy::ProcessInfo>,
    initial_head: Vec<u8>,
    max_http_head_bytes: usize,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut downstream = downstream;
    let request = match parse_http_request_head(&initial_head) {
        Ok(parsed) => parsed,
        Err(error) => {
            let context = FlowContext {
                flow_id,
                client_addr,
                server_host: "<unknown>".to_string(),
                server_port: 0,
                protocol: ApplicationProtocol::Http1,
            };
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::MitmHttpError,
                Some(format!("invalid forward-proxy request: {error}")),
                None,
                None,
            );
            write_forward_proxy_error_response(
                &mut downstream,
                "400 Bad Request",
                "invalid HTTP proxy request",
            )
            .await?;
            return Ok(());
        }
    };

    let target = match resolve_forward_http_route(&request) {
        Ok(value) => value,
        Err(error) => {
            let context = FlowContext {
                flow_id,
                client_addr,
                server_host: "<unknown>".to_string(),
                server_port: 0,
                protocol: ApplicationProtocol::Http1,
            };
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::MitmHttpError,
                Some(format!("invalid forward-proxy route: {error}")),
                None,
                None,
            );
            write_forward_proxy_error_response(
                &mut downstream,
                "400 Bad Request",
                "invalid HTTP proxy target",
            )
            .await?;
            return Ok(());
        }
    };

    let mut route_planner = FlowRoutePlanner::default();
    let route = match route_planner.bind_once(&engine.config, target) {
        Ok(value) => value,
        Err(error) => {
            let context = FlowContext {
                flow_id,
                client_addr,
                server_host: "<unknown>".to_string(),
                server_port: 0,
                protocol: ApplicationProtocol::Http1,
            };
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::RoutePlannerFailed,
                Some(format!("forward-proxy route planner failed: {error}")),
                None,
                None,
            );
            write_forward_proxy_error_response(
                &mut downstream,
                "502 Bad Gateway",
                "route planner failed for forward proxy request",
            )
            .await?;
            return Ok(());
        }
    };

    let outcome = engine.decide_connect(
        flow_id,
        client_addr.clone(),
        route.target_host.clone(),
        route.target_port,
        route.policy_path.clone(),
        process_info,
    );
    let context = FlowContext {
        flow_id: outcome.flow_id,
        client_addr,
        server_host: route.target_host.clone(),
        server_port: route.target_port,
        protocol: ApplicationProtocol::Http1,
    };

    if outcome.action == FlowAction::Block {
        write_forward_proxy_error_response(&mut downstream, "403 Forbidden", &outcome.reason)
            .await?;
        emit_stream_closed(
            &engine,
            context,
            CloseReasonCode::Blocked,
            Some(outcome.reason),
            None,
            None,
        );
        return Ok(());
    }

    let upstream_tcp = match connect_via_route(&route, RouteConnectIntent::ForwardHttpRequest).await
    {
        Ok(stream) => stream,
        Err(error) => {
            write_forward_proxy_error_response(
                &mut downstream,
                "502 Bad Gateway",
                &format!(
                    "upstream_connect_failed[{}]: {error}",
                    route.route_mode_label()
                ),
            )
            .await?;
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::UpstreamConnectFailed,
                Some(error.to_string()),
                None,
                None,
            );
            return Ok(());
        }
    };

    if outcome.action == FlowAction::Tunnel {
        return tunnel_http1_forward_stream(
            engine,
            context,
            downstream,
            upstream_tcp,
            initial_head,
        )
        .await;
    }

    let mut downstream_conn = BufferedConn::new(downstream);
    downstream_conn.read_buf = initial_head;
    let upstream_conn = BufferedConn::new(upstream_tcp);
    relay_http1_mitm_loop(
        engine,
        runtime_governor,
        flow_hooks,
        context,
        route.request_target_mode,
        downstream_conn,
        upstream_conn,
        max_http_head_bytes,
        outcome.override_state.strict_header_mode,
    )
    .await
}

async fn tunnel_http1_forward_stream<P, S, D>(
    engine: Arc<MitmEngine<P, S>>,
    context: FlowContext,
    mut downstream: D,
    mut upstream: TcpStream,
    initial_head: Vec<u8>,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let first_request = match parse_http_request_head(&initial_head) {
        Ok(value) => value,
        Err(error) => {
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::MitmHttpError,
                Some(format!(
                    "invalid first HTTP request in tunnel mode: {error}"
                )),
                None,
                None,
            );
            return Ok(());
        }
    };
    if let Err(error) = write_all_with_idle_timeout(
        &mut upstream,
        &first_request.raw,
        "forward_tunnel_initial_request_write",
    )
    .await
    {
        emit_stream_closed(
            &engine,
            context,
            CloseReasonCode::RelayError,
            Some(format!("forward initial request failed: {error}")),
            None,
            None,
        );
        return Ok(());
    }

    match copy_bidirectional_with_idle_timeout(&mut downstream, &mut upstream).await {
        Ok((from_client, from_server)) => {
            let per_flow_budget = engine.config.max_flow_body_buffer_bytes as u64;
            let (reason, detail) = if from_client > per_flow_budget || from_server > per_flow_budget
            {
                (
                    CloseReasonCode::MitmHttpError,
                    Some(format!(
                        "flow body budget exceeded (limit={per_flow_budget}, client_bytes={from_client}, server_bytes={from_server})"
                    )),
                )
            } else {
                (CloseReasonCode::RelayEof, None)
            };
            emit_stream_closed(
                &engine,
                context,
                reason,
                detail,
                Some(from_client + (initial_head.len() as u64)),
                Some(from_server),
            );
            Ok(())
        }
        Err(error) => {
            let reason = if is_idle_watchdog_timeout(&error) {
                CloseReasonCode::IdleWatchdogTimeout
            } else if is_stream_stage_timeout(&error) {
                CloseReasonCode::StreamStageTimeout
            } else {
                CloseReasonCode::RelayError
            };
            emit_stream_closed(
                &engine,
                context,
                reason,
                Some(error.to_string()),
                None,
                None,
            );
            if error.kind() == io::ErrorKind::InvalidData
                && error.to_string().contains("copy_bidirectional")
            {
                let _ = write_forward_proxy_error_response(
                    &mut downstream,
                    "400 Bad Request",
                    "HTTP proxy stream relay failed",
                )
                .await;
            }
            Ok(())
        }
    }
}

async fn write_forward_proxy_error_response<D>(
    downstream: &mut D,
    status: &str,
    body: &str,
) -> io::Result<()>
where
    D: AsyncWrite + Unpin,
{
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    write_all_with_idle_timeout(
        downstream,
        response.as_bytes(),
        "forward_proxy_error_response_write",
    )
    .await?;
    shutdown_with_idle_timeout(downstream, "forward_proxy_error_response_shutdown").await
}
