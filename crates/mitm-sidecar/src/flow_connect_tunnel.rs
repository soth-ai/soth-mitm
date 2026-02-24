include!("flow_forward_proxy_http1.rs");

async fn handle_client<P, S>(
    runtime: RuntimeHandles<P, S>,
    mut downstream: TcpStream,
    client_addr: String,
    max_connect_head_bytes: usize,
    max_http_head_bytes: usize,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let engine = Arc::clone(&runtime.engine);
    let cert_store = Arc::clone(&runtime.cert_store);
    let runtime_governor = Arc::clone(&runtime.runtime_governor);
    let tls_diagnostics = Arc::clone(&runtime.tls_diagnostics);
    let tls_learning = Arc::clone(&runtime.tls_learning);

    let mut input =
        match read_connect_head(&mut downstream, max_connect_head_bytes, &runtime_governor).await {
        Ok(parsed) => parsed,
        Err(error) => {
            let parse_code = match error.kind() {
                io::ErrorKind::UnexpectedEof => ParseFailureCode::IncompleteHeaders,
                io::ErrorKind::InvalidData => ParseFailureCode::HeaderTooLarge,
                _ => ParseFailureCode::ReadError,
            };

            let flow_id = engine.allocate_flow_id();
            let context = unknown_context(flow_id, client_addr);

            emit_connect_parse_failed(
                &engine,
                context.clone(),
                parse_code,
                Some(error.to_string()),
            );
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::ConnectParseFailed,
                Some(parse_code.as_str().to_string()),
                None,
                None,
            );

            if error.kind() != io::ErrorKind::UnexpectedEof {
                let status = if parse_code == ParseFailureCode::HeaderTooLarge {
                    "431 Request Header Fields Too Large"
                } else {
                    "400 Bad Request"
                };
                write_proxy_response(
                    &mut downstream,
                    status,
                    "invalid or incomplete CONNECT request",
                )
                .await?;
            }
            return Ok(());
        }
    };

    let (connect, header_len) = match parse_connect_request_head_with_mode(
        &input,
        engine.config.connect_parse_mode,
    ) {
        Ok(parsed) => parsed,
        Err(ConnectParseError::MethodNotConnect)
            if is_absolute_form_forward_http_request(&input) =>
        {
            return handle_forward_http1_proxy_request(
                engine,
                runtime_governor,
                downstream,
                client_addr,
                input,
                max_http_head_bytes,
            )
            .await;
        }
        Err(parse_error) => {
            let flow_id = engine.allocate_flow_id();
            let context = unknown_context(flow_id, client_addr);
            emit_connect_parse_failed(
                &engine,
                context.clone(),
                ParseFailureCode::Parser(parse_error),
                None,
            );
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::ConnectParseFailed,
                Some(parse_error.code().to_string()),
                None,
                None,
            );
            write_proxy_response(
                &mut downstream,
                "400 Bad Request",
                "invalid CONNECT request",
            )
            .await?;
            return Ok(());
        }
    };

    let mut route_planner = FlowRoutePlanner::default();
    let route = match route_planner.bind_once(
        &engine.config,
        RouteTarget::new(connect.server_host.clone(), connect.server_port, None),
    ) {
        Ok(binding) => binding,
        Err(error) => {
            let flow_id = engine.allocate_flow_id();
            let context = FlowContext {
                flow_id,
                client_addr,
                server_host: connect.server_host,
                server_port: connect.server_port,
                protocol: ApplicationProtocol::Tunnel,
            };
            write_proxy_response(
                &mut downstream,
                "502 Bad Gateway",
                "route planner failed for CONNECT target",
            )
            .await?;
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::RoutePlannerFailed,
                Some(error.to_string()),
                None,
                None,
            );
            return Ok(());
        }
    };

    let outcome = engine.decide_connect(
        client_addr.clone(),
        route.target_host.clone(),
        route.target_port,
        route.policy_path.clone(),
    );

    let context = FlowContext {
        flow_id: outcome.flow_id,
        client_addr,
        server_host: route.target_host.clone(),
        server_port: route.target_port,
        protocol: ApplicationProtocol::Tunnel,
    };

    let http3_requested_by = if engine.config.http3_passthrough {
        parse_http3_passthrough_hint(&input[..header_len])
    } else {
        None
    };
    if let Some(requested_by) = http3_requested_by {
        if outcome.action != FlowAction::Block {
            emit_http3_passthrough_event(
                &engine,
                context.clone(),
                requested_by,
                flow_action_label(outcome.action),
            );
        }
    }
    let action = if http3_requested_by.is_some() && outcome.action != FlowAction::Block {
        FlowAction::Tunnel
    } else {
        outcome.action
    };

    match action {
        FlowAction::Block => {
            write_proxy_response(&mut downstream, "403 Forbidden", &outcome.reason).await?;
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::Blocked,
                Some(outcome.reason),
                None,
                None,
            );
            Ok(())
        }
        FlowAction::Tunnel => {
            tunnel_connection(engine, context, route, &mut downstream, &mut input, header_len).await
        }
        FlowAction::Intercept => {
            intercept_http_connection(
                engine,
                cert_store,
                runtime_governor,
                tls_diagnostics,
                tls_learning,
                context,
                route,
                outcome.override_state,
                downstream,
                max_http_head_bytes,
            )
            .await
        }
    }
}

fn parse_http3_passthrough_hint(connect_head: &[u8]) -> Option<&'static str> {
    let head = std::str::from_utf8(connect_head).ok()?;
    for line in head.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let (name, value) = match line.split_once(':') {
            Some(parts) => parts,
            None => continue,
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("x-proxy-protocol") && value.eq_ignore_ascii_case("h3") {
            return Some("x-proxy-protocol");
        }
        if name.eq_ignore_ascii_case("x-http3-passthrough")
            && (value == "1"
                || value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("yes"))
        {
            return Some("x-http3-passthrough");
        }
    }
    None
}

fn flow_action_label(action: FlowAction) -> &'static str {
    match action {
        FlowAction::Intercept => "intercept",
        FlowAction::Tunnel => "tunnel",
        FlowAction::Block => "block",
    }
}

async fn tunnel_connection<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    context: FlowContext,
    route: RouteBinding,
    downstream: &mut TcpStream,
    input: &mut [u8],
    header_len: usize,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut upstream = match connect_via_route(&route, RouteConnectIntent::TargetTunnel).await {
        Ok(stream) => stream,
        Err(error) => {
            let detail = format!(
                "upstream_connect_failed[{}]: {error}",
                route.route_mode_label()
            );
            write_proxy_response(downstream, "502 Bad Gateway", &detail).await?;
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

    write_all_with_idle_timeout(
        downstream,
        b"HTTP/1.1 200 Connection Established\r\n\r\n",
        "connect_tunnel_established_write",
    )
    .await?;

    let buffered_client_data = &input[header_len..];
    if !buffered_client_data.is_empty() {
        write_all_with_idle_timeout(
            &mut upstream,
            buffered_client_data,
            "connect_tunnel_prefetch_write",
        )
        .await?;
    }

    match copy_bidirectional_with_idle_timeout(downstream, &mut upstream).await {
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
                Some(from_client),
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
            Err(error)
        }
    }
}

#[cfg(test)]
mod flow_connect_tunnel_tests {
    use super::parse_http3_passthrough_hint;

    #[test]
    fn detects_http3_passthrough_via_proxy_protocol_hint() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX-Proxy-Protocol: h3\r\n\r\n";
        assert_eq!(
            parse_http3_passthrough_hint(head),
            Some("x-proxy-protocol")
        );
    }

    #[test]
    fn detects_http3_passthrough_via_boolean_flag_hint() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX-HTTP3-Passthrough: yes\r\n\r\n";
        assert_eq!(
            parse_http3_passthrough_hint(head),
            Some("x-http3-passthrough")
        );
    }

    #[test]
    fn does_not_accept_vendor_specific_legacy_hint_headers() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX-Soth-Proxy-Protocol: h3\r\n\r\n";
        assert_eq!(parse_http3_passthrough_hint(head), None);
    }
}
