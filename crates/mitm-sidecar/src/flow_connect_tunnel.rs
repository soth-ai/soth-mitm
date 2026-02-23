async fn handle_client<P, S>(
    runtime: RuntimeHandles<P, S>,
    mut downstream: TcpStream,
    client_addr: String,
    max_connect_head_bytes: usize,
    max_http_head_bytes: usize,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let engine = Arc::clone(&runtime.engine);
    let cert_store = Arc::clone(&runtime.cert_store);
    let tls_diagnostics = Arc::clone(&runtime.tls_diagnostics);
    let tls_learning = Arc::clone(&runtime.tls_learning);

    let mut input = match read_connect_head(&mut downstream, max_connect_head_bytes).await {
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

    let (connect, header_len) = match parse_connect_request_head(&input) {
        Ok(parsed) => parsed,
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

    let outcome = engine.decide_connect(
        client_addr.clone(),
        connect.server_host.clone(),
        connect.server_port,
        None,
    );

    let context = FlowContext {
        flow_id: outcome.flow_id,
        client_addr,
        server_host: connect.server_host.clone(),
        server_port: connect.server_port,
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
        FlowAction::Tunnel | FlowAction::MetadataOnly => {
            tunnel_connection(engine, context, &mut downstream, &mut input, header_len).await
        }
        FlowAction::Intercept => {
            intercept_http_connection(
                engine,
                cert_store,
                tls_diagnostics,
                tls_learning,
                context,
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
        if name.eq_ignore_ascii_case("x-soth-proxy-protocol")
            && value.eq_ignore_ascii_case("h3")
        {
            return Some("x-soth-proxy-protocol");
        }
        if name.eq_ignore_ascii_case("x-soth-http3-passthrough")
            && (value == "1"
                || value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("yes"))
        {
            return Some("x-soth-http3-passthrough");
        }
    }
    None
}

fn flow_action_label(action: FlowAction) -> &'static str {
    match action {
        FlowAction::Intercept => "intercept",
        FlowAction::Tunnel => "tunnel",
        FlowAction::Block => "block",
        FlowAction::MetadataOnly => "metadata_only",
    }
}

async fn tunnel_connection<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    context: FlowContext,
    downstream: &mut TcpStream,
    input: &mut [u8],
    header_len: usize,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut upstream = match TcpStream::connect((&*context.server_host, context.server_port)).await
    {
        Ok(stream) => stream,
        Err(error) => {
            let detail = format!("upstream_connect_failed: {error}");
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

    downstream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let buffered_client_data = &input[header_len..];
    if !buffered_client_data.is_empty() {
        upstream.write_all(buffered_client_data).await?;
    }

    match tokio::io::copy_bidirectional(downstream, &mut upstream).await {
        Ok((from_client, from_server)) => {
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::RelayEof,
                None,
                Some(from_client),
                Some(from_server),
            );
            Ok(())
        }
        Err(error) => {
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::RelayError,
                Some(error.to_string()),
                None,
                None,
            );
            Err(error)
        }
    }
}
