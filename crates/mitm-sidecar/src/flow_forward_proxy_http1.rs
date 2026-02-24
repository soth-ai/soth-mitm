use http::Uri;

struct ForwardHttpRoute {
    server_host: String,
    server_port: u16,
    policy_path: String,
}

fn is_absolute_form_forward_http_request(input: &[u8]) -> bool {
    let Some(header_end) = input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
    else {
        return false;
    };
    let Ok(head) = std::str::from_utf8(&input[..header_end]) else {
        return false;
    };
    let Some(request_line) = head.split("\r\n").next() else {
        return false;
    };
    let mut parts = request_line.split_whitespace();
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(target) = parts.next() else {
        return false;
    };
    if method.eq_ignore_ascii_case("CONNECT") {
        return false;
    }
    if method.bytes().any(|byte| byte.is_ascii_lowercase()) {
        return false;
    }
    target.starts_with("http://")
}

#[allow(clippy::too_many_arguments)]
async fn handle_forward_http1_proxy_request<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    downstream: TcpStream,
    client_addr: String,
    initial_head: Vec<u8>,
    max_http_head_bytes: usize,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let request = match parse_http_request_head(&initial_head) {
        Ok(parsed) => parsed,
        Err(error) => {
            let flow_id = engine.allocate_flow_id();
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
            return write_forward_proxy_error_response(
                downstream,
                "400 Bad Request",
                "invalid HTTP proxy request",
            )
            .await;
        }
    };

    let route = match resolve_forward_http_route(&request) {
        Ok(value) => value,
        Err(error) => {
            let flow_id = engine.allocate_flow_id();
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
            return write_forward_proxy_error_response(
                downstream,
                "400 Bad Request",
                "invalid HTTP proxy target",
            )
            .await;
        }
    };

    let outcome = engine.decide_connect(
        client_addr.clone(),
        route.server_host.clone(),
        route.server_port,
        Some(route.policy_path),
    );
    let context = FlowContext {
        flow_id: outcome.flow_id,
        client_addr,
        server_host: route.server_host.clone(),
        server_port: route.server_port,
        protocol: ApplicationProtocol::Http1,
    };

    if outcome.action == FlowAction::Block {
        write_forward_proxy_error_response(downstream, "403 Forbidden", &outcome.reason).await?;
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

    let upstream_tcp = match TcpStream::connect((&*route.server_host, route.server_port)).await {
        Ok(stream) => stream,
        Err(error) => {
            write_forward_proxy_error_response(
                downstream,
                "502 Bad Gateway",
                &format!("upstream_connect_failed: {error}"),
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
        context,
        downstream_conn,
        upstream_conn,
        max_http_head_bytes,
    )
    .await
}

fn resolve_forward_http_route(request: &HttpRequestHead) -> io::Result<ForwardHttpRoute> {
    let uri = request.target.parse::<Uri>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy request target was not a valid URI",
        )
    })?;
    match uri.scheme_str() {
        Some("http") => {}
        Some("https") => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTPS absolute-form requires CONNECT",
            ));
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "only http absolute-form is supported for cleartext proxying",
            ));
        }
    }
    let server_host = uri
        .host()
        .map(str::to_string)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "absolute URI missing host"))?;
    let server_port = uri.port_u16().unwrap_or(80);
    let policy_path = uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Ok(ForwardHttpRoute {
        server_host,
        server_port,
        policy_path,
    })
}

fn build_upstream_http1_request_head(request: &HttpRequestHead) -> io::Result<Vec<u8>> {
    let target = normalize_forward_proxy_target_for_upstream(&request.target)?;
    let mut out = Vec::new();
    out.extend_from_slice(request.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.push(b' ');
    out.extend_from_slice(request.version.as_str().as_bytes());
    out.extend_from_slice(b"\r\n");
    for header in &request.headers {
        if header.name.eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

fn normalize_forward_proxy_target_for_upstream(target: &str) -> io::Result<String> {
    if target.starts_with('/') || target == "*" {
        return Ok(target.to_string());
    }
    let uri = target.parse::<Uri>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy request target was not a valid URI",
        )
    })?;
    if uri.scheme_str() != Some("http") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "only http absolute-form can be rewritten for upstream",
        ));
    }
    Ok(uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string()))
}

async fn tunnel_http1_forward_stream<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    context: FlowContext,
    mut downstream: TcpStream,
    mut upstream: TcpStream,
    initial_head: Vec<u8>,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let first_request = match parse_http_request_head(&initial_head) {
        Ok(value) => value,
        Err(error) => {
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::MitmHttpError,
                Some(format!("invalid first HTTP request in tunnel mode: {error}")),
                None,
                None,
            );
            return Ok(());
        }
    };
    if let Err(error) = upstream.write_all(&first_request.raw).await {
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

    match tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await {
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
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::RelayError,
                Some(error.to_string()),
                None,
                None,
            );
            if error.kind() == io::ErrorKind::InvalidData
                && error.to_string().contains("copy_bidirectional")
            {
                let _ = write_forward_proxy_error_response(
                    downstream,
                    "400 Bad Request",
                    "HTTP proxy stream relay failed",
                )
                .await;
            }
            Ok(())
        }
    }
}

async fn write_forward_proxy_error_response(
    mut downstream: TcpStream,
    status: &str,
    body: &str,
) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    downstream.write_all(response.as_bytes()).await?;
    downstream.shutdown().await
}
