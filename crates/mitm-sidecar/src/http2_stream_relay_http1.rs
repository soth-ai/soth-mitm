#[derive(Clone)]
struct H2ToH1UpstreamFactory {
    route: RouteBinding,
    connector: TlsConnector,
    server_name: tokio_rustls::rustls::pki_types::ServerName<'static>,
    initial_stream: Arc<
        tokio::sync::Mutex<Option<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>,
    >,
}

async fn relay_http2_downstream_to_http1_upstream<P, S, D>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    tunnel_context: FlowContext,
    process_info: Option<mitm_policy::ProcessInfo>,
    downstream_tls: D,
    upstream_tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    route: RouteBinding,
    connector: TlsConnector,
    server_name: tokio_rustls::rustls::pki_types::ServerName<'static>,
    max_http_head_bytes: usize,
    max_header_list_size: u32,
    strict_header_mode: bool,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut downstream_builder = h2::server::Builder::new();
    configure_h2_server(&mut downstream_builder, max_header_list_size);
    let mut downstream_connection = match downstream_builder.handshake(downstream_tls).await {
        Ok(connection) => connection,
        Err(error) => {
            emit_stream_closed(
                &engine,
                FlowContext {
                    protocol: ApplicationProtocol::Http2,
                    ..tunnel_context
                },
                CloseReasonCode::MitmHttpError,
                Some(format!("downstream HTTP/2 handshake failed: {error}")),
                None,
                None,
            );
            return Ok(());
        }
    };

    let upstream_factory = H2ToH1UpstreamFactory {
        route,
        connector,
        server_name,
        initial_stream: Arc::new(tokio::sync::Mutex::new(Some(upstream_tls))),
    };
    let http2_context = FlowContext {
        protocol: ApplicationProtocol::Http2,
        ..tunnel_context.clone()
    };
    let byte_counters = H2ByteCounters {
        request_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        response_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    };
    let mut stream_tasks = tokio::task::JoinSet::new();
    let mut first_error: Option<io::Error> = None;

    while let Some(next_stream) = downstream_connection.accept().await {
        match next_stream {
            Ok((request, respond)) => {
                let stream_engine = Arc::clone(&engine);
                let stream_runtime_governor = Arc::clone(&runtime_governor);
                let stream_context = FlowContext {
                    flow_id: stream_engine.allocate_flow_id(),
                    ..http2_context.clone()
                };
                let stream_flow_hooks = Arc::clone(&flow_hooks);
                let stream_upstream_factory = upstream_factory.clone();
                let stream_process_info = process_info.clone();
                let stream_byte_counters = byte_counters.clone();
                stream_tasks.spawn(async move {
                    stream_flow_hooks
                        .on_connection_open(stream_context.clone(), stream_process_info)
                        .await;
                    let stream_end_context = stream_context.clone();
                    let result = relay_http2_stream_to_http1_upstream(
                        stream_engine,
                        stream_runtime_governor,
                        Arc::clone(&stream_flow_hooks),
                        stream_context,
                        stream_upstream_factory,
                        request,
                        respond,
                        max_http_head_bytes,
                        max_header_list_size,
                        strict_header_mode,
                        stream_byte_counters,
                    )
                    .await;
                    if result.is_err() {
                        stream_flow_hooks.on_stream_end(stream_end_context).await;
                    }
                    result
                });
            }
            Err(error) => {
                if !is_h2_nonfatal_stream_error(&error) && first_error.is_none() {
                    first_error = Some(h2_error_to_io("downstream HTTP/2 accept failed", error));
                }
                break;
            }
        }
    }

    while let Some(task_result) = stream_tasks.join_next().await {
        match task_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if !is_benign_h2_stream_io_error(&error) && first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(join_error) => {
                if first_error.is_none() {
                    first_error = Some(io::Error::other(format!(
                        "HTTP/2->HTTP/1 stream task join failed: {join_error}"
                    )));
                }
            }
        }
    }

    let bytes_from_client = byte_counters
        .request_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    let bytes_from_server = byte_counters
        .response_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    if let Some(error) = first_error {
        let close_reason = if is_stream_stage_timeout(&error) {
            CloseReasonCode::StreamStageTimeout
        } else if is_idle_watchdog_timeout(&error) {
            CloseReasonCode::IdleWatchdogTimeout
        } else {
            CloseReasonCode::MitmHttpError
        };
        emit_stream_closed(
            &engine,
            http2_context,
            close_reason,
            Some(error.to_string()),
            Some(bytes_from_client),
            Some(bytes_from_server),
        );
    } else {
        emit_stream_closed(
            &engine,
            http2_context,
            CloseReasonCode::MitmHttpCompleted,
            None,
            Some(bytes_from_client),
            Some(bytes_from_server),
        );
    }

    Ok(())
}

async fn acquire_h2_h1_upstream_stream(
    upstream_factory: &H2ToH1UpstreamFactory,
) -> io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let mut guard = upstream_factory.initial_stream.lock().await;
    if let Some(stream) = guard.take() {
        return Ok(stream);
    }
    drop(guard);

    let upstream_tcp =
        connect_via_route(&upstream_factory.route, RouteConnectIntent::TargetTunnel).await?;
    let stream = with_stream_stage_timeout("http2_to_http1_upstream_tls_connect", async {
        upstream_factory
            .connector
            .connect(upstream_factory.server_name.clone(), upstream_tcp)
            .await
            .map_err(|error| io::Error::other(format!("upstream TLS handshake failed: {error}")))
    })
    .await?;
    if matches!(stream.get_ref().1.alpn_protocol(), Some(value) if value == mitm_http::ALPN_H2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream ALPN mismatch for HTTP/2->HTTP/1 translation: negotiated h2",
        ));
    }
    Ok(stream)
}

fn build_http1_request_head_from_h2(
    request_parts: &http::request::Parts,
    stream_context: &FlowContext,
    request_captured: &H2CapturedBody,
) -> io::Result<Vec<u8>> {
    let mut headers = request_parts.headers.clone();
    strip_hop_by_hop_and_transport_headers(&mut headers);
    ensure_handler_host_header_from_uri(&mut headers, stream_context, &request_parts.uri);
    headers.insert("connection", http::HeaderValue::from_static("close"));

    if request_captured.trailers.is_some() {
        headers.remove(http::header::CONTENT_LENGTH);
        headers.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
    } else if request_captured.bytes.is_empty() {
        headers.remove(http::header::CONTENT_LENGTH);
        headers.remove(http::header::TRANSFER_ENCODING);
    } else {
        headers.remove(http::header::TRANSFER_ENCODING);
        let content_length = http::HeaderValue::from_str(&request_captured.bytes.len().to_string())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        headers.insert(http::header::CONTENT_LENGTH, content_length);
    }

    let target = request_parts
        .uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let mut request_head = Vec::new();
    request_head.extend_from_slice(request_parts.method.as_str().as_bytes());
    request_head.extend_from_slice(b" ");
    request_head.extend_from_slice(target.as_bytes());
    request_head.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in &headers {
        request_head.extend_from_slice(name.as_str().as_bytes());
        request_head.extend_from_slice(b": ");
        request_head.extend_from_slice(value.as_bytes());
        request_head.extend_from_slice(b"\r\n");
    }
    request_head.extend_from_slice(b"\r\n");
    Ok(request_head)
}

include!("http2_stream_relay_http1_stream.rs");
