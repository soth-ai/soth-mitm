async fn intercept_http_connection<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    cert_store: Arc<MitmCertificateStore>,
    tls_diagnostics: Arc<TlsDiagnostics>,
    tls_learning: Arc<TlsLearningGuardrails>,
    tunnel_context: FlowContext,
    mut downstream: TcpStream,
    max_http_head_bytes: usize,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let upstream_tcp = match TcpStream::connect((
        &*tunnel_context.server_host,
        tunnel_context.server_port,
    ))
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            let detail = format!("upstream_connect_failed: {error}");
            write_proxy_response(&mut downstream, "502 Bad Gateway", &detail).await?;
            emit_stream_closed(
                &engine,
                tunnel_context,
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

    let handshake_context = FlowContext {
        protocol: ApplicationProtocol::Http1,
        ..tunnel_context.clone()
    };

    let issued_server_config = match cert_store.server_config_for_host_with_http2(
        &handshake_context.server_host,
        engine.config.http2_enabled,
    ) {
        Ok(config) => config,
        Err(error) => {
            emit_tls_event_with_detail(
                &engine,
                &tls_diagnostics,
                &tls_learning,
                EventType::TlsHandshakeFailed,
                handshake_context.clone(),
                "downstream",
                error.to_string(),
            );
            emit_stream_closed(
                &engine,
                tunnel_context,
                CloseReasonCode::TlsHandshakeFailed,
                Some(format!("downstream leaf issuance error: {error}")),
                None,
                None,
            );
            return Ok(());
        }
    };
    emit_tls_event_with_cache(
        &engine,
        EventType::TlsHandshakeStarted,
        handshake_context.clone(),
        "downstream",
        issued_server_config.cache_status.as_str(),
    );
    let acceptor = TlsAcceptor::from(issued_server_config.server_config);
    let downstream_tls = match acceptor.accept(downstream).await {
        Ok(stream) => stream,
        Err(error) => {
            emit_tls_event_with_detail(
                &engine,
                &tls_diagnostics,
                &tls_learning,
                EventType::TlsHandshakeFailed,
                handshake_context.clone(),
                "downstream",
                error.to_string(),
            );
            emit_stream_closed(
                &engine,
                tunnel_context,
                CloseReasonCode::TlsHandshakeFailed,
                Some(format!("downstream handshake failed: {error}")),
                None,
                None,
            );
            return Ok(());
        }
    };
    let downstream_alpn = downstream_tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(ToOwned::to_owned);
    let downstream_protocol =
        protocol_from_negotiated_alpn(downstream_alpn.as_deref(), engine.config.http2_enabled);
    let downstream_context = FlowContext {
        protocol: downstream_protocol,
        ..tunnel_context.clone()
    };
    emit_tls_event_with_negotiated_alpn(
        &engine,
        EventType::TlsHandshakeSucceeded,
        downstream_context.clone(),
        "downstream",
        downstream_alpn.as_deref(),
    );

    let should_offer_http2_upstream =
        engine.config.http2_enabled && downstream_protocol == ApplicationProtocol::Http2;
    let client_config = build_http_client_config(
        engine.config.upstream_tls_insecure_skip_verify,
        should_offer_http2_upstream,
    );
    let server_name = match ServerName::try_from(handshake_context.server_host.clone()) {
        Ok(value) => value,
        Err(_) => {
            emit_stream_closed(
                &engine,
                tunnel_context,
                CloseReasonCode::MitmHttpError,
                Some("invalid server name for upstream TLS".to_string()),
                None,
                None,
            );
            return Ok(());
        }
    };
    let connector = TlsConnector::from(client_config);
    let upstream_start_context = FlowContext {
        protocol: if should_offer_http2_upstream {
            ApplicationProtocol::Http2
        } else {
            ApplicationProtocol::Http1
        },
        ..tunnel_context.clone()
    };
    emit_tls_event(
        &engine,
        EventType::TlsHandshakeStarted,
        upstream_start_context,
        "upstream",
    );
    let upstream_tls = match connector.connect(server_name, upstream_tcp).await {
        Ok(stream) => stream,
        Err(error) => {
            emit_tls_event_with_detail(
                &engine,
                &tls_diagnostics,
                &tls_learning,
                EventType::TlsHandshakeFailed,
                downstream_context.clone(),
                "upstream",
                error.to_string(),
            );
            emit_stream_closed(
                &engine,
                tunnel_context,
                CloseReasonCode::TlsHandshakeFailed,
                Some(format!("upstream handshake failed: {error}")),
                None,
                None,
            );
            return Ok(());
        }
    };
    let upstream_alpn = upstream_tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(ToOwned::to_owned);
    let upstream_protocol =
        protocol_from_negotiated_alpn(upstream_alpn.as_deref(), should_offer_http2_upstream);
    let upstream_context = FlowContext {
        protocol: upstream_protocol,
        ..tunnel_context.clone()
    };
    emit_tls_event_with_negotiated_alpn(
        &engine,
        EventType::TlsHandshakeSucceeded,
        upstream_context.clone(),
        "upstream",
        upstream_alpn.as_deref(),
    );

    if downstream_protocol == ApplicationProtocol::Http2 {
        let http2_context = FlowContext {
            protocol: ApplicationProtocol::Http2,
            ..tunnel_context.clone()
        };
        if upstream_protocol != ApplicationProtocol::Http2 {
            let downstream_alpn_label =
                negotiated_alpn_label(downstream_alpn.as_deref()).unwrap_or("none");
            let upstream_alpn_label =
                negotiated_alpn_label(upstream_alpn.as_deref()).unwrap_or("none");
            emit_stream_closed(
                &engine,
                http2_context,
                CloseReasonCode::MitmHttpError,
                Some(format!(
                    "downstream negotiated HTTP/2 ({downstream_alpn_label}) but upstream did not ({upstream_alpn_label})"
                )),
                None,
                None,
            );
            return Ok(());
        }
        return relay_http2_connection(engine, tunnel_context, downstream_tls, upstream_tls).await;
    }

    let http_context = FlowContext {
        protocol: ApplicationProtocol::Http1,
        ..tunnel_context.clone()
    };
    let mut downstream_conn = BufferedConn::new(downstream_tls);
    let mut upstream_conn = BufferedConn::new(upstream_tls);
    let mut bytes_from_client = 0_u64;
    let mut bytes_from_server = 0_u64;

    loop {
        let request_raw =
            match read_until_pattern(&mut downstream_conn, b"\r\n\r\n", max_http_head_bytes).await?
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

        emit_request_headers_event(&engine, &http_context, &request);
        upstream_conn.stream.write_all(&request.raw).await?;

        bytes_from_client += relay_http_body(
            &engine,
            &http_context,
            EventType::RequestBodyChunk,
            &mut downstream_conn,
            &mut upstream_conn.stream,
            request.body_mode,
            max_http_head_bytes,
        )
        .await?;

        let response_raw =
            match read_until_pattern(&mut upstream_conn, b"\r\n\r\n", max_http_head_bytes).await? {
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

        emit_response_headers_event(&engine, &http_context, &response);
        downstream_conn.stream.write_all(&response.raw).await?;

        bytes_from_server += relay_http_body(
            &engine,
            &http_context,
            EventType::ResponseBodyChunk,
            &mut upstream_conn,
            &mut downstream_conn.stream,
            response.body_mode,
            max_http_head_bytes,
        )
        .await?;

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

async fn relay_http2_connection<P, S, D, U>(
    engine: Arc<MitmEngine<P, S>>,
    tunnel_context: FlowContext,
    downstream_tls: D,
    mut upstream_tls: U,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
    D: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut downstream_tls = downstream_tls;
    let http2_context = FlowContext {
        protocol: ApplicationProtocol::Http2,
        ..tunnel_context
    };

    match tokio::io::copy_bidirectional(&mut downstream_tls, &mut upstream_tls).await {
        Ok((from_client, from_server)) => {
            emit_stream_closed(
                &engine,
                http2_context,
                CloseReasonCode::MitmHttpCompleted,
                None,
                Some(from_client),
                Some(from_server),
            );
            Ok(())
        }
        Err(error) => {
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) {
                emit_stream_closed(
                    &engine,
                    http2_context,
                    CloseReasonCode::MitmHttpCompleted,
                    Some(format!("http2 relay ended with transport close: {error}")),
                    None,
                    None,
                );
                return Ok(());
            }
            emit_stream_closed(
                &engine,
                http2_context,
                CloseReasonCode::MitmHttpError,
                Some(format!("http2 relay error: {error}")),
                None,
                None,
            );
            Err(error)
        }
    }
}
