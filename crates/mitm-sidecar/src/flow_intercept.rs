#[allow(clippy::too_many_arguments)]
async fn intercept_http_connection<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    cert_store: Arc<MitmCertificateStore>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    tls_diagnostics: Arc<TlsDiagnostics>,
    tls_learning: Arc<TlsLearningGuardrails>,
    tunnel_context: FlowContext,
    mut downstream: TcpStream,
    max_http_head_bytes: usize,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
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
    let downstream_tls = match accept_downstream_tls(
        engine.config.downstream_tls_backend,
        downstream,
        &issued_server_config,
        engine.config.http2_enabled,
    )
    .await
    {
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
    let downstream_alpn = downstream_tls.negotiated_alpn();
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
        let max_header_list_size = engine.config.http2_max_header_list_size;
        return relay_http2_connection(
            engine,
            tunnel_context,
            downstream_tls,
            upstream_tls,
            max_header_list_size,
        )
        .await;
    }

    let downstream_conn = BufferedConn::new(downstream_tls);
    let upstream_conn = BufferedConn::new(upstream_tls);
    relay_http1_mitm_loop(
        engine,
        runtime_governor,
        tunnel_context,
        downstream_conn,
        upstream_conn,
        max_http_head_bytes,
    )
    .await
}
