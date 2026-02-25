#[cfg(unix)]
impl<P, S> SidecarServer<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    async fn run_with_optional_unix_listener(self, listener: TcpListener) -> io::Result<()> {
        let unix_listener = match self.bind_unix_listener().await? {
            Some(listener) => listener,
            None => return self.run_with_listener(listener).await,
        };
        self.run_with_dual_listener(listener, unix_listener).await
    }

    async fn bind_unix_listener(&self) -> io::Result<Option<tokio::net::UnixListener>> {
        let Some(socket_path) = self
            .config
            .unix_socket_path
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let listener = bind_unix_listener_with_socket_hardening(socket_path).await?;
        Ok(Some(listener))
    }

    async fn run_with_dual_listener(
        self,
        listener: TcpListener,
        unix_listener: tokio::net::UnixListener,
    ) -> io::Result<()> {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut stream, client_addr) = accepted?;
                    apply_per_connection_socket_hardening(&stream);
                    let Some(flow_permit) = self.runtime_governor.try_acquire_flow_permit() else {
                        self.runtime_governor.mark_budget_denial();
                        let _ = write_all_with_idle_timeout(
                            &mut stream,
                            b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 36\r\n\r\nproxy flow capacity exceeded; try later",
                            "flow_capacity_denied_write",
                        )
                        .await;
                        let _ =
                            shutdown_with_idle_timeout(&mut stream, "flow_capacity_denied_shutdown").await;
                        continue;
                    };
                    let runtime = RuntimeHandles {
                        engine: Arc::clone(&self.engine),
                        cert_store: Arc::clone(&self.cert_store),
                        runtime_governor: Arc::clone(&self.runtime_governor),
                        tls_diagnostics: Arc::clone(&self.tls_diagnostics),
                        tls_learning: Arc::clone(&self.tls_learning),
                        flow_hooks: Arc::clone(&self.flow_hooks),
                    };
                    let max_connect_head_bytes = self.config.max_connect_head_bytes;
                    let max_http_head_bytes = self.config.max_http_head_bytes;
                    let client_addr = client_addr.to_string();
                    tokio::spawn(async move {
                        let _flow_guard = runtime.runtime_governor.begin_flow(flow_permit);
                        let flow_id = runtime.engine.allocate_flow_id();
                        let accept_context = unknown_context(flow_id, client_addr.clone());
                        let process_info = runtime
                            .flow_hooks
                            .resolve_process_info(accept_context.clone())
                            .await;
                        runtime
                            .flow_hooks
                            .on_connection_open(accept_context, process_info.clone())
                            .await;
                        if let Err(error) = handle_client(
                            runtime,
                            stream,
                            client_addr,
                            flow_id,
                            process_info,
                            max_connect_head_bytes,
                            max_http_head_bytes,
                        )
                        .await
                        {
                            if !is_benign_socket_close_error(&error) {
                                eprintln!("connection handling failed: {error}");
                            }
                        }
                    });
                }
                accepted = unix_listener.accept() => {
                    let (stream, peer_addr) = accepted?;
                    let client_addr = build_unix_client_addr(
                        &stream,
                        self.config.unix_socket_path.as_deref(),
                        peer_addr.as_pathname(),
                    );
                    let Some(flow_permit) = self.runtime_governor.try_acquire_flow_permit() else {
                        self.runtime_governor.mark_budget_denial();
                        let mut stream = stream;
                        let _ = write_forward_proxy_error_response(
                            &mut stream,
                            "503 Service Unavailable",
                            "proxy flow capacity exceeded; try later",
                        )
                        .await;
                        continue;
                    };
                    let runtime = RuntimeHandles {
                        engine: Arc::clone(&self.engine),
                        cert_store: Arc::clone(&self.cert_store),
                        runtime_governor: Arc::clone(&self.runtime_governor),
                        tls_diagnostics: Arc::clone(&self.tls_diagnostics),
                        tls_learning: Arc::clone(&self.tls_learning),
                        flow_hooks: Arc::clone(&self.flow_hooks),
                    };
                    let max_connect_head_bytes = self.config.max_connect_head_bytes;
                    let max_http_head_bytes = self.config.max_http_head_bytes;
                    tokio::spawn(async move {
                        let _flow_guard = runtime.runtime_governor.begin_flow(flow_permit);
                        let flow_id = runtime.engine.allocate_flow_id();
                        let accept_context = unknown_context(flow_id, client_addr.clone());
                        let process_info = runtime
                            .flow_hooks
                            .resolve_process_info(accept_context.clone())
                            .await;
                        runtime
                            .flow_hooks
                            .on_connection_open(accept_context, process_info.clone())
                            .await;
                        if let Err(error) = handle_local_unix_client(
                            runtime,
                            stream,
                            client_addr,
                            flow_id,
                            process_info,
                            max_connect_head_bytes,
                            max_http_head_bytes,
                        )
                        .await
                        {
                            if !is_benign_socket_close_error(&error) {
                                eprintln!("unix local-capture handling failed: {error}");
                            }
                        }
                    });
                }
            }
        }
    }
}

#[cfg(unix)]
fn build_unix_client_addr(
    stream: &tokio::net::UnixStream,
    listener_path: Option<&str>,
    peer_path: Option<&std::path::Path>,
) -> String {
    let pid = stream
        .peer_cred()
        .ok()
        .and_then(|cred| cred.pid())
        .and_then(|pid| u32::try_from(pid).ok());
    let mut parts = Vec::new();
    if let Some(pid) = pid {
        parts.push(format!("pid={pid}"));
    }
    if let Some(path) = listener_path {
        if !path.is_empty() {
            parts.push(format!("path={path}"));
        }
    }
    if let Some(path) = peer_path {
        let value = path.to_string_lossy();
        if !value.is_empty() {
            parts.push(format!("peer={value}"));
        }
    }
    if parts.is_empty() {
        "unix:".to_string()
    } else {
        format!("unix:{}", parts.join(","))
    }
}

#[cfg(unix)]
async fn handle_local_unix_client<P, S>(
    runtime: RuntimeHandles<P, S>,
    mut downstream: tokio::net::UnixStream,
    client_addr: String,
    flow_id: u64,
    process_info: Option<mitm_policy::ProcessInfo>,
    max_connect_head_bytes: usize,
    max_http_head_bytes: usize,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let engine = Arc::clone(&runtime.engine);
    let runtime_governor = Arc::clone(&runtime.runtime_governor);
    let flow_hooks = Arc::clone(&runtime.flow_hooks);

    let input =
        match read_connect_head(&mut downstream, max_connect_head_bytes, &runtime_governor).await {
            Ok(parsed) => parsed,
            Err(error) => {
                let parse_code = match error.kind() {
                    io::ErrorKind::UnexpectedEof => ParseFailureCode::IncompleteHeaders,
                    io::ErrorKind::InvalidData => ParseFailureCode::HeaderTooLarge,
                    _ => ParseFailureCode::ReadError,
                };
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
                write_forward_proxy_error_response(
                    &mut downstream,
                    "400 Bad Request",
                    "invalid or incomplete local-capture HTTP request",
                )
                .await?;
                return Ok(());
            }
        };

    if !is_forward_http1_request_candidate(&input) {
        let context = unknown_context(flow_id, client_addr.clone());
        emit_connect_parse_failed(
            &engine,
            context.clone(),
            ParseFailureCode::Parser(ConnectParseError::MethodNotConnect),
            Some("unix_local_capture_requires_http1_request".to_string()),
        );
        emit_stream_closed(
            &engine,
            context,
            CloseReasonCode::ConnectParseFailed,
            Some("unix_local_capture_requires_http1_request".to_string()),
            None,
            None,
        );
        write_forward_proxy_error_response(
            &mut downstream,
            "400 Bad Request",
            "unix local-capture expects HTTP/1.1 request with Host header",
        )
        .await?;
        return Ok(());
    }

    handle_forward_http1_proxy_request(
        engine,
        runtime_governor,
        flow_hooks,
        downstream,
        client_addr,
        flow_id,
        process_info,
        input,
        max_http_head_bytes,
    )
    .await
}
