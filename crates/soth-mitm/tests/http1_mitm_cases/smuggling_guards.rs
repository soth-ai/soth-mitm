#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_proxy_rejects_https_absolute_form_with_deterministic_400() {
    let sink = VecEventConsumer::default();
    let (proxy_addr, proxy_task, sink, _diagnostics, _learning) =
        start_sidecar_with_sink(sink, MitmConfig::default()).await;

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    let request = b"GET https://example.com/secure HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    client.write_all(request).await.expect("write request");
    client.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut client).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1 400 Bad Request"),
        "{response_text}"
    );
    assert!(
        response_text.contains("invalid HTTP proxy target"),
        "{response_text}"
    );

    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let stream_closed = events
        .iter()
        .find(|event| event.kind == EventType::StreamClosed)
        .expect("stream closed event");
    assert_eq!(
        stream_closed
            .attributes
            .get("reason_code")
            .map(String::as_str),
        Some("mitm_http_error")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_proxy_rejects_te_cl_smuggling_request_with_deterministic_400() {
    let sink = VecEventConsumer::default();
    let (proxy_addr, proxy_task, sink, _diagnostics, _learning) =
        start_sidecar_with_sink(sink, MitmConfig::default()).await;

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    let request = b"POST http://127.0.0.1:65535/upload HTTP/1.1\r\nHost: 127.0.0.1:65535\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\nConnection: close\r\n\r\n0\r\n\r\n";
    client.write_all(request).await.expect("write request");
    client.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut client).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1 400 Bad Request"),
        "{response_text}"
    );
    assert!(
        response_text.contains("invalid HTTP proxy request"),
        "{response_text}"
    );

    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let stream_closed = events
        .iter()
        .find(|event| event.kind == EventType::StreamClosed)
        .expect("stream closed event");
    assert_eq!(
        stream_closed
            .attributes
            .get("reason_code")
            .map(String::as_str),
        Some("mitm_http_error")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_proxy_rejects_origin_form_self_target_with_deterministic_508() {
    let sink = VecEventConsumer::default();
    let (proxy_addr, proxy_task, sink, _diagnostics, _learning) =
        start_sidecar_with_sink(sink, MitmConfig::default()).await;

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    let request = format!(
        "GET /__soth/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        proxy_addr.port()
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    client.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut client).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1 508 Loop Detected"),
        "{response_text}"
    );
    assert!(
        response_text.contains("forward proxy self-target not allowed"),
        "{response_text}"
    );

    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let stream_closed = events
        .iter()
        .find(|event| event.kind == EventType::StreamClosed)
        .expect("stream closed event");
    assert_eq!(
        stream_closed
            .attributes
            .get("reason_code")
            .map(String::as_str),
        Some("route_planner_failed")
    );
    assert!(
        stream_closed
            .attributes
            .get("reason_detail")
            .map(String::as_str)
            .unwrap_or_default()
            .contains("self-target loop detected")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_proxy_local_handler_serves_origin_form_self_target() {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
    headers.insert(http::header::CONTENT_LENGTH, "999".parse().unwrap());
    headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
    headers.insert(http::header::CONNECTION, "keep-alive, x-remove".parse().unwrap());
    headers.insert(http::HeaderName::from_static("keep-alive"), "timeout=5".parse().unwrap());
    headers.insert(http::header::TE, "trailers".parse().unwrap());
    headers.insert(http::HeaderName::from_static("x-remove"), "bad".parse().unwrap());
    headers.insert(http::HeaderName::from_static("x-local"), "ok".parse().unwrap());
    let hooks = LocalRequestHooks::with_response(Some(HookRawResponse {
        status: 200,
        headers,
        body: soth_mitm::Bytes::from_static(b"{}"),
    }));
    let sink = VecEventConsumer::default();
    let (proxy_addr, proxy_task, sink, _diagnostics, _learning) = start_sidecar_with_flow_hooks(
        sink,
        MitmConfig::default(),
        Arc::new(hooks.clone()),
    )
    .await;

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    let request = format!(
        "POST /__soth/health?probe=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nContent-Length: 4\r\n\r\nping",
        proxy_addr.port()
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    client.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut client).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(response_text.starts_with("HTTP/1.1 200 OK"), "{response_text}");
    assert!(response_text.contains("content-type: application/json"), "{response_text}");
    assert!(response_text.contains("x-local: ok"), "{response_text}");
    assert!(response_text.contains("Content-Length: 2"), "{response_text}");
    assert!(response_text.ends_with("\r\n\r\n{}"), "{response_text}");
    assert!(!response_text.contains("Content-Length: 999"), "{response_text}");
    assert!(!response_text.contains("Transfer-Encoding"), "{response_text}");
    assert!(!response_text.contains("keep-alive"), "{response_text}");
    assert!(!response_text.contains("x-remove"), "{response_text}");
    assert!(!response_text.contains("\r\nTE:"), "{response_text}");

    let seen_request = hooks
        .seen_request()
        .await
        .expect("local request should reach hooks");
    assert_eq!(seen_request.method, "POST");
    assert_eq!(seen_request.path, "/__soth/health?probe=1");
    assert_eq!(seen_request.body, soth_mitm::Bytes::from_static(b"ping"));
    let expected_host = format!("127.0.0.1:{}", proxy_addr.port());
    assert_eq!(
        seen_request
            .headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok()),
        Some(expected_host.as_str())
    );
    assert!(!seen_request.headers.contains_key(http::header::CONNECTION));

    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let stream_closed = events
        .iter()
        .find(|event| event.kind == EventType::StreamClosed)
        .expect("stream closed event");
    assert_eq!(
        stream_closed
            .attributes
            .get("reason_code")
            .map(String::as_str),
        Some("mitm_http_completed")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_proxy_local_handler_none_falls_back_to_loop_rejection() {
    let hooks = LocalRequestHooks::with_response(None);
    let sink = VecEventConsumer::default();
    let (proxy_addr, proxy_task, _sink, _diagnostics, _learning) = start_sidecar_with_flow_hooks(
        sink,
        MitmConfig::default(),
        Arc::new(hooks.clone()),
    )
    .await;

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    let request = format!(
        "GET /__soth/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        proxy_addr.port()
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    client.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut client).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1 508 Loop Detected"),
        "{response_text}"
    );
    assert!(hooks.seen_request().await.is_some());

    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_proxy_local_handler_suppresses_body_for_204() {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::HeaderName::from_static("x-local"), "empty".parse().unwrap());
    let hooks = LocalRequestHooks::with_response(Some(HookRawResponse {
        status: 204,
        headers,
        body: soth_mitm::Bytes::from_static(b"must-not-be-sent"),
    }));
    let sink = VecEventConsumer::default();
    let (proxy_addr, proxy_task, _sink, _diagnostics, _learning) = start_sidecar_with_flow_hooks(
        sink,
        MitmConfig::default(),
        Arc::new(hooks),
    )
    .await;

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    let request = format!(
        "GET /__soth/empty HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        proxy_addr.port()
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    client.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut client).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1 204 No Content"),
        "{response_text}"
    );
    assert!(response_text.contains("x-local: empty"), "{response_text}");
    assert!(!response_text.contains("Content-Length"), "{response_text}");
    assert!(!response_text.contains("must-not-be-sent"), "{response_text}");

    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_proxy_local_handler_coerces_invalid_status_to_403() {
    let hooks = LocalRequestHooks::with_response(Some(HookRawResponse {
        status: 700,
        headers: http::HeaderMap::new(),
        body: soth_mitm::Bytes::from_static(b"invalid status"),
    }));
    let sink = VecEventConsumer::default();
    let (proxy_addr, proxy_task, _sink, _diagnostics, _learning) = start_sidecar_with_flow_hooks(
        sink,
        MitmConfig::default(),
        Arc::new(hooks),
    )
    .await;

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    let request = format!(
        "GET /__soth/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        proxy_addr.port()
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    client.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut client).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1 403 Forbidden"),
        "{response_text}"
    );
    assert!(response_text.contains("Content-Length: 14"), "{response_text}");
    assert!(response_text.ends_with("\r\n\r\ninvalid status"), "{response_text}");

    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_rejects_self_target_with_deterministic_508() {
    let sink = VecEventConsumer::default();
    let (proxy_addr, proxy_task, sink, _diagnostics, _learning) =
        start_sidecar_with_sink(sink, MitmConfig::default()).await;

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    let connect = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        proxy_addr.port(),
        proxy_addr.port()
    );
    client
        .write_all(connect.as_bytes())
        .await
        .expect("write CONNECT");
    client.flush().await.expect("flush CONNECT");

    let response_text = read_response_head(&mut client).await;
    assert!(
        response_text.starts_with("HTTP/1.1 508 Loop Detected"),
        "{response_text}"
    );
    assert!(
        response_text.contains("proxy CONNECT target resolves to listener itself"),
        "{response_text}"
    );

    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let stream_closed = events
        .iter()
        .find(|event| event.kind == EventType::StreamClosed)
        .expect("stream closed event");
    assert_eq!(
        stream_closed
            .attributes
            .get("reason_code")
            .map(String::as_str),
        Some("route_planner_failed")
    );
    assert!(
        stream_closed
            .attributes
            .get("reason_detail")
            .map(String::as_str)
            .unwrap_or_default()
            .contains("self-target loop detected")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intercept_path_rejects_te_cl_smuggling_before_upstream_http_bytes() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("accept upstream TLS");
        let mut buffer = [0_u8; 1];
        match tokio::time::timeout(Duration::from_millis(300), tls.read(&mut buffer)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(read)) => panic!("expected no upstream HTTP bytes, got {read}"),
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) => {}
            Ok(Err(error)) => panic!("upstream read failed: {error}"),
            Err(_) => {}
        }
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink, _diagnostics, _learning) =
        start_sidecar_with_sink(sink, config).await;

    let mut tcp = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    let connect = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    );
    tcp.write_all(connect.as_bytes())
        .await
        .expect("write CONNECT");
    let connect_response = read_response_head(&mut tcp).await;
    assert!(
        connect_response.starts_with("HTTP/1.1 200 Connection Established"),
        "{connect_response}"
    );

    let connector = TlsConnector::from(build_http1_client_config(true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    let request = b"POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\nConnection: close\r\n\r\n0\r\n\r\n";
    tls.write_all(request).await.expect("write request");
    tls.flush().await.expect("flush request");
    let _ = read_to_end_allow_unexpected_eof(&mut tls).await;

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let stream_closed = events
        .iter()
        .find(|event| event.kind == EventType::StreamClosed)
        .expect("stream closed event");
    assert_eq!(
        stream_closed
            .attributes
            .get("reason_code")
            .map(String::as_str),
        Some("mitm_http_error")
    );
}
