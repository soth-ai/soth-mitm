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
