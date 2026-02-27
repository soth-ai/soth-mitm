#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intercept_get_over_tls_forwards_and_emits_http_events() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("TLS accept");

        let request_head = read_http_head(&mut tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /hello HTTP/1.1"),
            "{request_text}"
        );

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nworld";
        tls.write_all(response).await.expect("write response");
        tls.shutdown().await.expect("shutdown upstream TLS");
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
    tls.write_all(b"GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    tls.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut tls).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1 200 OK"),
        "{response_text}"
    );
    assert!(response_text.ends_with("world"), "{response_text}");

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|e| e.kind == EventType::RequestHeaders));
    assert!(events.iter().any(|e| e.kind == EventType::ResponseHeaders));
    assert!(events
        .iter()
        .any(|e| e.kind == EventType::ResponseBodyChunk));
    for peer in ["downstream", "upstream"] {
        assert!(
            events.iter().any(|event| {
                event.kind == EventType::TlsHandshakeStarted
                    && event.attributes.get("peer").map(String::as_str) == Some(peer)
            }),
            "missing TLS handshake started event for peer={peer}"
        );
        assert!(
            events.iter().any(|event| {
                event.kind == EventType::TlsHandshakeSucceeded
                    && event.attributes.get("peer").map(String::as_str) == Some(peer)
            }),
            "missing TLS handshake succeeded event for peer={peer}"
        );
    }
    assert!(
        !events
            .iter()
            .any(|event| event.kind == EventType::TlsHandshakeFailed),
        "unexpected TLS handshake failure in success fixture"
    );

    let stream_closed = events
        .iter()
        .find(|e| e.kind == EventType::StreamClosed)
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
async fn ai_host_tunnel_guardrail_skips_upstream_mitm_tls_path() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http1_server_config_for_host("api.openai.com").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("TLS accept");

        let request_head = read_http_head(&mut tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(request_text.starts_with("GET /ai HTTP/1.1"), "{request_text}");

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nokay";
        tls.write_all(response).await.expect("write response");
        tls.shutdown().await.expect("shutdown upstream TLS");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        route_mode: RouteMode::Reverse,
        reverse_upstream: Some(RouteEndpointConfig {
            host: "127.0.0.1".to_string(),
            port: upstream_addr.port(),
        }),
        ignore_hosts: vec!["api.openai.com".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink, _diagnostics, _learning) =
        start_sidecar_with_sink(sink, config).await;

    let mut tcp = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    tcp.write_all(b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n")
        .await
        .expect("write CONNECT");
    let connect_response = read_response_head(&mut tcp).await;
    assert!(
        connect_response.starts_with("HTTP/1.1 200 Connection Established"),
        "{connect_response}"
    );

    let connector = TlsConnector::from(build_http1_client_config(true));
    let server_name = ServerName::try_from("api.openai.com".to_string()).expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect through tunnel");
    tls.write_all(b"GET /ai HTTP/1.1\r\nHost: api.openai.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    tls.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut tls).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(response_text.starts_with("HTTP/1.1 200 OK"), "{response_text}");
    assert!(response_text.ends_with("okay"), "{response_text}");

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::ConnectDecision
            && event.attributes.get("reason").map(String::as_str) == Some("ignored_host")
    }));
    assert!(
        !events.iter().any(|event| {
            matches!(
                event.kind,
                EventType::TlsHandshakeStarted
                    | EventType::TlsHandshakeSucceeded
                    | EventType::TlsHandshakeFailed
            ) && event.attributes.get("peer").map(String::as_str) == Some("upstream")
        }),
        "ignored AI hosts must not hit upstream MITM TLS handshake path"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intercept_post_emits_request_and_response_body_chunks() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("TLS accept");

        let request_head = read_http_head(&mut tls).await;
        let content_length = parse_content_length(&request_head);
        let mut body = vec![0_u8; content_length];
        tls.read_exact(&mut body).await.expect("read request body");
        assert_eq!(&body, b"hello");

        let response = b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        tls.write_all(response).await.expect("write response");
        tls.shutdown().await.expect("shutdown upstream TLS");
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
    tls.write_all(
        b"POST /submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    )
    .await
    .expect("write request");
    tls.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut tls).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1 201 Created"),
        "{response_text}"
    );
    assert!(response_text.ends_with("ok"), "{response_text}");

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let request_body_total = events
        .iter()
        .filter(|event| event.kind == EventType::RequestBodyChunk)
        .map(|event| {
            event
                .attributes
                .get("bytes")
                .expect("request chunk bytes")
                .parse::<u64>()
                .expect("bytes parses")
        })
        .sum::<u64>();
    assert_eq!(request_body_total, 5);

    let response_body_total = events
        .iter()
        .filter(|event| event.kind == EventType::ResponseBodyChunk)
        .map(|event| {
            event
                .attributes
                .get("bytes")
                .expect("response chunk bytes")
                .parse::<u64>()
                .expect("bytes parses")
        })
        .sum::<u64>();
    assert_eq!(response_body_total, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_http_absolute_form_request_relays_without_connect() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let (mut upstream, _) = upstream_listener.accept().await.expect("accept upstream");
        let request_head = read_http_head(&mut upstream).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /plain HTTP/1.1"),
            "{request_text}"
        );

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong";
        upstream.write_all(response).await.expect("write response");
        upstream.shutdown().await.expect("shutdown upstream");
    });

    let sink = VecEventConsumer::default();
    let (proxy_addr, proxy_task, sink, _diagnostics, _learning) =
        start_sidecar_with_sink(sink, MitmConfig::default()).await;

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    let request = format!(
        "GET http://127.0.0.1:{}/plain HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    client.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut client).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(response_text.starts_with("HTTP/1.1 200 OK"), "{response_text}");
    assert!(response_text.ends_with("pong"), "{response_text}");

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|event| event.kind == EventType::ConnectReceived));
    assert!(events.iter().any(|event| event.kind == EventType::ConnectDecision));
    assert!(events.iter().any(|event| event.kind == EventType::RequestHeaders));
    assert!(events.iter().any(|event| event.kind == EventType::ResponseHeaders));
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
