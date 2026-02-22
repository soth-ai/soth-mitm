#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downstream_tls_failure_emits_source_provider_and_host_counter() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let (_tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        tokio::time::sleep(Duration::from_millis(150)).await;
    });

    let sink = VecEventSink::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink, diagnostics, learning) =
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

    tcp.write_all(b"not-a-tls-client-hello")
        .await
        .expect("write invalid tls bytes");
    tcp.shutdown().await.expect("shutdown client tcp");

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(60)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let downstream_failure = events
        .iter()
        .find(|event| {
            event.kind == EventType::TlsHandshakeFailed
                && event.attributes.get("peer").map(String::as_str) == Some("downstream")
        })
        .expect("downstream TLS failure event");
    assert_eq!(
        downstream_failure
            .attributes
            .get("tls_failure_source")
            .map(String::as_str),
        Some("downstream")
    );
    assert_eq!(
        downstream_failure
            .attributes
            .get("tls_ops_provider")
            .map(String::as_str),
        Some("rustls")
    );
    assert_eq!(
        downstream_failure
            .attributes
            .get("tls_failure_host_count")
            .map(String::as_str),
        Some("1")
    );

    let snapshot = diagnostics.snapshot();
    let host = snapshot.hosts.get("127.0.0.1").expect("host diagnostics");
    assert_eq!(host.total_failures, 1);
    assert_eq!(host.by_source.get("downstream"), Some(&1));

    let learning_snapshot = learning.snapshot();
    assert_eq!(learning_snapshot.applied_total, 1);
    assert_eq!(learning_snapshot.ignored_total, 0);
    let learning_host = learning_snapshot
        .hosts
        .get("127.0.0.1")
        .expect("learning host");
    assert_eq!(learning_host.applied_total, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intercept_reuses_cached_leaf_cert_for_same_host() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        for _ in 0..2 {
            let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
            let mut tls = acceptor.accept(tcp).await.expect("TLS accept");
            let _request_head = read_http_head(&mut tls).await;
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx";
            tls.write_all(response).await.expect("write response");
            tls.shutdown().await.expect("shutdown upstream TLS");
        }
    });

    let sink = VecEventSink::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink, _diagnostics, _learning) =
        start_sidecar_with_sink(sink, config).await;

    for _ in 0..2 {
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
        tls.write_all(b"GET /cache HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        tls.flush().await.expect("flush request");
        let _ = read_to_end_allow_unexpected_eof(&mut tls).await;
    }

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let downstream_tls_starts = events
        .iter()
        .filter(|event| event.kind == EventType::TlsHandshakeStarted)
        .filter(|event| event.attributes.get("peer").map(String::as_str) == Some("downstream"))
        .collect::<Vec<_>>();
    assert!(
        downstream_tls_starts.len() >= 2,
        "expected at least two downstream TLS start events"
    );

    let statuses = downstream_tls_starts
        .iter()
        .filter_map(|event| event.attributes.get("cert_cache_status"))
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert!(
        statuses.contains(&"miss"),
        "expected at least one cert cache miss in downstream TLS starts"
    );
    assert!(
        statuses.contains(&"hit"),
        "expected at least one cert cache hit in downstream TLS starts"
    );
}
