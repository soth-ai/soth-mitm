#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intercept_upstream_tls_failure_emits_taxonomy_reason() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let _ = acceptor.accept(tcp).await;
    });

    let sink = VecEventSink::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: false,
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

    let connector = TlsConnector::from(build_http1_client_config(true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    let _ = tls
        .write_all(b"GET /tls-failure HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await;
    let _ = tls.flush().await;
    let _ = read_to_end_allow_unexpected_eof(&mut tls).await;

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(40)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let upstream_failed = events
        .iter()
        .find(|event| {
            event.kind == EventType::TlsHandshakeFailed
                && event.attributes.get("peer").map(String::as_str) == Some("upstream")
        })
        .expect("expected upstream TLS failure event");
    assert_eq!(
        upstream_failed
            .attributes
            .get("tls_failure_reason")
            .map(String::as_str),
        Some("unknown_ca")
    );
    assert_eq!(
        upstream_failed
            .attributes
            .get("tls_failure_source")
            .map(String::as_str),
        Some("upstream")
    );
    assert_eq!(
        upstream_failed
            .attributes
            .get("tls_ops_provider")
            .map(String::as_str),
        Some("rustls")
    );
    assert_eq!(
        upstream_failed
            .attributes
            .get("tls_failure_host_count")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        upstream_failed
            .attributes
            .get("tls_failure_host_rolling_count")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        upstream_failed
            .attributes
            .get("tls_learning_decision")
            .map(String::as_str),
        Some("applied")
    );
    assert_eq!(
        upstream_failed
            .attributes
            .get("tls_learning_reason_code")
            .map(String::as_str),
        Some("authoritative")
    );
    assert!(
        upstream_failed
            .attributes
            .get("detail")
            .map(|detail| !detail.is_empty())
            .unwrap_or(false),
        "expected non-empty TLS failure detail"
    );

    let stream_closed = events
        .iter()
        .find(|event| event.kind == EventType::StreamClosed)
        .expect("stream closed event");
    assert_eq!(
        stream_closed
            .attributes
            .get("reason_code")
            .map(String::as_str),
        Some("tls_handshake_failed")
    );

    let snapshot = diagnostics.snapshot();
    assert_eq!(snapshot.total_failures, 1);
    let host = snapshot.hosts.get("127.0.0.1").expect("host diagnostics");
    assert_eq!(host.total_failures, 1);
    assert_eq!(host.rolling_failures, 1);
    assert_eq!(host.by_source.get("upstream"), Some(&1));
    assert_eq!(host.by_reason.get("unknown_ca"), Some(&1));

    let learning_snapshot = learning.snapshot();
    assert_eq!(learning_snapshot.applied_total, 1);
    assert_eq!(learning_snapshot.ignored_total, 0);
    let learning_host = learning_snapshot
        .hosts
        .get("127.0.0.1")
        .expect("learning host");
    assert_eq!(learning_host.applied_total, 1);
    assert_eq!(learning_host.by_reason.get("unknown_ca"), Some(&1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_upstream_tls_failures_increment_host_scoped_counters() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        for _ in 0..2 {
            let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
            let _ = acceptor.accept(tcp).await;
        }
    });

    let sink = VecEventSink::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: false,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink, diagnostics, learning) =
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
        let _ = tls
            .write_all(
                b"GET /tls-failure-twice HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .await;
        let _ = tls.flush().await;
        let _ = read_to_end_allow_unexpected_eof(&mut tls).await;
    }

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(40)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let upstream_failures = events
        .iter()
        .filter(|event| {
            event.kind == EventType::TlsHandshakeFailed
                && event.attributes.get("peer").map(String::as_str) == Some("upstream")
        })
        .collect::<Vec<_>>();
    assert!(
        upstream_failures.len() >= 2,
        "expected at least two upstream TLS failures"
    );
    for event in &upstream_failures {
        assert_eq!(
            event
                .attributes
                .get("tls_failure_source")
                .map(String::as_str),
            Some("upstream")
        );
        assert_eq!(
            event.attributes.get("tls_ops_provider").map(String::as_str),
            Some("rustls")
        );
        assert!(
            event.attributes.contains_key("tls_failure_host_count"),
            "missing host counter"
        );
    }

    let host_counts = upstream_failures
        .iter()
        .filter_map(|event| event.attributes.get("tls_failure_host_count"))
        .map(|value| value.parse::<u64>().expect("host count parses"))
        .collect::<Vec<_>>();
    assert!(
        host_counts.contains(&1),
        "expected first upstream failure host counter"
    );
    assert!(
        host_counts.contains(&2),
        "expected second upstream failure host counter"
    );

    let snapshot = diagnostics.snapshot();
    assert_eq!(snapshot.total_failures, 2);
    let host = snapshot.hosts.get("127.0.0.1").expect("host diagnostics");
    assert_eq!(host.total_failures, 2);
    assert_eq!(host.rolling_failures, 2);
    assert_eq!(host.by_source.get("upstream"), Some(&2));
    assert_eq!(host.by_reason.get("unknown_ca"), Some(&2));

    let learning_snapshot = learning.snapshot();
    assert_eq!(learning_snapshot.applied_total, 2);
    assert_eq!(learning_snapshot.ignored_total, 0);
    let learning_host = learning_snapshot
        .hosts
        .get("127.0.0.1")
        .expect("learning host");
    assert_eq!(learning_host.applied_total, 2);
    assert_eq!(learning_host.by_reason.get("unknown_ca"), Some(&2));
}
