use std::sync::Arc;
use std::time::Duration;

use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::{EventType, VecEventSink};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer, TlsDiagnostics, TlsLearningGuardrails};
use mitm_tls::{build_http1_client_config, build_http1_server_config_for_host};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn build_engine(
    config: MitmConfig,
    sink: VecEventSink,
) -> MitmEngine<DefaultPolicyEngine, VecEventSink> {
    let policy =
        DefaultPolicyEngine::new(config.ignore_hosts.clone(), config.blocked_hosts.clone());
    MitmEngine::new(config, policy, sink)
}

async fn start_sidecar_with_sink(
    sink: VecEventSink,
    config: MitmConfig,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
    VecEventSink,
    Arc<TlsDiagnostics>,
    Arc<TlsLearningGuardrails>,
) {
    let sidecar_config = SidecarConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: 64 * 1024,
    };
    let engine = build_engine(config, sink.clone());
    let server = SidecarServer::new(sidecar_config, engine).expect("build sidecar");
    let diagnostics = server.tls_diagnostics_handle();
    let learning = server.tls_learning_handle();
    let listener = server.bind_listener().await.expect("bind sidecar");
    let addr = listener.local_addr().expect("listener local addr");
    let handle = tokio::spawn(server.run_with_listener(listener));
    (addr, handle, sink, diagnostics, learning)
}

async fn read_response_head(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !data.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.expect("read response");
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8_lossy(&data).to_string()
}

async fn read_http_head<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut data = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !data.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.expect("read HTTP head");
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);
    }
    data
}

async fn read_to_end_allow_unexpected_eof<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(read) => out.extend_from_slice(&buf[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionAborted => break,
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => break,
            Err(error) => panic!("read response: {error}"),
        }
    }
    out
}

fn parse_content_length(head_bytes: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head_bytes);
    for line in text.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value.trim().parse::<usize>().expect("valid content-length");
            }
        }
    }
    0
}

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

    let sink = VecEventSink::default();
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

    let sink = VecEventSink::default();
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
