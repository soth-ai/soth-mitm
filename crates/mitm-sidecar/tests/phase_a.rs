use std::collections::HashMap;
use std::time::Duration;

use mitm_core::{ConnectParseMode, MitmConfig, MitmEngine};
use mitm_observe::{EventType, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn build_engine(
    config: MitmConfig,
    sink: VecEventConsumer,
) -> MitmEngine<DefaultPolicyEngine, VecEventConsumer> {
    let policy =
        DefaultPolicyEngine::new(config.ignore_hosts.clone(), config.blocked_hosts.clone());
    MitmEngine::new(config, policy, sink)
}

async fn start_sidecar_with_sink(
    sink: VecEventConsumer,
    config: MitmConfig,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
    VecEventConsumer,
) {
    let sidecar_config = SidecarConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: 64 * 1024,
        idle_watchdog_timeout: std::time::Duration::from_secs(30),
        upstream_connect_timeout: std::time::Duration::from_secs(10),
        stream_stage_timeout: std::time::Duration::from_secs(5),
        unix_socket_path: None,
    };
    let engine = build_engine(config, sink.clone());
    let server = SidecarServer::new(sidecar_config, engine).expect("build sidecar");
    let listener = server.bind_listener().await.expect("bind sidecar");
    let addr = listener.local_addr().expect("listener local addr");
    let handle = tokio::spawn(server.run_with_listener(listener));
    (addr, handle, sink)
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

fn assert_event_ordering_metadata(events: &[mitm_observe::Event]) {
    assert!(!events.is_empty(), "expected at least one event");

    let mut last_sequence_id = 0_u64;
    let mut last_monotonic_ns = 0_u128;
    let mut per_flow_last = HashMap::<u64, u64>::new();

    for event in events {
        assert!(event.sequence_id > 0, "missing global sequence id");
        assert!(
            event.sequence_id > last_sequence_id,
            "global sequence id must be strictly increasing"
        );
        last_sequence_id = event.sequence_id;

        assert!(event.flow_sequence_id > 0, "missing flow sequence id");
        let flow_last = per_flow_last
            .entry(event.context.flow_id)
            .or_insert(event.flow_sequence_id.saturating_sub(1));
        assert!(
            event.flow_sequence_id > *flow_last,
            "flow sequence id must be strictly increasing per flow"
        );
        *flow_last = event.flow_sequence_id;

        assert!(
            event.occurred_at_monotonic_ns > 0,
            "missing monotonic timestamp"
        );
        assert!(
            event.occurred_at_monotonic_ns > last_monotonic_ns,
            "monotonic timestamp must be strictly increasing"
        );
        last_monotonic_ns = event.occurred_at_monotonic_ns;
    }
}

fn assert_exactly_one_stream_closed_per_flow(events: &[mitm_observe::Event]) {
    let mut by_flow = HashMap::<u64, usize>::new();
    for event in events {
        if event.kind == EventType::StreamClosed {
            *by_flow.entry(event.context.flow_id).or_insert(0) += 1;
        }
    }
    assert!(!by_flow.is_empty(), "expected at least one stream_closed");
    for (flow_id, count) in by_flow {
        assert_eq!(
            count, 1,
            "flow_id={flow_id} emitted {count} stream_closed events"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_action_returns_403_and_emits_reason_code() {
    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        blocked_hosts: vec!["blocked.example".to_string()],
        ..MitmConfig::default()
    };

    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    client
        .write_all(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
        .await
        .expect("write CONNECT");

    let response = read_response_head(&mut client).await;
    assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");

    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert_event_ordering_metadata(&events);
    assert_exactly_one_stream_closed_per_flow(&events);
    assert!(events.iter().any(|e| e.kind == EventType::ConnectReceived));
    assert!(events.iter().any(|e| e.kind == EventType::ConnectDecision));

    let stream_closed = events
        .iter()
        .find(|e| e.kind == EventType::StreamClosed)
        .expect("stream_closed emitted");
    assert_eq!(
        stream_closed
            .attributes
            .get("reason_code")
            .map(String::as_str),
        Some("blocked")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_connect_emits_parse_failure_events() {
    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        ignore_hosts: vec!["127.0.0.1".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    client
        .write_all(b"GET / HTTP/1.2\r\nHost: example.com\r\n\r\n")
        .await
        .expect("write malformed request");

    let response = read_response_head(&mut client).await;
    assert!(response.starts_with("HTTP/1.1 400"), "response: {response}");

    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert_event_ordering_metadata(&events);
    assert_exactly_one_stream_closed_per_flow(&events);
    let parse_failed = events
        .iter()
        .find(|e| e.kind == EventType::ConnectParseFailed)
        .expect("connect_parse_failed emitted");
    assert_eq!(
        parse_failed
            .attributes
            .get("parse_error_code")
            .map(String::as_str),
        Some("method_not_connect")
    );

    let stream_closed = events
        .iter()
        .find(|e| e.kind == EventType::StreamClosed)
        .expect("stream_closed emitted");
    assert_eq!(
        stream_closed
            .attributes
            .get("reason_code")
            .map(String::as_str),
        Some("connect_parse_failed")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_connect_parser_rejects_lowercase_method() {
    let sink = VecEventConsumer::default();
    let config = MitmConfig::default();
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    client
        .write_all(b"connect example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .expect("write malformed connect line");

    let response = read_response_head(&mut client).await;
    assert!(response.starts_with("HTTP/1.1 400"), "response: {response}");

    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let parse_failed = events
        .iter()
        .find(|e| e.kind == EventType::ConnectParseFailed)
        .expect("connect_parse_failed emitted");
    assert_eq!(
        parse_failed
            .attributes
            .get("parse_error_code")
            .map(String::as_str),
        Some("method_not_connect")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lenient_connect_parser_accepts_lowercase_absolute_form() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let (mut conn, _) = upstream.accept().await.expect("accept upstream");
        let mut buffer = [0_u8; 4];
        conn.read_exact(&mut buffer).await.expect("read upstream");
        assert_eq!(&buffer, b"ping");
        conn.write_all(b"pong").await.expect("write upstream");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        connect_parse_mode: ConnectParseMode::Lenient,
        ignore_hosts: vec!["127.0.0.1".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    let connect = format!(
        "connect https://{}:{}/mitm HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        upstream_addr.ip(),
        upstream_addr.port(),
        upstream_addr.ip(),
        upstream_addr.port()
    );
    client
        .write_all(connect.as_bytes())
        .await
        .expect("write CONNECT");

    let response = read_response_head(&mut client).await;
    assert!(
        response.starts_with("HTTP/1.1 200 Connection Established"),
        "response: {response}"
    );

    client
        .write_all(b"ping")
        .await
        .expect("write tunnel payload");
    let mut pong = [0_u8; 4];
    client
        .read_exact(&mut pong)
        .await
        .expect("read tunnel payload");
    assert_eq!(&pong, b"pong");

    client.shutdown().await.expect("shutdown client");
    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|e| e.kind == EventType::ConnectDecision));
    assert!(events.iter().any(|e| {
        e.kind == EventType::StreamClosed
            && e.attributes.get("reason_code").map(String::as_str) == Some("relay_eof")
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_action_relays_data_end_to_end() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let (mut conn, _) = upstream.accept().await.expect("accept upstream");
        let mut buffer = [0_u8; 4];
        conn.read_exact(&mut buffer).await.expect("read upstream");
        assert_eq!(&buffer, b"ping");
        conn.write_all(b"pong").await.expect("write upstream");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        ignore_hosts: vec!["127.0.0.1".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    let connect = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        upstream_addr.ip(),
        upstream_addr.port(),
        upstream_addr.ip(),
        upstream_addr.port()
    );
    client
        .write_all(connect.as_bytes())
        .await
        .expect("write CONNECT");

    let response = read_response_head(&mut client).await;
    assert!(
        response.starts_with("HTTP/1.1 200 Connection Established"),
        "response: {response}"
    );

    client
        .write_all(b"ping")
        .await
        .expect("write tunnel payload");
    let mut pong = [0_u8; 4];
    client
        .read_exact(&mut pong)
        .await
        .expect("read tunnel payload");
    assert_eq!(&pong, b"pong");

    client.shutdown().await.expect("shutdown client");
    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert_event_ordering_metadata(&events);
    assert_exactly_one_stream_closed_per_flow(&events);
    assert!(events.iter().any(|e| e.kind == EventType::ConnectDecision));
    let stream_closed = events
        .iter()
        .find(|e| e.kind == EventType::StreamClosed)
        .expect("stream_closed emitted");
    assert_eq!(
        stream_closed
            .attributes
            .get("reason_code")
            .map(String::as_str),
        Some("relay_eof")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_short_lived_tunnels_500() {
    const N: usize = 500;
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        for _ in 0..N {
            let (mut conn, _) = upstream.accept().await.expect("accept upstream");
            tokio::spawn(async move {
                let mut scratch = [0_u8; 16];
                let _ = conn.read(&mut scratch).await;
            });
        }
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        ignore_hosts: vec!["127.0.0.1".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, _sink) = start_sidecar_with_sink(sink, config).await;

    let mut tasks = Vec::with_capacity(N);
    for _ in 0..N {
        let connect_addr = proxy_addr;
        let target_ip = upstream_addr.ip();
        let target_port = upstream_addr.port();
        tasks.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(connect_addr)
                .await
                .expect("connect proxy");
            let connect = format!(
                "CONNECT {target_ip}:{target_port} HTTP/1.1\r\nHost: {target_ip}:{target_port}\r\n\r\n"
            );
            client
                .write_all(connect.as_bytes())
                .await
                .expect("write CONNECT");
            let response = read_response_head(&mut client).await;
            assert!(
                response.starts_with("HTTP/1.1 200 Connection Established"),
                "response: {response}"
            );
        }));
    }

    for task in tasks {
        task.await.expect("client task");
    }

    upstream_task.await.expect("upstream accept loop");
    tokio::time::sleep(Duration::from_millis(50)).await;
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_host_never_opens_upstream_socket() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        blocked_hosts: vec!["127.0.0.1".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, _sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    let connect = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        upstream_addr.ip(),
        upstream_addr.port(),
        upstream_addr.ip(),
        upstream_addr.port()
    );
    client
        .write_all(connect.as_bytes())
        .await
        .expect("write CONNECT");

    let response = read_response_head(&mut client).await;
    assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");

    let accept_result = tokio::time::timeout(Duration::from_millis(200), upstream.accept()).await;
    assert!(
        accept_result.is_err(),
        "blocked flow unexpectedly opened an upstream TCP socket"
    );
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_action_does_not_emit_tls_handshake_events() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let (mut conn, _) = upstream.accept().await.expect("accept upstream");
        let mut buffer = [0_u8; 4];
        conn.read_exact(&mut buffer).await.expect("read upstream");
        assert_eq!(&buffer, b"ping");
        conn.write_all(b"pong").await.expect("write upstream");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        ignore_hosts: vec!["127.0.0.1".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    let connect = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        upstream_addr.ip(),
        upstream_addr.port(),
        upstream_addr.ip(),
        upstream_addr.port()
    );
    client
        .write_all(connect.as_bytes())
        .await
        .expect("write CONNECT");
    let response = read_response_head(&mut client).await;
    assert!(
        response.starts_with("HTTP/1.1 200 Connection Established"),
        "response: {response}"
    );

    client
        .write_all(b"ping")
        .await
        .expect("write tunnel payload");
    let mut pong = [0_u8; 4];
    client
        .read_exact(&mut pong)
        .await
        .expect("read tunnel payload");
    assert_eq!(&pong, b"pong");

    client.shutdown().await.expect("shutdown client");
    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(30)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(
        events.iter().all(|event| {
            event.kind != EventType::TlsHandshakeStarted
                && event.kind != EventType::TlsHandshakeSucceeded
                && event.kind != EventType::TlsHandshakeFailed
        }),
        "tunnel-only flows must not emit TLS handshake MITM events"
    );
}
