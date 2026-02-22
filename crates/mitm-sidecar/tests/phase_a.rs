use std::time::Duration;

use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::{EventType, VecEventSink};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
) {
    let sidecar_config = SidecarConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: 64 * 1024,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_action_returns_403_and_emits_reason_code() {
    let sink = VecEventSink::default();
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
    let sink = VecEventSink::default();
    let config = MitmConfig {
        ignore_hosts: vec!["127.0.0.1".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("write malformed request");

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

    let sink = VecEventSink::default();
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

    let sink = VecEventSink::default();
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
