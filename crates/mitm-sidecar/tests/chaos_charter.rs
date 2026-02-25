use std::sync::Arc;
use std::time::Duration;

use mitm_core::{MitmConfig, MitmEngine};
use mitm_http::ApplicationProtocol;
use mitm_observe::{Event, EventType, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{RuntimeGovernor, SidecarConfig, SidecarServer};
use mitm_tls::{
    build_http1_client_config, build_http1_server_config_for_host, build_http_client_config,
    build_http_server_config_for_host,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
    Arc<RuntimeGovernor>,
) {
    let sidecar_config = SidecarConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: 64 * 1024,
        idle_watchdog_timeout: std::time::Duration::from_secs(30),
        stream_stage_timeout: std::time::Duration::from_secs(5),
        unix_socket_path: None,
    };
    let engine = build_engine(config, sink.clone());
    let server = SidecarServer::new(sidecar_config, engine).expect("build sidecar");
    let runtime = server.runtime_observability_handle();
    let listener = server.bind_listener().await.expect("bind sidecar");
    let addr = listener.local_addr().expect("listener local addr");
    let handle = tokio::spawn(server.run_with_listener(listener));
    (addr, handle, sink, runtime)
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

fn stream_closed_event<'a>(
    events: &'a [Event],
    protocol: ApplicationProtocol,
    reason_code: &str,
) -> Option<&'a Event> {
    events.iter().find(|event| {
        event.kind == EventType::StreamClosed
            && event.context.protocol == protocol
            && event.attributes.get("reason_code").map(String::as_str) == Some(reason_code)
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_fragmented_client_hello_emits_failed_handshake_close() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let (_stream, _) = upstream_listener.accept().await.expect("accept upstream");
        sleep(Duration::from_millis(80)).await;
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink, _runtime) = start_sidecar_with_sink(sink, config).await;

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

    // Malformed TLS ClientHello bytes written one-at-a-time to simulate fragmented handshake traffic.
    let malformed_client_hello = [
        0x16_u8, 0x03, 0x03, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c, 0x03, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for byte in malformed_client_hello {
        tcp.write_all(&[byte])
            .await
            .expect("write fragmented TLS byte");
        sleep(Duration::from_millis(2)).await;
    }
    let _ = tcp.shutdown().await;

    upstream_task.await.expect("upstream task");
    sleep(Duration::from_millis(60)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::TlsHandshakeFailed
            && event.attributes.get("peer").map(String::as_str) == Some("downstream")
    }));
    assert!(
        stream_closed_event(&events, ApplicationProtocol::Tunnel, "tls_handshake_failed").is_some()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_hpack_payload_emits_http2_error_close() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = match acceptor.accept(tcp).await {
            Ok(stream) => stream,
            Err(_) => return false,
        };
        let mut h2_conn = match h2::server::handshake(tls).await {
            Ok(connection) => connection,
            Err(_) => return false,
        };
        let received = tokio::time::timeout(Duration::from_millis(300), h2_conn.accept()).await;
        matches!(received, Ok(Some(Ok(_))))
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink, _runtime) = start_sidecar_with_sink(sink, config).await;

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

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .expect("write preface");
    tls.write_all(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await
        .expect("write settings frame");
    // HEADERS frame with invalid HPACK payload (0xff), END_STREAM | END_HEADERS on stream 1.
    tls.write_all(&[0x00, 0x00, 0x01, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, 0xff])
        .await
        .expect("write malformed headers frame");
    tls.flush().await.expect("flush malformed frames");
    let mut scratch = [0_u8; 64];
    let _ = tokio::time::timeout(Duration::from_millis(200), tls.read(&mut scratch)).await;
    let _ = tls.shutdown().await;

    let saw_upstream_request = tokio::time::timeout(Duration::from_secs(1), upstream_task)
        .await
        .expect("upstream task timeout")
        .expect("upstream task");
    assert!(
        !saw_upstream_request,
        "malformed downstream HPACK bytes should not reach upstream request handling"
    );

    sleep(Duration::from_millis(60)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(stream_closed_event(&events, ApplicationProtocol::Http2, "mitm_http_error").is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn infinite_sse_stream_hits_decoder_budget_and_closes_deterministically() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("TLS accept");
        let _request_head = read_http_head(&mut tls).await;

        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/event-stream\r\n",
            "Cache-Control: no-cache\r\n",
            "Connection: keep-alive\r\n",
            "\r\n"
        );
        tls.write_all(response.as_bytes())
            .await
            .expect("write headers");
        tls.flush().await.expect("flush headers");

        let large_data_line = format!("data: {}\n", "x".repeat(2048));
        for _ in 0..8 {
            if let Err(error) = tls.write_all(large_data_line.as_bytes()).await {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                ) {
                    break;
                }
                panic!("write oversized SSE line: {error}");
            }
            tls.flush().await.expect("flush SSE line");
            sleep(Duration::from_millis(5)).await;
        }
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: false,
        max_flow_decoder_buffer_bytes: 128,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink, runtime) = start_sidecar_with_sink(sink, config).await;

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
        b"GET /infinite-sse HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n",
    )
    .await
    .expect("write request");
    tls.flush().await.expect("flush request");
    let _ = read_http_head(&mut tls).await;
    let _ = tokio::time::timeout(Duration::from_millis(200), async {
        let mut scratch = [0_u8; 64];
        let _ = tls.read(&mut scratch).await;
    })
    .await;
    let _ = tls.shutdown().await;

    let _ = tokio::time::timeout(Duration::from_secs(1), upstream_task).await;
    sleep(Duration::from_millis(80)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(stream_closed_event(&events, ApplicationProtocol::Http1, "mitm_http_error").is_some());
    assert!(
        runtime.snapshot().decoder_failure_count >= 1,
        "expected decoder failure metric increment for oversized SSE chaos case"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jitter_and_loss_in_tunnel_path_emit_relay_error_close() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut first = [0_u8; 4];
        stream
            .read_exact(&mut first)
            .await
            .expect("read first tunnel chunk");
        assert_eq!(&first, b"ping");
        sleep(Duration::from_millis(20)).await;
        drop(stream);
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        ignore_hosts: vec!["127.0.0.1".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink, _runtime) = start_sidecar_with_sink(sink, config).await;

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

    tcp.write_all(b"ping").await.expect("write first payload");
    tcp.flush().await.expect("flush first payload");
    sleep(Duration::from_millis(60)).await;
    let _ = tcp.write_all(b"pong").await;
    let mut scratch = [0_u8; 32];
    let _ = tokio::time::timeout(Duration::from_millis(200), tcp.read(&mut scratch)).await;
    let _ = tcp.shutdown().await;
    drop(tcp);

    upstream_task.await.expect("upstream task");
    sleep(Duration::from_millis(160)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let close_reasons = events
        .iter()
        .filter(|event| {
            event.kind == EventType::StreamClosed
                && event.context.protocol == ApplicationProtocol::Tunnel
        })
        .map(|event| {
            event
                .attributes
                .get("reason_code")
                .cloned()
                .unwrap_or_else(|| "<missing>".to_string())
        })
        .collect::<Vec<_>>();
    let saw_expected_close =
        stream_closed_event(&events, ApplicationProtocol::Tunnel, "relay_error").is_some()
            || stream_closed_event(&events, ApplicationProtocol::Tunnel, "relay_eof").is_some();
    assert!(
        saw_expected_close,
        "expected tunnel close with relay_error or relay_eof, got reasons: {close_reasons:?}"
    );
}
