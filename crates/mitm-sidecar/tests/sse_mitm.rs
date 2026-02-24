use std::time::Duration;

use mitm_core::{MitmConfig, MitmEngine};
use mitm_http::ApplicationProtocol;
use mitm_observe::{Event, EventType, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};
use mitm_tls::{build_http1_client_config, build_http1_server_config_for_host};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
) {
    let sidecar_config = SidecarConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: 64 * 1024,
        idle_watchdog_timeout: std::time::Duration::from_secs(30),
        stream_stage_timeout: std::time::Duration::from_secs(5),
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

fn attr<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
    event.attributes.get(key).map(String::as_str)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parses_sse_events_incrementally_and_flushes_tail_on_stream_close() {
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
            request_text.starts_with("GET /sse HTTP/1.1"),
            "{request_text}"
        );

        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/event-stream; charset=utf-8\r\n",
            "Cache-Control: no-cache\r\n",
            "Connection: close\r\n",
            "\r\n"
        );
        tls.write_all(response.as_bytes())
            .await
            .expect("write headers");
        tls.flush().await.expect("flush headers");

        tls.write_all(b"id: 1\n").await.expect("write sse id");
        tls.write_all(b"event: message\n")
            .await
            .expect("write sse event");
        tls.write_all(b"data: hello\n")
            .await
            .expect("write sse data1");
        tls.write_all(b"data: world\n\n")
            .await
            .expect("write sse data2");
        tls.flush().await.expect("flush first sse event");

        tokio::time::sleep(Duration::from_millis(20)).await;

        tls.write_all(b"retry: 2000\n")
            .await
            .expect("write sse retry");
        tls.write_all(b"data: tail-without-terminator")
            .await
            .expect("write trailing sse data");
        tls.shutdown().await.expect("shutdown upstream TLS");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: false,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;

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
    tls.write_all(b"GET /sse HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    tls.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut tls).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1 200 OK"),
        "{response_text}"
    );
    assert!(response_text.contains("data: hello"), "{response_text}");
    assert!(
        response_text.contains("data: tail-without-terminator"),
        "{response_text}"
    );

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(30)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let sse_events = events
        .iter()
        .filter(|event| event.kind == EventType::SseEvent)
        .collect::<Vec<_>>();
    assert_eq!(sse_events.len(), 2, "expected 2 parsed SSE events");
    assert!(sse_events
        .iter()
        .all(|event| event.context.protocol == ApplicationProtocol::Sse));

    let first = sse_events[0];
    assert_eq!(attr(first, "sequence_no"), Some("1"));
    assert_eq!(attr(first, "id"), Some("1"));
    assert_eq!(attr(first, "event"), Some("message"));
    assert_eq!(attr(first, "data_line_count"), Some("2"));
    assert_eq!(attr(first, "data"), Some("hello\nworld"));
    assert_eq!(attr(first, "retry_ms"), None);

    let second = sse_events[1];
    assert_eq!(attr(second, "sequence_no"), Some("2"));
    assert_eq!(attr(second, "retry_ms"), Some("2000"));
    assert_eq!(attr(second, "data_line_count"), Some("1"));
    assert_eq!(attr(second, "data"), Some("tail-without-terminator"));

    assert!(events.iter().any(|event| {
        event.kind == EventType::StreamClosed
            && event.attributes.get("reason_code").map(String::as_str)
                == Some("mitm_http_completed")
    }));
}
