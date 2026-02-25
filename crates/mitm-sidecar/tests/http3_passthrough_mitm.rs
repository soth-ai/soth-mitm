use std::time::Duration;

use mitm_core::{MitmConfig, MitmEngine};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_hint_forces_tunnel_passthrough_and_emits_telemetry() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut request = [0_u8; 4];
        stream
            .read_exact(&mut request)
            .await
            .expect("read tunnel bytes");
        assert_eq!(&request, b"ping");
        stream
            .write_all(b"pong")
            .await
            .expect("write tunneled response");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        http3_passthrough: true,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    let connect = format!(
        concat!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
            "Host: 127.0.0.1:{}\r\n",
            "X-Proxy-Protocol: h3\r\n",
            "\r\n"
        ),
        upstream_addr.port(),
        upstream_addr.port()
    );
    client
        .write_all(connect.as_bytes())
        .await
        .expect("write CONNECT");
    let connect_response = read_response_head(&mut client).await;
    assert!(
        connect_response.starts_with("HTTP/1.1 200 Connection Established"),
        "{connect_response}"
    );

    client
        .write_all(b"ping")
        .await
        .expect("write tunnel payload");
    let mut echoed = [0_u8; 4];
    client
        .read_exact(&mut echoed)
        .await
        .expect("read tunnel echo");
    assert_eq!(&echoed, b"pong");
    client.shutdown().await.expect("shutdown client");

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::Http3Passthrough
            && event
                .attributes
                .get("passthrough_protocol")
                .map(String::as_str)
                == Some("http3")
            && event.attributes.get("passthrough_mode").map(String::as_str) == Some("tunnel")
            && event.attributes.get("requested_by").map(String::as_str) == Some("x-proxy-protocol")
            && event.attributes.get("policy_action").map(String::as_str) == Some("intercept")
    }));
    assert!(
        !events
            .iter()
            .any(|event| event.kind == EventType::TlsHandshakeStarted),
        "http3 passthrough should not perform TLS MITM handshakes"
    );
    assert!(events.iter().any(|event| {
        event.kind == EventType::StreamClosed
            && event.attributes.get("reason_code").map(String::as_str) == Some("relay_eof")
    }));
}
