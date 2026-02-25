use std::time::Duration;

use mitm_core::{MitmConfig, MitmEngine, RouteEndpointConfig, RouteMode};
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
        idle_watchdog_timeout: Duration::from_secs(30),
        stream_stage_timeout: Duration::from_secs(5),
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

async fn start_echo_upstream_once() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo upstream");
    let port = listener.local_addr().expect("upstream addr").port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept upstream");
        let mut payload = [0_u8; 4];
        stream
            .read_exact(&mut payload)
            .await
            .expect("read upstream payload");
        assert_eq!(&payload, b"ping");
        stream
            .write_all(b"pong")
            .await
            .expect("write upstream echo");
    });
    (port, task)
}

async fn start_http_connect_proxy_once() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP proxy fixture");
    let port = listener.local_addr().expect("proxy addr").port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept proxy");

        let mut head = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream
                .read(&mut buffer)
                .await
                .expect("read proxy CONNECT head");
            if read == 0 {
                panic!("proxy fixture saw EOF before CONNECT head");
            }
            head.extend_from_slice(&buffer[..read]);
        }
        let text = String::from_utf8_lossy(&head).to_string();
        let first_line = text.lines().next().unwrap_or_default();
        assert_eq!(
            first_line, "CONNECT ignored-http.example:443 HTTP/1.1",
            "unexpected CONNECT line: {first_line}"
        );

        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .expect("write CONNECT response");

        let mut payload = [0_u8; 4];
        stream
            .read_exact(&mut payload)
            .await
            .expect("read tunneled payload");
        assert_eq!(&payload, b"ping");
        stream
            .write_all(b"pong")
            .await
            .expect("write tunneled echo");
    });
    (port, task)
}

async fn start_socks5_proxy_once() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind SOCKS5 fixture");
    let port = listener.local_addr().expect("socks addr").port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept SOCKS5");

        let mut greeting = [0_u8; 3];
        stream
            .read_exact(&mut greeting)
            .await
            .expect("read SOCKS5 greeting");
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        stream
            .write_all(&[0x05, 0x00])
            .await
            .expect("write SOCKS5 auth select");

        let mut request_header = [0_u8; 4];
        stream
            .read_exact(&mut request_header)
            .await
            .expect("read SOCKS5 request header");
        assert_eq!(request_header[0], 0x05);
        assert_eq!(request_header[1], 0x01);
        assert_eq!(request_header[2], 0x00);

        match request_header[3] {
            0x01 => {
                let mut addr = [0_u8; 4];
                stream.read_exact(&mut addr).await.expect("read ipv4 addr");
            }
            0x03 => {
                let mut len = [0_u8; 1];
                stream.read_exact(&mut len).await.expect("read domain len");
                let mut domain = vec![0_u8; len[0] as usize];
                stream
                    .read_exact(&mut domain)
                    .await
                    .expect("read domain bytes");
            }
            0x04 => {
                let mut addr = [0_u8; 16];
                stream.read_exact(&mut addr).await.expect("read ipv6 addr");
            }
            other => panic!("unexpected SOCKS5 ATYP: {other}"),
        }
        let mut port = [0_u8; 2];
        stream
            .read_exact(&mut port)
            .await
            .expect("read target port");

        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .expect("write SOCKS5 connect success");

        let mut payload = [0_u8; 4];
        stream
            .read_exact(&mut payload)
            .await
            .expect("read SOCKS tunneled payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").await.expect("write SOCKS echo");
    });
    (port, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_mode_tunnel_relays_to_target() {
    let sink = VecEventConsumer::default();
    let (upstream_port, upstream_task) = start_echo_upstream_once().await;
    let config = MitmConfig {
        ignore_hosts: vec!["127.0.0.1".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, _sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    let connect = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    client
        .write_all(connect.as_bytes())
        .await
        .expect("write CONNECT");
    let response = read_response_head(&mut client).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );

    client.write_all(b"ping").await.expect("write payload");
    let mut echoed = [0_u8; 4];
    client
        .read_exact(&mut echoed)
        .await
        .expect("read echoed payload");
    assert_eq!(&echoed, b"pong");

    upstream_task.await.expect("upstream task");
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reverse_mode_tunnel_uses_reverse_endpoint() {
    let sink = VecEventConsumer::default();
    let (reverse_port, reverse_task) = start_echo_upstream_once().await;
    let config = MitmConfig {
        route_mode: RouteMode::Reverse,
        reverse_upstream: Some(RouteEndpointConfig {
            host: "127.0.0.1".to_string(),
            port: reverse_port,
        }),
        ignore_hosts: vec!["requested.invalid".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, _sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    client
        .write_all(b"CONNECT requested.invalid:443 HTTP/1.1\r\nHost: requested.invalid:443\r\n\r\n")
        .await
        .expect("write CONNECT");
    let response = read_response_head(&mut client).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );

    client.write_all(b"ping").await.expect("write payload");
    let mut echoed = [0_u8; 4];
    client
        .read_exact(&mut echoed)
        .await
        .expect("read echoed payload");
    assert_eq!(&echoed, b"pong");

    reverse_task.await.expect("reverse task");
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_http_mode_honors_ignore_host_and_relays_tunnel() {
    let sink = VecEventConsumer::default();
    let (proxy_port, upstream_proxy_task) = start_http_connect_proxy_once().await;
    let config = MitmConfig {
        route_mode: RouteMode::UpstreamHttp,
        upstream_http_proxy: Some(RouteEndpointConfig {
            host: "127.0.0.1".to_string(),
            port: proxy_port,
        }),
        ignore_hosts: vec!["ignored-http.example".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, sidecar_task, sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    client
        .write_all(
            b"CONNECT ignored-http.example:443 HTTP/1.1\r\nHost: ignored-http.example:443\r\n\r\n",
        )
        .await
        .expect("write CONNECT");
    let response = read_response_head(&mut client).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );

    client.write_all(b"ping").await.expect("write payload");
    let mut echoed = [0_u8; 4];
    client
        .read_exact(&mut echoed)
        .await
        .expect("read echoed payload");
    assert_eq!(&echoed, b"pong");

    upstream_proxy_task.await.expect("upstream proxy task");
    sidecar_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::ConnectDecision
            && event.attributes.get("reason").map(String::as_str) == Some("ignored_host")
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_socks5_mode_honors_ignore_host_and_relays_tunnel() {
    let sink = VecEventConsumer::default();
    let (socks_port, socks_task) = start_socks5_proxy_once().await;
    let config = MitmConfig {
        route_mode: RouteMode::UpstreamSocks5,
        upstream_socks5_proxy: Some(RouteEndpointConfig {
            host: "127.0.0.1".to_string(),
            port: socks_port,
        }),
        ignore_hosts: vec!["ignored-socks.example".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, sidecar_task, sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    client
        .write_all(
            b"CONNECT ignored-socks.example:443 HTTP/1.1\r\nHost: ignored-socks.example:443\r\n\r\n",
        )
        .await
        .expect("write CONNECT");
    let response = read_response_head(&mut client).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );

    client.write_all(b"ping").await.expect("write payload");
    let mut echoed = [0_u8; 4];
    client
        .read_exact(&mut echoed)
        .await
        .expect("read echoed payload");
    assert_eq!(&echoed, b"pong");

    socks_task.await.expect("socks task");
    sidecar_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::ConnectDecision
            && event.attributes.get("reason").map(String::as_str) == Some("ignored_host")
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_socks5_blocked_target_never_dials_proxy() {
    let sink = VecEventConsumer::default();
    let socks_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind socks listener");
    let socks_port = socks_listener.local_addr().expect("socks addr").port();
    let config = MitmConfig {
        route_mode: RouteMode::UpstreamSocks5,
        upstream_socks5_proxy: Some(RouteEndpointConfig {
            host: "127.0.0.1".to_string(),
            port: socks_port,
        }),
        blocked_hosts: vec!["blocked-socks.example".to_string()],
        ..MitmConfig::default()
    };
    let (proxy_addr, sidecar_task, sink) = start_sidecar_with_sink(sink, config).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    client
        .write_all(
            b"CONNECT blocked-socks.example:443 HTTP/1.1\r\nHost: blocked-socks.example:443\r\n\r\n",
        )
        .await
        .expect("write CONNECT");
    let response = read_response_head(&mut client).await;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "unexpected response: {response}"
    );

    let accept_result =
        tokio::time::timeout(Duration::from_millis(300), socks_listener.accept()).await;
    assert!(
        accept_result.is_err(),
        "blocked target unexpectedly opened an upstream SOCKS5 socket"
    );

    sidecar_task.abort();
    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::StreamClosed
            && event.attributes.get("reason_code").map(String::as_str) == Some("blocked")
    }));
}
