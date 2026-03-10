use std::io;
use std::time::Duration;

use soth_mitm::test_engine::{MitmConfig, MitmEngine};
use soth_mitm::test_observe::{Event, EventType, VecEventConsumer};
use soth_mitm::test_policy::DefaultPolicyEngine;
use soth_mitm::test_protocol::ApplicationProtocol;
use soth_mitm::test_server::{SidecarConfig, SidecarServer};
use soth_mitm::test_tls::{build_http1_client_config, build_http1_server_config_for_host};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebSocketFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
    masked: bool,
}

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
        accept_retry_backoff_ms: 100,
        idle_watchdog_timeout: std::time::Duration::from_secs(30),
        websocket_idle_watchdog_timeout: std::time::Duration::from_secs(120),
        upstream_connect_timeout: std::time::Duration::from_secs(10),
        stream_stage_timeout: std::time::Duration::from_secs(5),
        h2_body_idle_timeout: std::time::Duration::from_secs(5),
        h2_response_overflow_mode: soth_mitm::test_server::H2ResponseOverflowMode::TruncateContinue,
        unix_socket_path: None,
    };
    start_sidecar_with_sink_and_config(sink, config, sidecar_config).await
}

async fn start_sidecar_with_sink_and_config(
    sink: VecEventConsumer,
    config: MitmConfig,
    sidecar_config: SidecarConfig,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
    VecEventConsumer,
) {
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

async fn write_ws_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    opcode: u8,
    payload: &[u8],
    mask: Option<[u8; 4]>,
) -> io::Result<()> {
    write_ws_frame_with_fin(stream, true, opcode, payload, mask).await
}

async fn write_ws_frame_with_fin<S: AsyncWrite + Unpin>(
    stream: &mut S,
    fin: bool,
    opcode: u8,
    payload: &[u8],
    mask: Option<[u8; 4]>,
) -> io::Result<()> {
    let fin_opcode = (if fin { 0b1000_0000 } else { 0 }) | (opcode & 0b0000_1111);
    let masked = mask.is_some();
    let payload_len = payload.len() as u64;
    let mut header = Vec::with_capacity(14);
    header.push(fin_opcode);
    let mask_bit = if masked { 0b1000_0000 } else { 0 };
    if payload_len <= 125 {
        header.push(mask_bit | payload_len as u8);
    } else if payload_len <= u16::MAX as u64 {
        header.push(mask_bit | 126);
        header.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        header.push(mask_bit | 127);
        header.extend_from_slice(&payload_len.to_be_bytes());
    }
    if let Some(masking_key) = mask {
        header.extend_from_slice(&masking_key);
    }
    stream.write_all(&header).await?;
    if let Some(masking_key) = mask {
        let mut masked_payload = payload.to_vec();
        for (idx, byte) in masked_payload.iter_mut().enumerate() {
            *byte ^= masking_key[idx % 4];
        }
        stream.write_all(&masked_payload).await?;
    } else {
        stream.write_all(payload).await?;
    }
    stream.flush().await?;
    Ok(())
}

async fn read_ws_frame<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<WebSocketFrame> {
    let mut initial_header = [0_u8; 2];
    stream.read_exact(&mut initial_header).await?;
    let fin = (initial_header[0] & 0b1000_0000) != 0;
    let opcode = initial_header[0] & 0b0000_1111;
    let masked = (initial_header[1] & 0b1000_0000) != 0;
    let payload_len = match initial_header[1] & 0b0111_1111 {
        len @ 0..=125 => len as u64,
        126 => {
            let mut ext = [0_u8; 2];
            stream.read_exact(&mut ext).await?;
            u16::from_be_bytes(ext) as u64
        }
        127 => {
            let mut ext = [0_u8; 8];
            stream.read_exact(&mut ext).await?;
            u64::from_be_bytes(ext)
        }
        _ => unreachable!("masked payload length marker is always <= 127"),
    };
    let masking_key = if masked {
        let mut key = [0_u8; 4];
        stream.read_exact(&mut key).await?;
        Some(key)
    } else {
        None
    };
    let mut payload = vec![0_u8; payload_len as usize];
    if payload_len > 0 {
        stream.read_exact(&mut payload).await?;
    }
    if let Some(mask) = masking_key {
        for (idx, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[idx % 4];
        }
    }
    Ok(WebSocketFrame {
        fin,
        opcode,
        payload,
        masked,
    })
}

fn attr<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
    event.attributes.get(key).map(String::as_str)
}

async fn connect_websocket_via_proxy(
    proxy_addr: std::net::SocketAddr,
    upstream_port: u16,
    websocket_key: &str,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut tcp = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    let connect = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
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
    let upgrade_request = format!(
        "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {websocket_key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    tls.write_all(upgrade_request.as_bytes())
        .await
        .expect("write websocket upgrade request");
    tls.flush().await.expect("flush websocket upgrade request");

    let upgrade_response = read_http_head(&mut tls).await;
    let upgrade_text = String::from_utf8_lossy(&upgrade_response);
    assert!(
        upgrade_text.starts_with("HTTP/1.1 101 Switching Protocols"),
        "{upgrade_text}"
    );
    tls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_upgrade_relays_text_and_binary_frames_without_corruption() {
    let text_payload = b"hello-websocket".to_vec();
    let binary_payload = vec![0, 1, 2, 3, 4, 251, 252, 253, 254, 255];
    let text_payload_upstream = text_payload.clone();
    let binary_payload_upstream = binary_payload.clone();

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
            request_text.starts_with("GET /ws HTTP/1.1"),
            "{request_text}"
        );
        assert!(
            request_text
                .to_ascii_lowercase()
                .contains("upgrade: websocket"),
            "{request_text}"
        );
        assert!(
            request_text
                .to_ascii_lowercase()
                .contains("connection: upgrade"),
            "{request_text}"
        );

        let upgrade_response = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
            "\r\n"
        );
        tls.write_all(upgrade_response.as_bytes())
            .await
            .expect("write upgrade response");
        tls.flush().await.expect("flush upgrade response");

        let text_frame = read_ws_frame(&mut tls).await.expect("read text frame");
        assert_eq!(text_frame.opcode, 0x1);
        assert_eq!(text_frame.payload, text_payload_upstream);
        write_ws_frame(&mut tls, 0x1, &text_frame.payload, None)
            .await
            .expect("write text echo frame");

        let binary_frame = read_ws_frame(&mut tls).await.expect("read binary frame");
        assert_eq!(binary_frame.opcode, 0x2);
        assert_eq!(binary_frame.payload, binary_payload_upstream);
        write_ws_frame(&mut tls, 0x2, &binary_frame.payload, None)
            .await
            .expect("write binary echo frame");

        let close_frame = read_ws_frame(&mut tls).await.expect("read close frame");
        assert_eq!(close_frame.opcode, 0x8);
        write_ws_frame(&mut tls, 0x8, &[], None)
            .await
            .expect("write close frame");
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
    let upgrade_request = concat!(
        "GET /ws HTTP/1.1\r\n",
        "Host: 127.0.0.1\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "\r\n"
    );
    tls.write_all(upgrade_request.as_bytes())
        .await
        .expect("write websocket upgrade request");
    tls.flush().await.expect("flush websocket upgrade request");

    let upgrade_response = read_http_head(&mut tls).await;
    let upgrade_text = String::from_utf8_lossy(&upgrade_response);
    assert!(
        upgrade_text.starts_with("HTTP/1.1 101 Switching Protocols"),
        "{upgrade_text}"
    );

    write_ws_frame(&mut tls, 0x1, &text_payload, Some([1, 2, 3, 4]))
        .await
        .expect("write masked text frame");

    let echoed_text = read_ws_frame(&mut tls)
        .await
        .expect("read echoed text frame");
    assert_eq!(echoed_text.opcode, 0x1);
    assert_eq!(echoed_text.payload, text_payload);
    assert!(!echoed_text.masked);

    write_ws_frame(&mut tls, 0x2, &binary_payload, Some([4, 3, 2, 1]))
        .await
        .expect("write masked binary frame");

    let echoed_binary = read_ws_frame(&mut tls)
        .await
        .expect("read echoed binary frame");
    assert_eq!(echoed_binary.opcode, 0x2);
    assert_eq!(echoed_binary.payload, binary_payload);
    assert!(!echoed_binary.masked);

    write_ws_frame(&mut tls, 0x8, &[], Some([9, 9, 9, 9]))
        .await
        .expect("write close frame");
    let close_echo = tokio::time::timeout(Duration::from_secs(1), read_ws_frame(&mut tls))
        .await
        .expect("close echo timeout")
        .expect("close echo frame");
    assert_eq!(close_echo.opcode, 0x8);

    upstream_task.await.expect("upstream task");
    let events_result = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let events = sink.snapshot();
            let turn_started_count = events
                .iter()
                .filter(|event| event.kind == EventType::WebSocketTurnStarted)
                .count();
            let turn_completed_count = events
                .iter()
                .filter(|event| event.kind == EventType::WebSocketTurnCompleted)
                .count();
            let has_close_completion = events.iter().any(|event| {
                event.kind == EventType::WebSocketTurnCompleted
                    && attr(event, "flush_reason") == Some("close_frame")
            });
            if turn_started_count >= 1 && turn_completed_count >= 1 && has_close_completion {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    proxy_task.abort();
    let events = events_result.expect("websocket turn events should be observed");

    assert!(events.iter().any(|event| {
        event.kind == EventType::WebSocketOpened
            && event.context.protocol == ApplicationProtocol::WebSocket
    }));

    let websocket_frame_events = events
        .iter()
        .filter(|event| event.kind == EventType::WebSocketFrame)
        .collect::<Vec<_>>();
    assert!(
        websocket_frame_events.len() >= 4,
        "expected websocket frame metadata events"
    );
    assert!(websocket_frame_events
        .iter()
        .all(|event| attr(event, "ws_codec_impl") == Some("soketto")));
    assert!(websocket_frame_events.iter().any(|event| {
        event.attributes.get("direction").map(String::as_str) == Some("client_to_server")
            && event.attributes.get("opcode_label").map(String::as_str) == Some("binary")
            && event.attributes.get("payload_len").map(String::as_str)
                == Some(&binary_payload.len().to_string())
    }));
    assert!(websocket_frame_events.iter().any(|event| {
        event.attributes.get("direction").map(String::as_str) == Some("server_to_client")
            && event.attributes.get("opcode_label").map(String::as_str) == Some("text")
    }));

    let turn_started = events
        .iter()
        .filter(|event| event.kind == EventType::WebSocketTurnStarted)
        .collect::<Vec<_>>();
    assert!(
        turn_started.len() >= 1,
        "expected at least 1 websocket turn start, got {}",
        turn_started.len()
    );

    let turn_completed = events
        .iter()
        .filter(|event| event.kind == EventType::WebSocketTurnCompleted)
        .collect::<Vec<_>>();
    assert!(
        turn_completed.len() >= 1,
        "expected at least 1 websocket turn completion, got {}",
        turn_completed.len()
    );
    assert!(
        turn_completed
            .iter()
            .any(|event| attr(event, "flush_reason") == Some("close_frame")),
        "expected close-frame completion"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_server_initiated_turns_emit_expected_boundaries() {
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
            request_text.starts_with("GET /ws HTTP/1.1"),
            "{request_text}"
        );

        let upgrade_response = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
            "\r\n"
        );
        tls.write_all(upgrade_response.as_bytes())
            .await
            .expect("write upgrade response");
        tls.flush().await.expect("flush upgrade response");

        write_ws_frame(&mut tls, 0x1, b"server-first", None)
            .await
            .expect("write server initiated frame");
        let client_frame = read_ws_frame(&mut tls).await.expect("read client frame");
        assert_eq!(client_frame.opcode, 0x1);
        write_ws_frame(&mut tls, 0x1, b"server-second", None)
            .await
            .expect("write server rollover frame");

        let close_frame = read_ws_frame(&mut tls).await.expect("read close frame");
        assert_eq!(close_frame.opcode, 0x8);
        write_ws_frame(&mut tls, 0x8, &[], None)
            .await
            .expect("write close frame");
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
    let upgrade_request = concat!(
        "GET /ws HTTP/1.1\r\n",
        "Host: 127.0.0.1\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "\r\n"
    );
    tls.write_all(upgrade_request.as_bytes())
        .await
        .expect("write websocket upgrade request");
    tls.flush().await.expect("flush websocket upgrade request");

    let upgrade_response = read_http_head(&mut tls).await;
    let upgrade_text = String::from_utf8_lossy(&upgrade_response);
    assert!(
        upgrade_text.starts_with("HTTP/1.1 101 Switching Protocols"),
        "{upgrade_text}"
    );

    let server_first = read_ws_frame(&mut tls)
        .await
        .expect("read server-first frame");
    assert_eq!(server_first.opcode, 0x1);
    assert_eq!(server_first.payload, b"server-first".to_vec());

    write_ws_frame(&mut tls, 0x1, b"client-reply", Some([7, 7, 7, 7]))
        .await
        .expect("write client reply frame");

    let server_second = read_ws_frame(&mut tls)
        .await
        .expect("read server-second frame");
    assert_eq!(server_second.opcode, 0x1);
    assert_eq!(server_second.payload, b"server-second".to_vec());

    write_ws_frame(&mut tls, 0x8, &[], Some([8, 8, 8, 8]))
        .await
        .expect("write close frame");
    let close_echo = tokio::time::timeout(Duration::from_secs(1), read_ws_frame(&mut tls))
        .await
        .expect("close echo timeout")
        .expect("close echo frame");
    assert_eq!(close_echo.opcode, 0x8);

    upstream_task.await.expect("upstream task");
    let events_result = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let events = sink.snapshot();
            let turn_started = events
                .iter()
                .filter(|event| event.kind == EventType::WebSocketTurnStarted)
                .collect::<Vec<_>>();
            let turn_completed = events
                .iter()
                .filter(|event| event.kind == EventType::WebSocketTurnCompleted)
                .collect::<Vec<_>>();
            let started = !turn_started.is_empty();
            let closed = turn_completed
                .iter()
                .any(|event| attr(event, "flush_reason") == Some("close_frame"));
            if started && closed {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    proxy_task.abort();
    let events = events_result.expect("websocket turn rollover events should be observed");

    let turn_started = events
        .iter()
        .filter(|event| event.kind == EventType::WebSocketTurnStarted)
        .collect::<Vec<_>>();
    let turn_completed = events
        .iter()
        .filter(|event| event.kind == EventType::WebSocketTurnCompleted)
        .collect::<Vec<_>>();

    assert!(turn_started
        .iter()
        .any(|event| { attr(event, "initiated_by") == Some("server_to_client") }));
    assert!(turn_completed
        .iter()
        .any(|event| { attr(event, "flush_reason") == Some("close_frame") }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_forwards_ping_and_pong_frames() {
    let client_ping_payload = b"client-ping".to_vec();
    let server_ping_payload = b"server-ping".to_vec();
    let client_ping_payload_upstream = client_ping_payload.clone();
    let server_ping_payload_upstream = server_ping_payload.clone();

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
            request_text.starts_with("GET /ws HTTP/1.1"),
            "{request_text}"
        );

        let upgrade_response = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
            "\r\n"
        );
        tls.write_all(upgrade_response.as_bytes())
            .await
            .expect("write upgrade response");
        tls.flush().await.expect("flush upgrade response");

        let client_ping = tokio::time::timeout(Duration::from_secs(1), read_ws_frame(&mut tls))
            .await
            .expect("client ping timeout")
            .expect("client ping frame");
        assert_eq!(client_ping.opcode, 0x9);
        assert_eq!(client_ping.payload, client_ping_payload_upstream);
        assert!(client_ping.masked);

        write_ws_frame(&mut tls, 0xA, &client_ping.payload, None)
            .await
            .expect("write server pong");
        write_ws_frame(&mut tls, 0x9, &server_ping_payload_upstream, None)
            .await
            .expect("write server ping");

        let client_pong = tokio::time::timeout(Duration::from_secs(1), read_ws_frame(&mut tls))
            .await
            .expect("client pong timeout")
            .expect("client pong frame");
        assert_eq!(client_pong.opcode, 0xA);
        assert_eq!(client_pong.payload, server_ping_payload_upstream);
        assert!(client_pong.masked);

        let close_frame = read_ws_frame(&mut tls).await.expect("read close frame");
        assert_eq!(close_frame.opcode, 0x8);
        write_ws_frame(&mut tls, 0x8, &[], None)
            .await
            .expect("write close frame");
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
    let upgrade_request = concat!(
        "GET /ws HTTP/1.1\r\n",
        "Host: 127.0.0.1\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "\r\n"
    );
    tls.write_all(upgrade_request.as_bytes())
        .await
        .expect("write websocket upgrade request");
    tls.flush().await.expect("flush websocket upgrade request");

    let upgrade_response = read_http_head(&mut tls).await;
    let upgrade_text = String::from_utf8_lossy(&upgrade_response);
    assert!(
        upgrade_text.starts_with("HTTP/1.1 101 Switching Protocols"),
        "{upgrade_text}"
    );

    write_ws_frame(&mut tls, 0x9, &client_ping_payload, Some([1, 2, 3, 4]))
        .await
        .expect("write client ping");

    let server_pong = tokio::time::timeout(Duration::from_secs(1), read_ws_frame(&mut tls))
        .await
        .expect("server pong timeout")
        .expect("server pong frame");
    assert_eq!(server_pong.opcode, 0xA);
    assert_eq!(server_pong.payload, client_ping_payload);
    assert!(!server_pong.masked);

    let server_ping = tokio::time::timeout(Duration::from_secs(1), read_ws_frame(&mut tls))
        .await
        .expect("server ping timeout")
        .expect("server ping frame");
    assert_eq!(server_ping.opcode, 0x9);
    assert_eq!(server_ping.payload, server_ping_payload);
    assert!(!server_ping.masked);

    write_ws_frame(&mut tls, 0xA, &server_ping.payload, Some([5, 6, 7, 8]))
        .await
        .expect("write client pong");
    write_ws_frame(&mut tls, 0x8, &[], Some([9, 9, 9, 9]))
        .await
        .expect("write close frame");

    let close_echo = tokio::time::timeout(Duration::from_secs(1), read_ws_frame(&mut tls))
        .await
        .expect("close echo timeout")
        .expect("close echo frame");
    assert_eq!(close_echo.opcode, 0x8);

    upstream_task.await.expect("upstream task");
    let events_result = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let events = sink.snapshot();
            let has_client_ping = events.iter().any(|event| {
                event.kind == EventType::WebSocketFrame
                    && attr(event, "direction") == Some("client_to_server")
                    && attr(event, "opcode_label") == Some("ping")
            });
            let has_client_pong = events.iter().any(|event| {
                event.kind == EventType::WebSocketFrame
                    && attr(event, "direction") == Some("client_to_server")
                    && attr(event, "opcode_label") == Some("pong")
            });
            let has_server_ping = events.iter().any(|event| {
                event.kind == EventType::WebSocketFrame
                    && attr(event, "direction") == Some("server_to_client")
                    && attr(event, "opcode_label") == Some("ping")
            });
            let has_server_pong = events.iter().any(|event| {
                event.kind == EventType::WebSocketFrame
                    && attr(event, "direction") == Some("server_to_client")
                    && attr(event, "opcode_label") == Some("pong")
            });
            let has_close_completion = events.iter().any(|event| {
                event.kind == EventType::WebSocketTurnCompleted
                    && attr(event, "flush_reason") == Some("close_frame")
            });
            if has_client_ping
                && has_client_pong
                && has_server_ping
                && has_server_pong
                && has_close_completion
            {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    proxy_task.abort();
    let events = events_result.expect("ping/pong websocket events should be observed");

    assert!(events.iter().any(|event| {
        event.kind == EventType::WebSocketOpened
            && event.context.protocol == ApplicationProtocol::WebSocket
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_upgrade_with_invalid_request_key_is_rejected_before_relay() {
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
            request_text
                .to_ascii_lowercase()
                .contains("upgrade: websocket"),
            "{request_text}"
        );
        assert!(
            request_text
                .to_ascii_lowercase()
                .contains("sec-websocket-key: dgvzdc1rzxk="),
            "{request_text}"
        );

        let upgrade_response = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
            "\r\n"
        );
        tls.write_all(upgrade_response.as_bytes())
            .await
            .expect("write upgrade response");
        tls.flush().await.expect("flush upgrade response");

        let mut buf = [0_u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(750), tls.read(&mut buf)).await;
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
    let upgrade_request = concat!(
        "GET /ws HTTP/1.1\r\n",
        "Host: 127.0.0.1\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: dGVzdC1rZXk=\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "\r\n"
    );
    tls.write_all(upgrade_request.as_bytes())
        .await
        .expect("write websocket upgrade request");
    tls.flush().await.expect("flush websocket upgrade request");

    let upgrade_response = read_http_head(&mut tls).await;
    let upgrade_text = String::from_utf8_lossy(&upgrade_response);
    assert!(
        upgrade_text.starts_with("HTTP/1.1 101 Switching Protocols"),
        "{upgrade_text}"
    );

    // Validation fails (invalid key shape) → plain relay, no WS hooks.
    // Connection closes once upstream disconnects.
    let connection_closed = tokio::time::timeout(Duration::from_secs(2), async {
        let mut probe = [0_u8; 1];
        loop {
            match tls.read(&mut probe).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    })
    .await;
    assert!(
        connection_closed.is_ok(),
        "proxy should close after upstream disconnects"
    );
    // Drop the client TLS stream so the proxy's plain relay finishes.
    drop(tls);

    upstream_task.await.expect("upstream task");
    let events_result = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let events = sink.snapshot();
            let has_close = events
                .iter()
                .any(|event| event.kind == EventType::StreamClosed);
            if has_close {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    proxy_task.abort();
    let events = events_result.expect("stream close event should be observed");
    let close_event = events
        .iter()
        .find(|e| e.kind == EventType::StreamClosed)
        .expect("StreamClosed event");
    let reason = attr(close_event, "reason_code").unwrap_or("<none>");
    assert!(
        reason == "relay_eof" || reason == "relay_error",
        "expected relay_eof or relay_error, got: {reason}"
    );

    // No WebSocketOpened event should exist — hooks were not fired.
    assert!(
        !events
            .iter()
            .any(|event| event.kind == EventType::WebSocketOpened),
        "on_websocket_start should not fire for invalid handshake"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_rejects_invalid_mask_direction() {
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
            request_text
                .to_ascii_lowercase()
                .contains("upgrade: websocket"),
            "{request_text}"
        );

        let upgrade_response = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
            "\r\n"
        );
        tls.write_all(upgrade_response.as_bytes())
            .await
            .expect("write upgrade response");
        tls.flush().await.expect("flush upgrade response");

        let maybe_frame =
            tokio::time::timeout(Duration::from_millis(750), read_ws_frame(&mut tls)).await;
        if let Ok(Ok(frame)) = maybe_frame {
            panic!("unexpected frame reached upstream for invalid mask direction: {frame:?}");
        }
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: false,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;
    let mut tls =
        connect_websocket_via_proxy(proxy_addr, upstream_addr.port(), "dGhlIHNhbXBsZSBub25jZQ==")
            .await;

    write_ws_frame(&mut tls, 0x1, b"unmasked-client-frame", None)
        .await
        .expect("write unmasked websocket text frame");
    let connection_closed = tokio::time::timeout(Duration::from_secs(1), async {
        let mut probe = [0_u8; 1];
        match tls.read(&mut probe).await {
            Ok(0) => true,
            Ok(_) => false,
            Err(_) => true,
        }
    })
    .await
    .expect("wait for websocket close");
    assert!(
        connection_closed,
        "proxy must close invalid masked websocket flow"
    );

    upstream_task.await.expect("upstream task");
    let events = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let events = sink.snapshot();
            if events.iter().any(|event| {
                event.kind == EventType::StreamClosed
                    && attr(event, "reason_code") == Some("websocket_error")
                    && attr(event, "reason_detail")
                        .map(|detail| detail.contains("client_frame_unmasked"))
                        .unwrap_or(false)
            }) {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("websocket invalid-mask close event should be observed");
    proxy_task.abort();

    assert!(events.iter().any(|event| {
        event.kind == EventType::StreamClosed
            && attr(event, "reason_code") == Some("websocket_error")
            && attr(event, "reason_detail")
                .map(|detail| detail.contains("client_frame_unmasked"))
                .unwrap_or(false)
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_rejects_fragmented_control_frames() {
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
        let upgrade_response = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
            "\r\n"
        );
        tls.write_all(upgrade_response.as_bytes())
            .await
            .expect("write upgrade response");
        tls.flush().await.expect("flush upgrade response");

        let maybe_frame =
            tokio::time::timeout(Duration::from_millis(750), read_ws_frame(&mut tls)).await;
        if let Ok(Ok(frame)) = maybe_frame {
            panic!("unexpected frame reached upstream for fragmented control frame: {frame:?}");
        }
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: false,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;
    let mut tls =
        connect_websocket_via_proxy(proxy_addr, upstream_addr.port(), "dGhlIHNhbXBsZSBub25jZQ==")
            .await;

    write_ws_frame_with_fin(&mut tls, false, 0x9, b"fragmented-ping", Some([1, 2, 3, 4]))
        .await
        .expect("write fragmented ping frame");
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        let mut probe = [0_u8; 1];
        let _ = tls.read(&mut probe).await;
    })
    .await;

    upstream_task.await.expect("upstream task");
    let events = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let events = sink.snapshot();
            if events.iter().any(|event| {
                event.kind == EventType::StreamClosed
                    && attr(event, "reason_code") == Some("websocket_error")
                    && attr(event, "reason_detail")
                        .map(|detail| detail.contains("fragmented_control_frame"))
                        .unwrap_or(false)
            }) {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("websocket fragmented-control close event should be observed");
    proxy_task.abort();

    assert!(events.iter().any(|event| {
        event.kind == EventType::StreamClosed
            && attr(event, "reason_code") == Some("websocket_error")
            && attr(event, "reason_detail")
                .map(|detail| detail.contains("fragmented_control_frame"))
                .unwrap_or(false)
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_rejects_reserved_opcode() {
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
        let upgrade_response = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
            "\r\n"
        );
        tls.write_all(upgrade_response.as_bytes())
            .await
            .expect("write upgrade response");
        tls.flush().await.expect("flush upgrade response");

        let maybe_frame =
            tokio::time::timeout(Duration::from_millis(750), read_ws_frame(&mut tls)).await;
        if let Ok(Ok(frame)) = maybe_frame {
            panic!("unexpected frame reached upstream for reserved opcode: {frame:?}");
        }
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: false,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;
    let mut tls =
        connect_websocket_via_proxy(proxy_addr, upstream_addr.port(), "dGhlIHNhbXBsZSBub25jZQ==")
            .await;

    write_ws_frame(&mut tls, 0x3, b"reserved-opcode", Some([7, 7, 7, 7]))
        .await
        .expect("write reserved opcode frame");
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        let mut probe = [0_u8; 1];
        let _ = tls.read(&mut probe).await;
    })
    .await;

    upstream_task.await.expect("upstream task");
    let events = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let events = sink.snapshot();
            if events.iter().any(|event| {
                event.kind == EventType::StreamClosed
                    && attr(event, "reason_code") == Some("websocket_error")
                    && attr(event, "reason_detail")
                        .map(|detail| detail.contains("reserved_opcode"))
                        .unwrap_or(false)
            }) {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("websocket reserved-opcode close event should be observed");
    proxy_task.abort();

    assert!(events.iter().any(|event| {
        event.kind == EventType::StreamClosed
            && attr(event, "reason_code") == Some("websocket_error")
            && attr(event, "reason_detail")
                .map(|detail| detail.contains("reserved_opcode"))
                .unwrap_or(false)
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_handles_large_fragmented_message_under_limit() {
    let fragment_a = vec![0x11_u8; 8192];
    let fragment_b = vec![0x22_u8; 6144];
    let expected_message = [fragment_a.clone(), fragment_b.clone()].concat();

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
        let upgrade_response = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
            "\r\n"
        );
        tls.write_all(upgrade_response.as_bytes())
            .await
            .expect("write upgrade response");
        tls.flush().await.expect("flush upgrade response");

        let first = read_ws_frame(&mut tls).await.expect("read first fragment");
        assert_eq!(first.opcode, 0x1);
        assert!(!first.fin);
        assert!(first.masked);

        let second = read_ws_frame(&mut tls).await.expect("read second fragment");
        assert_eq!(second.opcode, 0x0);
        assert!(second.fin);
        assert!(second.masked);

        let upstream_message = [first.payload.clone(), second.payload.clone()].concat();
        assert_eq!(upstream_message, expected_message);

        write_ws_frame_with_fin(&mut tls, false, 0x1, &first.payload, None)
            .await
            .expect("echo first fragment");
        write_ws_frame_with_fin(&mut tls, true, 0x0, &second.payload, None)
            .await
            .expect("echo second fragment");

        let close_frame = read_ws_frame(&mut tls).await.expect("read close frame");
        assert_eq!(close_frame.opcode, 0x8);
        write_ws_frame(&mut tls, 0x8, &[], None)
            .await
            .expect("write close frame");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: false,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, _sink) = start_sidecar_with_sink(sink, config).await;
    let mut tls =
        connect_websocket_via_proxy(proxy_addr, upstream_addr.port(), "dGhlIHNhbXBsZSBub25jZQ==")
            .await;

    write_ws_frame_with_fin(&mut tls, false, 0x1, &fragment_a, Some([1, 2, 3, 4]))
        .await
        .expect("write first client fragment");
    write_ws_frame_with_fin(&mut tls, true, 0x0, &fragment_b, Some([5, 6, 7, 8]))
        .await
        .expect("write second client fragment");

    let echoed_first = read_ws_frame(&mut tls)
        .await
        .expect("read echoed first fragment");
    assert_eq!(echoed_first.opcode, 0x1);
    assert!(!echoed_first.fin);
    assert_eq!(echoed_first.payload, fragment_a);
    assert!(!echoed_first.masked);

    let echoed_second = read_ws_frame(&mut tls)
        .await
        .expect("read echoed second fragment");
    assert_eq!(echoed_second.opcode, 0x0);
    assert!(echoed_second.fin);
    assert_eq!(echoed_second.payload, fragment_b);
    assert!(!echoed_second.masked);

    write_ws_frame(&mut tls, 0x8, &[], Some([9, 9, 9, 9]))
        .await
        .expect("write close frame");
    let close_echo = tokio::time::timeout(Duration::from_secs(1), read_ws_frame(&mut tls))
        .await
        .expect("close echo timeout")
        .expect("close echo frame");
    assert_eq!(close_echo.opcode, 0x8);

    upstream_task.await.expect("upstream task");
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_rejects_message_over_limit_with_deterministic_error() {
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
        let upgrade_response = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
            "\r\n"
        );
        tls.write_all(upgrade_response.as_bytes())
            .await
            .expect("write upgrade response");
        tls.flush().await.expect("flush upgrade response");

        let maybe_frame =
            tokio::time::timeout(Duration::from_millis(750), read_ws_frame(&mut tls)).await;
        if let Ok(Ok(frame)) = maybe_frame {
            panic!("unexpected over-limit frame reached upstream: {frame:?}");
        }
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: false,
        max_flow_body_buffer_bytes: 128,
        max_flow_decoder_buffer_bytes: 64,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;
    let mut tls =
        connect_websocket_via_proxy(proxy_addr, upstream_addr.port(), "dGhlIHNhbXBsZSBub25jZQ==")
            .await;

    let over_limit_payload = vec![0xAB_u8; 256];
    write_ws_frame(&mut tls, 0x1, &over_limit_payload, Some([4, 5, 6, 7]))
        .await
        .expect("write over-limit frame");
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        let mut probe = [0_u8; 1];
        let _ = tls.read(&mut probe).await;
    })
    .await;

    upstream_task.await.expect("upstream task");
    let events = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let events = sink.snapshot();
            if events.iter().any(|event| {
                event.kind == EventType::StreamClosed
                    && attr(event, "reason_code") == Some("websocket_error")
                    && attr(event, "reason_detail")
                        .map(|detail| detail.contains("payload_too_large"))
                        .unwrap_or(false)
            }) {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("websocket over-limit close event should be observed");
    proxy_task.abort();

    assert!(events.iter().any(|event| {
        event.kind == EventType::StreamClosed
            && attr(event, "reason_code") == Some("websocket_error")
            && attr(event, "reason_detail")
                .map(|detail| detail.contains("payload_too_large"))
                .unwrap_or(false)
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_idle_session_survives_when_within_ws_timeout_policy() {
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
        let upgrade_response = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
            "\r\n"
        );
        tls.write_all(upgrade_response.as_bytes())
            .await
            .expect("write upgrade response");
        tls.flush().await.expect("flush upgrade response");

        let first = read_ws_frame(&mut tls).await.expect("read post-idle frame");
        assert_eq!(first.opcode, 0x1);
        assert_eq!(first.payload, b"idle-safe".to_vec());
        write_ws_frame(&mut tls, 0x1, &first.payload, None)
            .await
            .expect("write post-idle echo");

        let close_frame = read_ws_frame(&mut tls).await.expect("read close frame");
        assert_eq!(close_frame.opcode, 0x8);
        write_ws_frame(&mut tls, 0x8, &[], None)
            .await
            .expect("write close frame");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: false,
        ..MitmConfig::default()
    };
    let sidecar_config = SidecarConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: 64 * 1024,
        accept_retry_backoff_ms: 100,
        idle_watchdog_timeout: std::time::Duration::from_millis(150),
        websocket_idle_watchdog_timeout: std::time::Duration::from_millis(1500),
        upstream_connect_timeout: std::time::Duration::from_secs(10),
        stream_stage_timeout: std::time::Duration::from_secs(5),
        h2_body_idle_timeout: std::time::Duration::from_secs(5),
        h2_response_overflow_mode: soth_mitm::test_server::H2ResponseOverflowMode::TruncateContinue,
        unix_socket_path: None,
    };
    let (proxy_addr, proxy_task, sink) =
        start_sidecar_with_sink_and_config(sink, config, sidecar_config).await;
    let mut tls =
        connect_websocket_via_proxy(proxy_addr, upstream_addr.port(), "dGhlIHNhbXBsZSBub25jZQ==")
            .await;

    tokio::time::sleep(Duration::from_millis(450)).await;
    write_ws_frame(&mut tls, 0x1, b"idle-safe", Some([6, 6, 6, 6]))
        .await
        .expect("write post-idle frame");
    let echoed = read_ws_frame(&mut tls).await.expect("read post-idle echo");
    assert_eq!(echoed.opcode, 0x1);
    assert_eq!(echoed.payload, b"idle-safe".to_vec());

    write_ws_frame(&mut tls, 0x8, &[], Some([9, 9, 9, 9]))
        .await
        .expect("write close frame");
    let close_echo = tokio::time::timeout(Duration::from_secs(1), read_ws_frame(&mut tls))
        .await
        .expect("close echo timeout")
        .expect("close echo frame");
    assert_eq!(close_echo.opcode, 0x8);

    upstream_task.await.expect("upstream task");
    let events = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let events = sink.snapshot();
            if events.iter().any(|event| {
                event.kind == EventType::StreamClosed
                    && event.context.protocol == ApplicationProtocol::WebSocket
            }) {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("websocket close events should be observed");
    proxy_task.abort();

    assert!(events.iter().any(|event| {
        event.kind == EventType::StreamClosed
            && event.context.protocol == ApplicationProtocol::WebSocket
            && attr(event, "reason_code") == Some("websocket_completed")
    }));
    assert!(!events.iter().any(|event| {
        event.kind == EventType::StreamClosed
            && event.context.protocol == ApplicationProtocol::WebSocket
            && attr(event, "reason_code") == Some("idle_watchdog_timeout")
    }));
}
