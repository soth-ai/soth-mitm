use std::io;
use std::time::Duration;

use mitm_core::{MitmConfig, MitmEngine};
use mitm_http::ApplicationProtocol;
use mitm_observe::{Event, EventType, VecEventSink};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};
use mitm_tls::{build_http1_client_config, build_http1_server_config_for_host};
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
    let fin_opcode = 0b1000_0000 | (opcode & 0b0000_1111);
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
            "Sec-WebSocket-Accept: testaccept==\r\n",
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

    let sink = VecEventSink::default();
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
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
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

    assert!(events.iter().any(|event| {
        event.kind == EventType::WebSocketClosed
            && event.context.protocol == ApplicationProtocol::WebSocket
            && event.attributes.get("close_reason").map(String::as_str) == Some("close_frame")
    }));
    assert!(events.iter().any(|event| {
        event.kind == EventType::StreamClosed
            && event.context.protocol == ApplicationProtocol::WebSocket
            && event.attributes.get("reason_code").map(String::as_str)
                == Some("websocket_completed")
    }));

    let turn_started = events
        .iter()
        .filter(|event| event.kind == EventType::WebSocketTurnStarted)
        .collect::<Vec<_>>();
    assert!(
        turn_started.len() >= 2,
        "expected at least 2 websocket turn starts, got {}",
        turn_started.len()
    );
    assert!(turn_started.iter().any(|event| {
        attr(event, "turn_id") == Some("1")
            && attr(event, "initiated_by") == Some("client_to_server")
    }));
    assert!(turn_started.iter().any(|event| {
        attr(event, "turn_id") == Some("2")
            && attr(event, "initiated_by") == Some("client_to_server")
    }));

    let turn_completed = events
        .iter()
        .filter(|event| event.kind == EventType::WebSocketTurnCompleted)
        .collect::<Vec<_>>();
    assert!(
        turn_completed.len() >= 2,
        "expected at least 2 websocket turn completions, got {}",
        turn_completed.len()
    );
    assert!(turn_completed.iter().any(|event| {
        attr(event, "turn_id") == Some("1") && attr(event, "flush_reason") == Some("rollover")
    }));
    assert!(turn_completed.iter().any(|event| {
        attr(event, "turn_id") == Some("2") && attr(event, "flush_reason") == Some("close_frame")
    }));
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
            "Sec-WebSocket-Accept: testaccept==\r\n",
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

    let sink = VecEventSink::default();
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
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let turn_started = events
        .iter()
        .filter(|event| event.kind == EventType::WebSocketTurnStarted)
        .collect::<Vec<_>>();
    let turn_completed = events
        .iter()
        .filter(|event| event.kind == EventType::WebSocketTurnCompleted)
        .collect::<Vec<_>>();

    assert!(
        turn_started.iter().any(|event| {
            attr(event, "turn_id") == Some("1")
                && attr(event, "initiated_by") == Some("server_to_client")
        }),
        "missing server-initiated turn start"
    );
    assert!(turn_completed.iter().any(|event| {
        attr(event, "turn_id") == Some("1")
            && attr(event, "initiated_by") == Some("server_to_client")
            && attr(event, "flush_reason") == Some("rollover")
    }));
    assert!(turn_completed.iter().any(|event| {
        attr(event, "turn_id") == Some("2") && attr(event, "flush_reason") == Some("close_frame")
    }));
}
