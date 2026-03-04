use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{env, str::FromStr};

use mitm_core::{MitmConfig, MitmEngine};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{RuntimeGovernor, SidecarConfig, SidecarServer};
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

fn env_or_default<T>(name: &str, default: T) -> T
where
    T: FromStr + Copy,
{
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
        .unwrap_or(default)
}

fn build_engine(
    config: MitmConfig,
) -> MitmEngine<DefaultPolicyEngine, mitm_observe::NoopEventConsumer> {
    let policy =
        DefaultPolicyEngine::new(config.ignore_hosts.clone(), config.blocked_hosts.clone());
    MitmEngine::new(config, policy, mitm_observe::NoopEventConsumer)
}

async fn start_sidecar(
    config: MitmConfig,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
    Arc<RuntimeGovernor>,
) {
    let sidecar_config = SidecarConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: 64 * 1024,
        accept_retry_backoff_ms: 100,
        idle_watchdog_timeout: std::time::Duration::from_secs(30),
        websocket_idle_watchdog_timeout: std::time::Duration::from_secs(600),
        upstream_connect_timeout: std::time::Duration::from_secs(10),
        stream_stage_timeout: std::time::Duration::from_secs(15),
        unix_socket_path: None,
    };
    let engine = build_engine(config);
    let server = SidecarServer::new(sidecar_config, engine).expect("build sidecar");
    let runtime = server.runtime_observability_handle();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind sidecar listener");
    let addr = listener.local_addr().expect("sidecar listener local addr");
    let handle = tokio::spawn(server.run_with_listener(listener));
    (addr, handle, runtime)
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

async fn write_ws_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    opcode: u8,
    payload: &[u8],
    mask: Option<[u8; 4]>,
) -> io::Result<()> {
    write_ws_frame_with_fin(stream, true, opcode, payload, mask).await
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

async fn try_connect_websocket_via_proxy(
    proxy_addr: std::net::SocketAddr,
    upstream_port: u16,
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut tcp = TcpStream::connect(proxy_addr).await?;
    let connect = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    tcp.write_all(connect.as_bytes()).await?;
    let connect_response = read_response_head(&mut tcp).await;
    if !connect_response.starts_with("HTTP/1.1 200 Connection Established") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("unexpected CONNECT response: {connect_response}"),
        ));
    }

    let connector = TlsConnector::from(build_http1_client_config(true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("server name conversion failed: {error}"),
        )
    })?;
    let mut tls = connector.connect(server_name, tcp).await.map_err(|error| {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("TLS connect to sidecar failed: {error}"),
        )
    })?;
    let upgrade_request = concat!(
        "GET /ws HTTP/1.1\r\n",
        "Host: 127.0.0.1\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "\r\n"
    );
    tls.write_all(upgrade_request.as_bytes()).await?;
    tls.flush().await?;

    let upgrade_response = read_http_head(&mut tls).await;
    let upgrade_text = String::from_utf8_lossy(&upgrade_response);
    if !upgrade_text.starts_with("HTTP/1.1 101 Switching Protocols") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("unexpected websocket upgrade response: {upgrade_text}"),
        ));
    }
    Ok(tls)
}

async fn connect_websocket_via_proxy(
    proxy_addr: std::net::SocketAddr,
    upstream_port: u16,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    try_connect_websocket_via_proxy(proxy_addr, upstream_port)
        .await
        .expect("connect websocket via proxy")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetFaultProfile {
    Jitter,
    LossAndJitter,
    Reset,
}

fn websocket_fault_profile(connection_id: u64) -> NetFaultProfile {
    match connection_id % 3 {
        0 => NetFaultProfile::Jitter,
        1 => NetFaultProfile::LossAndJitter,
        _ => NetFaultProfile::Reset,
    }
}

fn websocket_fault_jitter_millis(profile: NetFaultProfile, chunk_index: u64) -> u64 {
    match profile {
        NetFaultProfile::Jitter => 3 + (chunk_index % 4) * 4,
        NetFaultProfile::LossAndJitter => 4 + (chunk_index % 5) * 5,
        NetFaultProfile::Reset => 2 + (chunk_index % 3) * 3,
    }
}

async fn relay_faulty_direction<R, W>(
    mut source: R,
    mut sink: W,
    profile: NetFaultProfile,
    drop_every_nth_chunk: Option<u64>,
    deadline: Instant,
    hard_reset_on_exit: bool,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0_u8; 4096];
    let mut chunk_index = 0_u64;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(now);
        let read = match tokio::time::timeout(remaining, source.read(&mut buf)).await {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => return Err(error),
            Err(_) => break,
        };
        if read == 0 {
            break;
        }
        chunk_index += 1;
        tokio::time::sleep(Duration::from_millis(websocket_fault_jitter_millis(
            profile,
            chunk_index,
        )))
        .await;
        if drop_every_nth_chunk
            .map(|interval| chunk_index % interval == 0)
            .unwrap_or(false)
        {
            continue;
        }
        sink.write_all(&buf[..read]).await?;
        sink.flush().await?;
    }
    if !hard_reset_on_exit {
        let _ = sink.shutdown().await;
    }
    Ok(())
}

async fn run_websocket_fault_bridge(
    downstream: TcpStream,
    upstream_addr: std::net::SocketAddr,
    profile: NetFaultProfile,
) -> io::Result<()> {
    let upstream = TcpStream::connect(upstream_addr).await?;

    let deadline = Instant::now()
        + if matches!(profile, NetFaultProfile::Reset) {
            Duration::from_millis(260)
        } else {
            Duration::from_millis(1200)
        };
    let drop_every_nth_chunk = if matches!(profile, NetFaultProfile::LossAndJitter) {
        Some(13_u64)
    } else {
        None
    };
    let hard_reset_on_exit = matches!(profile, NetFaultProfile::Reset);

    let (downstream_read, downstream_write) = downstream.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();

    let downstream_to_upstream = tokio::spawn(relay_faulty_direction(
        downstream_read,
        upstream_write,
        profile,
        drop_every_nth_chunk,
        deadline,
        hard_reset_on_exit,
    ));
    let upstream_to_downstream = tokio::spawn(relay_faulty_direction(
        upstream_read,
        downstream_write,
        profile,
        None,
        deadline,
        hard_reset_on_exit,
    ));

    let _ = downstream_to_upstream.await;
    let _ = upstream_to_downstream.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_reliability_soak_settles_without_stuck_flows() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        loop {
            let (tcp, _) = match upstream_listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let _ = read_http_head(&mut tls).await;
                let upgrade_response = concat!(
                    "HTTP/1.1 101 Switching Protocols\r\n",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "Sec-WebSocket-Accept: testaccept==\r\n",
                    "\r\n"
                );
                if tls.write_all(upgrade_response.as_bytes()).await.is_err() {
                    return;
                }
                if tls.flush().await.is_err() {
                    return;
                }

                loop {
                    let frame = match read_ws_frame(&mut tls).await {
                        Ok(frame) => frame,
                        Err(_) => break,
                    };
                    if frame.opcode == 0x8 {
                        let _ = write_ws_frame(&mut tls, 0x8, &[], None).await;
                        break;
                    }
                    let _ = write_ws_frame_with_fin(
                        &mut tls,
                        frame.fin,
                        frame.opcode,
                        &frame.payload,
                        None,
                    )
                    .await;
                }
            });
        }
    });

    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: false,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, runtime) = start_sidecar(config).await;

    let total_clients = env_or_default("SOTH_MITM_WS_SOAK_CLIENTS", 48_u32).max(1);
    let mut clients = Vec::new();
    for client_id in 0..total_clients {
        let proxy_addr = proxy_addr;
        let upstream_port = upstream_addr.port();
        clients.push(tokio::spawn(async move {
            let mut tls = connect_websocket_via_proxy(proxy_addr, upstream_port).await;
            let payload = format!("soak-client-{client_id}").into_bytes();
            write_ws_frame(&mut tls, 0x1, &payload, Some([1, 2, 3, 4]))
                .await
                .expect("write soak payload");
            let echoed = read_ws_frame(&mut tls).await.expect("read soak echo");
            assert_eq!(echoed.opcode, 0x1);
            assert_eq!(echoed.payload, payload);

            write_ws_frame(&mut tls, 0x8, &[], Some([9, 9, 9, 9]))
                .await
                .expect("write soak close");
            let close_echo = read_ws_frame(&mut tls).await.expect("read soak close echo");
            assert_eq!(close_echo.opcode, 0x8);
        }));
    }
    for client in clients {
        client.await.expect("client task join");
    }

    let settle_deadline = Instant::now() + Duration::from_secs(10);
    let settled_snapshot = loop {
        let snapshot = runtime.snapshot();
        if snapshot.active_flows == 0 && snapshot.current_in_flight_bytes == 0 {
            break snapshot;
        }
        assert!(
            Instant::now() < settle_deadline,
            "runtime did not settle in soak window: active_flows={} in_flight={} flow_count={} idle_timeouts={} stage_timeouts={} stuck_flows={}",
            snapshot.active_flows,
            snapshot.current_in_flight_bytes,
            snapshot.flow_count,
            snapshot.idle_timeout_count,
            snapshot.stream_stage_timeout_count,
            snapshot.stuck_flow_count
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    proxy_task.abort();
    upstream_task.abort();

    assert_eq!(
        settled_snapshot.idle_timeout_count, 0,
        "websocket soak should not hit idle timeouts"
    );
    assert_eq!(
        settled_snapshot.stream_stage_timeout_count, 0,
        "websocket soak should not hit stream-stage timeouts"
    );
    assert!(
        settled_snapshot.stuck_flow_count <= 1,
        "stuck-flow telemetry exceeded bounded allowance in websocket soak: {}",
        settled_snapshot.stuck_flow_count
    );
    assert!(
        settled_snapshot.flow_count >= total_clients as u64,
        "flow count below expected floor after websocket soak: {}",
        settled_snapshot.flow_count
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_chaos_soak_mixed_lanes_settle_without_stuck_flows() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        loop {
            let (tcp, _) = match upstream_listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let _ = read_http_head(&mut tls).await;
                let upgrade_response = concat!(
                    "HTTP/1.1 101 Switching Protocols\r\n",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "Sec-WebSocket-Accept: testaccept==\r\n",
                    "\r\n"
                );
                if tls.write_all(upgrade_response.as_bytes()).await.is_err() {
                    return;
                }
                if tls.flush().await.is_err() {
                    return;
                }

                loop {
                    let frame =
                        match tokio::time::timeout(Duration::from_secs(2), read_ws_frame(&mut tls))
                            .await
                        {
                            Ok(Ok(frame)) => frame,
                            Ok(Err(_)) => break,
                            Err(_) => {
                                let _ = tls.shutdown().await;
                                break;
                            }
                        };
                    match frame.opcode {
                        0x8 => {
                            let _ = write_ws_frame(&mut tls, 0x8, &[], None).await;
                            break;
                        }
                        0x9 => {
                            let _ = write_ws_frame(&mut tls, 0xA, &frame.payload, None).await;
                        }
                        0x1 | 0x2 | 0x0 => {
                            if frame.payload.starts_with(b"drop-now-") {
                                let _ = tls.shutdown().await;
                                break;
                            }
                            let _ = write_ws_frame_with_fin(
                                &mut tls,
                                frame.fin,
                                frame.opcode,
                                &frame.payload,
                                None,
                            )
                            .await;
                        }
                        _ => {}
                    }
                }
            });
        }
    });

    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: false,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, runtime) = start_sidecar(config).await;

    let total_clients = env_or_default("SOTH_MITM_WS_CHAOS_CLIENTS", 96_u32).max(6);
    let mut clients = Vec::new();
    for client_id in 0..total_clients {
        let proxy_addr = proxy_addr;
        let upstream_port = upstream_addr.port();
        clients.push(tokio::spawn(async move {
            let lane = client_id % 6;
            let lane_deadline = Duration::from_secs(8);
            tokio::time::timeout(lane_deadline, async move {
                let mut tls = connect_websocket_via_proxy(proxy_addr, upstream_port).await;
                match lane {
                    0 => {
                        let payload = format!("lane0-client-{client_id}").into_bytes();
                        write_ws_frame(&mut tls, 0x1, &payload, Some([1, 2, 3, 4]))
                            .await
                            .expect("lane0 write text");
                        let echoed = read_ws_frame(&mut tls).await.expect("lane0 read echo");
                        assert_eq!(echoed.opcode, 0x1);
                        assert_eq!(echoed.payload, payload);
                        write_ws_frame(&mut tls, 0x8, &[], Some([9, 9, 9, 9]))
                            .await
                            .expect("lane0 write close");
                        let close_echo = read_ws_frame(&mut tls).await.expect("lane0 close echo");
                        assert_eq!(close_echo.opcode, 0x8);
                    }
                    1 => {
                        for seq in 0..6_u8 {
                            let payload = vec![seq; 16];
                            write_ws_frame(
                                &mut tls,
                                0x9,
                                &payload,
                                Some([seq, seq ^ 0x11, seq ^ 0x22, seq ^ 0x33]),
                            )
                            .await
                            .expect("lane1 write ping");
                            let pong = read_ws_frame(&mut tls).await.expect("lane1 read pong");
                            assert_eq!(pong.opcode, 0xA);
                            assert_eq!(pong.payload, payload);
                        }
                        write_ws_frame(&mut tls, 0x8, &[], Some([3, 3, 3, 3]))
                            .await
                            .expect("lane1 write close");
                        let close_echo = read_ws_frame(&mut tls).await.expect("lane1 close echo");
                        assert_eq!(close_echo.opcode, 0x8);
                    }
                    2 => {
                        let part_a = format!("frag-a-{client_id}").into_bytes();
                        let part_b = format!("frag-b-{client_id}").into_bytes();
                        write_ws_frame_with_fin(&mut tls, false, 0x1, &part_a, Some([5, 6, 7, 8]))
                            .await
                            .expect("lane2 write first fragment");
                        write_ws_frame_with_fin(&mut tls, true, 0x0, &part_b, Some([8, 7, 6, 5]))
                            .await
                            .expect("lane2 write second fragment");
                        let echoed_a = read_ws_frame(&mut tls)
                            .await
                            .expect("lane2 read fragment a");
                        let echoed_b = read_ws_frame(&mut tls)
                            .await
                            .expect("lane2 read fragment b");
                        assert_eq!(echoed_a.opcode, 0x1);
                        assert!(!echoed_a.fin);
                        assert_eq!(echoed_a.payload, part_a);
                        assert_eq!(echoed_b.opcode, 0x0);
                        assert!(echoed_b.fin);
                        assert_eq!(echoed_b.payload, part_b);
                        write_ws_frame(&mut tls, 0x8, &[], Some([4, 4, 4, 4]))
                            .await
                            .expect("lane2 write close");
                        let close_echo = read_ws_frame(&mut tls).await.expect("lane2 close echo");
                        assert_eq!(close_echo.opcode, 0x8);
                    }
                    3 => {
                        let payload = format!("drop-client-{client_id}").into_bytes();
                        write_ws_frame(&mut tls, 0x2, &payload, Some([7, 1, 7, 1]))
                            .await
                            .expect("lane3 write binary");
                        drop(tls);
                    }
                    4 => {
                        tokio::time::sleep(Duration::from_millis(900)).await;
                        let payload = format!("idle-client-{client_id}").into_bytes();
                        write_ws_frame(&mut tls, 0x1, &payload, Some([2, 2, 2, 2]))
                            .await
                            .expect("lane4 write text");
                        let echoed = read_ws_frame(&mut tls).await.expect("lane4 read echo");
                        assert_eq!(echoed.opcode, 0x1);
                        assert_eq!(echoed.payload, payload);
                        write_ws_frame(&mut tls, 0x8, &[], Some([1, 1, 1, 1]))
                            .await
                            .expect("lane4 write close");
                        let close_echo = read_ws_frame(&mut tls).await.expect("lane4 close echo");
                        assert_eq!(close_echo.opcode, 0x8);
                    }
                    _ => {
                        let payload = format!("drop-now-{client_id}").into_bytes();
                        write_ws_frame(&mut tls, 0x1, &payload, Some([6, 6, 6, 6]))
                            .await
                            .expect("lane5 write abort payload");
                        let read =
                            tokio::time::timeout(Duration::from_secs(2), read_ws_frame(&mut tls))
                                .await
                                .expect("lane5 read timeout waiting for server abort");
                        assert!(read.is_err(), "lane5 expected server-side abrupt close");
                    }
                }
            })
            .await
            .expect("client lane timed out");
        }));
    }
    for client in clients {
        client.await.expect("client task join");
    }

    let settle_deadline = Instant::now() + Duration::from_secs(15);
    let settled_snapshot = loop {
        let snapshot = runtime.snapshot();
        if snapshot.active_flows == 0 && snapshot.current_in_flight_bytes == 0 {
            break snapshot;
        }
        assert!(
            Instant::now() < settle_deadline,
            "runtime did not settle in chaos soak window: active_flows={} in_flight={} flow_count={} idle_timeouts={} stage_timeouts={} stuck_flows={}",
            snapshot.active_flows,
            snapshot.current_in_flight_bytes,
            snapshot.flow_count,
            snapshot.idle_timeout_count,
            snapshot.stream_stage_timeout_count,
            snapshot.stuck_flow_count
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    proxy_task.abort();
    upstream_task.abort();

    assert_eq!(
        settled_snapshot.idle_timeout_count, 0,
        "websocket chaos soak should not hit idle timeouts"
    );
    assert_eq!(
        settled_snapshot.stream_stage_timeout_count, 0,
        "websocket chaos soak should not hit stream-stage timeouts"
    );
    assert!(
        settled_snapshot.stuck_flow_count <= 2,
        "stuck-flow telemetry exceeded bounded allowance in websocket chaos soak: {}",
        settled_snapshot.stuck_flow_count
    );
    assert!(
        settled_snapshot.flow_count >= total_clients as u64,
        "flow count below expected floor after websocket chaos soak: {}",
        settled_snapshot.flow_count
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_network_fault_lane_settles_without_stuck_flows() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        loop {
            let (tcp, _) = match upstream_listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let _ = read_http_head(&mut tls).await;
                let upgrade_response = concat!(
                    "HTTP/1.1 101 Switching Protocols\r\n",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "Sec-WebSocket-Accept: testaccept==\r\n",
                    "\r\n"
                );
                if tls.write_all(upgrade_response.as_bytes()).await.is_err() {
                    return;
                }
                if tls.flush().await.is_err() {
                    return;
                }
                loop {
                    let frame =
                        match tokio::time::timeout(Duration::from_secs(2), read_ws_frame(&mut tls))
                            .await
                        {
                            Ok(Ok(frame)) => frame,
                            Ok(Err(_)) => break,
                            Err(_) => break,
                        };
                    match frame.opcode {
                        0x8 => {
                            let _ = write_ws_frame(&mut tls, 0x8, &[], None).await;
                            break;
                        }
                        0x9 => {
                            let _ = write_ws_frame(&mut tls, 0xA, &frame.payload, None).await;
                        }
                        0x1 | 0x2 | 0x0 => {
                            let _ = write_ws_frame_with_fin(
                                &mut tls,
                                frame.fin,
                                frame.opcode,
                                &frame.payload,
                                None,
                            )
                            .await;
                        }
                        _ => {}
                    }
                }
            });
        }
    });

    let fault_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket fault listener");
    let fault_addr = fault_listener.local_addr().expect("fault listener addr");
    let fault_connection_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let fault_proxy_task = {
        let fault_connection_counter = Arc::clone(&fault_connection_counter);
        tokio::spawn(async move {
            loop {
                let (downstream, _) = match fault_listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let upstream_addr = upstream_addr;
                let connection_id =
                    fault_connection_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tokio::spawn(async move {
                    let profile = websocket_fault_profile(connection_id);
                    let _ = run_websocket_fault_bridge(downstream, upstream_addr, profile).await;
                });
            }
        })
    };

    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: false,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, runtime) = start_sidecar(config).await;

    let total_clients = env_or_default("SOTH_MITM_WS_NETFAULT_CLIENTS", 72_u32).max(9);
    let mut clients = Vec::new();
    for client_id in 0..total_clients {
        let proxy_addr = proxy_addr;
        let upstream_port = fault_addr.port();
        clients.push(tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(8), async move {
                let mut tls = match try_connect_websocket_via_proxy(proxy_addr, upstream_port).await
                {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                for seq in 0..4_u8 {
                    let payload = format!("netfault-client-{client_id}-{seq}").into_bytes();
                    if write_ws_frame(
                        &mut tls,
                        0x1,
                        &payload,
                        Some([seq, seq ^ 0x33, seq ^ 0x55, seq ^ 0x77]),
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                    match tokio::time::timeout(Duration::from_millis(900), read_ws_frame(&mut tls))
                        .await
                    {
                        Ok(Ok(frame)) if frame.opcode == 0x8 => return,
                        Ok(Ok(_)) => {}
                        Ok(Err(_)) | Err(_) => return,
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let _ = write_ws_frame(&mut tls, 0x8, &[], Some([7, 7, 7, 7])).await;
                let _ =
                    tokio::time::timeout(Duration::from_millis(400), read_ws_frame(&mut tls)).await;
            })
            .await
            .expect("network-fault client lane timed out");
        }));
    }
    for client in clients {
        client.await.expect("network-fault client task join");
    }

    let settle_deadline = Instant::now() + Duration::from_secs(15);
    let settled_snapshot = loop {
        let snapshot = runtime.snapshot();
        if snapshot.active_flows == 0 && snapshot.current_in_flight_bytes == 0 {
            break snapshot;
        }
        assert!(
            Instant::now() < settle_deadline,
            "runtime did not settle in websocket network-fault lane: active_flows={} in_flight={} flow_count={} idle_timeouts={} stage_timeouts={} stuck_flows={}",
            snapshot.active_flows,
            snapshot.current_in_flight_bytes,
            snapshot.flow_count,
            snapshot.idle_timeout_count,
            snapshot.stream_stage_timeout_count,
            snapshot.stuck_flow_count
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    proxy_task.abort();
    fault_proxy_task.abort();
    upstream_task.abort();

    assert_eq!(
        settled_snapshot.idle_timeout_count, 0,
        "websocket network-fault lane should not hit idle timeouts"
    );
    assert_eq!(
        settled_snapshot.stream_stage_timeout_count, 0,
        "websocket network-fault lane should not hit stream-stage timeouts"
    );
    assert!(
        settled_snapshot.stuck_flow_count <= 4,
        "stuck-flow telemetry exceeded bounded allowance in websocket network-fault lane: {}",
        settled_snapshot.stuck_flow_count
    );
    assert!(
        settled_snapshot.flow_count >= total_clients as u64 / 2,
        "flow count below expected floor after websocket network-fault lane: {}",
        settled_snapshot.flow_count
    );
}
