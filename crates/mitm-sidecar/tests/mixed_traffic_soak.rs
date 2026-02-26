use std::collections::{BTreeSet, HashSet};
use std::env;
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bytes::Bytes;
use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::{EventConsumer, EventType, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{RuntimeGovernor, SidecarConfig, SidecarServer};
use mitm_tls::{
    build_http1_client_config, build_http1_server_config_for_host, build_http_client_config,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

static H2_EXCHANGE_SEQ: AtomicU64 = AtomicU64::new(1);
static H2_UPSTREAM_CONN_SEQ: AtomicU64 = AtomicU64::new(1);
static SOAK_DEBUG_ENABLED: OnceLock<bool> = OnceLock::new();

fn soak_debug_enabled() -> bool {
    *SOAK_DEBUG_ENABLED.get_or_init(|| {
        env::var("SOTH_MITM_SOAK_DEBUG")
            .ok()
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

fn soak_debug(message: impl AsRef<str>) {
    if soak_debug_enabled() {
        eprintln!("{}", message.as_ref());
    }
}

fn soak_bind_retries() -> u32 {
    env::var("SOTH_MITM_SOAK_BIND_RETRIES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(10)
}

fn soak_bind_retry_delay() -> Duration {
    let millis = env::var("SOTH_MITM_SOAK_BIND_RETRY_MILLIS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(25);
    Duration::from_millis(millis.max(1))
}

fn soak_h2_upstream_accept_timeout() -> Duration {
    let secs = env::var("SOTH_MITM_SOAK_H2_UPSTREAM_ACCEPT_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(10);
    Duration::from_secs(secs)
}

fn should_retry_bind(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse
    )
}

async fn bind_loopback_listener_with_retry(label: &str) -> TcpListener {
    let retries = soak_bind_retries();
    let retry_delay = soak_bind_retry_delay();
    for attempt in 0..=retries {
        match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => return listener,
            Err(error) if should_retry_bind(&error) && attempt < retries => {
                soak_debug(format!(
                    "[soak-bind] {label} attempt={} failed: {}; retrying in {}ms",
                    attempt + 1,
                    error,
                    retry_delay.as_millis()
                ));
                sleep(retry_delay).await;
            }
            Err(error) => panic!("{label}: {error}"),
        }
    }
    unreachable!("bind retries exhausted unexpectedly")
}

fn build_engine_with_sink<S>(config: MitmConfig, sink: S) -> MitmEngine<DefaultPolicyEngine, S>
where
    S: EventConsumer + Send + Sync + 'static,
{
    let policy =
        DefaultPolicyEngine::new(config.ignore_hosts.clone(), config.blocked_hosts.clone());
    MitmEngine::new(config, policy, sink)
}

fn build_engine(
    config: MitmConfig,
) -> MitmEngine<DefaultPolicyEngine, mitm_observe::NoopEventConsumer> {
    build_engine_with_sink(config, mitm_observe::NoopEventConsumer)
}

async fn run_with_timeout<F>(label: &str, future: F) -> io::Result<()>
where
    F: Future<Output = io::Result<()>>,
{
    let configured_exchange_timeout_seconds = env::var("SOTH_MITM_SOAK_EXCHANGE_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(20);
    let timeout_seconds = if label == "tls_h2_exchange"
        && env::var("SOTH_MITM_SOAK_EXCHANGE_TIMEOUT_SECONDS").is_err()
    {
        let stage_timeout_seconds = env::var("SOTH_MITM_SOAK_STAGE_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(10);
        let retries = env::var("SOTH_MITM_SOAK_H2_RETRIES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(2);
        let retry_envelope = stage_timeout_seconds
            .saturating_mul(retries.saturating_add(1))
            .saturating_add(5);
        configured_exchange_timeout_seconds.max(retry_envelope)
    } else {
        configured_exchange_timeout_seconds
    };
    timeout(Duration::from_secs(timeout_seconds), future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{label} timed out")))?
}

async fn run_stage_timeout<T, F>(label: &str, seconds: u64, future: F) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    timeout(Duration::from_secs(seconds), future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{label} timed out")))?
}

async fn run_stage_timeout_raw<T, F>(label: &str, seconds: u64, future: F) -> io::Result<T>
where
    F: Future<Output = T>,
{
    timeout(Duration::from_secs(seconds), future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{label} timed out")))
}

async fn start_sidecar(
    config: MitmConfig,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
    std::sync::Arc<RuntimeGovernor>,
) {
    let sidecar_config = SidecarConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: 64 * 1024,
        idle_watchdog_timeout: std::time::Duration::from_secs(30),
        upstream_connect_timeout: std::time::Duration::from_secs(10),
        stream_stage_timeout: std::time::Duration::from_secs(15),
        unix_socket_path: None,
    };
    let engine = build_engine(config);
    let server = SidecarServer::new(sidecar_config, engine).expect("build sidecar");
    let runtime = server.runtime_observability_handle();
    let listener = bind_loopback_listener_with_retry("bind sidecar").await;
    let addr = listener.local_addr().expect("listener local addr");
    let handle = tokio::spawn(server.run_with_listener(listener));
    (addr, handle, runtime)
}

async fn start_sidecar_with_vec_sink(
    config: MitmConfig,
    sink: VecEventConsumer,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
    std::sync::Arc<RuntimeGovernor>,
    VecEventConsumer,
) {
    let sidecar_config = SidecarConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: 64 * 1024,
        idle_watchdog_timeout: std::time::Duration::from_secs(30),
        upstream_connect_timeout: std::time::Duration::from_secs(10),
        stream_stage_timeout: std::time::Duration::from_secs(15),
        unix_socket_path: None,
    };
    let engine = build_engine_with_sink(config, sink.clone());
    let server = SidecarServer::new(sidecar_config, engine).expect("build sidecar");
    let runtime = server.runtime_observability_handle();
    let listener = bind_loopback_listener_with_retry("bind sidecar").await;
    let addr = listener.local_addr().expect("listener local addr");
    let handle = tokio::spawn(server.run_with_listener(listener));
    (addr, handle, runtime, sink)
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
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break,
            Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => break,
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => break,
            Err(error) => panic!("read stream: {error}"),
        }
    }
    out
}

async fn start_tunnel_upstream() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = bind_loopback_listener_with_retry("bind tunnel upstream").await;
    let port = listener.local_addr().expect("tunnel upstream addr").port();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut ping = [0_u8; 4];
                if socket.read_exact(&mut ping).await.is_ok() && &ping == b"ping" {
                    let _ = socket.write_all(b"pong").await;
                }
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, task)
}

async fn start_plain_http_upstream() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = bind_loopback_listener_with_retry("bind plain HTTP upstream").await;
    let port = listener
        .local_addr()
        .expect("plain HTTP upstream addr")
        .port();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let request_head = read_http_head(&mut socket).await;
                let request_text = String::from_utf8_lossy(&request_head);
                assert!(
                    request_text.starts_with("GET /plain HTTP/1.1"),
                    "{request_text}"
                );
                let response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong";
                let _ = socket.write_all(response).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, task)
}

async fn start_tls_http1_upstream() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = bind_loopback_listener_with_retry("bind TLS HTTP/1 upstream").await;
    let port = listener
        .local_addr()
        .expect("TLS HTTP/1 upstream addr")
        .port();
    let task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let request_head = read_http_head(&mut tls).await;
                let request_text = String::from_utf8_lossy(&request_head);
                let request_line = request_text.lines().next().unwrap_or_default();

                if request_line.starts_with("GET /sse HTTP/1.1") {
                    let response = concat!(
                        "HTTP/1.1 200 OK\r\n",
                        "Content-Type: text/event-stream\r\n",
                        "Connection: close\r\n",
                        "\r\n",
                        "event: tick\n",
                        "data: one\n\n",
                        "data: two\n\n"
                    );
                    let _ = tls.write_all(response.as_bytes()).await;
                    let _ = tls.shutdown().await;
                    return;
                }

                assert!(
                    request_line.starts_with("GET /hello HTTP/1.1"),
                    "{request_text}"
                );
                let response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nworld";
                let _ = tls.write_all(response).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, task)
}

async fn start_tls_h2_upstream() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = bind_loopback_listener_with_retry("bind TLS H2 upstream").await;
    let port = listener.local_addr().expect("TLS H2 upstream addr").port();
    let task = tokio::spawn(async move {
        let server_config = mitm_tls::build_http_server_config_for_host("127.0.0.1", true)
            .expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let h2_accept_timeout = soak_h2_upstream_accept_timeout();
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let conn_id = H2_UPSTREAM_CONN_SEQ.fetch_add(1, Ordering::Relaxed);
                soak_debug(format!("[h2-upstream:{conn_id}] accepted tcp"));
                let tls = match acceptor.accept(tcp).await {
                    Ok(stream) => {
                        soak_debug(format!("[h2-upstream:{conn_id}] tls accepted"));
                        stream
                    }
                    Err(_) => return,
                };
                if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
                    soak_debug(format!("[h2-upstream:{conn_id}] non-h2 ALPN"));
                    return;
                }
                soak_debug(format!("[h2-upstream:{conn_id}] h2 handshake start"));
                let mut h2_conn = match h2::server::handshake(tls).await {
                    Ok(connection) => {
                        soak_debug(format!("[h2-upstream:{conn_id}] h2 handshake done"));
                        connection
                    }
                    Err(_) => return,
                };
                let stream_result = match timeout(h2_accept_timeout, h2_conn.accept()).await {
                    Ok(Some(result)) => result,
                    Ok(None) => return,
                    Err(_) => {
                        soak_debug(format!(
                            "[h2-upstream:{conn_id}] timed out waiting for request stream"
                        ));
                        return;
                    }
                };
                soak_debug(format!("[h2-upstream:{conn_id}] got request stream"));
                let (request, mut respond) = match stream_result {
                    Ok(value) => value,
                    Err(_) => return,
                };
                let (parts, mut body) = request.into_parts();
                assert_eq!(parts.method, http::Method::POST);
                let response = http::Response::builder()
                    .status(200)
                    .header("content-length", "2")
                    .body(())
                    .expect("h2 response");
                let mut send = match respond.send_response(response, false) {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                if send.send_data(Bytes::from_static(b"ok"), true).is_err() {
                    return;
                }
                soak_debug(format!("[h2-upstream:{conn_id}] response sent"));
                let _ = timeout(Duration::from_millis(250), async {
                    while let Some(next) = body.data().await {
                        if next.is_err() {
                            break;
                        }
                    }
                    let _ = body.trailers().await;
                })
                .await;
                h2_conn.graceful_shutdown();
                let _ = timeout(Duration::from_secs(1), async {
                    let _ = std::future::poll_fn(|cx| h2_conn.poll_closed(cx)).await;
                })
                .await;
                soak_debug(format!("[h2-upstream:{conn_id}] closed"));
            });
        }
    });
    (port, task)
}

async fn run_tunnel_exchange(
    proxy_addr: std::net::SocketAddr,
    upstream_port: u16,
) -> io::Result<()> {
    let mut tcp = TcpStream::connect(proxy_addr).await?;
    let connect = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nx-proxy-protocol: h3\r\n\r\n"
    );
    tcp.write_all(connect.as_bytes()).await?;
    let connect_response = read_response_head(&mut tcp).await;
    if !connect_response.starts_with("HTTP/1.1 200 Connection Established") {
        return Err(io::Error::other(format!(
            "unexpected tunnel CONNECT response: {connect_response}"
        )));
    }
    tcp.write_all(b"ping").await?;
    let mut pong = [0_u8; 4];
    tcp.read_exact(&mut pong).await?;
    if &pong != b"pong" {
        return Err(io::Error::other("unexpected tunnel payload"));
    }
    let _ = tcp.shutdown().await;
    Ok(())
}

async fn run_forward_http_exchange(
    proxy_addr: std::net::SocketAddr,
    upstream_port: u16,
) -> io::Result<()> {
    let mut tcp = TcpStream::connect(proxy_addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/plain HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    tcp.write_all(request.as_bytes()).await?;
    let response = read_to_end_allow_unexpected_eof(&mut tcp).await;
    let text = String::from_utf8_lossy(&response);
    if !text.starts_with("HTTP/1.1 200 OK") || !text.ends_with("pong") {
        return Err(io::Error::other(format!(
            "unexpected forward HTTP response: {text}"
        )));
    }
    Ok(())
}

async fn run_tls_http1_exchange(
    proxy_addr: std::net::SocketAddr,
    upstream_port: u16,
) -> io::Result<()> {
    let mut tcp = TcpStream::connect(proxy_addr).await?;
    let connect = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    tcp.write_all(connect.as_bytes()).await?;
    let connect_response = read_response_head(&mut tcp).await;
    if !connect_response.starts_with("HTTP/1.1 200 Connection Established") {
        return Err(io::Error::other(format!(
            "unexpected TLS/H1 CONNECT response: {connect_response}"
        )));
    }
    let connector = TlsConnector::from(build_http1_client_config(true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let mut tls = connector.connect(server_name, tcp).await?;
    tls.write_all(b"GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await?;
    tls.flush().await?;
    let response = read_to_end_allow_unexpected_eof(&mut tls).await;
    let text = String::from_utf8_lossy(&response);
    if !text.starts_with("HTTP/1.1 200 OK") || !text.ends_with("world") {
        return Err(io::Error::other(format!(
            "unexpected TLS/H1 response: {text}"
        )));
    }
    Ok(())
}

async fn run_tls_sse_exchange(
    proxy_addr: std::net::SocketAddr,
    upstream_port: u16,
) -> io::Result<()> {
    let mut tcp = TcpStream::connect(proxy_addr).await?;
    let connect = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    tcp.write_all(connect.as_bytes()).await?;
    let connect_response = read_response_head(&mut tcp).await;
    if !connect_response.starts_with("HTTP/1.1 200 Connection Established") {
        return Err(io::Error::other(format!(
            "unexpected TLS/SSE CONNECT response: {connect_response}"
        )));
    }
    let connector = TlsConnector::from(build_http1_client_config(true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let mut tls = connector.connect(server_name, tcp).await?;
    tls.write_all(b"GET /sse HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await?;
    tls.flush().await?;
    let response = read_to_end_allow_unexpected_eof(&mut tls).await;
    let text = String::from_utf8_lossy(&response);
    if !text.starts_with("HTTP/1.1 200 OK")
        || !text.contains("text/event-stream")
        || !text.contains("data: one")
    {
        return Err(io::Error::other(format!(
            "unexpected TLS/SSE response: {text}"
        )));
    }
    Ok(())
}

async fn run_tls_h2_exchange_once(
    proxy_addr: std::net::SocketAddr,
    upstream_port: u16,
) -> io::Result<()> {
    let stage_timeout_secs = env::var("SOTH_MITM_SOAK_STAGE_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(10);
    let exchange_id = H2_EXCHANGE_SEQ.fetch_add(1, Ordering::Relaxed);
    soak_debug(format!("[h2-exchange:{exchange_id}] start"));
    let mut tcp = run_stage_timeout(
        "tls_h2_tcp_connect",
        stage_timeout_secs,
        TcpStream::connect(proxy_addr),
    )
    .await?;
    let connect = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    run_stage_timeout(
        "tls_h2_connect_write",
        stage_timeout_secs,
        tcp.write_all(connect.as_bytes()),
    )
    .await?;
    soak_debug(format!("[h2-exchange:{exchange_id}] CONNECT sent"));
    let connect_response = run_stage_timeout_raw(
        "tls_h2_connect_response",
        stage_timeout_secs,
        read_response_head(&mut tcp),
    )
    .await?;
    if !connect_response.starts_with("HTTP/1.1 200 Connection Established") {
        return Err(io::Error::other(format!(
            "unexpected TLS/H2 CONNECT response: {connect_response}"
        )));
    }

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let tls = run_stage_timeout(
        "tls_h2_tls_connect",
        stage_timeout_secs,
        connector.connect(server_name, tcp),
    )
    .await?;
    soak_debug(format!(
        "[h2-exchange:{exchange_id}] downstream TLS connected"
    ));
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err(io::Error::other("sidecar did not negotiate h2 ALPN"));
    }

    let (mut h2_client, h2_connection) =
        run_stage_timeout("tls_h2_client_handshake", stage_timeout_secs, async {
            h2::client::handshake(tls)
                .await
                .map_err(|error| io::Error::other(format!("h2 client handshake failed: {error}")))
        })
        .await?;
    soak_debug(format!(
        "[h2-exchange:{exchange_id}] h2 client handshake done"
    ));
    let mut h2_connection_task = tokio::spawn(async move {
        let _ = h2_connection.await;
    });

    let request = http::Request::builder()
        .method("POST")
        .uri("https://127.0.0.1/grpc.Test/Say")
        .header("host", "127.0.0.1")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .expect("h2 request");
    let (response_future, mut send_stream) =
        run_stage_timeout("tls_h2_send_request", stage_timeout_secs, async {
            h2_client
                .send_request(request, false)
                .map_err(|error| io::Error::other(format!("h2 send request failed: {error}")))
        })
        .await?;
    run_stage_timeout("tls_h2_send_data", stage_timeout_secs, async {
        send_stream
            .send_data(Bytes::from_static(b"\x00\x00\x00\x00\x00"), true)
            .map_err(|error| io::Error::other(format!("h2 send data failed: {error}")))
    })
    .await?;
    soak_debug(format!("[h2-exchange:{exchange_id}] request frame sent"));

    let response = run_stage_timeout("tls_h2_response", stage_timeout_secs, async {
        response_future
            .await
            .map_err(|error| io::Error::other(format!("h2 response failed: {error}")))
    })
    .await?;
    soak_debug(format!(
        "[h2-exchange:{exchange_id}] response headers received"
    ));
    if response.status() != http::StatusCode::OK {
        return Err(io::Error::other(format!(
            "unexpected h2 status: {}",
            response.status()
        )));
    }
    let mut body = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) =
        run_stage_timeout_raw("tls_h2_body_chunk", stage_timeout_secs, body.data()).await?
    {
        let chunk =
            chunk.map_err(|error| io::Error::other(format!("h2 body read failed: {error}")))?;
        payload.extend_from_slice(&chunk);
    }
    soak_debug(format!(
        "[h2-exchange:{exchange_id}] response body complete"
    ));
    if payload != b"ok" {
        return Err(io::Error::other("unexpected h2 response payload"));
    }

    drop(h2_client);
    let h2_teardown_grace = Duration::from_millis(100);
    if timeout(h2_teardown_grace, &mut h2_connection_task)
        .await
        .is_err()
    {
        soak_debug(format!(
            "[h2-exchange:{exchange_id}] forcing client h2 driver teardown"
        ));
        h2_connection_task.abort();
        let _ = h2_connection_task.await;
    }
    soak_debug(format!("[h2-exchange:{exchange_id}] done"));
    Ok(())
}

async fn run_tls_h2_exchange(
    proxy_addr: std::net::SocketAddr,
    upstream_port: u16,
) -> io::Result<()> {
    let retries = env::var("SOTH_MITM_SOAK_H2_RETRIES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(2);
    let mut last_error: Option<io::Error> = None;
    for attempt in 0..=retries {
        match run_tls_h2_exchange_once(proxy_addr, upstream_port).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                if attempt == retries {
                    last_error = Some(error);
                    break;
                }
                soak_debug(format!(
                    "[h2-exchange-retry] attempt={} failed with {}; retrying",
                    attempt + 1,
                    error
                ));
                sleep(Duration::from_millis(25)).await;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("tls_h2_exchange failed without detail")))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn mixed_traffic_soak_respects_runtime_budget_envelope() {
    let soak_seconds = env::var("SOTH_MITM_SOAK_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    if soak_seconds == 0 {
        eprintln!(
            "skipping mixed_traffic_soak_respects_runtime_budget_envelope; set SOTH_MITM_SOAK_SECONDS>0"
        );
        return;
    }
    let min_iterations = env::var("SOTH_MITM_SOAK_MIN_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1);
    let max_iterations = env::var("SOTH_MITM_SOAK_MAX_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok());
    let serial_mode = env::var("SOTH_MITM_SOAK_SERIAL")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(true);
    let exchanges = env::var("SOTH_MITM_SOAK_EXCHANGES")
        .unwrap_or_else(|_| "tunnel,forward,tls_http1,tls_sse,tls_h2".to_string());
    let selected: BTreeSet<&str> = exchanges
        .split([',', ' '])
        .filter(|value| !value.is_empty())
        .collect();
    let run_tunnel = selected.contains("tunnel");
    let run_forward = selected.contains("forward");
    let run_tls_http1 = selected.contains("tls_http1");
    let run_tls_sse = selected.contains("tls_sse");
    let run_tls_h2 = selected.contains("tls_h2");
    let expected_flows_per_iteration = [
        run_tunnel,
        run_forward,
        run_tls_http1,
        run_tls_sse,
        run_tls_h2,
    ]
    .into_iter()
    .filter(|enabled| *enabled)
    .count() as u64;

    let max_concurrent_flows = 256_usize;
    let max_in_flight_bytes = 32 * 1024 * 1024_usize;
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        max_concurrent_flows,
        max_in_flight_bytes,
        ..MitmConfig::default()
    };

    let (tunnel_port, tunnel_task) = start_tunnel_upstream().await;
    let (plain_http_port, plain_http_task) = start_plain_http_upstream().await;
    let (tls_http1_port, tls_http1_task) = start_tls_http1_upstream().await;
    let (tls_h2_port, tls_h2_task) = start_tls_h2_upstream().await;

    let (proxy_addr, proxy_task, runtime) = start_sidecar(config).await;
    let deadline = Instant::now() + Duration::from_secs(soak_seconds);
    let mut iterations = 0_u64;

    while Instant::now() < deadline {
        if let Some(limit) = max_iterations {
            if iterations >= limit {
                break;
            }
        }
        if serial_mode {
            if run_tunnel {
                run_with_timeout(
                    "tunnel_exchange",
                    run_tunnel_exchange(proxy_addr, tunnel_port),
                )
                .await
                .expect("tunnel exchange should succeed");
                sleep(Duration::from_millis(20)).await;
            }
            if run_forward {
                run_with_timeout(
                    "forward_http_exchange",
                    run_forward_http_exchange(proxy_addr, plain_http_port),
                )
                .await
                .expect("forward HTTP exchange should succeed");
                sleep(Duration::from_millis(20)).await;
            }
            if run_tls_http1 {
                run_with_timeout(
                    "tls_http1_exchange",
                    run_tls_http1_exchange(proxy_addr, tls_http1_port),
                )
                .await
                .expect("TLS/H1 exchange should succeed");
                sleep(Duration::from_millis(20)).await;
            }
            if run_tls_sse {
                run_with_timeout(
                    "tls_sse_exchange",
                    run_tls_sse_exchange(proxy_addr, tls_http1_port),
                )
                .await
                .expect("TLS/SSE exchange should succeed");
                sleep(Duration::from_millis(20)).await;
            }
            if run_tls_h2 {
                run_with_timeout(
                    "tls_h2_exchange",
                    run_tls_h2_exchange(proxy_addr, tls_h2_port),
                )
                .await
                .expect("TLS/H2 exchange should succeed");
            }
        } else {
            let mixed_result = tokio::try_join!(
                async {
                    if run_tunnel {
                        run_with_timeout(
                            "tunnel_exchange",
                            run_tunnel_exchange(proxy_addr, tunnel_port),
                        )
                        .await
                    } else {
                        Ok(())
                    }
                },
                async {
                    if run_forward {
                        run_with_timeout(
                            "forward_http_exchange",
                            run_forward_http_exchange(proxy_addr, plain_http_port),
                        )
                        .await
                    } else {
                        Ok(())
                    }
                },
                async {
                    if run_tls_http1 {
                        run_with_timeout(
                            "tls_http1_exchange",
                            run_tls_http1_exchange(proxy_addr, tls_http1_port),
                        )
                        .await
                    } else {
                        Ok(())
                    }
                },
                async {
                    if run_tls_sse {
                        run_with_timeout(
                            "tls_sse_exchange",
                            run_tls_sse_exchange(proxy_addr, tls_http1_port),
                        )
                        .await
                    } else {
                        Ok(())
                    }
                },
                async {
                    if run_tls_h2 {
                        run_with_timeout(
                            "tls_h2_exchange",
                            run_tls_h2_exchange(proxy_addr, tls_h2_port),
                        )
                        .await
                    } else {
                        Ok(())
                    }
                },
            );
            if let Err(error) = mixed_result {
                let snapshot = runtime.snapshot();
                panic!(
                    "mixed traffic iteration failed at iteration={} active_flows={} in_flight={} budget_denials={} backpressure={} idle_timeouts={} stage_timeouts={} stuck_flows={} error={error}",
                    iterations,
                    snapshot.active_flows,
                    snapshot.current_in_flight_bytes,
                    snapshot.budget_denial_count,
                    snapshot.backpressure_activation_count,
                    snapshot.idle_timeout_count,
                    snapshot.stream_stage_timeout_count,
                    snapshot.stuck_flow_count,
                );
            }
        }
        iterations += 1;

        let snapshot = runtime.snapshot();
        if soak_debug_enabled() {
            soak_debug(format!(
                "[soak-iter] iteration={} active_flows={} in_flight={} flow_count={} budget_denials={} backpressure={} idle_timeouts={} stage_timeouts={} stuck_flows={}",
                iterations,
                snapshot.active_flows,
                snapshot.current_in_flight_bytes,
                snapshot.flow_count,
                snapshot.budget_denial_count,
                snapshot.backpressure_activation_count,
                snapshot.idle_timeout_count,
                snapshot.stream_stage_timeout_count,
                snapshot.stuck_flow_count,
            ));
        }
        assert!(
            snapshot.current_in_flight_bytes <= max_in_flight_bytes as u64,
            "in-flight bytes exceeded budget: {} > {}",
            snapshot.current_in_flight_bytes,
            max_in_flight_bytes
        );
        assert!(
            snapshot.active_flows <= max_concurrent_flows as u64,
            "active flows exceeded budget: {} > {}",
            snapshot.active_flows,
            max_concurrent_flows
        );
    }

    let settle_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let snapshot = runtime.snapshot();
        if snapshot.active_flows == 0 && snapshot.current_in_flight_bytes == 0 {
            break;
        }
        assert!(
            Instant::now() < settle_deadline,
            "runtime did not settle: active_flows={} in_flight={} flow_count={} budget_denials={} backpressure={} idle_timeouts={} stage_timeouts={} stuck_flows={}",
            snapshot.active_flows,
            snapshot.current_in_flight_bytes,
            snapshot.flow_count,
            snapshot.budget_denial_count,
            snapshot.backpressure_activation_count,
            snapshot.idle_timeout_count,
            snapshot.stream_stage_timeout_count,
            snapshot.stuck_flow_count,
        );
        sleep(Duration::from_millis(20)).await;
    }

    let snapshot = runtime.snapshot();
    assert!(
        iterations >= min_iterations,
        "insufficient soak iterations: got={iterations}, min={min_iterations}"
    );
    assert!(
        snapshot.flow_count >= iterations * expected_flows_per_iteration,
        "flow count lower than expected floor: flow_count={} iterations={iterations} expected_flows_per_iteration={expected_flows_per_iteration}",
        snapshot.flow_count
    );
    assert!(
        snapshot.in_flight_bytes_watermark > 0,
        "expected non-zero in-flight watermark"
    );
    assert_eq!(
        snapshot.budget_denial_count, 0,
        "no budget denials expected for configured soak envelope"
    );
    assert_eq!(
        snapshot.idle_timeout_count, 0,
        "no idle watchdog timeouts expected for configured soak envelope"
    );
    assert!(
        snapshot.stream_stage_timeout_count <= iterations,
        "stream-stage timeouts exceeded bounded allowance: stage_timeouts={} iterations={iterations}",
        snapshot.stream_stage_timeout_count
    );
    assert!(
        snapshot.stuck_flow_count <= (iterations * 2),
        "stuck-flow telemetry exceeded bounded allowance: stuck_flows={} iterations={iterations}",
        snapshot.stuck_flow_count
    );

    proxy_task.abort();
    tunnel_task.abort();
    plain_http_task.abort();
    tls_http1_task.abort();
    tls_h2_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_traffic_close_reasons_are_deterministic() {
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        max_concurrent_flows: 256,
        max_in_flight_bytes: 32 * 1024 * 1024,
        ..MitmConfig::default()
    };
    let sink = VecEventConsumer::default();

    let (tunnel_port, tunnel_task) = start_tunnel_upstream().await;
    let (plain_http_port, plain_http_task) = start_plain_http_upstream().await;
    let (tls_http1_port, tls_http1_task) = start_tls_http1_upstream().await;
    let (tls_h2_port, tls_h2_task) = start_tls_h2_upstream().await;
    let (proxy_addr, proxy_task, runtime, sink) = start_sidecar_with_vec_sink(config, sink).await;

    run_with_timeout(
        "tunnel_exchange",
        run_tunnel_exchange(proxy_addr, tunnel_port),
    )
    .await
    .expect("tunnel exchange should succeed");
    run_with_timeout(
        "forward_http_exchange",
        run_forward_http_exchange(proxy_addr, plain_http_port),
    )
    .await
    .expect("forward HTTP exchange should succeed");
    run_with_timeout(
        "tls_http1_exchange",
        run_tls_http1_exchange(proxy_addr, tls_http1_port),
    )
    .await
    .expect("TLS/H1 exchange should succeed");
    run_with_timeout(
        "tls_sse_exchange",
        run_tls_sse_exchange(proxy_addr, tls_http1_port),
    )
    .await
    .expect("TLS/SSE exchange should succeed");
    run_with_timeout(
        "tls_h2_exchange",
        run_tls_h2_exchange(proxy_addr, tls_h2_port),
    )
    .await
    .expect("TLS/H2 exchange should succeed");

    timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = runtime.snapshot();
            if snapshot.active_flows == 0 {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("runtime should settle after mixed traffic exchange");

    let allowed_reasons: BTreeSet<&'static str> = BTreeSet::from([
        "blocked",
        "connect_parse_failed",
        "tls_handshake_failed",
        "route_planner_failed",
        "upstream_connect_failed",
        "relay_eof",
        "relay_error",
        "idle_watchdog_timeout",
        "stream_stage_timeout",
        "mitm_http_completed",
        "mitm_http_error",
        "websocket_completed",
        "websocket_error",
    ]);

    let events = sink.snapshot();
    let mut seen_flows = HashSet::new();
    let mut unknown_reasons = BTreeSet::new();
    for event in events
        .iter()
        .filter(|event| event.kind == EventType::StreamClosed)
    {
        assert!(
            seen_flows.insert(event.context.flow_id),
            "duplicate stream_closed event for flow_id={}",
            event.context.flow_id
        );
        let reason = event
            .attributes
            .get("reason_code")
            .map(String::as_str)
            .unwrap_or("<missing>");
        if !allowed_reasons.contains(reason) {
            unknown_reasons.insert(reason.to_string());
        }
    }
    assert!(
        !seen_flows.is_empty(),
        "expected at least one stream_closed event"
    );
    assert!(
        unknown_reasons.is_empty(),
        "unexpected stream_closed reason codes: {:?}",
        unknown_reasons
    );

    proxy_task.abort();
    tunnel_task.abort();
    plain_http_task.abort();
    tls_http1_task.abort();
    tls_h2_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_h2_exchange_harness_path_succeeds() {
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        max_concurrent_flows: 256,
        max_in_flight_bytes: 32 * 1024 * 1024,
        ..MitmConfig::default()
    };
    let (tls_h2_port, tls_h2_task) = start_tls_h2_upstream().await;
    let (proxy_addr, proxy_task, runtime) = start_sidecar(config).await;

    run_with_timeout(
        "tls_h2_exchange",
        run_tls_h2_exchange(proxy_addr, tls_h2_port),
    )
    .await
    .expect("TLS/H2 exchange should succeed");

    let snapshot = runtime.snapshot();
    assert_eq!(
        snapshot.budget_denial_count, 0,
        "unexpected budget denials in focused TLS/H2 exchange"
    );
    proxy_task.abort();
    tls_h2_task.abort();
}
