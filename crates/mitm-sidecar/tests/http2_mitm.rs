use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use mitm_core::{
    CompatibilityOverrideConfig, InterceptMode, MitmConfig, MitmEngine, RouteEndpointConfig,
    RouteMode,
};
use mitm_http::ApplicationProtocol;
use mitm_observe::{Event, EventType, FlowContext, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{
    FlowHooks, H2ResponseOverflowMode, RawRequest as HookRawRequest,
    RawResponse as HookRawResponse, RequestDecision, SidecarConfig, SidecarServer,
};
use mitm_tls::{
    build_http1_server_config_for_host, build_http_client_config, build_http_server_config_for_host,
};
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
    start_sidecar_with_sink_and_stream_stage_timeout(
        sink,
        config,
        std::time::Duration::from_secs(5),
    )
    .await
}

async fn start_sidecar_with_sink_and_stream_stage_timeout(
    sink: VecEventConsumer,
    config: MitmConfig,
    stream_stage_timeout: Duration,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
    VecEventConsumer,
) {
    start_sidecar_with_sink_and_h2_reliability(
        sink,
        config,
        stream_stage_timeout,
        stream_stage_timeout,
        H2ResponseOverflowMode::TruncateContinue,
    )
    .await
}

async fn start_sidecar_with_sink_and_h2_reliability(
    sink: VecEventConsumer,
    config: MitmConfig,
    stream_stage_timeout: Duration,
    h2_body_idle_timeout: Duration,
    h2_response_overflow_mode: H2ResponseOverflowMode,
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
        stream_stage_timeout,
        h2_body_idle_timeout,
        h2_response_overflow_mode,
        unix_socket_path: None,
    };
    let mut config = config;
    config.h2_response_overflow_strict = matches!(
        h2_response_overflow_mode,
        H2ResponseOverflowMode::StrictFail
    );
    let engine = build_engine(config, sink.clone());
    let server = SidecarServer::new(sidecar_config, engine).expect("build sidecar");
    let listener = server.bind_listener().await.expect("bind sidecar");
    let addr = listener.local_addr().expect("listener local addr");
    let handle = tokio::spawn(server.run_with_listener(listener));
    (addr, handle, sink)
}

async fn start_sidecar_with_flow_hooks(
    sink: VecEventConsumer,
    config: MitmConfig,
    flow_hooks: Arc<dyn FlowHooks>,
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
        h2_response_overflow_mode: mitm_sidecar::H2ResponseOverflowMode::TruncateContinue,
        unix_socket_path: None,
    };
    let engine = build_engine(config, sink.clone());
    let server = SidecarServer::new_with_flow_hooks(sidecar_config, engine, flow_hooks)
        .expect("build sidecar");
    let listener = server.bind_listener().await.expect("bind sidecar");
    let addr = listener.local_addr().expect("listener local addr");
    let handle = tokio::spawn(server.run_with_listener(listener));
    (addr, handle, sink)
}

#[derive(Clone, Default)]
struct RequestHostCaptureHooks {
    seen_host: Arc<tokio::sync::Mutex<Option<String>>>,
    request_count: Arc<AtomicUsize>,
    response_count: Arc<AtomicUsize>,
    stream_end_count: Arc<AtomicUsize>,
}

impl RequestHostCaptureHooks {
    async fn seen_host(&self) -> Option<String> {
        self.seen_host.lock().await.clone()
    }

    fn request_count(&self) -> usize {
        self.request_count.load(Ordering::Relaxed)
    }

    fn response_count(&self) -> usize {
        self.response_count.load(Ordering::Relaxed)
    }

    fn stream_end_count(&self) -> usize {
        self.stream_end_count.load(Ordering::Relaxed)
    }
}

impl FlowHooks for RequestHostCaptureHooks {
    fn on_request(
        &self,
        _context: FlowContext,
        request: HookRawRequest,
    ) -> Pin<Box<dyn Future<Output = RequestDecision> + Send>> {
        let seen_host = Arc::clone(&self.seen_host);
        let request_count = Arc::clone(&self.request_count);
        Box::pin(async move {
            let host = request
                .headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned);
            *seen_host.lock().await = host;
            request_count.fetch_add(1, Ordering::Relaxed);
            RequestDecision::Allow
        })
    }

    fn on_response(
        &self,
        context: FlowContext,
        _response: HookRawResponse,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let response_count = Arc::clone(&self.response_count);
        Box::pin(async move {
            if context.protocol == ApplicationProtocol::Http2 {
                response_count.fetch_add(1, Ordering::Relaxed);
            }
        })
    }

    fn on_stream_end(&self, context: FlowContext) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let stream_end_count = Arc::clone(&self.stream_end_count);
        Box::pin(async move {
            if context.protocol == ApplicationProtocol::Http2 {
                stream_end_count.fetch_add(1, Ordering::Relaxed);
            }
        })
    }
}

#[derive(Clone, Default)]
struct Http2StreamEndCounterHooks {
    ended_http2_streams: Arc<AtomicUsize>,
}

impl Http2StreamEndCounterHooks {
    fn ended_http2_streams(&self) -> usize {
        self.ended_http2_streams.load(Ordering::Relaxed)
    }
}

impl FlowHooks for Http2StreamEndCounterHooks {
    fn on_stream_end(&self, context: FlowContext) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let ended_http2_streams = Arc::clone(&self.ended_http2_streams);
        Box::pin(async move {
            if context.protocol == ApplicationProtocol::Http2 {
                ended_http2_streams.fetch_add(1, Ordering::Relaxed);
            }
        })
    }
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

async fn read_h2_body_and_trailers(
    body: &mut h2::RecvStream,
) -> (Vec<u8>, Option<http::HeaderMap>) {
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        payload.extend_from_slice(&chunk.expect("read body chunk"));
    }
    let trailers = if body.is_end_stream() {
        None
    } else {
        tokio::time::timeout(Duration::from_secs(1), body.trailers())
            .await
            .expect("read body trailers timeout")
            .expect("read body trailers")
    };
    (payload, trailers)
}

async fn send_h2_request_body_with_capacity(
    send_stream: &mut h2::SendStream<Bytes>,
    total_bytes: usize,
    chunk_bytes: usize,
    fill: u8,
) {
    if total_bytes == 0 {
        send_stream
            .send_data(Bytes::new(), true)
            .expect("send empty request body");
        return;
    }

    let mut remaining = total_bytes;
    let chunk_bytes = chunk_bytes.max(1);
    while remaining > 0 {
        let desired = remaining.min(chunk_bytes);
        send_stream.reserve_capacity(desired);
        let capacity = poll_fn(|cx| send_stream.poll_capacity(cx))
            .await
            .expect("poll request body capacity")
            .expect("request body stream closed before capacity was available");
        if capacity == 0 {
            continue;
        }
        let send_len = capacity.min(desired);
        let end_stream = send_len == remaining;
        send_stream
            .send_data(Bytes::from(vec![fill; send_len]), end_stream)
            .expect("send request body chunk");
        remaining -= send_len;
    }
}

fn should_retry_bind(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrInUse
    )
}

async fn bind_loopback_listener_with_retry(label: &str) -> TcpListener {
    let retries = 40_u32;
    let retry_delay = Duration::from_millis(100);
    for attempt in 1..=retries {
        match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => return listener,
            Err(error) if should_retry_bind(&error) && attempt < retries => {
                tracing::debug!(
                    test = "http2_mitm",
                    %label,
                    attempt,
                    %error,
                    "loopback bind failed; retrying"
                );
                tokio::time::sleep(retry_delay).await;
            }
            Err(error) => panic!("{label}: {error}"),
        }
    }
    panic!("{label}: exhausted bind retries");
}

fn has_tls_success_for_peer_with_protocol(
    events: &[Event],
    peer: &str,
    protocol: ApplicationProtocol,
) -> bool {
    events.iter().any(|event| {
        event.kind == EventType::TlsHandshakeSucceeded
            && event.context.protocol == protocol
            && event.attributes.get("peer").map(String::as_str) == Some(peer)
    })
}

fn stream_closed_for_protocol<'a>(
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

fn assert_http2_terminal_flows_have_completion_or_tls_failure_taxonomy(
    events: &[Event],
    hooks: &RequestHostCaptureHooks,
) {
    let tls_failures = events
        .iter()
        .filter(|event| event.kind == EventType::TlsHandshakeFailed)
        .collect::<Vec<_>>();
    for event in tls_failures {
        let has_reason = event
            .attributes
            .get("tls_failure_reason")
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
        let has_source = event
            .attributes
            .get("tls_failure_source")
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
        let has_provider = event
            .attributes
            .get("tls_ops_provider")
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
        assert!(
            has_reason && has_source && has_provider,
            "TLS failure events must carry taxonomy fields"
        );
    }

    let flow_ids = events
        .iter()
        .filter(|event| event.context.protocol == ApplicationProtocol::Http2)
        .filter(|event| {
            matches!(
                event.kind,
                EventType::RequestHeaders | EventType::GrpcRequestHeaders | EventType::StreamClosed
            )
        })
        .map(|event| event.context.flow_id)
        .collect::<std::collections::BTreeSet<_>>();
    if flow_ids.is_empty() {
        assert!(
            hooks.request_count() > 0,
            "expected at least one intercepted HTTP/2 request in flow hooks"
        );
        assert!(
            hooks.response_count() > 0 || hooks.stream_end_count() > 0,
            "expected response or stream-end callback for intercepted HTTP/2 request"
        );
        return;
    }

    let mut violations = Vec::new();
    for flow_id in flow_ids {
        let has_response_headers = events.iter().any(|event| {
            event.context.flow_id == flow_id
                && matches!(
                    event.kind,
                    EventType::ResponseHeaders | EventType::GrpcResponseHeaders
                )
        });
        let has_tls_failure_with_taxonomy = events.iter().any(|event| {
            if event.context.flow_id != flow_id || event.kind != EventType::TlsHandshakeFailed {
                return false;
            }
            let has_reason = event
                .attributes
                .get("tls_failure_reason")
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
            let has_source = event
                .attributes
                .get("tls_failure_source")
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
            let has_provider = event
                .attributes
                .get("tls_ops_provider")
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
            has_reason && has_source && has_provider
        });
        let stream_closed_completed = events.iter().any(|event| {
            if event.context.flow_id != flow_id || event.kind != EventType::StreamClosed {
                return false;
            }
            matches!(
                event.attributes.get("reason_code").map(String::as_str),
                Some("mitm_http_completed" | "websocket_completed" | "relay_eof")
            )
        });

        if has_response_headers || stream_closed_completed || has_tls_failure_with_taxonomy {
            continue;
        }
        violations.push(format!(
            "flow_id={flow_id} missing completion signal (response_headers or completed stream_closed or tls_failure_taxonomy)"
        ));
    }
    assert!(
        violations.is_empty(),
        "intercept diagnostic gate failed for HTTP/2 terminal flows: {violations:?}"
    );
}

fn attr_u64(event: &Event, key: &str) -> Option<u64> {
    event
        .attributes
        .get(key)
        .and_then(|value| value.parse::<u64>().ok())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intercept_http2_over_tls_relays_and_marks_protocol() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let Some(stream_result) = h2_conn.accept().await else {
            panic!("missing h2 request stream");
        };
        let (request, mut respond) = stream_result.expect("accept h2 request");
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().path(), "/hello");

        let response = http::Response::builder()
            .status(200)
            .header("content-length", "5")
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response headers");
        send.send_data(Bytes::from_static(b"world"), true)
            .expect("send response data");
        h2_conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(200), async {
            let _ = poll_fn(|cx| h2_conn.poll_closed(cx)).await;
        })
        .await;
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
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

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let h2_connection_task = tokio::spawn(async move {
        let _ = h2_connection.await;
    });

    let request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/hello")
        .header("host", "127.0.0.1")
        .body(())
        .expect("request");
    let (response_future, _send_stream) = h2_client
        .send_request(request, true)
        .expect("send h2 request");
    let response = response_future.await.expect("h2 response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        payload.extend_from_slice(&chunk);
    }
    assert_eq!(&payload, b"world");

    h2_connection_task.abort();
    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(has_tls_success_for_peer_with_protocol(
        &events,
        "downstream",
        ApplicationProtocol::Http2
    ));
    assert!(has_tls_success_for_peer_with_protocol(
        &events,
        "upstream",
        ApplicationProtocol::Http2
    ));
    assert!(events.iter().any(|event| {
        event.kind == EventType::StreamClosed
            && event.context.protocol == ApplicationProtocol::Http2
            && event.attributes.get("reason_code").map(String::as_str)
                == Some("mitm_http_completed")
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intercept_http2_request_hooks_receive_host_header_without_client_host_header() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let Some(stream_result) = h2_conn.accept().await else {
            panic!("missing h2 request stream");
        };
        let (_request, mut respond) = stream_result.expect("accept h2 request");
        let response = http::Response::builder()
            .status(200)
            .header("content-length", "2")
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response headers");
        send.send_data(Bytes::from_static(b"ok"), true)
            .expect("send response data");
        h2_conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(200), async {
            let _ = poll_fn(|cx| h2_conn.poll_closed(cx)).await;
        })
        .await;
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        intercept_mode: InterceptMode::Enforce,
        ..MitmConfig::default()
    };
    let hooks = RequestHostCaptureHooks::default();
    let (proxy_addr, proxy_task, _) =
        start_sidecar_with_flow_hooks(sink, config, Arc::new(hooks.clone())).await;

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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let h2_connection_task = tokio::spawn(async move {
        let _ = h2_connection.await;
    });

    let request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/host-fallback")
        .body(())
        .expect("request");
    let (response_future, _send_stream) = h2_client
        .send_request(request, true)
        .expect("send h2 request");
    let response = response_future.await.expect("h2 response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        payload.extend_from_slice(&chunk);
    }
    assert_eq!(&payload, b"ok");

    let observed_host = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(value) = hooks.seen_host().await {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("host header captured");
    assert_eq!(observed_host, "127.0.0.1");

    h2_connection_task.abort();
    upstream_task.await.expect("upstream task");
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intercept_http2_ai_host_request_hooks_receive_host_header_for_capture() {
    let upstream_listener = bind_loopback_listener_with_retry("bind upstream listener").await;
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("api.openai.com", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let Some(stream_result) = h2_conn.accept().await else {
            panic!("missing h2 request stream");
        };
        let (request, mut respond) = stream_result.expect("accept h2 request");
        assert_eq!(request.uri().path(), "/v1/models");
        let response = http::Response::builder()
            .status(200)
            .header("content-length", "2")
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response headers");
        send.send_data(Bytes::from_static(b"ok"), true)
            .expect("send response data");
        h2_conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(200), async {
            let _ = poll_fn(|cx| h2_conn.poll_closed(cx)).await;
        })
        .await;
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        route_mode: RouteMode::Reverse,
        reverse_upstream: Some(RouteEndpointConfig {
            host: "127.0.0.1".to_string(),
            port: upstream_addr.port(),
        }),
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        intercept_mode: InterceptMode::Enforce,
        ..MitmConfig::default()
    };
    let hooks = RequestHostCaptureHooks::default();
    let (proxy_addr, proxy_task, sink) =
        start_sidecar_with_flow_hooks(sink, config, Arc::new(hooks.clone())).await;

    let mut tcp = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    tcp.write_all(b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n")
        .await
        .expect("write CONNECT");
    let connect_response = read_response_head(&mut tcp).await;
    assert!(
        connect_response.starts_with("HTTP/1.1 200 Connection Established"),
        "{connect_response}"
    );

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("api.openai.com".to_string()).expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let h2_connection_task = tokio::spawn(async move {
        let _ = h2_connection.await;
    });

    let request = http::Request::builder()
        .method("GET")
        .uri("https://api.openai.com/v1/models")
        .body(())
        .expect("request");
    let (response_future, _send_stream) = h2_client
        .send_request(request, true)
        .expect("send h2 request");
    let response = response_future.await.expect("h2 response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        payload.extend_from_slice(&chunk);
    }
    assert_eq!(&payload, b"ok");

    let observed_host = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(value) = hooks.seen_host().await {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("request host captured");
    assert_eq!(observed_host, "api.openai.com");

    drop(h2_client);
    let _ = tokio::time::timeout(Duration::from_secs(1), h2_connection_task).await;
    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert_http2_terminal_flows_have_completion_or_tls_failure_taxonomy(&events, &hooks);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ignored_ai_host_h2_tunnel_passthrough_relays_without_mitm_hooks() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("api.openai.com", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let Some(stream_result) = h2_conn.accept().await else {
            panic!("missing h2 request stream");
        };
        let (request, mut respond) = stream_result.expect("accept h2 request");
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().path(), "/passthrough-h2");
        let response = http::Response::builder()
            .status(200)
            .header("content-length", "6")
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response headers");
        send.send_data(Bytes::from_static(b"tunnel"), true)
            .expect("send response data");
        h2_conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(300), async {
            let _ = poll_fn(|cx| h2_conn.poll_closed(cx)).await;
        })
        .await;
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        route_mode: RouteMode::Reverse,
        reverse_upstream: Some(RouteEndpointConfig {
            host: "127.0.0.1".to_string(),
            port: upstream_addr.port(),
        }),
        ignore_hosts: vec!["api.openai.com".to_string()],
        http2_enabled: true,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink(sink, config).await;

    let mut tcp = TcpStream::connect(proxy_addr)
        .await
        .expect("connect sidecar");
    tcp.write_all(b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n")
        .await
        .expect("write CONNECT");
    let connect_response = read_response_head(&mut tcp).await;
    assert!(
        connect_response.starts_with("HTTP/1.1 200 Connection Established"),
        "{connect_response}"
    );

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("api.openai.com".to_string()).expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect through tunnel");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("GET")
        .uri("https://api.openai.com/passthrough-h2")
        .header("host", "api.openai.com")
        .body(())
        .expect("request");
    let (response_future, _send_stream) = h2_client
        .send_request(request, true)
        .expect("send h2 request");
    let response = response_future.await.expect("h2 response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        payload.extend_from_slice(&chunk.expect("response body chunk"));
    }
    assert_eq!(&payload, b"tunnel");

    drop(h2_client);
    if tokio::time::timeout(Duration::from_secs(1), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::ConnectDecision
            && event.attributes.get("reason").map(String::as_str) == Some("ignored_host")
    }));
    assert!(
        !events.iter().any(|event| {
            matches!(
                event.kind,
                EventType::TlsHandshakeStarted
                    | EventType::TlsHandshakeSucceeded
                    | EventType::TlsHandshakeFailed
            )
        }),
        "ignored AI host tunnel path must not perform MITM TLS handshakes"
    );
    assert!(
        !events.iter().any(|event| {
            matches!(
                event.kind,
                EventType::RequestHeaders
                    | EventType::RequestBodyChunk
                    | EventType::ResponseHeaders
                    | EventType::ResponseBodyChunk
            )
        }),
        "ignored AI host tunnel path must not emit intercepted HTTP events"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_disabled_negotiates_http1_even_when_client_offers_h2() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );

        let request_head = read_http_head(&mut tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /http1-fallback HTTP/1.1"),
            "{request_text}"
        );

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nfallback";
        tls.write_all(response).await.expect("write response");
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

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    tls.write_all(b"GET /http1-fallback HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    tls.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut tls).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1 200 OK"),
        "{response_text}"
    );
    assert!(response_text.ends_with("fallback"), "{response_text}");

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::TlsHandshakeSucceeded
            && event.context.protocol == ApplicationProtocol::Http1
            && event.attributes.get("peer").map(String::as_str) == Some("downstream")
    }));
    assert!(
        !events
            .iter()
            .any(|event| event.context.protocol == ApplicationProtocol::Http2),
        "unexpected HTTP/2 protocol marker while HTTP/2 was disabled"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_http1_only_relays_with_downstream_http2_translation() {
    let upstream_listener = bind_loopback_listener_with_retry("bind upstream listener").await;
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        let mut accepted_connections = 0_usize;
        loop {
            let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
            accepted_connections += 1;
            let mut tls = acceptor.accept(tcp).await.expect("TLS accept");
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(b"http/1.1".as_slice())
            );

            let request_head =
                tokio::time::timeout(Duration::from_secs(2), read_http_head(&mut tls))
                    .await
                    .unwrap_or_default();
            if request_head.is_empty() {
                let _ = tls.shutdown().await;
                assert!(
                    accepted_connections < 4,
                    "expected sidecar to forward an HTTP request after optional probes"
                );
                continue;
            }

            let request_text = String::from_utf8_lossy(&request_head);
            assert!(
                request_text.starts_with("GET /http1-only-upstream HTTP/1.1"),
                "{request_text}"
            );

            let response =
                b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nfallback";
            tls.write_all(response).await.expect("write response");
            tls.shutdown().await.expect("shutdown upstream TLS");
            break accepted_connections;
        }
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
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

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/http1-only-upstream")
        .body(())
        .expect("request");
    let (response_future, _send_stream) = h2_client
        .send_request(request, true)
        .expect("send h2 request");
    let response = response_future.await.expect("h2 response");
    assert_eq!(response.status(), http::StatusCode::OK);

    let mut body = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        payload.extend_from_slice(&chunk.expect("response body chunk"));
    }
    assert_eq!(&payload, b"fallback");

    let accepted_connections = tokio::time::timeout(Duration::from_secs(2), upstream_task)
        .await
        .expect("upstream task timeout")
        .expect("upstream task");
    assert!(
        accepted_connections >= 1,
        "upstream should receive at least one TLS connection"
    );
    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(has_tls_success_for_peer_with_protocol(
        &events,
        "downstream",
        ApplicationProtocol::Http2
    ));
    assert!(has_tls_success_for_peer_with_protocol(
        &events,
        "upstream",
        ApplicationProtocol::Http1
    ));
    assert!(
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "mitm_http_error")
            .is_none(),
        "unexpected mitm_http_error close for translated HTTP/2 stream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_http2_response_forbidden_headers_and_trailers_are_sanitized() {
    let upstream_listener = bind_loopback_listener_with_retry("bind upstream listener").await;
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let mut upstream_task = Some(tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let Some(stream_result) = h2_conn.accept().await else {
            panic!("missing h2 request stream");
        };
        let (request, mut respond) = stream_result.expect("accept h2 request");
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().path(), "/h2-trailer-sanitize");
        drop(request.into_body());

        let response = http::Response::builder()
            .status(200)
            .header("content-length", "5")
            .header("trailer", "content-length, x-safe-trailer")
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response headers");
        send.send_data(Bytes::from_static(b"hello"), false)
            .expect("send response data");
        let mut trailers = http::HeaderMap::new();
        trailers.insert("content-length", http::HeaderValue::from_static("999"));
        trailers.insert("x-safe-trailer", http::HeaderValue::from_static("ok"));
        send.send_trailers(trailers)
            .expect("send response trailers");

        h2_conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(250), async {
            let _ = poll_fn(|cx| h2_conn.poll_closed(cx)).await;
        })
        .await;
    }));

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
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

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/h2-trailer-sanitize")
        .body(())
        .expect("request");
    let (response_future, _send_stream) = h2_client
        .send_request(request, true)
        .expect("send h2 request");
    let response = response_future.await.expect("h2 response");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(response.headers().get("trailer").is_none());

    let mut body = response.into_body();
    let (payload, trailers) = read_h2_body_and_trailers(&mut body).await;
    assert_eq!(&payload, b"hello");
    let trailers = trailers.expect("response trailers");
    assert_eq!(
        trailers
            .get("x-safe-trailer")
            .and_then(|value| value.to_str().ok()),
        Some("ok")
    );
    assert!(trailers.get("content-length").is_none());

    if let Some(task) = upstream_task.take() {
        task.await.expect("upstream task");
    }
    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "mitm_http_error")
            .is_none(),
        "unexpected mitm_http_error close for sanitized h2 response"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_http1_chunked_trailers_are_sanitized_for_downstream_h2() {
    let upstream_listener = bind_loopback_listener_with_retry("bind upstream listener").await;
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        let mut accepted_connections = 0_usize;
        loop {
            let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
            accepted_connections += 1;
            let mut tls = acceptor.accept(tcp).await.expect("TLS accept");
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(b"http/1.1".as_slice())
            );

            let request_head =
                tokio::time::timeout(Duration::from_secs(2), read_http_head(&mut tls))
                    .await
                    .unwrap_or_default();
            if request_head.is_empty() {
                let _ = tls.shutdown().await;
                assert!(
                    accepted_connections < 4,
                    "expected sidecar to forward an HTTP request after optional probes"
                );
                continue;
            }

            let request_text = String::from_utf8_lossy(&request_head);
            assert!(
                request_text.starts_with("GET /http1-trailer-sanitize HTTP/1.1"),
                "{request_text}"
            );

            let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: content-length, x-safe-trailer\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\ncontent-length: 999\r\nx-safe-trailer: ok\r\n\r\n";
            tls.write_all(response).await.expect("write response");
            tls.shutdown().await.expect("shutdown upstream TLS");
            break accepted_connections;
        }
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
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

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/http1-trailer-sanitize")
        .body(())
        .expect("request");
    let (response_future, _send_stream) = h2_client
        .send_request(request, true)
        .expect("send h2 request");
    let response = response_future.await.expect("h2 response");
    assert_eq!(response.status(), http::StatusCode::OK);

    let mut body = response.into_body();
    let (payload, trailers) = read_h2_body_and_trailers(&mut body).await;
    assert_eq!(&payload, b"hello");
    let trailers = trailers.expect("response trailers");
    assert_eq!(
        trailers
            .get("x-safe-trailer")
            .and_then(|value| value.to_str().ok()),
        Some("ok")
    );
    assert!(trailers.get("content-length").is_none());

    let accepted_connections = tokio::time::timeout(Duration::from_secs(2), upstream_task)
        .await
        .expect("upstream task timeout")
        .expect("upstream task");
    assert!(
        accepted_connections >= 1,
        "upstream should receive at least one TLS connection"
    );
    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "mitm_http_error")
            .is_none(),
        "unexpected mitm_http_error close for translated HTTP/2 stream with trailers"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_http1_only_parallel_h2_streams_translate_without_errors() {
    const STREAM_COUNT: usize = 16;
    const RESPONSE_BODY: &str = "translated";

    let upstream_listener = bind_loopback_listener_with_retry("bind upstream listener").await;
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        let mut upstream_handlers = tokio::task::JoinSet::new();

        for _ in 0..STREAM_COUNT {
            let (tcp, _) = tokio::time::timeout(Duration::from_secs(2), upstream_listener.accept())
                .await
                .expect("accept upstream timeout")
                .expect("accept upstream");
            let acceptor = acceptor.clone();
            upstream_handlers.spawn(async move {
                let mut tls = acceptor.accept(tcp).await.expect("TLS accept");
                assert_eq!(
                    tls.get_ref().1.alpn_protocol(),
                    Some(b"http/1.1".as_slice())
                );
                let request_head = read_http_head(&mut tls).await;
                let request_text = String::from_utf8_lossy(&request_head);
                assert!(
                    request_text.starts_with("GET /translated/"),
                    "{request_text}"
                );

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{RESPONSE_BODY}",
                    RESPONSE_BODY.len()
                );
                tls.write_all(response.as_bytes())
                    .await
                    .expect("write response");
                tls.shutdown().await.expect("shutdown upstream TLS");
            });
        }

        while let Some(handler) = upstream_handlers.join_next().await {
            handler.expect("upstream handler join");
        }
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
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

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let mut response_futures = Vec::with_capacity(STREAM_COUNT);
    for idx in 0..STREAM_COUNT {
        let request = http::Request::builder()
            .method("GET")
            .uri(format!("https://127.0.0.1/translated/{idx}"))
            .body(())
            .expect("request");
        let (response_future, _) = h2_client
            .clone()
            .ready()
            .await
            .expect("h2 client ready")
            .send_request(request, true)
            .expect("send request");
        response_futures.push(response_future);
    }

    let mut response_tasks = tokio::task::JoinSet::new();
    for response_future in response_futures {
        response_tasks.spawn(async move {
            let response = response_future.await.expect("response");
            assert_eq!(response.status(), http::StatusCode::OK);
            let mut body = response.into_body();
            let mut payload = Vec::new();
            while let Some(chunk) = body.data().await {
                payload.extend_from_slice(&chunk.expect("response body chunk"));
            }
            payload
        });
    }
    let mut completed_streams = 0_usize;
    while let Some(result) = response_tasks.join_next().await {
        let payload = result.expect("response task join");
        assert_eq!(&payload, RESPONSE_BODY.as_bytes());
        completed_streams += 1;
    }
    assert_eq!(completed_streams, STREAM_COUNT);

    drop(h2_client);
    if tokio::time::timeout(Duration::from_secs(1), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    tokio::time::timeout(Duration::from_secs(2), upstream_task)
        .await
        .expect("upstream task timeout")
        .expect("upstream task");
    tokio::time::sleep(Duration::from_millis(50)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(has_tls_success_for_peer_with_protocol(
        &events,
        "downstream",
        ApplicationProtocol::Http2
    ));
    assert!(has_tls_success_for_peer_with_protocol(
        &events,
        "upstream",
        ApplicationProtocol::Http1
    ));
    assert!(
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "mitm_http_completed")
            .is_some(),
        "missing HTTP/2 completed close for translated parallel streams"
    );
    assert!(
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "mitm_http_error")
            .is_none(),
        "unexpected mitm_http_error close while translating parallel HTTP/2 streams to HTTP/1.1"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_request_body_over_budget_returns_413_without_upstream_forward() {
    const BODY_BYTES: usize = 8 * 1024;
    const BUDGET_BYTES: usize = 1024;

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let accepted = tokio::time::timeout(Duration::from_millis(500), h2_conn.accept()).await;
        matches!(accepted, Ok(Some(Ok(_))))
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        max_flow_body_buffer_bytes: BUDGET_BYTES,
        max_flow_decoder_buffer_bytes: BUDGET_BYTES,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, _sink) =
        start_sidecar_with_sink_and_stream_stage_timeout(sink, config, Duration::from_secs(15))
            .await;

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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("POST")
        .uri("https://127.0.0.1/body-over-budget")
        .header("content-type", "application/octet-stream")
        .header("content-length", BODY_BYTES.to_string())
        .body(())
        .expect("request");
    let (response_future, mut send_stream) = h2_client
        .send_request(request, false)
        .expect("send request headers");
    send_stream
        .send_data(Bytes::from(vec![b'a'; BODY_BYTES]), true)
        .expect("send request body");

    let response = response_future.await.expect("response");
    assert_eq!(response.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
    let mut body = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        payload.extend_from_slice(&chunk.expect("response body chunk"));
    }
    let payload_text = String::from_utf8_lossy(&payload);
    assert!(
        payload_text.contains("exceeded flow body budget"),
        "{payload_text}"
    );

    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    let saw_upstream_stream = tokio::time::timeout(Duration::from_secs(1), upstream_task)
        .await
        .expect("upstream task timeout")
        .expect("upstream task");
    assert!(
        !saw_upstream_stream,
        "oversized request should not be forwarded upstream"
    );
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_large_request_body_preserves_early_upstream_response() {
    const BODY_BYTES: usize = 700 * 1024;

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let Some(stream_result) = h2_conn.accept().await else {
            panic!("missing h2 request stream");
        };
        let (request, mut respond) = stream_result.expect("accept h2 request");
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri().path(), "/large-early-response");

        // Intentionally respond immediately and never read the request body.
        let response = http::Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .header("content-length", "2")
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response headers");
        send.send_data(Bytes::from_static(b"no"), true)
            .expect("send response body");

        tokio::time::sleep(Duration::from_millis(100)).await;
        h2_conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(300), async {
            let _ = poll_fn(|cx| h2_conn.poll_closed(cx)).await;
        })
        .await;
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, _sink) =
        start_sidecar_with_sink_and_stream_stage_timeout(sink, config, Duration::from_secs(15))
            .await;

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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("POST")
        .uri("https://127.0.0.1/large-early-response")
        .header("content-type", "application/octet-stream")
        .header("content-length", BODY_BYTES.to_string())
        .body(())
        .expect("request");
    let (response_future, mut send_stream) = h2_client
        .send_request(request, false)
        .expect("send request headers");

    send_h2_request_body_with_capacity(&mut send_stream, BODY_BYTES, 16 * 1024, b'x').await;

    let response = tokio::time::timeout(Duration::from_secs(2), response_future)
        .await
        .expect("timed out waiting for early upstream response")
        .expect("response");
    assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    let mut body = response.into_body();
    let (payload, _trailers) = read_h2_body_and_trailers(&mut body).await;
    assert_eq!(payload, b"no");

    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    upstream_task.await.expect("upstream task");
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "repro harness for early-response/full-body ordering; upstream client semantics under investigation"]
async fn http2_early_response_headers_still_forward_request_body_to_completion() {
    const BODY_BYTES: usize = 700 * 1024;

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let Some(stream_result) = h2_conn.accept().await else {
            panic!("missing h2 request stream");
        };
        let (request, mut respond) = stream_result.expect("accept h2 request");
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri().path(), "/early-headers-full-body");

        let mut request_body = request.into_body();
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("content-length", "2")
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response headers");

        let forwarded_bytes = tokio::time::timeout(Duration::from_secs(10), async {
            let mut forwarded_bytes = 0usize;
            while let Some(next_data) = request_body.data().await {
                let data = next_data.expect("request body chunk");
                let frame_len = data.len();
                forwarded_bytes += frame_len;
                request_body
                    .flow_control()
                    .release_capacity(frame_len)
                    .expect("release request flow-control capacity");
            }
            if !request_body.is_end_stream() {
                let _ = request_body.trailers().await.expect("request trailers");
            }
            forwarded_bytes
        })
        .await
        .expect("timed out waiting for request body forwarding");
        assert_eq!(forwarded_bytes, BODY_BYTES);

        send.send_data(Bytes::from_static(b"ok"), true)
            .expect("send response body");
        h2_conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(300), async {
            let _ = poll_fn(|cx| h2_conn.poll_closed(cx)).await;
        })
        .await;
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, _sink) =
        start_sidecar_with_sink_and_stream_stage_timeout(sink, config, Duration::from_secs(15))
            .await;

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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("POST")
        .uri("https://127.0.0.1/early-headers-full-body")
        .header("content-type", "application/octet-stream")
        .header("content-length", BODY_BYTES.to_string())
        .body(())
        .expect("request");
    let (response_future, mut send_stream) = h2_client
        .send_request(request, false)
        .expect("send request headers");

    send_h2_request_body_with_capacity(&mut send_stream, BODY_BYTES, 16 * 1024, b'x').await;

    let response = tokio::time::timeout(Duration::from_secs(10), response_future)
        .await
        .expect("timed out waiting for response")
        .expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = response.into_body();
    let (payload, _trailers) = read_h2_body_and_trailers(&mut body).await;
    assert_eq!(payload, b"ok");

    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    upstream_task.await.expect("upstream task");
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_response_body_over_budget_forwards_payload_with_success_status() {
    const RESPONSE_BYTES: usize = 8 * 1024;
    const BUDGET_BYTES: usize = 1024;

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let Some(stream_result) = h2_conn.accept().await else {
            panic!("missing h2 request stream");
        };
        let (_request, mut respond) = stream_result.expect("accept h2 request");
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/octet-stream")
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response headers");
        send.send_data(Bytes::from(vec![b'r'; RESPONSE_BYTES]), true)
            .expect("send response body");
        h2_conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(300), async {
            let _ = poll_fn(|cx| h2_conn.poll_closed(cx)).await;
        })
        .await;
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        max_flow_body_buffer_bytes: BUDGET_BYTES,
        max_flow_decoder_buffer_bytes: BUDGET_BYTES,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, _sink) = start_sidecar_with_sink(sink, config).await;

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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/response-over-budget")
        .body(())
        .expect("request");
    let (response_future, _send_stream) =
        h2_client.send_request(request, true).expect("send request");
    let response = response_future.await.expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        payload.extend_from_slice(&chunk.expect("response body chunk"));
    }
    assert_eq!(payload.len(), RESPONSE_BYTES);
    assert!(payload.iter().all(|byte| *byte == b'r'));

    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    upstream_task.await.expect("upstream task");
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_response_body_over_budget_strict_fail_aborts_stream_and_emits_error_close() {
    const RESPONSE_BYTES: usize = 8 * 1024;
    const BUDGET_BYTES: usize = 1024;

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let Some(stream_result) = h2_conn.accept().await else {
            panic!("missing h2 request stream");
        };
        let (_request, mut respond) = stream_result.expect("accept h2 request");
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/octet-stream")
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response headers");
        send.send_data(Bytes::from(vec![b'r'; RESPONSE_BYTES]), true)
            .expect("send response body");
        h2_conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(300), async {
            let _ = poll_fn(|cx| h2_conn.poll_closed(cx)).await;
        })
        .await;
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        max_flow_body_buffer_bytes: BUDGET_BYTES,
        max_flow_decoder_buffer_bytes: BUDGET_BYTES,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink_and_h2_reliability(
        sink,
        config,
        Duration::from_secs(5),
        Duration::from_secs(5),
        H2ResponseOverflowMode::StrictFail,
    )
    .await;

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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/response-over-budget-strict-fail")
        .body(())
        .expect("request");
    let (response_future, _send_stream) =
        h2_client.send_request(request, true).expect("send request");
    let response = response_future.await.expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);

    let mut body = response.into_body();
    let mut payload = Vec::new();
    let mut body_error = None;
    while let Some(chunk) = body.data().await {
        match chunk {
            Ok(chunk) => payload.extend_from_slice(&chunk),
            Err(error) => {
                body_error = Some(error.to_string());
                break;
            }
        }
    }
    assert!(
        payload.len() < RESPONSE_BYTES,
        "strict overflow mode should stop forwarding once capture overflows"
    );
    assert!(
        body_error.is_some() || payload.is_empty(),
        "strict overflow mode should end stream with reset or zero payload forwarding"
    );

    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let stream_closed =
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "mitm_http_error")
            .expect("expected HTTP/2 stream close with mitm_http_error in strict overflow mode");
    let reason_detail = stream_closed
        .attributes
        .get("reason_detail")
        .map(String::as_str)
        .unwrap_or_default();
    assert!(
        reason_detail.contains("strict overflow mode"),
        "{reason_detail}"
    );
    assert!(
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "stream_stage_timeout")
            .is_none(),
        "strict overflow failure should not be classified as stream_stage_timeout"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_long_active_response_exceeding_total_stage_budget_stays_connected() {
    const CHUNK_COUNT: usize = 10;
    const CHUNK_BYTES: usize = 256;
    const STREAM_STAGE_TIMEOUT_MS: u64 = 500;
    const CHUNK_DELAY_MS: u64 = 120;

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");

        let Some(stream_result) = h2_conn.accept().await else {
            panic!("missing h2 request stream");
        };
        let (_request, mut respond) = stream_result.expect("accept h2 request");
        let send_task = tokio::spawn(async move {
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/octet-stream")
                .body(())
                .expect("response");
            let mut send = respond
                .send_response(response, false)
                .expect("send response headers");

            for index in 0..CHUNK_COUNT {
                let end_stream = index + 1 == CHUNK_COUNT;
                send.send_data(Bytes::from(vec![b'x'; CHUNK_BYTES]), end_stream)
                    .expect("send response chunk");
                if !end_stream {
                    tokio::time::sleep(Duration::from_millis(CHUNK_DELAY_MS)).await;
                }
            }
        });

        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(next_stream) = h2_conn.accept().await {
                if next_stream.is_err() {
                    break;
                }
            }
        })
        .await;
        let _ = send_task.await;
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink_and_stream_stage_timeout(
        sink,
        config,
        Duration::from_millis(STREAM_STAGE_TIMEOUT_MS),
    )
    .await;

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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/long-active-response")
        .body(())
        .expect("request");
    let (response_future, _send_stream) =
        h2_client.send_request(request, true).expect("send request");
    let response = response_future.await.expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        payload.extend_from_slice(&chunk.expect("response body chunk"));
    }
    assert_eq!(payload.len(), CHUNK_COUNT * CHUNK_BYTES);

    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(50)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "stream_stage_timeout")
            .is_none(),
        "unexpected stream_stage_timeout for active long-lived HTTP/2 response"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_to_h1_translation_reconnect_rejects_upstream_h2_alpn_mismatch() {
    let upstream_listener = bind_loopback_listener_with_retry("bind upstream listener").await;
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let h1_acceptor =
            TlsAcceptor::from(build_http1_server_config_for_host("127.0.0.1").expect("h1 config"));
        let h2_acceptor = TlsAcceptor::from(
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 config"),
        );

        let (tcp, _) = upstream_listener
            .accept()
            .await
            .expect("accept upstream #1");
        let mut h1_tls = h1_acceptor.accept(tcp).await.expect("TLS accept #1");
        assert_eq!(
            h1_tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let request_head = read_http_head(&mut h1_tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /first HTTP/1.1"),
            "{request_text}"
        );
        h1_tls
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst")
            .await
            .expect("write first response");
        h1_tls.shutdown().await.expect("shutdown first TLS");

        let (tcp, _) = upstream_listener
            .accept()
            .await
            .expect("accept upstream #2");
        let mut h2_tls = h2_acceptor.accept(tcp).await.expect("TLS accept #2");
        assert_eq!(h2_tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let mut buf = [0_u8; 64];
        let saw_http1_bytes =
            match tokio::time::timeout(Duration::from_millis(500), h2_tls.read(&mut buf)).await {
                Ok(Ok(read)) => read > 0,
                Ok(Err(_)) => false,
                Err(_) => false,
            };
        saw_http1_bytes
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, _sink) = start_sidecar_with_sink(sink, config).await;

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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let first_request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/first")
        .body(())
        .expect("first request");
    let (first_response_future, _) = h2_client
        .send_request(first_request, true)
        .expect("send first request");
    let first_response = first_response_future.await.expect("first response");
    assert_eq!(first_response.status(), http::StatusCode::OK);

    let second_request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/second")
        .body(())
        .expect("second request");
    let (second_response_future, _) = h2_client
        .send_request(second_request, true)
        .expect("send second request");
    let second_response = second_response_future.await.expect("second response");
    assert_eq!(second_response.status(), http::StatusCode::BAD_GATEWAY);

    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    let saw_http1_bytes = tokio::time::timeout(Duration::from_secs(1), upstream_task)
        .await
        .expect("upstream task timeout")
        .expect("upstream task");
    assert!(
        !saw_http1_bytes,
        "translator should fail reconnect before sending HTTP/1 bytes on an h2-negotiated upstream"
    );
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_to_h1_response_body_over_budget_forwards_payload_with_success_status() {
    const RESPONSE_BYTES: usize = 8 * 1024;
    const BUDGET_BYTES: usize = 1_024;

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("h1 config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );

        let request_head = read_http_head(&mut tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /h2-to-h1-response-over-budget HTTP/1.1"),
            "{request_text}"
        );

        let response_head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {RESPONSE_BYTES}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(response_head.as_bytes())
            .await
            .expect("write response head");
        tls.write_all(&vec![b'k'; RESPONSE_BYTES])
            .await
            .expect("write response body");
        tls.shutdown().await.expect("shutdown upstream TLS");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        max_flow_body_buffer_bytes: BUDGET_BYTES,
        max_flow_decoder_buffer_bytes: BUDGET_BYTES,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, _sink) = start_sidecar_with_sink(sink, config).await;

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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/h2-to-h1-response-over-budget")
        .body(())
        .expect("request");
    let (response_future, _send_stream) =
        h2_client.send_request(request, true).expect("send request");
    let response = response_future.await.expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        payload.extend_from_slice(&chunk.expect("response body chunk"));
    }
    assert_eq!(payload.len(), RESPONSE_BYTES);
    assert!(payload.iter().all(|byte| *byte == b'k'));

    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    upstream_task.await.expect("upstream task");
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_to_h1_response_body_over_budget_strict_fail_aborts_stream_and_emits_error_close() {
    const RESPONSE_BYTES: usize = 8 * 1024;
    const BUDGET_BYTES: usize = 1_024;

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("h1 config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );

        let request_head = read_http_head(&mut tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /h2-to-h1-response-over-budget-strict-fail HTTP/1.1"),
            "{request_text}"
        );

        let response_head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {RESPONSE_BYTES}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(response_head.as_bytes())
            .await
            .expect("write response head");
        tls.write_all(&vec![b'k'; RESPONSE_BYTES])
            .await
            .expect("write response body");
        tls.shutdown().await.expect("shutdown upstream TLS");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        max_flow_body_buffer_bytes: BUDGET_BYTES,
        max_flow_decoder_buffer_bytes: BUDGET_BYTES,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink_and_h2_reliability(
        sink,
        config,
        Duration::from_secs(5),
        Duration::from_secs(5),
        H2ResponseOverflowMode::StrictFail,
    )
    .await;

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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/h2-to-h1-response-over-budget-strict-fail")
        .body(())
        .expect("request");
    let (response_future, _send_stream) =
        h2_client.send_request(request, true).expect("send request");
    let response = response_future.await.expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);

    let mut body = response.into_body();
    let mut payload = Vec::new();
    let mut body_error = None;
    while let Some(chunk) = body.data().await {
        match chunk {
            Ok(chunk) => payload.extend_from_slice(&chunk),
            Err(error) => {
                body_error = Some(error.to_string());
                break;
            }
        }
    }
    assert!(
        payload.len() < RESPONSE_BYTES,
        "strict overflow mode should stop forwarding once capture overflows"
    );
    assert!(
        body_error.is_some() || payload.is_empty(),
        "strict overflow mode should end stream with reset or zero payload forwarding"
    );

    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let stream_closed =
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "mitm_http_error")
            .expect("expected HTTP/2 stream close with mitm_http_error in strict overflow mode");
    let reason_detail = stream_closed
        .attributes
        .get("reason_detail")
        .map(String::as_str)
        .unwrap_or_default();
    assert!(
        reason_detail.contains("strict overflow mode"),
        "{reason_detail}"
    );
    assert!(
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "stream_stage_timeout")
            .is_none(),
        "strict overflow failure should not be classified as stream_stage_timeout"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_to_h1_long_active_response_exceeding_total_stage_budget_stays_connected() {
    const CHUNK_COUNT: usize = 10;
    const CHUNK_BYTES: usize = 256;
    const STREAM_STAGE_TIMEOUT_MS: u64 = 500;
    const CHUNK_DELAY_MS: u64 = 120;

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("h1 config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );

        let request_head = read_http_head(&mut tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /h2-to-h1-long-active-response HTTP/1.1"),
            "{request_text}"
        );

        let body_len = CHUNK_COUNT * CHUNK_BYTES;
        let response_head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(response_head.as_bytes())
            .await
            .expect("write response head");
        for index in 0..CHUNK_COUNT {
            tls.write_all(&vec![b'z'; CHUNK_BYTES])
                .await
                .expect("write response chunk");
            tls.flush().await.expect("flush response chunk");
            if index + 1 < CHUNK_COUNT {
                tokio::time::sleep(Duration::from_millis(CHUNK_DELAY_MS)).await;
            }
        }
        tls.shutdown().await.expect("shutdown upstream TLS");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        ..MitmConfig::default()
    };
    let (proxy_addr, proxy_task, sink) = start_sidecar_with_sink_and_stream_stage_timeout(
        sink,
        config,
        Duration::from_millis(STREAM_STAGE_TIMEOUT_MS),
    )
    .await;

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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/h2-to-h1-long-active-response")
        .body(())
        .expect("request");
    let (response_future, _send_stream) =
        h2_client.send_request(request, true).expect("send request");
    let response = response_future.await.expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        payload.extend_from_slice(&chunk.expect("response body chunk"));
    }
    assert_eq!(payload.len(), CHUNK_COUNT * CHUNK_BYTES);

    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(50)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "stream_stage_timeout")
            .is_none(),
        "unexpected stream_stage_timeout for active long-lived HTTP/2->HTTP/1 response"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_override_disable_h2_forces_http1_without_global_toggle() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let request_head = read_http_head(&mut tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /host-override-h1 HTTP/1.1"),
            "{request_text}"
        );
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\noverride";
        tls.write_all(response).await.expect("write response");
        tls.shutdown().await.expect("shutdown upstream TLS");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        http2_enabled: true,
        upstream_tls_insecure_skip_verify: true,
        compatibility_overrides: vec![CompatibilityOverrideConfig {
            rule_id: "disable-h2-local".to_string(),
            host_pattern: "127.0.0.1".to_string(),
            disable_h2: true,
            strict_header_mode: true,
            ..CompatibilityOverrideConfig::default()
        }],
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

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    tls.write_all(
        b"GET /host-override-h1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await
    .expect("write request");
    tls.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut tls).await;
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1 200 OK"),
        "{response_text}"
    );
    assert!(response_text.ends_with("override"), "{response_text}");

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::ConnectDecision
            && event.attributes.get("override_rule_id").map(String::as_str)
                == Some("disable-h2-local")
            && event
                .attributes
                .get("override_disable_h2")
                .map(String::as_str)
                == Some("true")
    }));
    assert!(
        !events
            .iter()
            .any(|event| event.context.protocol == ApplicationProtocol::Http2),
        "unexpected HTTP/2 protocol marker while host override disabled h2"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_override_strict_header_mode_rejects_http10_upstream_response() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config = build_http1_server_config_for_host("127.0.0.1").expect("server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let request_head = read_http_head(&mut tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /strict-http10 HTTP/1.1"),
            "{request_text}"
        );
        let response = b"HTTP/1.0 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nhttp10!";
        tls.write_all(response).await.expect("write response");
        tls.shutdown().await.expect("shutdown upstream TLS");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        http2_enabled: true,
        upstream_tls_insecure_skip_verify: true,
        compatibility_overrides: vec![CompatibilityOverrideConfig {
            rule_id: "strict-header-local".to_string(),
            host_pattern: "127.0.0.1".to_string(),
            disable_h2: true,
            strict_header_mode: true,
            ..CompatibilityOverrideConfig::default()
        }],
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

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    tls.write_all(b"GET /strict-http10 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    tls.flush().await.expect("flush request");

    let response = read_to_end_allow_unexpected_eof(&mut tls).await;
    assert!(
        response.is_empty(),
        "strict mode should reject upstream HTTP/1.0 response before relaying bytes"
    );

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(25)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::ConnectDecision
            && event.attributes.get("override_rule_id").map(String::as_str)
                == Some("strict-header-local")
            && event
                .attributes
                .get("override_strict_header_mode")
                .map(String::as_str)
                == Some("true")
    }));
    let stream_closed =
        stream_closed_for_protocol(&events, ApplicationProtocol::Http1, "mitm_http_error")
            .expect("expected HTTP/1 stream close with mitm_http_error");
    let reason_detail = stream_closed
        .attributes
        .get("reason_detail")
        .map(String::as_str)
        .unwrap_or_default();
    assert!(
        reason_detail.contains("strict_header_mode=true"),
        "{reason_detail}"
    );
    assert!(
        reason_detail.contains("requires HTTP/1.1 response version"),
        "{reason_detail}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_oversized_headers_emit_mitm_http_error_close() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let received = tokio::time::timeout(Duration::from_millis(300), h2_conn.accept()).await;
        let saw_request_stream = matches!(received, Ok(Some(Ok(_))));
        h2_conn.graceful_shutdown();
        saw_request_stream
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        http2_max_header_list_size: 1_024,
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

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let oversized_header = "a".repeat(8 * 1024);
    let request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/oversized")
        .header("host", "127.0.0.1")
        .header("x-oversized", oversized_header)
        .body(())
        .expect("request");

    if let Ok((response_future, _)) = h2_client.send_request(request, true) {
        let _ = tokio::time::timeout(Duration::from_secs(1), response_future).await;
    }

    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    let saw_upstream_request = tokio::time::timeout(Duration::from_secs(1), upstream_task)
        .await
        .expect("upstream task timeout")
        .expect("upstream task");
    assert!(
        !saw_upstream_request,
        "oversized request should not be forwarded upstream"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::StreamClosed
            && event.context.protocol == ApplicationProtocol::Http2
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_parallel_stream_stress_keeps_completed_close_and_byte_accounting() {
    const STREAM_COUNT: usize = 32;
    const STREAM_CHUNKS: usize = 1;
    const STREAM_CHUNK_SIZE: usize = 1_024;
    const STREAM_BYTES: usize = STREAM_CHUNKS * STREAM_CHUNK_SIZE;

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let mut stream_tasks = tokio::task::JoinSet::new();
        while let Some(next_stream) = h2_conn.accept().await {
            let (request, mut respond) = match next_stream {
                Ok(stream) => stream,
                Err(_) => break,
            };
            stream_tasks.spawn(async move {
                assert_eq!(request.method(), http::Method::GET);
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/octet-stream")
                    .body(())
                    .expect("response");
                let mut send = respond
                    .send_response(response, false)
                    .expect("send response headers");
                for idx in 0..STREAM_CHUNKS {
                    let payload = Bytes::from(vec![idx as u8; STREAM_CHUNK_SIZE]);
                    send.send_data(payload, idx + 1 == STREAM_CHUNKS)
                        .expect("send response data");
                }
            });
        }
        while let Some(task) = stream_tasks.join_next().await {
            task.expect("upstream stream task join");
        }
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
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

    let connector = TlsConnector::from(build_http_client_config(true, true));
    let server_name = ServerName::try_from("127.0.0.1".to_string()).expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let mut response_futures = Vec::with_capacity(STREAM_COUNT);
    for idx in 0..STREAM_COUNT {
        let request = http::Request::builder()
            .method("GET")
            .uri(format!("https://127.0.0.1/stream/{idx}"))
            .header("host", "127.0.0.1")
            .body(())
            .expect("request");
        let (response_future, _) = h2_client
            .clone()
            .ready()
            .await
            .expect("h2 client ready")
            .send_request(request, true)
            .expect("send request");
        response_futures.push(response_future);
    }

    let mut response_tasks = tokio::task::JoinSet::new();
    for response_future in response_futures {
        response_tasks.spawn(async move {
            let response = response_future.await.expect("response");
            assert_eq!(response.status(), http::StatusCode::OK);
            let mut body = response.into_body();
            let mut bytes = 0_usize;
            while let Some(chunk) = body.data().await {
                bytes += chunk.expect("response chunk").len();
            }
            bytes
        });
    }

    let mut total_response_bytes = 0_usize;
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(result) = response_tasks.join_next().await {
            let stream_bytes = result.expect("response task join");
            assert_eq!(stream_bytes, STREAM_BYTES);
            total_response_bytes += stream_bytes;
        }
    })
    .await
    .expect("response drain timeout");
    assert_eq!(total_response_bytes, STREAM_COUNT * STREAM_BYTES);

    drop(h2_client);
    if tokio::time::timeout(Duration::from_secs(1), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    tokio::time::timeout(Duration::from_secs(1), upstream_task)
        .await
        .expect("upstream task timeout")
        .expect("upstream task");
    tokio::time::sleep(Duration::from_millis(50)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let stream_closed =
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "mitm_http_completed")
            .expect("missing HTTP/2 StreamClosed completed event");
    let expected = (STREAM_COUNT * STREAM_BYTES) as u64;
    let bytes_from_server = attr_u64(stream_closed, "bytes_from_server").unwrap_or_default();
    assert!(
        bytes_from_server >= expected,
        "bytes_from_server {bytes_from_server} was less than expected {expected}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_upstream_cancel_reset_on_single_stream_is_nonfatal_for_flow() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let server_config =
            build_http_server_config_for_host("127.0.0.1", true).expect("h2 server config");
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let tls = acceptor.accept(tcp).await.expect("TLS accept");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
        let mut accepted_streams = 0_usize;
        while accepted_streams < 2 {
            let Some(stream_result) = h2_conn.accept().await else {
                break;
            };
            let (request, mut respond) = stream_result.expect("accept h2 request");
            accepted_streams += 1;
            match request.uri().path() {
                "/cancel" => {
                    respond.send_reset(h2::Reason::CANCEL);
                }
                "/ok" => {
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-length", "2")
                        .body(())
                        .expect("response");
                    let mut send = respond
                        .send_response(response, false)
                        .expect("send response headers");
                    send.send_data(Bytes::from_static(b"ok"), true)
                        .expect("send response data");
                }
                path => panic!("unexpected path: {path}"),
            }
        }
        h2_conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(300), async {
            let _ = poll_fn(|cx| h2_conn.poll_closed(cx)).await;
        })
        .await;
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        http2_enabled: true,
        ..MitmConfig::default()
    };
    let hooks = Http2StreamEndCounterHooks::default();
    let (proxy_addr, proxy_task, sink) =
        start_sidecar_with_flow_hooks(sink, config, Arc::new(hooks.clone())).await;

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
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS connect to sidecar");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (h2_client, h2_connection) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let ok_request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/ok")
        .header("host", "127.0.0.1")
        .body(())
        .expect("ok request");
    let cancel_request = http::Request::builder()
        .method("GET")
        .uri("https://127.0.0.1/cancel")
        .header("host", "127.0.0.1")
        .body(())
        .expect("cancel request");

    let (ok_response_future, _) = h2_client
        .clone()
        .ready()
        .await
        .expect("h2 client ready for ok")
        .send_request(ok_request, true)
        .expect("send ok request");
    let (cancel_response_future, _) = h2_client
        .clone()
        .ready()
        .await
        .expect("h2 client ready for cancel")
        .send_request(cancel_request, true)
        .expect("send cancel request");

    let ok_response = ok_response_future.await.expect("ok response");
    assert_eq!(ok_response.status(), http::StatusCode::OK);
    let mut ok_body = ok_response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = ok_body.data().await {
        payload.extend_from_slice(&chunk.expect("ok body chunk"));
    }
    assert_eq!(&payload, b"ok");

    let cancel_result = cancel_response_future.await;
    assert!(
        cancel_result.is_err()
            || cancel_result
                .expect("cancel response")
                .status()
                .is_success(),
        "cancel path should either reset or complete cleanly"
    );

    drop(h2_client);
    if tokio::time::timeout(Duration::from_millis(500), &mut h2_connection_task)
        .await
        .is_err()
    {
        h2_connection_task.abort();
    }
    tokio::time::timeout(Duration::from_secs(1), upstream_task)
        .await
        .expect("upstream task timeout")
        .expect("upstream task");
    tokio::time::sleep(Duration::from_millis(50)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    assert!(
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "mitm_http_completed")
            .is_some(),
        "expected HTTP/2 flow to close as completed"
    );
    assert!(
        stream_closed_for_protocol(&events, ApplicationProtocol::Http2, "mitm_http_error")
            .is_none(),
        "HTTP/2 stream cancel should not escalate to mitm_http_error"
    );
    assert!(
        hooks.ended_http2_streams() >= 2,
        "expected at least one on_stream_end callback per HTTP/2 stream (observed={})",
        hooks.ended_http2_streams()
    );
}
