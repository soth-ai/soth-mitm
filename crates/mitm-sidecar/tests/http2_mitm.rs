use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use mitm_core::{
    CompatibilityOverrideConfig, MitmConfig, MitmEngine, RouteEndpointConfig, RouteMode,
};
use mitm_http::ApplicationProtocol;
use mitm_observe::{Event, EventType, FlowContext, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{
    FlowHooks, RawRequest as HookRawRequest, RequestDecision, SidecarConfig, SidecarServer,
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
    let sidecar_config = SidecarConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: 64 * 1024,
        idle_watchdog_timeout: std::time::Duration::from_secs(30),
        upstream_connect_timeout: std::time::Duration::from_secs(10),
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
        idle_watchdog_timeout: std::time::Duration::from_secs(30),
        upstream_connect_timeout: std::time::Duration::from_secs(10),
        stream_stage_timeout: std::time::Duration::from_secs(5),
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
}

impl RequestHostCaptureHooks {
    async fn seen_host(&self) -> Option<String> {
        self.seen_host.lock().await.clone()
    }
}

impl FlowHooks for RequestHostCaptureHooks {
    fn on_request(
        &self,
        _context: FlowContext,
        request: HookRawRequest,
    ) -> Pin<Box<dyn Future<Output = RequestDecision> + Send>> {
        let seen_host = Arc::clone(&self.seen_host);
        Box::pin(async move {
            let host = request
                .headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned);
            *seen_host.lock().await = host;
            RequestDecision::Allow
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
    h2_connection_task.abort();
    upstream_task.await.expect("upstream task");
    proxy_task.abort();

    let _events = sink.snapshot();
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
}
