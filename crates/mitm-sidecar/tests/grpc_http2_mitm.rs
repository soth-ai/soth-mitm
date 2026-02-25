use std::future::poll_fn;
use std::time::Duration;

use bytes::Bytes;
use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::{Event, EventType, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};
use mitm_tls::{build_http_client_config, build_http_server_config_for_host};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        stream_stage_timeout: std::time::Duration::from_secs(15),
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

async fn read_h2_body_and_trailers(
    body: &mut h2::RecvStream,
) -> (Vec<u8>, Option<http::HeaderMap>) {
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("read body chunk");
        payload.extend_from_slice(&chunk);
    }
    let trailers = body.trailers().await.expect("read body trailers");
    (payload, trailers)
}

fn frame_grpc_message(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn attr<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
    event.attributes.get(key).map(String::as_str)
}

fn header_value<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn grpc_metadata_events(events: &[Event]) -> Vec<&Event> {
    events
        .iter()
        .filter(|event| {
            matches!(
                event.kind,
                EventType::GrpcRequestHeaders
                    | EventType::GrpcResponseHeaders
                    | EventType::GrpcResponseTrailers
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_unary_http2_emits_header_and_trailer_events_in_stable_sequence() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let request_payload = frame_grpc_message(b"hello");
    let response_payload = frame_grpc_message(b"world");
    let response_payload_clone = response_payload.clone();
    let request_payload_clone = request_payload.clone();

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
        assert_eq!(request.uri().path(), "/greeter.Greeter/SayHello");
        assert_eq!(
            header_value(request.headers(), "content-type"),
            Some("application/grpc+proto")
        );
        assert_eq!(header_value(request.headers(), "te"), Some("trailers"));

        let mut body = request.into_body();
        let (actual_payload, request_trailers) = read_h2_body_and_trailers(&mut body).await;
        assert_eq!(actual_payload, request_payload_clone);
        assert!(request_trailers.is_none());

        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response headers");
        send.send_data(Bytes::from(response_payload_clone), false)
            .expect("send response payload");
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        trailers.insert("grpc-message", http::HeaderValue::from_static("ok"));
        send.send_trailers(trailers)
            .expect("send response trailers");

        h2_conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(250), async {
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
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("POST")
        .uri("https://127.0.0.1/greeter.Greeter/SayHello")
        .header("host", "127.0.0.1")
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        .header("user-agent", "grpc-rust-test/0.1")
        .body(())
        .expect("request");
    let (response_future, mut request_stream) = h2_client
        .send_request(request, false)
        .expect("send grpc request headers");
    request_stream
        .send_data(Bytes::from(request_payload), true)
        .expect("send grpc request payload");

    let response = response_future.await.expect("grpc response");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        header_value(response.headers(), "content-type"),
        Some("application/grpc")
    );

    let mut response_body = response.into_body();
    let (actual_response_payload, response_trailers) =
        read_h2_body_and_trailers(&mut response_body).await;
    assert_eq!(actual_response_payload, response_payload);
    let response_trailers = response_trailers.expect("expected grpc trailers");
    assert_eq!(header_value(&response_trailers, "grpc-status"), Some("0"));
    assert_eq!(header_value(&response_trailers, "grpc-message"), Some("ok"));

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
    let grpc_events = grpc_metadata_events(&events);
    assert_eq!(
        grpc_events.len(),
        3,
        "expected request/header/trailer events"
    );
    assert_eq!(grpc_events[0].kind, EventType::GrpcRequestHeaders);
    assert_eq!(grpc_events[1].kind, EventType::GrpcResponseHeaders);
    assert_eq!(grpc_events[2].kind, EventType::GrpcResponseTrailers);
    assert_eq!(attr(grpc_events[0], "grpc_event_sequence"), Some("1"));
    assert_eq!(attr(grpc_events[1], "grpc_event_sequence"), Some("2"));
    assert_eq!(attr(grpc_events[2], "grpc_event_sequence"), Some("3"));
    assert_eq!(
        attr(grpc_events[0], "grpc_detection_mode"),
        Some("content_type_and_path")
    );
    assert_eq!(
        attr(grpc_events[0], "grpc_request_content_type"),
        Some("application/grpc+proto")
    );
    assert_eq!(
        attr(grpc_events[0], "grpc_service"),
        Some("greeter.Greeter")
    );
    assert_eq!(attr(grpc_events[0], "grpc_method"), Some("SayHello"));
    assert_eq!(attr(grpc_events[1], "status_code"), Some("200"));
    assert_eq!(
        attr(grpc_events[1], "grpc_response_content_type"),
        Some("application/grpc")
    );
    assert_eq!(attr(grpc_events[2], "grpc_status"), Some("0"));
    assert_eq!(attr(grpc_events[2], "grpc_message"), Some("ok"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_streaming_http2_path_pattern_detection_emits_stable_sequence() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");

    let request_part_one = frame_grpc_message(b"chunk-one");
    let request_part_two = frame_grpc_message(b"chunk-two");
    let expected_request = [&request_part_one[..], &request_part_two[..]].concat();
    let response_part_one = frame_grpc_message(b"feature-a");
    let response_part_two = frame_grpc_message(b"feature-b");
    let expected_response = [&response_part_one[..], &response_part_two[..]].concat();
    let expected_response_clone = expected_response.clone();
    let expected_request_clone = expected_request.clone();

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
        assert_eq!(request.uri().path(), "/routeguide.RouteGuide/ListFeatures");
        assert_eq!(
            header_value(request.headers(), "content-type"),
            Some("application/octet-stream")
        );

        let mut request_body = request.into_body();
        let (actual_request_payload, request_trailers) =
            read_h2_body_and_trailers(&mut request_body).await;
        assert_eq!(actual_request_payload, expected_request_clone);
        assert!(request_trailers.is_none());

        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc+proto")
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response headers");
        send.send_data(Bytes::from(response_part_one), false)
            .expect("send response chunk 1");
        send.send_data(Bytes::from(response_part_two), false)
            .expect("send response chunk 2");
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        trailers.insert(
            "grpc-message",
            http::HeaderValue::from_static("stream-complete"),
        );
        send.send_trailers(trailers)
            .expect("send response trailers");

        h2_conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(250), async {
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
    let mut h2_connection_task = tokio::spawn(h2_connection);

    let request = http::Request::builder()
        .method("POST")
        .uri("https://127.0.0.1/routeguide.RouteGuide/ListFeatures")
        .header("host", "127.0.0.1")
        .header("content-type", "application/octet-stream")
        .header("te", "trailers")
        .body(())
        .expect("request");
    let (response_future, mut request_stream) = h2_client
        .send_request(request, false)
        .expect("send grpc-like streaming headers");
    request_stream
        .send_data(Bytes::from(request_part_one), false)
        .expect("send request chunk 1");
    request_stream
        .send_data(Bytes::from(request_part_two), true)
        .expect("send request chunk 2");

    let response = response_future.await.expect("streaming response");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        header_value(response.headers(), "content-type"),
        Some("application/grpc+proto")
    );
    let mut response_body = response.into_body();
    let (actual_response_payload, response_trailers) =
        read_h2_body_and_trailers(&mut response_body).await;
    assert_eq!(actual_response_payload, expected_response_clone);
    let response_trailers = response_trailers.expect("expected response trailers");
    assert_eq!(header_value(&response_trailers, "grpc-status"), Some("0"));
    assert_eq!(
        header_value(&response_trailers, "grpc-message"),
        Some("stream-complete")
    );

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
    let grpc_events = grpc_metadata_events(&events);
    assert_eq!(
        grpc_events.len(),
        3,
        "expected request/header/trailer events"
    );
    assert_eq!(grpc_events[0].kind, EventType::GrpcRequestHeaders);
    assert_eq!(grpc_events[1].kind, EventType::GrpcResponseHeaders);
    assert_eq!(grpc_events[2].kind, EventType::GrpcResponseTrailers);
    assert_eq!(attr(grpc_events[0], "grpc_event_sequence"), Some("1"));
    assert_eq!(attr(grpc_events[1], "grpc_event_sequence"), Some("2"));
    assert_eq!(attr(grpc_events[2], "grpc_event_sequence"), Some("3"));
    assert_eq!(
        attr(grpc_events[0], "grpc_detection_mode"),
        Some("path_pattern")
    );
    assert_eq!(
        attr(grpc_events[0], "grpc_service"),
        Some("routeguide.RouteGuide")
    );
    assert_eq!(attr(grpc_events[0], "grpc_method"), Some("ListFeatures"));
    assert_eq!(
        attr(grpc_events[0], "grpc_request_content_type"),
        Some("application/octet-stream")
    );
    assert_eq!(
        attr(grpc_events[1], "grpc_response_content_type"),
        Some("application/grpc+proto")
    );
    assert_eq!(attr(grpc_events[2], "grpc_status"), Some("0"));
    assert_eq!(
        attr(grpc_events[2], "grpc_message"),
        Some("stream-complete")
    );
}
