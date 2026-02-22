use std::future::poll_fn;
use std::time::Duration;

use bytes::Bytes;
use mitm_core::{MitmConfig, MitmEngine};
use mitm_http::ApplicationProtocol;
use mitm_observe::{Event, EventType, VecEventSink};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};
use mitm_tls::{
    build_http1_server_config_for_host, build_http_client_config, build_http_server_config_for_host,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

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

    let sink = VecEventSink::default();
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
