use std::sync::Arc;
use std::time::Duration;

use mitm_core::{
    MitmConfig, MitmEngine, TlsFingerprintClass, TlsFingerprintMode, TlsProfile, UpstreamSniMode,
};
use mitm_observe::{Event, EventType, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};
use mitm_tls::{build_http1_client_config, CertificateAuthorityConfig, MitmCertificateStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
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
        idle_watchdog_timeout: Duration::from_secs(30),
        upstream_connect_timeout: Duration::from_secs(10),
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

fn tls12_only_server_config_for_host(host: &str) -> Arc<rustls::ServerConfig> {
    let cert_store =
        MitmCertificateStore::new(CertificateAuthorityConfig::default()).expect("cert store");
    let issued = cert_store
        .server_config_for_host(host)
        .expect("issue leaf config");

    let leaf_der = CertificateDer::from_pem_slice(issued.leaf_identity.leaf_cert_pem.as_bytes())
        .expect("leaf cert pem parse");
    let ca_der = CertificateDer::from_pem_slice(issued.leaf_identity.ca_cert_pem.as_bytes())
        .expect("ca cert pem parse");
    let key_der = PrivatePkcs8KeyDer::from_pem_slice(issued.leaf_identity.leaf_key_pem.as_bytes())
        .expect("leaf key pem parse");

    let mut server_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_no_client_auth()
            .with_single_cert(vec![leaf_der, ca_der], PrivateKeyDer::from(key_der))
            .expect("tls12 server config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(server_config)
}

fn assert_fingerprint_provenance(event: &Event, mode: &str, class: &str) {
    assert_eq!(
        event
            .attributes
            .get("tls_fingerprint_mode")
            .map(String::as_str),
        Some(mode),
        "{:?}",
        event.attributes
    );
    assert_eq!(
        event
            .attributes
            .get("tls_fingerprint_class")
            .map(String::as_str),
        Some(class),
        "{:?}",
        event.attributes
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_mode_emits_native_fingerprint_provenance() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(tls12_only_server_config_for_host("127.0.0.1"));
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("accept upstream tls");
        let request_head = read_http_head(&mut tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /native HTTP/1.1"),
            "{request_text}"
        );
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        tls.write_all(response).await.expect("write response");
        tls.shutdown().await.expect("shutdown upstream tls");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        tls_profile: TlsProfile::Compat,
        upstream_sni_mode: UpstreamSniMode::Auto,
        upstream_tls_insecure_skip_verify: true,
        tls_fingerprint_mode: TlsFingerprintMode::Native,
        tls_fingerprint_class: TlsFingerprintClass::Native,
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
    tls.write_all(b"GET /native HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    let _ = read_to_end_allow_unexpected_eof(&mut tls).await;

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(40)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let upstream_succeeded = events
        .iter()
        .find(|event| {
            event.kind == EventType::TlsHandshakeSucceeded
                && event.attributes.get("peer").map(String::as_str) == Some("upstream")
        })
        .expect("expected upstream tls success");
    assert_fingerprint_provenance(upstream_succeeded, "native", "native");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compat_class_firefox_like_emits_provenance_on_success() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(tls12_only_server_config_for_host("127.0.0.1"));
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("accept upstream tls");
        let request_head = read_http_head(&mut tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /firefox-like HTTP/1.1"),
            "{request_text}"
        );
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong";
        tls.write_all(response).await.expect("write response");
        tls.shutdown().await.expect("shutdown upstream tls");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        tls_profile: TlsProfile::Default,
        upstream_sni_mode: UpstreamSniMode::Auto,
        upstream_tls_insecure_skip_verify: true,
        tls_fingerprint_mode: TlsFingerprintMode::CompatClass,
        tls_fingerprint_class: TlsFingerprintClass::FirefoxLike,
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
    tls.write_all(b"GET /firefox-like HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    let _ = read_to_end_allow_unexpected_eof(&mut tls).await;

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(40)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let upstream_succeeded = events
        .iter()
        .find(|event| {
            event.kind == EventType::TlsHandshakeSucceeded
                && event.attributes.get("peer").map(String::as_str) == Some("upstream")
        })
        .expect("expected upstream tls success");
    assert_fingerprint_provenance(upstream_succeeded, "compat_class", "firefox_like");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compat_class_preserves_strict_profile_failure_behavior() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(tls12_only_server_config_for_host("127.0.0.1"));
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let _ = acceptor.accept(tcp).await;
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        tls_profile: TlsProfile::Strict,
        upstream_sni_mode: UpstreamSniMode::Auto,
        upstream_tls_insecure_skip_verify: true,
        tls_fingerprint_mode: TlsFingerprintMode::CompatClass,
        tls_fingerprint_class: TlsFingerprintClass::ChromeLike,
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
    let _ = tls
        .write_all(
            b"GET /strict-compat-class HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .await;
    let _ = tls.flush().await;
    let _ = read_to_end_allow_unexpected_eof(&mut tls).await;

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(40)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let upstream_failed = events
        .iter()
        .find(|event| {
            event.kind == EventType::TlsHandshakeFailed
                && event.attributes.get("peer").map(String::as_str) == Some("upstream")
        })
        .expect("expected upstream tls failure");
    assert_eq!(
        upstream_failed
            .attributes
            .get("tls_failure_reason")
            .map(String::as_str),
        Some("handshake")
    );
    assert_fingerprint_provenance(upstream_failed, "compat_class", "chrome_like");
}
