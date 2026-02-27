use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mitm_core::{MitmConfig, MitmEngine, UpstreamClientAuthMode};
use mitm_observe::{EventType, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};
use mitm_tls::{build_http1_client_config, CertificateAuthorityConfig, MitmCertificateStore};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamClientAuthRequirement {
    Requested,
    Required,
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
            Err(error) => panic!("read response: {error}"),
        }
    }
    out
}

fn tls_server_config_for_host_with_client_auth(
    host: &str,
    requirement: UpstreamClientAuthRequirement,
    client_auth_ca_pem: Option<&str>,
) -> Arc<rustls::ServerConfig> {
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

    let mut server_config = {
        let client_auth_ca_pem = client_auth_ca_pem.expect("client auth CA PEM required");
        let ca_for_clients = CertificateDer::from_pem_slice(client_auth_ca_pem.as_bytes())
            .expect("parse client auth CA");
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(ca_for_clients)
            .expect("add client auth trust anchor");

        let verifier_builder = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots));
        let verifier = match requirement {
            UpstreamClientAuthRequirement::Requested => verifier_builder
                .allow_unauthenticated()
                .build()
                .expect("optional client verifier"),
            UpstreamClientAuthRequirement::Required => {
                verifier_builder.build().expect("required client verifier")
            }
        };

        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![leaf_der, ca_der], PrivateKeyDer::from(key_der))
            .expect("tls12 client-auth server config")
    };
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(server_config)
}

fn build_upstream_client_auth_fixture() -> (String, String, String) {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "mtls-test-client-ca");
    ca_dn.push(DnType::OrganizationName, "soth-mitm");
    ca_params.distinguished_name = ca_dn;

    let ca_key =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate client-auth CA key");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .expect("self-sign client-auth CA");
    let ca_pem = ca_cert.pem();
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let mut client_params =
        CertificateParams::new(Vec::<String>::new()).expect("client cert params");
    client_params.is_ca = IsCa::NoCa;
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let mut client_dn = DistinguishedName::new();
    client_dn.push(DnType::CommonName, "soth-mitm-upstream-client");
    client_dn.push(DnType::OrganizationName, "soth-mitm");
    client_params.distinguished_name = client_dn;

    let client_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("generate upstream client key");
    let client_cert = client_params
        .signed_by(&client_key, &ca_issuer)
        .expect("sign upstream client cert");

    (ca_pem, client_cert.pem(), client_key.serialize_pem())
}

fn write_client_auth_material(cert_pem: &str, key_pem: &str) -> (TempDir, String, String) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let cert_path = dir.path().join("upstream-client.crt");
    let key_path = dir.path().join("upstream-client.key");
    std::fs::write(&cert_path, cert_pem.as_bytes()).expect("write client cert");
    std::fs::write(&key_path, key_pem.as_bytes()).expect("write client key");
    (
        dir,
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_mode_without_material_fails_deterministically() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let _ = timeout(Duration::from_secs(5), upstream_listener.accept()).await;
    });

    let sink = VecEventConsumer::default();
    let missing_paths = tempfile::tempdir().expect("create missing-path dir");
    let missing_cert_path = missing_paths.path().join("missing-client.crt");
    let missing_key_path = missing_paths.path().join("missing-client.key");
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        upstream_client_auth_mode: UpstreamClientAuthMode::Required,
        upstream_client_cert_pem_path: Some(missing_cert_path.to_string_lossy().to_string()),
        upstream_client_key_pem_path: Some(missing_key_path.to_string_lossy().to_string()),
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
        .write_all(b"GET /upstream-required-missing HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await;
    let _ = tls.flush().await;
    let _ = read_to_end_allow_unexpected_eof(&mut tls).await;

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(40)).await;
    proxy_task.abort();

    let events = sink.snapshot();
    let failure = events
        .iter()
        .find(|event| {
            event.kind == EventType::TlsHandshakeFailed
                && event.attributes.get("peer").map(String::as_str) == Some("upstream")
        })
        .expect("expected upstream tls failure");
    assert!(
        failure
            .attributes
            .get("detail")
            .map(String::as_str)
            .unwrap_or_default()
            .contains("upstream TLS client-auth material load failed"),
        "{:?}",
        failure.attributes
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn if_requested_without_material_falls_back_and_succeeds() {
    let (client_ca_pem, _client_cert_pem, _client_key_pem) = build_upstream_client_auth_fixture();
    let observed_peer_cert = Arc::new(AtomicBool::new(false));

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let observed_peer_cert_clone = Arc::clone(&observed_peer_cert);
    let upstream_task = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(tls_server_config_for_host_with_client_auth(
            "127.0.0.1",
            UpstreamClientAuthRequirement::Requested,
            Some(&client_ca_pem),
        ));
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("accept upstream tls");
        let peer_cert_present = tls
            .get_ref()
            .1
            .peer_certificates()
            .map(|certs| !certs.is_empty())
            .unwrap_or(false);
        observed_peer_cert_clone.store(peer_cert_present, Ordering::SeqCst);

        let request_head = read_http_head(&mut tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /if-requested-fallback HTTP/1.1"),
            "{request_text}"
        );
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        tls.write_all(response).await.expect("write response");
        tls.shutdown().await.expect("shutdown upstream TLS");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        upstream_client_auth_mode: UpstreamClientAuthMode::IfRequested,
        upstream_client_cert_pem_path: None,
        upstream_client_key_pem_path: None,
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
    tls.write_all(
        b"GET /if-requested-fallback HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
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

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(40)).await;
    proxy_task.abort();

    assert!(
        !observed_peer_cert.load(Ordering::SeqCst),
        "unexpected client cert for if_requested fallback path"
    );
    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::TlsHandshakeSucceeded
            && event.attributes.get("peer").map(String::as_str) == Some("upstream")
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_with_material_succeeds_against_required_upstream_client_auth() {
    let (client_ca_pem, client_cert_pem, client_key_pem) = build_upstream_client_auth_fixture();
    let (_temp_dir, cert_path, key_path) =
        write_client_auth_material(&client_cert_pem, &client_key_pem);
    let observed_peer_cert = Arc::new(AtomicBool::new(false));

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let observed_peer_cert_clone = Arc::clone(&observed_peer_cert);
    let upstream_task = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(tls_server_config_for_host_with_client_auth(
            "127.0.0.1",
            UpstreamClientAuthRequirement::Required,
            Some(&client_ca_pem),
        ));
        let (tcp, _) = upstream_listener.accept().await.expect("accept upstream");
        let mut tls = acceptor.accept(tcp).await.expect("accept upstream tls");
        let peer_cert_present = tls
            .get_ref()
            .1
            .peer_certificates()
            .map(|certs| !certs.is_empty())
            .unwrap_or(false);
        observed_peer_cert_clone.store(peer_cert_present, Ordering::SeqCst);

        let request_head = read_http_head(&mut tls).await;
        let request_text = String::from_utf8_lossy(&request_head);
        assert!(
            request_text.starts_with("GET /required-with-material HTTP/1.1"),
            "{request_text}"
        );
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong";
        tls.write_all(response).await.expect("write response");
        tls.shutdown().await.expect("shutdown upstream TLS");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        upstream_tls_insecure_skip_verify: true,
        upstream_client_auth_mode: UpstreamClientAuthMode::Required,
        upstream_client_cert_pem_path: Some(cert_path),
        upstream_client_key_pem_path: Some(key_path),
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
    tls.write_all(
        b"GET /required-with-material HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
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
    assert!(response_text.ends_with("pong"), "{response_text}");

    upstream_task.await.expect("upstream task");
    tokio::time::sleep(Duration::from_millis(40)).await;
    proxy_task.abort();

    assert!(
        observed_peer_cert.load(Ordering::SeqCst),
        "required mode should present a client cert to upstream"
    );
    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventType::TlsHandshakeSucceeded
            && event.attributes.get("peer").map(String::as_str) == Some("upstream")
    }));
}
