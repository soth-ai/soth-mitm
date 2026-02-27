use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use mitm_core::{MitmConfig, MitmEngine, RouteEndpointConfig, RouteMode};
use mitm_observe::{EventType, FlowContext, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{
    FlowHooks, RawRequest as HookRawRequest, RequestDecision, SidecarConfig, SidecarServer,
    TlsDiagnostics, TlsLearningGuardrails,
};
use mitm_tls::{build_http1_client_config, build_http1_server_config_for_host};
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
    Arc<TlsDiagnostics>,
    Arc<TlsLearningGuardrails>,
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
    let diagnostics = server.tls_diagnostics_handle();
    let learning = server.tls_learning_handle();
    let listener = server.bind_listener().await.expect("bind sidecar");
    let addr = listener.local_addr().expect("listener local addr");
    let handle = tokio::spawn(server.run_with_listener(listener));
    (addr, handle, sink, diagnostics, learning)
}

async fn start_sidecar_with_flow_hooks(
    sink: VecEventConsumer,
    config: MitmConfig,
    flow_hooks: Arc<dyn FlowHooks>,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
    VecEventConsumer,
    Arc<TlsDiagnostics>,
    Arc<TlsLearningGuardrails>,
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
    let diagnostics = server.tls_diagnostics_handle();
    let learning = server.tls_learning_handle();
    let listener = server.bind_listener().await.expect("bind sidecar");
    let addr = listener.local_addr().expect("listener local addr");
    let handle = tokio::spawn(server.run_with_listener(listener));
    (addr, handle, sink, diagnostics, learning)
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

fn parse_content_length(head_bytes: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head_bytes);
    for line in text.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value.trim().parse::<usize>().expect("valid content-length");
            }
        }
    }
    0
}

include!("http1_mitm_cases/success_paths.rs");
include!("http1_mitm_cases/upstream_and_counters.rs");
include!("http1_mitm_cases/downstream_and_cache.rs");
include!("http1_mitm_cases/smuggling_guards.rs");
