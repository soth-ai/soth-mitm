use std::io;
use std::sync::Arc;

use mitm_core::{parse_connect_request_head, ConnectParseError, MitmEngine};
use mitm_http::ApplicationProtocol;
use mitm_observe::{Event, EventSink, EventType, FlowContext};
use mitm_policy::{FlowAction, PolicyEngine};
use mitm_tls::{
    build_http1_client_config, classify_tls_error, CertificateAuthorityConfig,
    MitmCertificateStore, TlsConfigError,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

mod mitmproxy_tls_ops;
mod tls_diagnostics;
mod tls_learning;

pub use mitmproxy_tls_ops::{
    adapt_mitmproxy_tls_callback, MitmproxyTlsAdapterEvent, MitmproxyTlsCallback,
    MitmproxyTlsFailure, MitmproxyTlsHook,
};
pub use tls_diagnostics::{
    TlsDiagnostics, TlsDiagnosticsSnapshot, TlsFailureCounterUpdate, TlsHostFailureSnapshot,
};
pub use tls_learning::{
    TlsLearningDecision, TlsLearningGuardrails, TlsLearningHostSnapshot, TlsLearningOutcome,
    TlsLearningSignal, TlsLearningSnapshot,
};

const IO_CHUNK_SIZE: usize = 8 * 1024;
const CHUNK_LINE_LIMIT: usize = 8 * 1024;
const TLS_OPS_PROVIDER: &str = "rustls";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub max_connect_head_bytes: usize,
    pub max_http_head_bytes: usize,
}

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 8080,
            max_connect_head_bytes: 64 * 1024,
            max_http_head_bytes: 64 * 1024,
        }
    }
}

pub struct SidecarServer<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    config: SidecarConfig,
    engine: Arc<MitmEngine<P, S>>,
    cert_store: Arc<MitmCertificateStore>,
    tls_diagnostics: Arc<TlsDiagnostics>,
    tls_learning: Arc<TlsLearningGuardrails>,
}

#[derive(Clone)]
struct RuntimeHandles<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    engine: Arc<MitmEngine<P, S>>,
    cert_store: Arc<MitmCertificateStore>,
    tls_diagnostics: Arc<TlsDiagnostics>,
    tls_learning: Arc<TlsLearningGuardrails>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReasonCode {
    Blocked,
    ConnectParseFailed,
    TlsHandshakeFailed,
    UpstreamConnectFailed,
    RelayEof,
    RelayError,
    MitmHttpCompleted,
    MitmHttpError,
}

impl CloseReasonCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::ConnectParseFailed => "connect_parse_failed",
            Self::TlsHandshakeFailed => "tls_handshake_failed",
            Self::UpstreamConnectFailed => "upstream_connect_failed",
            Self::RelayEof => "relay_eof",
            Self::RelayError => "relay_error",
            Self::MitmHttpCompleted => "mitm_http_completed",
            Self::MitmHttpError => "mitm_http_error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseFailureCode {
    IncompleteHeaders,
    HeaderTooLarge,
    ReadError,
    Parser(ConnectParseError),
}

impl ParseFailureCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::IncompleteHeaders => "incomplete_headers",
            Self::HeaderTooLarge => "header_too_large",
            Self::ReadError => "read_error",
            Self::Parser(code) => code.code(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpBodyMode {
    None,
    ContentLength(u64),
    Chunked,
    CloseDelimited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpHeader {
    name: String,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpRequestHead {
    raw: Vec<u8>,
    method: String,
    target: String,
    version: HttpVersion,
    headers: Vec<HttpHeader>,
    body_mode: HttpBodyMode,
    connection_close: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpResponseHead {
    raw: Vec<u8>,
    version: HttpVersion,
    status_code: u16,
    reason_phrase: String,
    headers: Vec<HttpHeader>,
    body_mode: HttpBodyMode,
    connection_close: bool,
}

struct BufferedConn<S> {
    stream: S,
    read_buf: Vec<u8>,
}

impl<S> BufferedConn<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            read_buf: Vec::new(),
        }
    }
}

impl<P, S> SidecarServer<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    pub fn new(config: SidecarConfig, engine: MitmEngine<P, S>) -> io::Result<Self> {
        let ca_config = CertificateAuthorityConfig {
            ca_cert_pem_path: engine.config.ca_cert_pem_path.clone(),
            ca_key_pem_path: engine.config.ca_key_pem_path.clone(),
            ca_common_name: engine.config.ca_common_name.clone(),
            ca_organization: engine.config.ca_organization.clone(),
            leaf_cert_cache_capacity: engine.config.leaf_cert_cache_capacity,
            ca_rotate_after_seconds: engine.config.ca_rotate_after_seconds,
        };
        let cert_store =
            MitmCertificateStore::new(ca_config).map_err(tls_error_to_io_invalid_input)?;
        let tls_diagnostics = Arc::new(TlsDiagnostics::default());
        let tls_learning = Arc::new(TlsLearningGuardrails::new());
        Ok(Self {
            config,
            engine: Arc::new(engine),
            cert_store: Arc::new(cert_store),
            tls_diagnostics,
            tls_learning,
        })
    }

    pub fn tls_diagnostics_snapshot(&self) -> TlsDiagnosticsSnapshot {
        self.tls_diagnostics.snapshot()
    }

    pub fn tls_diagnostics_handle(&self) -> Arc<TlsDiagnostics> {
        Arc::clone(&self.tls_diagnostics)
    }

    pub fn tls_learning_snapshot(&self) -> TlsLearningSnapshot {
        self.tls_learning.snapshot()
    }

    pub fn tls_learning_handle(&self) -> Arc<TlsLearningGuardrails> {
        Arc::clone(&self.tls_learning)
    }

    pub fn ingest_tls_learning_signal(&self, signal: TlsLearningSignal) -> TlsLearningOutcome {
        let context = FlowContext {
            flow_id: self.engine.allocate_flow_id(),
            client_addr: "<tls-learning>".to_string(),
            server_host: signal.host.clone(),
            server_port: 0,
            protocol: ApplicationProtocol::Tunnel,
        };
        ingest_tls_learning_signal_with_audit(&self.engine, &self.tls_learning, context, signal)
    }

    pub fn ingest_mitmproxy_tls_callback(
        &self,
        callback: MitmproxyTlsCallback,
    ) -> MitmproxyTlsAdapterEvent {
        let mut adapted = adapt_mitmproxy_tls_callback(&callback);

        if let Some(failure) = adapted.failure.as_ref() {
            let counters = self.tls_diagnostics.record_failure(
                &adapted.context.server_host,
                &failure.source,
                &failure.reason,
            );
            adapted.attributes.insert(
                "tls_failure_host_count".to_string(),
                counters.host_total_failures.to_string(),
            );
            adapted.attributes.insert(
                "tls_failure_host_rolling_count".to_string(),
                counters.host_rolling_failures.to_string(),
            );
            adapted.attributes.insert(
                "tls_failure_source_count".to_string(),
                counters.source_total_failures.to_string(),
            );
            adapted.attributes.insert(
                "tls_failure_reason_count".to_string(),
                counters.reason_total_failures.to_string(),
            );
            adapted.attributes.insert(
                "tls_failure_global_count".to_string(),
                counters.global_total_failures.to_string(),
            );

            let learning_signal = TlsLearningSignal::new(
                adapted.context.server_host.clone(),
                failure.reason.clone(),
                failure.source.clone(),
                adapted
                    .attributes
                    .get("tls_ops_provider")
                    .cloned()
                    .unwrap_or_else(|| "mitmproxy".to_string()),
                false,
            );
            let learning_outcome = ingest_tls_learning_signal_with_audit(
                &self.engine,
                &self.tls_learning,
                adapted.context.clone(),
                learning_signal,
            );
            adapted.attributes.insert(
                "tls_learning_decision".to_string(),
                learning_outcome.decision.as_str().to_string(),
            );
            adapted.attributes.insert(
                "tls_learning_reason_code".to_string(),
                learning_outcome.reason_code.to_string(),
            );
            adapted.attributes.insert(
                "tls_learning_host_count".to_string(),
                learning_outcome.host_applied_total.to_string(),
            );
            adapted.attributes.insert(
                "tls_learning_global_applied".to_string(),
                learning_outcome.global_applied_total.to_string(),
            );
            adapted.attributes.insert(
                "tls_learning_global_ignored".to_string(),
                learning_outcome.global_ignored_total.to_string(),
            );
        }

        let mut event = Event::new(adapted.kind, adapted.context.clone());
        event.attributes = adapted.attributes.clone();
        self.engine.emit_event(event);
        adapted
    }

    pub async fn run(self) -> io::Result<()> {
        let listener = self.bind_listener().await?;
        self.run_with_listener(listener).await
    }

    pub async fn bind_listener(&self) -> io::Result<TcpListener> {
        let bind_addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        TcpListener::bind(&bind_addr).await
    }

    pub async fn run_with_listener(self, listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, client_addr) = listener.accept().await?;
            let runtime = RuntimeHandles {
                engine: Arc::clone(&self.engine),
                cert_store: Arc::clone(&self.cert_store),
                tls_diagnostics: Arc::clone(&self.tls_diagnostics),
                tls_learning: Arc::clone(&self.tls_learning),
            };
            let max_connect_head_bytes = self.config.max_connect_head_bytes;
            let max_http_head_bytes = self.config.max_http_head_bytes;
            tokio::spawn(async move {
                if let Err(error) = handle_client(
                    runtime,
                    stream,
                    client_addr.to_string(),
                    max_connect_head_bytes,
                    max_http_head_bytes,
                )
                .await
                {
                    eprintln!("connection handling failed: {error}");
                }
            });
        }
    }
}

async fn handle_client<P, S>(
    runtime: RuntimeHandles<P, S>,
    mut downstream: TcpStream,
    client_addr: String,
    max_connect_head_bytes: usize,
    max_http_head_bytes: usize,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let engine = Arc::clone(&runtime.engine);
    let cert_store = Arc::clone(&runtime.cert_store);
    let tls_diagnostics = Arc::clone(&runtime.tls_diagnostics);
    let tls_learning = Arc::clone(&runtime.tls_learning);

    let mut input = match read_connect_head(&mut downstream, max_connect_head_bytes).await {
        Ok(parsed) => parsed,
        Err(error) => {
            let parse_code = match error.kind() {
                io::ErrorKind::UnexpectedEof => ParseFailureCode::IncompleteHeaders,
                io::ErrorKind::InvalidData => ParseFailureCode::HeaderTooLarge,
                _ => ParseFailureCode::ReadError,
            };

            let flow_id = engine.allocate_flow_id();
            let context = unknown_context(flow_id, client_addr);

            emit_connect_parse_failed(
                &engine,
                context.clone(),
                parse_code,
                Some(error.to_string()),
            );
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::ConnectParseFailed,
                Some(parse_code.as_str().to_string()),
                None,
                None,
            );

            if error.kind() != io::ErrorKind::UnexpectedEof {
                let status = if parse_code == ParseFailureCode::HeaderTooLarge {
                    "431 Request Header Fields Too Large"
                } else {
                    "400 Bad Request"
                };
                write_proxy_response(
                    &mut downstream,
                    status,
                    "invalid or incomplete CONNECT request",
                )
                .await?;
            }
            return Ok(());
        }
    };

    let (connect, header_len) = match parse_connect_request_head(&input) {
        Ok(parsed) => parsed,
        Err(parse_error) => {
            let flow_id = engine.allocate_flow_id();
            let context = unknown_context(flow_id, client_addr);
            emit_connect_parse_failed(
                &engine,
                context.clone(),
                ParseFailureCode::Parser(parse_error),
                None,
            );
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::ConnectParseFailed,
                Some(parse_error.code().to_string()),
                None,
                None,
            );
            write_proxy_response(
                &mut downstream,
                "400 Bad Request",
                "invalid CONNECT request",
            )
            .await?;
            return Ok(());
        }
    };

    let outcome = engine.decide_connect(
        client_addr.clone(),
        connect.server_host.clone(),
        connect.server_port,
        None,
    );

    let context = FlowContext {
        flow_id: outcome.flow_id,
        client_addr,
        server_host: connect.server_host.clone(),
        server_port: connect.server_port,
        protocol: ApplicationProtocol::Tunnel,
    };

    match outcome.action {
        FlowAction::Block => {
            write_proxy_response(&mut downstream, "403 Forbidden", &outcome.reason).await?;
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::Blocked,
                Some(outcome.reason),
                None,
                None,
            );
            Ok(())
        }
        FlowAction::Tunnel | FlowAction::MetadataOnly => {
            tunnel_connection(engine, context, &mut downstream, &mut input, header_len).await
        }
        FlowAction::Intercept => {
            intercept_http1_connection(
                engine,
                cert_store,
                tls_diagnostics,
                tls_learning,
                context,
                downstream,
                max_http_head_bytes,
            )
            .await
        }
    }
}

async fn tunnel_connection<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    context: FlowContext,
    downstream: &mut TcpStream,
    input: &mut [u8],
    header_len: usize,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut upstream = match TcpStream::connect((&*context.server_host, context.server_port)).await
    {
        Ok(stream) => stream,
        Err(error) => {
            let detail = format!("upstream_connect_failed: {error}");
            write_proxy_response(downstream, "502 Bad Gateway", &detail).await?;
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::UpstreamConnectFailed,
                Some(error.to_string()),
                None,
                None,
            );
            return Ok(());
        }
    };

    downstream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let buffered_client_data = &input[header_len..];
    if !buffered_client_data.is_empty() {
        upstream.write_all(buffered_client_data).await?;
    }

    match tokio::io::copy_bidirectional(downstream, &mut upstream).await {
        Ok((from_client, from_server)) => {
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::RelayEof,
                None,
                Some(from_client),
                Some(from_server),
            );
            Ok(())
        }
        Err(error) => {
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::RelayError,
                Some(error.to_string()),
                None,
                None,
            );
            Err(error)
        }
    }
}

async fn intercept_http1_connection<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    cert_store: Arc<MitmCertificateStore>,
    tls_diagnostics: Arc<TlsDiagnostics>,
    tls_learning: Arc<TlsLearningGuardrails>,
    tunnel_context: FlowContext,
    mut downstream: TcpStream,
    max_http_head_bytes: usize,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let upstream_tcp = match TcpStream::connect((
        &*tunnel_context.server_host,
        tunnel_context.server_port,
    ))
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            let detail = format!("upstream_connect_failed: {error}");
            write_proxy_response(&mut downstream, "502 Bad Gateway", &detail).await?;
            emit_stream_closed(
                &engine,
                tunnel_context,
                CloseReasonCode::UpstreamConnectFailed,
                Some(error.to_string()),
                None,
                None,
            );
            return Ok(());
        }
    };

    downstream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let http_context = FlowContext {
        protocol: ApplicationProtocol::Http1,
        ..tunnel_context.clone()
    };

    let issued_server_config = match cert_store.server_config_for_host(&http_context.server_host) {
        Ok(config) => config,
        Err(error) => {
            emit_tls_event_with_detail(
                &engine,
                &tls_diagnostics,
                &tls_learning,
                EventType::TlsHandshakeFailed,
                http_context.clone(),
                "downstream",
                error.to_string(),
            );
            emit_stream_closed(
                &engine,
                tunnel_context,
                CloseReasonCode::TlsHandshakeFailed,
                Some(format!("downstream leaf issuance error: {error}")),
                None,
                None,
            );
            return Ok(());
        }
    };
    emit_tls_event_with_cache(
        &engine,
        EventType::TlsHandshakeStarted,
        http_context.clone(),
        "downstream",
        issued_server_config.cache_status.as_str(),
    );
    let acceptor = TlsAcceptor::from(issued_server_config.server_config);
    let downstream_tls = match acceptor.accept(downstream).await {
        Ok(stream) => {
            emit_tls_event(
                &engine,
                EventType::TlsHandshakeSucceeded,
                http_context.clone(),
                "downstream",
            );
            stream
        }
        Err(error) => {
            emit_tls_event_with_detail(
                &engine,
                &tls_diagnostics,
                &tls_learning,
                EventType::TlsHandshakeFailed,
                http_context.clone(),
                "downstream",
                error.to_string(),
            );
            emit_stream_closed(
                &engine,
                tunnel_context,
                CloseReasonCode::TlsHandshakeFailed,
                Some(format!("downstream handshake failed: {error}")),
                None,
                None,
            );
            return Ok(());
        }
    };

    let client_config = build_http1_client_config(engine.config.upstream_tls_insecure_skip_verify);
    let server_name = match ServerName::try_from(http_context.server_host.clone()) {
        Ok(value) => value,
        Err(_) => {
            emit_stream_closed(
                &engine,
                tunnel_context,
                CloseReasonCode::MitmHttpError,
                Some("invalid server name for upstream TLS".to_string()),
                None,
                None,
            );
            return Ok(());
        }
    };
    let connector = TlsConnector::from(client_config);
    emit_tls_event(
        &engine,
        EventType::TlsHandshakeStarted,
        http_context.clone(),
        "upstream",
    );
    let upstream_tls = match connector.connect(server_name, upstream_tcp).await {
        Ok(stream) => {
            emit_tls_event(
                &engine,
                EventType::TlsHandshakeSucceeded,
                http_context.clone(),
                "upstream",
            );
            stream
        }
        Err(error) => {
            emit_tls_event_with_detail(
                &engine,
                &tls_diagnostics,
                &tls_learning,
                EventType::TlsHandshakeFailed,
                http_context.clone(),
                "upstream",
                error.to_string(),
            );
            emit_stream_closed(
                &engine,
                tunnel_context,
                CloseReasonCode::TlsHandshakeFailed,
                Some(format!("upstream handshake failed: {error}")),
                None,
                None,
            );
            return Ok(());
        }
    };

    let mut downstream_conn = BufferedConn::new(downstream_tls);
    let mut upstream_conn = BufferedConn::new(upstream_tls);
    let mut bytes_from_client = 0_u64;
    let mut bytes_from_server = 0_u64;

    loop {
        let request_raw =
            match read_until_pattern(&mut downstream_conn, b"\r\n\r\n", max_http_head_bytes).await?
            {
                Some(value) => value,
                None => {
                    emit_stream_closed(
                        &engine,
                        tunnel_context,
                        CloseReasonCode::MitmHttpCompleted,
                        None,
                        Some(bytes_from_client),
                        Some(bytes_from_server),
                    );
                    return Ok(());
                }
            };

        let request = match parse_http_request_head(&request_raw) {
            Ok(parsed) => parsed,
            Err(error) => {
                emit_stream_closed(
                    &engine,
                    tunnel_context,
                    CloseReasonCode::MitmHttpError,
                    Some(format!("request parse error: {error}")),
                    Some(bytes_from_client),
                    Some(bytes_from_server),
                );
                return Ok(());
            }
        };

        emit_request_headers_event(&engine, &http_context, &request);
        upstream_conn.stream.write_all(&request.raw).await?;

        bytes_from_client += relay_http_body(
            &engine,
            &http_context,
            EventType::RequestBodyChunk,
            &mut downstream_conn,
            &mut upstream_conn.stream,
            request.body_mode,
            max_http_head_bytes,
        )
        .await?;

        let response_raw =
            match read_until_pattern(&mut upstream_conn, b"\r\n\r\n", max_http_head_bytes).await? {
                Some(value) => value,
                None => {
                    emit_stream_closed(
                        &engine,
                        tunnel_context,
                        CloseReasonCode::MitmHttpError,
                        Some("upstream closed before response headers".to_string()),
                        Some(bytes_from_client),
                        Some(bytes_from_server),
                    );
                    return Ok(());
                }
            };

        let response = match parse_http_response_head(&response_raw, &request.method) {
            Ok(parsed) => parsed,
            Err(error) => {
                emit_stream_closed(
                    &engine,
                    tunnel_context,
                    CloseReasonCode::MitmHttpError,
                    Some(format!("response parse error: {error}")),
                    Some(bytes_from_client),
                    Some(bytes_from_server),
                );
                return Ok(());
            }
        };

        emit_response_headers_event(&engine, &http_context, &response);
        downstream_conn.stream.write_all(&response.raw).await?;

        bytes_from_server += relay_http_body(
            &engine,
            &http_context,
            EventType::ResponseBodyChunk,
            &mut upstream_conn,
            &mut downstream_conn.stream,
            response.body_mode,
            max_http_head_bytes,
        )
        .await?;

        if request.connection_close
            || response.connection_close
            || response.body_mode == HttpBodyMode::CloseDelimited
        {
            emit_stream_closed(
                &engine,
                tunnel_context,
                CloseReasonCode::MitmHttpCompleted,
                None,
                Some(bytes_from_client),
                Some(bytes_from_server),
            );
            return Ok(());
        }
    }
}

async fn read_connect_head(
    stream: &mut TcpStream,
    max_connect_head_bytes: usize,
) -> io::Result<Vec<u8>> {
    let mut data = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];

    while !data.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed before CONNECT headers completed",
            ));
        }

        data.push(byte[0]);
        if data.len() > max_connect_head_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CONNECT header exceeded configured limit",
            ));
        }
    }

    Ok(data)
}

async fn read_until_pattern<S: AsyncRead + Unpin>(
    conn: &mut BufferedConn<S>,
    pattern: &[u8],
    max_bytes: usize,
) -> io::Result<Option<Vec<u8>>> {
    loop {
        if let Some(start) = find_subsequence(&conn.read_buf, pattern) {
            let end = start + pattern.len();
            let bytes = conn.read_buf.drain(..end).collect::<Vec<_>>();
            return Ok(Some(bytes));
        }

        if conn.read_buf.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP header exceeded configured limit",
            ));
        }

        let mut chunk = [0_u8; IO_CHUNK_SIZE];
        let read = conn.stream.read(&mut chunk).await?;
        if read == 0 {
            if conn.read_buf.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before message boundary was reached",
            ));
        }
        conn.read_buf.extend_from_slice(&chunk[..read]);
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_http_request_head(raw: &[u8]) -> io::Result<HttpRequestHead> {
    let text = std::str::from_utf8(raw).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "request headers were not valid UTF-8",
        )
    })?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request line is missing"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request method is missing"))?;
    let target = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request target is missing"))?;
    let version_text = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP version is missing"))?;
    if parts.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request line had too many fields",
        ));
    }
    let version = parse_http_version(version_text)?;

    let headers = parse_http_headers(lines)?;
    let body_mode = parse_request_body_mode(&headers)?;
    let connection_close = is_connection_close(version, &headers);

    Ok(HttpRequestHead {
        raw: raw.to_vec(),
        method: method.to_string(),
        target: target.to_string(),
        version,
        headers,
        body_mode,
        connection_close,
    })
}

fn parse_http_response_head(raw: &[u8], request_method: &str) -> io::Result<HttpResponseHead> {
    let text = std::str::from_utf8(raw).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "response headers were not valid UTF-8",
        )
    })?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "response status line is missing",
        )
    })?;
    let mut parts = status_line.split_whitespace();
    let version_text = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "response version is missing"))?;
    let status_text = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "response status is missing"))?;
    let reason_phrase = parts.collect::<Vec<_>>().join(" ");
    let version = parse_http_version(version_text)?;
    let status_code = status_text
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid response status code"))?;

    let headers = parse_http_headers(lines)?;
    let mut connection_close = is_connection_close(version, &headers);
    let body_mode = parse_response_body_mode(&headers, request_method, status_code)?;
    if body_mode == HttpBodyMode::CloseDelimited {
        connection_close = true;
    }

    Ok(HttpResponseHead {
        raw: raw.to_vec(),
        version,
        status_code,
        reason_phrase,
        headers,
        body_mode,
        connection_close,
    })
}

fn parse_http_version(text: &str) -> io::Result<HttpVersion> {
    match text {
        "HTTP/1.0" => Ok(HttpVersion::Http10),
        "HTTP/1.1" => Ok(HttpVersion::Http11),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "only HTTP/1.0 and HTTP/1.1 are supported in MITM mode",
        )),
    }
}

fn parse_http_headers<'a>(lines: impl Iterator<Item = &'a str>) -> io::Result<Vec<HttpHeader>> {
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed header line"))?;
        headers.push(HttpHeader {
            name: name.trim().to_string(),
            value: value.trim().to_string(),
        });
    }
    Ok(headers)
}

fn parse_request_body_mode(headers: &[HttpHeader]) -> io::Result<HttpBodyMode> {
    if has_header_token(headers, "transfer-encoding", "chunked") {
        return Ok(HttpBodyMode::Chunked);
    }
    if let Some(length) = parse_content_length(headers)? {
        return Ok(if length == 0 {
            HttpBodyMode::None
        } else {
            HttpBodyMode::ContentLength(length)
        });
    }
    Ok(HttpBodyMode::None)
}

fn parse_response_body_mode(
    headers: &[HttpHeader],
    request_method: &str,
    status_code: u16,
) -> io::Result<HttpBodyMode> {
    if request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status_code)
        || status_code == 204
        || status_code == 304
    {
        return Ok(HttpBodyMode::None);
    }

    if has_header_token(headers, "transfer-encoding", "chunked") {
        return Ok(HttpBodyMode::Chunked);
    }
    if let Some(length) = parse_content_length(headers)? {
        return Ok(if length == 0 {
            HttpBodyMode::None
        } else {
            HttpBodyMode::ContentLength(length)
        });
    }

    Ok(HttpBodyMode::CloseDelimited)
}

fn parse_content_length(headers: &[HttpHeader]) -> io::Result<Option<u64>> {
    let mut value = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let parsed = header.value.parse::<u64>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length value")
            })?;
            value = Some(parsed);
        }
    }
    Ok(value)
}

fn has_header_token(headers: &[HttpHeader], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .flat_map(|header| header.value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case(token))
}

fn is_connection_close(version: HttpVersion, headers: &[HttpHeader]) -> bool {
    if has_header_token(headers, "connection", "close") {
        return true;
    }
    if version == HttpVersion::Http10 && !has_header_token(headers, "connection", "keep-alive") {
        return true;
    }
    false
}

async fn relay_http_body<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
    mode: HttpBodyMode,
    max_http_head_bytes: usize,
) -> io::Result<u64>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    match mode {
        HttpBodyMode::None => Ok(0),
        HttpBodyMode::ContentLength(length) => {
            relay_exact(engine, context, event_kind, source, sink, length).await
        }
        HttpBodyMode::Chunked => {
            relay_chunked(
                engine,
                context,
                event_kind,
                source,
                sink,
                max_http_head_bytes,
            )
            .await
        }
        HttpBodyMode::CloseDelimited => {
            relay_until_eof(engine, context, event_kind, source, sink).await
        }
    }
}

async fn relay_exact<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
    mut length: u64,
) -> io::Result<u64>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut total = 0_u64;

    if !source.read_buf.is_empty() && length > 0 {
        let take = std::cmp::min(length as usize, source.read_buf.len());
        sink.write_all(&source.read_buf[..take]).await?;
        source.read_buf.drain(..take);
        length -= take as u64;
        total += take as u64;
        emit_body_chunk_event(engine, context.clone(), event_kind, take as u64);
    }

    let mut chunk = [0_u8; IO_CHUNK_SIZE];
    while length > 0 {
        let read = source
            .stream
            .read(&mut chunk[..std::cmp::min(IO_CHUNK_SIZE, length as usize)])
            .await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before body completed",
            ));
        }
        sink.write_all(&chunk[..read]).await?;
        length -= read as u64;
        total += read as u64;
        emit_body_chunk_event(engine, context.clone(), event_kind, read as u64);
    }

    Ok(total)
}

async fn relay_chunked<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
    max_http_head_bytes: usize,
) -> io::Result<u64>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut total = 0_u64;
    loop {
        let line = read_chunk_line(source).await?;
        sink.write_all(&line).await?;
        let chunk_len = parse_chunk_len(&line)?;
        if chunk_len == 0 {
            let trailers = read_until_pattern(source, b"\r\n\r\n", max_http_head_bytes)
                .await?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed before chunked trailers completed",
                    )
                })?;
            sink.write_all(&trailers).await?;
            return Ok(total);
        }

        total += relay_exact(engine, context, event_kind, source, sink, chunk_len).await?;

        let chunk_terminator = read_exact_from_source(source, 2).await?;
        if chunk_terminator.as_slice() != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunk terminator",
            ));
        }
        sink.write_all(&chunk_terminator).await?;
    }
}

async fn relay_until_eof<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
) -> io::Result<u64>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut total = 0_u64;
    if !source.read_buf.is_empty() {
        sink.write_all(&source.read_buf).await?;
        total += source.read_buf.len() as u64;
        emit_body_chunk_event(
            engine,
            context.clone(),
            event_kind,
            source.read_buf.len() as u64,
        );
        source.read_buf.clear();
    }

    let mut chunk = [0_u8; IO_CHUNK_SIZE];
    loop {
        let read = source.stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        sink.write_all(&chunk[..read]).await?;
        total += read as u64;
        emit_body_chunk_event(engine, context.clone(), event_kind, read as u64);
    }
    Ok(total)
}

async fn read_chunk_line<S: AsyncRead + Unpin>(
    source: &mut BufferedConn<S>,
) -> io::Result<Vec<u8>> {
    let line = read_until_pattern(source, b"\r\n", CHUNK_LINE_LIMIT)
        .await?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before chunk size line was read",
            )
        })?;
    Ok(line)
}

fn parse_chunk_len(line: &[u8]) -> io::Result<u64> {
    let text = std::str::from_utf8(line).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "chunk size line had invalid UTF-8",
        )
    })?;
    let trimmed = text.trim();
    let size_text = trimmed.split(';').next().unwrap_or(trimmed).trim();
    u64::from_str_radix(size_text, 16).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "chunk size line had invalid hex length",
        )
    })
}

async fn read_exact_from_source<S: AsyncRead + Unpin>(
    source: &mut BufferedConn<S>,
    exact_len: usize,
) -> io::Result<Vec<u8>> {
    while source.read_buf.len() < exact_len {
        let mut chunk = [0_u8; IO_CHUNK_SIZE];
        let read = source.stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before fixed-length body completed",
            ));
        }
        source.read_buf.extend_from_slice(&chunk[..read]);
    }
    Ok(source.read_buf.drain(..exact_len).collect::<Vec<_>>())
}

async fn write_proxy_response(stream: &mut TcpStream, status: &str, body: &str) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

fn emit_request_headers_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: &FlowContext,
    request: &HttpRequestHead,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::RequestHeaders, context.clone());
    event
        .attributes
        .insert("method".to_string(), request.method.clone());
    event
        .attributes
        .insert("target".to_string(), request.target.clone());
    event
        .attributes
        .insert("version".to_string(), request.version.as_str().to_string());
    event.attributes.insert(
        "header_count".to_string(),
        request.headers.len().to_string(),
    );
    engine.emit_event(event);
}

fn emit_response_headers_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: &FlowContext,
    response: &HttpResponseHead,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::ResponseHeaders, context.clone());
    event
        .attributes
        .insert("status_code".to_string(), response.status_code.to_string());
    event
        .attributes
        .insert("reason_phrase".to_string(), response.reason_phrase.clone());
    event
        .attributes
        .insert("version".to_string(), response.version.as_str().to_string());
    event.attributes.insert(
        "header_count".to_string(),
        response.headers.len().to_string(),
    );
    engine.emit_event(event);
}

fn emit_body_chunk_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    kind: EventType,
    bytes: u64,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    if bytes == 0 {
        return;
    }
    let mut event = Event::new(kind, context);
    event
        .attributes
        .insert("bytes".to_string(), bytes.to_string());
    engine.emit_event(event);
}

fn emit_tls_event<P, S>(
    engine: &MitmEngine<P, S>,
    kind: EventType,
    context: FlowContext,
    peer: &str,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(kind, context);
    event
        .attributes
        .insert("peer".to_string(), peer.to_string());
    engine.emit_event(event);
}

fn emit_tls_event_with_cache<P, S>(
    engine: &MitmEngine<P, S>,
    kind: EventType,
    context: FlowContext,
    peer: &str,
    cert_cache_status: &str,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(kind, context);
    event
        .attributes
        .insert("peer".to_string(), peer.to_string());
    event.attributes.insert(
        "cert_cache_status".to_string(),
        cert_cache_status.to_string(),
    );
    engine.emit_event(event);
}

fn emit_tls_event_with_detail<P, S>(
    engine: &MitmEngine<P, S>,
    tls_diagnostics: &TlsDiagnostics,
    tls_learning: &TlsLearningGuardrails,
    kind: EventType,
    context: FlowContext,
    peer: &str,
    detail: String,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let failure_metadata = if kind == EventType::TlsHandshakeFailed {
        let reason = classify_tls_error(&detail).code().to_string();
        let source = peer.to_string();
        let provider = TLS_OPS_PROVIDER.to_string();
        let counters = tls_diagnostics.record_failure(&context.server_host, &source, &reason);
        let learning_signal = TlsLearningSignal::new(
            context.server_host.clone(),
            reason.clone(),
            source.clone(),
            provider.clone(),
            false,
        );
        let learning_outcome = ingest_tls_learning_signal_with_audit(
            engine,
            tls_learning,
            context.clone(),
            learning_signal,
        );
        Some((reason, source, provider, counters, learning_outcome))
    } else {
        None
    };

    let mut event = Event::new(kind, context);
    event
        .attributes
        .insert("peer".to_string(), peer.to_string());
    event.attributes.insert("detail".to_string(), detail);
    if let Some((reason, source, provider, counters, learning_outcome)) = failure_metadata {
        event
            .attributes
            .insert("tls_failure_reason".to_string(), reason);
        event
            .attributes
            .insert("tls_failure_source".to_string(), source);
        event
            .attributes
            .insert("tls_ops_provider".to_string(), provider);
        event.attributes.insert(
            "tls_failure_host_count".to_string(),
            counters.host_total_failures.to_string(),
        );
        event.attributes.insert(
            "tls_failure_host_rolling_count".to_string(),
            counters.host_rolling_failures.to_string(),
        );
        event.attributes.insert(
            "tls_failure_source_count".to_string(),
            counters.source_total_failures.to_string(),
        );
        event.attributes.insert(
            "tls_failure_reason_count".to_string(),
            counters.reason_total_failures.to_string(),
        );
        event.attributes.insert(
            "tls_failure_global_count".to_string(),
            counters.global_total_failures.to_string(),
        );
        event.attributes.insert(
            "tls_learning_decision".to_string(),
            learning_outcome.decision.as_str().to_string(),
        );
        event.attributes.insert(
            "tls_learning_reason_code".to_string(),
            learning_outcome.reason_code.to_string(),
        );
        event.attributes.insert(
            "tls_learning_host_count".to_string(),
            learning_outcome.host_applied_total.to_string(),
        );
        event.attributes.insert(
            "tls_learning_global_applied".to_string(),
            learning_outcome.global_applied_total.to_string(),
        );
        event.attributes.insert(
            "tls_learning_global_ignored".to_string(),
            learning_outcome.global_ignored_total.to_string(),
        );
    }
    engine.emit_event(event);
}

fn ingest_tls_learning_signal_with_audit<P, S>(
    engine: &MitmEngine<P, S>,
    tls_learning: &TlsLearningGuardrails,
    context: FlowContext,
    signal: TlsLearningSignal,
) -> TlsLearningOutcome
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let outcome = tls_learning.ingest(signal.clone());
    if outcome.decision == TlsLearningDecision::Ignored {
        emit_tls_learning_audit_event(engine, context, signal, outcome);
    }
    outcome
}

fn emit_tls_learning_audit_event<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    signal: TlsLearningSignal,
    outcome: TlsLearningOutcome,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::TlsLearningAudit, context);
    event.attributes.insert(
        "tls_learning_decision".to_string(),
        outcome.decision.as_str().to_string(),
    );
    event.attributes.insert(
        "tls_learning_reason_code".to_string(),
        outcome.reason_code.to_string(),
    );
    event.attributes.insert(
        "tls_learning_global_applied".to_string(),
        outcome.global_applied_total.to_string(),
    );
    event.attributes.insert(
        "tls_learning_global_ignored".to_string(),
        outcome.global_ignored_total.to_string(),
    );
    event
        .attributes
        .insert("signal_host".to_string(), signal.host);
    event
        .attributes
        .insert("signal_reason".to_string(), signal.failure_reason);
    event
        .attributes
        .insert("signal_source".to_string(), signal.failure_source);
    event
        .attributes
        .insert("signal_provider".to_string(), signal.provider);
    event
        .attributes
        .insert("signal_inferred".to_string(), signal.inferred.to_string());
    engine.emit_event(event);
}

fn emit_stream_closed<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    reason_code: CloseReasonCode,
    reason_detail: Option<String>,
    bytes_from_client: Option<u64>,
    bytes_from_server: Option<u64>,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::StreamClosed, context);
    event
        .attributes
        .insert("reason_code".to_string(), reason_code.as_str().to_string());
    if let Some(detail) = reason_detail {
        event.attributes.insert("reason_detail".to_string(), detail);
    }

    if let Some(value) = bytes_from_client {
        event
            .attributes
            .insert("bytes_from_client".to_string(), value.to_string());
    }
    if let Some(value) = bytes_from_server {
        event
            .attributes
            .insert("bytes_from_server".to_string(), value.to_string());
    }
    engine.emit_event(event);
}

fn emit_connect_parse_failed<P, S>(
    engine: &MitmEngine<P, S>,
    context: FlowContext,
    parse_failure: ParseFailureCode,
    parse_detail: Option<String>,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut event = Event::new(EventType::ConnectParseFailed, context);
    event.attributes.insert(
        "parse_error_code".to_string(),
        parse_failure.as_str().to_string(),
    );
    if let Some(detail) = parse_detail {
        event
            .attributes
            .insert("parse_error_detail".to_string(), detail);
    }
    engine.emit_event(event);
}

fn unknown_context(flow_id: u64, client_addr: String) -> FlowContext {
    FlowContext {
        flow_id,
        client_addr,
        server_host: "<unknown>".to_string(),
        server_port: 0,
        protocol: ApplicationProtocol::Tunnel,
    }
}

fn tls_error_to_io_invalid_input(error: TlsConfigError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
