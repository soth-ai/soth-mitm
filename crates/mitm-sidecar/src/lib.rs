use std::io;
use std::sync::Arc;

use mitm_core::{parse_connect_request_head_with_mode, ConnectParseError, MitmEngine};
use mitm_http::{negotiated_alpn_label, protocol_from_negotiated_alpn, ApplicationProtocol};
use mitm_observe::{Event, EventConsumer, EventType, FlowContext};
use mitm_policy::{FlowAction, PolicyEngine};
use mitm_tls::{
    build_http_client_config, classify_tls_error, CertificateAuthorityConfig, MitmCertificateStore,
    TlsConfigError,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

mod mitmproxy_tls_ops;
mod runtime_governor;
mod tls_diagnostics;
mod tls_learning;

pub use mitmproxy_tls_ops::{
    adapt_mitmproxy_tls_callback, MitmproxyTlsAdapterEvent, MitmproxyTlsCallback,
    MitmproxyTlsFailure, MitmproxyTlsHook,
};
pub use runtime_governor::{RuntimeBudgetConfig, RuntimeGovernor, RuntimeObservabilitySnapshot};
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
    S: EventConsumer + Send + Sync + 'static,
{
    config: SidecarConfig,
    engine: Arc<MitmEngine<P, S>>,
    cert_store: Arc<MitmCertificateStore>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    tls_diagnostics: Arc<TlsDiagnostics>,
    tls_learning: Arc<TlsLearningGuardrails>,
}

#[derive(Clone)]
struct RuntimeHandles<P, S>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    engine: Arc<MitmEngine<P, S>>,
    cert_store: Arc<MitmCertificateStore>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    tls_diagnostics: Arc<TlsDiagnostics>,
    tls_learning: Arc<TlsLearningGuardrails>,
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
    S: EventConsumer + Send + Sync + 'static,
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
        let runtime_governor = Arc::new(runtime_governor::RuntimeGovernor::new(
            RuntimeBudgetConfig {
                max_concurrent_flows: engine.config.max_concurrent_flows,
                max_in_flight_bytes: engine.config.max_in_flight_bytes,
            },
        ));
        runtime_governor::install_global_runtime_governor(Arc::clone(&runtime_governor));
        runtime_governor::set_event_queue_depth_global(0);
        let tls_diagnostics = Arc::new(TlsDiagnostics::default());
        let tls_learning = Arc::new(TlsLearningGuardrails::new());
        Ok(Self {
            config,
            engine: Arc::new(engine),
            cert_store: Arc::new(cert_store),
            runtime_governor,
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

    pub fn runtime_observability_snapshot(&self) -> RuntimeObservabilitySnapshot {
        self.runtime_governor.snapshot()
    }

    pub fn runtime_observability_handle(&self) -> Arc<RuntimeGovernor> {
        Arc::clone(&self.runtime_governor)
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
            let (mut stream, client_addr) = listener.accept().await?;
            let Some(flow_permit) = self.runtime_governor.try_acquire_flow_permit() else {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 36\r\n\r\nproxy flow capacity exceeded; try later",
                    )
                    .await;
                let _ = stream.shutdown().await;
                continue;
            };
            let runtime = RuntimeHandles {
                engine: Arc::clone(&self.engine),
                cert_store: Arc::clone(&self.cert_store),
                runtime_governor: Arc::clone(&self.runtime_governor),
                tls_diagnostics: Arc::clone(&self.tls_diagnostics),
                tls_learning: Arc::clone(&self.tls_learning),
            };
            let max_connect_head_bytes = self.config.max_connect_head_bytes;
            let max_http_head_bytes = self.config.max_http_head_bytes;
            tokio::spawn(async move {
                let _flow_guard = runtime.runtime_governor.begin_flow(flow_permit);
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

include!("flow_connect_tunnel.rs");
include!("close_codes.rs");
include!("downstream_tls.rs");
include!("flow_intercept.rs");
include!("flow_intercept_http1.rs");
include!("http2_relay_support.rs");
include!("http2_stream_relay.rs");
include!("websocket_relay.rs");
include!("websocket_relay_support.rs");
include!("websocket_turn_tracker.rs");
include!("websocket_events.rs");
include!("http_head_parser.rs");
include!("http_head_parser_api.rs");
include!("http_body_relay.rs");
include!("event_emitters.rs");
include!("event_emitters_protocol.rs");
include!("sse_stream_observer.rs");
