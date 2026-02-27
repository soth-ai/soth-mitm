use super::super::connection_meta::{
    parse_unix_client_addr_meta, process_info_from_unix_client_addr,
    socket_family_from_flow_context,
};
use super::build_handler_flow_hooks;
use crate::config::MitmConfig;
use crate::handler::InterceptHandler;
use crate::metrics::ProxyMetricsStore;
use crate::types::{ProcessInfo, RawRequest, RawResponse};
use crate::HandlerDecision;
use bytes::Bytes;
use futures::FutureExt;
use http::HeaderMap;
use mitm_http::ApplicationProtocol;
use mitm_observe::FlowContext;
use mitm_policy::ProcessInfo as PolicyProcessInfo;
use mitm_sidecar::{FlowHooks, RawRequest as SidecarRawRequest, RawResponse as SidecarRawResponse};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[test]
fn parses_unix_client_addr_metadata() {
    let parsed = parse_unix_client_addr_meta("unix:pid=4242,path=/tmp/soth-mitm.sock")
        .expect("unix metadata should parse");
    assert_eq!(parsed.pid, Some(4242));
    assert_eq!(parsed.path, Some(PathBuf::from("/tmp/soth-mitm.sock")));
}

#[test]
fn unix_client_addr_maps_socket_family_and_process_info() {
    let context = FlowContext {
        flow_id: 9,
        client_addr: "unix:pid=1234,path=/tmp/soth.sock".to_string(),
        server_host: "127.0.0.1".to_string(),
        server_port: 11434,
        protocol: ApplicationProtocol::Http1,
    };
    let socket_family = socket_family_from_flow_context(&context);
    assert!(matches!(
        socket_family,
        crate::types::SocketFamily::UnixDomain { .. }
    ));
    let process = process_info_from_unix_client_addr(&context.client_addr)
        .expect("pid metadata should map to process info");
    assert_eq!(process.pid, 1234);
}

#[tokio::test]
async fn request_timeout_cancels_future_and_records_metric() {
    let drop_seen = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(CancellableRequestHandler {
        drop_seen: Arc::clone(&drop_seen),
    });
    let metrics_store = Arc::new(ProxyMetricsStore::default());
    let hooks = build_hooks(
        handler,
        Arc::clone(&metrics_store),
        Duration::from_millis(10),
        Duration::from_millis(200),
        true,
    );
    let context = sample_context(101);
    register_connection(&hooks, context.clone()).await;

    let decision = hooks
        .on_request(context.clone(), sample_sidecar_request())
        .await;
    assert!(
        matches!(decision, mitm_sidecar::RequestDecision::Allow),
        "timed-out request handler should default to Allow"
    );

    wait_for(Duration::from_millis(200), || {
        drop_seen.load(Ordering::Relaxed)
    })
    .await;
    assert!(
        drop_seen.load(Ordering::Relaxed),
        "timed-out request future should be dropped (cancelled)"
    );
    assert_eq!(
        metrics_store.snapshot().handler_timeout_count,
        1,
        "request timeout must increment handler timeout metric"
    );
}

#[tokio::test]
async fn request_panic_recover_true_defaults_allow_and_records_metric() {
    let handler = Arc::new(PanicRequestHandler);
    let metrics_store = Arc::new(ProxyMetricsStore::default());
    let hooks = build_hooks(
        handler,
        Arc::clone(&metrics_store),
        Duration::from_millis(100),
        Duration::from_millis(100),
        true,
    );
    let context = sample_context(102);
    register_connection(&hooks, context.clone()).await;

    let decision = hooks.on_request(context, sample_sidecar_request()).await;
    assert!(
        matches!(decision, mitm_sidecar::RequestDecision::Allow),
        "panic with recover=true should default to Allow"
    );
    assert_eq!(
        metrics_store.snapshot().handler_panic_count,
        1,
        "panic should increment handler panic metric"
    );
}

#[tokio::test]
async fn request_panic_recover_false_bubbles_panic() {
    let handler = Arc::new(PanicRequestHandler);
    let metrics_store = Arc::new(ProxyMetricsStore::default());
    let hooks = build_hooks(
        handler,
        Arc::clone(&metrics_store),
        Duration::from_millis(100),
        Duration::from_millis(100),
        false,
    );
    let context = sample_context(103);
    register_connection(&hooks, context.clone()).await;

    let panic = AssertUnwindSafe(async {
        let _ = hooks.on_request(context, sample_sidecar_request()).await;
    })
    .catch_unwind()
    .await;
    assert!(panic.is_err(), "panic should bubble when recover=false");
    assert_eq!(
        metrics_store.snapshot().handler_panic_count,
        1,
        "panic should still be counted before unwind"
    );
}

#[tokio::test]
async fn response_fire_and_forget_does_not_block_forward_path() {
    let completed = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(DelayedResponseHandler {
        delay: Duration::from_millis(80),
        completed: Arc::clone(&completed),
    });
    let metrics_store = Arc::new(ProxyMetricsStore::default());
    let hooks = build_hooks(
        handler,
        Arc::clone(&metrics_store),
        Duration::from_millis(200),
        Duration::from_millis(500),
        true,
    );
    let context = sample_context(104);
    register_connection(&hooks, context.clone()).await;

    let started = Instant::now();
    hooks.on_response(context, sample_sidecar_response()).await;
    assert!(
        started.elapsed() < Duration::from_millis(30),
        "on_response should return quickly and run handler asynchronously"
    );

    wait_for(Duration::from_millis(500), || {
        completed.load(Ordering::Relaxed) == 1
    })
    .await;
    assert_eq!(
        completed.load(Ordering::Relaxed),
        1,
        "response callback should eventually complete in spawned task"
    );
}

#[tokio::test]
async fn response_timeout_records_metric_without_blocking() {
    let completed = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(DelayedResponseHandler {
        delay: Duration::from_millis(200),
        completed: Arc::clone(&completed),
    });
    let metrics_store = Arc::new(ProxyMetricsStore::default());
    let hooks = build_hooks(
        handler,
        Arc::clone(&metrics_store),
        Duration::from_millis(200),
        Duration::from_millis(20),
        true,
    );
    let context = sample_context(105);
    register_connection(&hooks, context.clone()).await;

    hooks.on_response(context, sample_sidecar_response()).await;
    wait_for(Duration::from_millis(400), || {
        metrics_store.snapshot().handler_timeout_count >= 1
    })
    .await;
    assert!(
        metrics_store.snapshot().handler_timeout_count >= 1,
        "response timeout should increment handler timeout metric"
    );
    assert_eq!(
        completed.load(Ordering::Relaxed),
        0,
        "timed-out response callback future should be cancelled before completion"
    );
}

#[tokio::test]
async fn stream_end_invokes_connection_close_once() {
    let stream_end_count = Arc::new(AtomicUsize::new(0));
    let close_count = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(StreamLifecycleHandler {
        stream_end_count: Arc::clone(&stream_end_count),
        close_count: Arc::clone(&close_count),
    });
    let metrics_store = Arc::new(ProxyMetricsStore::default());
    let hooks = build_hooks(
        handler,
        metrics_store,
        Duration::from_millis(100),
        Duration::from_millis(100),
        true,
    );
    let context = sample_context(106);
    register_connection(&hooks, context.clone()).await;

    hooks.on_stream_end(context).await;
    assert_eq!(stream_end_count.load(Ordering::Relaxed), 1);
    assert_eq!(close_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn lifecycle_sync_callbacks_use_response_timeout_budget() {
    let close_count = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(SlowLifecycleCloseHandler {
        close_delay: Duration::from_millis(80),
        close_count: Arc::clone(&close_count),
    });
    let metrics_store = Arc::new(ProxyMetricsStore::default());
    let hooks = build_hooks(
        handler,
        Arc::clone(&metrics_store),
        Duration::from_millis(10),
        Duration::from_millis(200),
        true,
    );
    let context = sample_context(207);
    register_connection(&hooks, context.clone()).await;

    let started = Instant::now();
    hooks.on_stream_end(context).await;
    assert!(
        started.elapsed() >= Duration::from_millis(70),
        "lifecycle close callback should honor lifecycle timeout budget (response timeout), not request timeout"
    );
    assert_eq!(close_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn duplicate_stream_end_callbacks_are_deduplicated() {
    let stream_end_count = Arc::new(AtomicUsize::new(0));
    let close_count = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(StreamLifecycleHandler {
        stream_end_count: Arc::clone(&stream_end_count),
        close_count: Arc::clone(&close_count),
    });
    let metrics_store = Arc::new(ProxyMetricsStore::default());
    let hooks = build_hooks(
        handler,
        metrics_store,
        Duration::from_millis(100),
        Duration::from_millis(100),
        true,
    );
    let context = sample_context(206);
    register_connection(&hooks, context.clone()).await;

    hooks.on_stream_end(context.clone()).await;
    hooks.on_stream_end(context).await;

    assert_eq!(
        stream_end_count.load(Ordering::Relaxed),
        1,
        "stream end callback must fire once per flow"
    );
    assert_eq!(
        close_count.load(Ordering::Relaxed),
        1,
        "connection close callback must fire once per flow"
    );
}

#[tokio::test]
async fn late_response_after_stream_end_does_not_resurrect_dispatcher() {
    let completed = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(DelayedResponseHandler {
        delay: Duration::from_millis(120),
        completed: Arc::clone(&completed),
    });
    let metrics_store = Arc::new(ProxyMetricsStore::default());
    let hooks = build_hooks(
        handler,
        Arc::clone(&metrics_store),
        Duration::from_millis(200),
        Duration::from_millis(400),
        true,
    );
    let context = sample_context(208);
    register_connection(&hooks, context.clone()).await;

    hooks
        .on_response(context.clone(), sample_sidecar_response())
        .await;
    let hooks_for_end = Arc::clone(&hooks);
    let context_for_end = context.clone();
    let finalize = tokio::spawn(async move {
        hooks_for_end.on_stream_end(context_for_end).await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    hooks.on_response(context, sample_sidecar_response()).await;

    tokio::time::timeout(Duration::from_secs(1), finalize)
        .await
        .expect("stream_end should complete")
        .expect("stream_end task should not panic");
    tokio::time::sleep(Duration::from_millis(160)).await;

    assert_eq!(
        completed.load(Ordering::Relaxed),
        1,
        "late response after stream_end should not create a new flow dispatcher"
    );
    let _ = metrics_store.snapshot();
}

#[tokio::test]
async fn should_intercept_tls_receives_process_info_from_connect_path() {
    let observed_pid = Arc::new(AtomicU32::new(0));
    let handler = Arc::new(ProcessAwareTlsHandler {
        observed_pid: Arc::clone(&observed_pid),
    });
    let metrics_store = Arc::new(ProxyMetricsStore::default());
    let hooks = build_hooks(
        handler,
        metrics_store,
        Duration::from_millis(100),
        Duration::from_millis(100),
        true,
    );
    let context = sample_context(107);
    let policy_process = Some(PolicyProcessInfo {
        pid: 4242,
        bundle_id: Some("com.soth.tests".to_string()),
        process_name: Some("curl".to_string()),
    });

    let _ = hooks.should_intercept_tls(context, policy_process).await;
    assert_eq!(
        observed_pid.load(Ordering::Relaxed),
        4242,
        "process info should flow into TLS intercept decision hook"
    );
}

#[tokio::test]
async fn request_connection_meta_includes_tls_info_for_http2_flow() {
    let observed_tls_proto = Arc::new(std::sync::Mutex::new(None::<String>));
    let observed_tls_sni = Arc::new(std::sync::Mutex::new(None::<String>));
    let handler = Arc::new(TlsMetaCaptureHandler {
        observed_tls_proto: Arc::clone(&observed_tls_proto),
        observed_tls_sni: Arc::clone(&observed_tls_sni),
    });
    let metrics_store = Arc::new(ProxyMetricsStore::default());
    let hooks = build_hooks(
        handler,
        metrics_store,
        Duration::from_millis(100),
        Duration::from_millis(100),
        true,
    );
    let mut context = sample_context(108);
    context.protocol = ApplicationProtocol::Http2;
    register_connection(&hooks, context.clone()).await;

    let _ = hooks.on_request(context, sample_sidecar_request()).await;

    let negotiated = observed_tls_proto.lock().expect("tls proto lock").clone();
    let sni = observed_tls_sni.lock().expect("tls sni lock").clone();
    assert_eq!(negotiated.as_deref(), Some("h2"));
    assert_eq!(sni.as_deref(), Some("api.example.com"));
}

fn build_hooks<H: InterceptHandler>(
    handler: Arc<H>,
    metrics_store: Arc<ProxyMetricsStore>,
    request_timeout: Duration,
    response_timeout: Duration,
    recover_from_panics: bool,
) -> Arc<dyn FlowHooks> {
    let mut config = MitmConfig::default();
    config.process_attribution.enabled = false;
    config.handler.request_timeout_ms = request_timeout.as_millis() as u64;
    config.handler.response_timeout_ms = response_timeout.as_millis() as u64;
    config.handler.recover_from_panics = recover_from_panics;
    build_handler_flow_hooks(&config, handler, metrics_store)
}

fn sample_context(flow_id: u64) -> FlowContext {
    FlowContext {
        flow_id,
        client_addr: "127.0.0.1:56000".to_string(),
        server_host: "api.example.com".to_string(),
        server_port: 443,
        protocol: ApplicationProtocol::Http1,
    }
}

async fn register_connection(hooks: &Arc<dyn FlowHooks>, context: FlowContext) {
    hooks
        .on_connection_open(
            context,
            Some(PolicyProcessInfo {
                pid: 7001,
                bundle_id: Some("com.soth.fixture".to_string()),
                process_name: Some("fixture-client".to_string()),
            }),
        )
        .await;
}

fn sample_sidecar_request() -> SidecarRawRequest {
    SidecarRawRequest {
        method: "GET".to_string(),
        path: "/v1/test".to_string(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    }
}

fn sample_sidecar_response() -> SidecarRawResponse {
    SidecarRawResponse {
        status: 200,
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"{\"ok\":true}"),
    }
}

async fn wait_for<F>(timeout: Duration, predicate: F)
where
    F: Fn() -> bool,
{
    let start = Instant::now();
    while !predicate() && start.elapsed() < timeout {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[derive(Debug)]
struct PanicRequestHandler;

impl InterceptHandler for PanicRequestHandler {
    fn on_request(
        &self,
        _request: &RawRequest,
    ) -> impl std::future::Future<Output = HandlerDecision> + Send {
        async move {
            panic!("intentional panic in on_request");
        }
    }
}

#[derive(Debug)]
struct DelayedResponseHandler {
    delay: Duration,
    completed: Arc<AtomicUsize>,
}

impl InterceptHandler for DelayedResponseHandler {
    fn on_request(
        &self,
        _request: &RawRequest,
    ) -> impl std::future::Future<Output = HandlerDecision> + Send {
        async { HandlerDecision::Allow }
    }

    fn on_response(&self, _response: &RawResponse) -> impl std::future::Future<Output = ()> + Send {
        let delay = self.delay;
        let completed = Arc::clone(&self.completed);
        async move {
            tokio::time::sleep(delay).await;
            completed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
struct StreamLifecycleHandler {
    stream_end_count: Arc<AtomicUsize>,
    close_count: Arc<AtomicUsize>,
}

impl InterceptHandler for StreamLifecycleHandler {
    fn on_request(
        &self,
        _request: &RawRequest,
    ) -> impl std::future::Future<Output = HandlerDecision> + Send {
        async { HandlerDecision::Allow }
    }

    fn on_stream_end(&self, _connection_id: Uuid) -> impl std::future::Future<Output = ()> + Send {
        let stream_end_count = Arc::clone(&self.stream_end_count);
        async move {
            stream_end_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn on_connection_close(&self, _connection_id: Uuid) {
        self.close_count.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct SlowLifecycleCloseHandler {
    close_delay: Duration,
    close_count: Arc<AtomicUsize>,
}

impl InterceptHandler for SlowLifecycleCloseHandler {
    fn on_request(
        &self,
        _request: &RawRequest,
    ) -> impl std::future::Future<Output = HandlerDecision> + Send {
        async { HandlerDecision::Allow }
    }

    fn on_connection_close(&self, _connection_id: Uuid) {
        std::thread::sleep(self.close_delay);
        self.close_count.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct ProcessAwareTlsHandler {
    observed_pid: Arc<AtomicU32>,
}

impl InterceptHandler for ProcessAwareTlsHandler {
    fn should_intercept_tls(&self, _host: &str, process_info: Option<&ProcessInfo>) -> bool {
        let pid = process_info.map(|value| value.pid).unwrap_or(0);
        self.observed_pid.store(pid, Ordering::Relaxed);
        true
    }
}

#[derive(Debug)]
struct TlsMetaCaptureHandler {
    observed_tls_proto: Arc<std::sync::Mutex<Option<String>>>,
    observed_tls_sni: Arc<std::sync::Mutex<Option<String>>>,
}

impl InterceptHandler for TlsMetaCaptureHandler {
    fn on_request(
        &self,
        request: &RawRequest,
    ) -> impl std::future::Future<Output = HandlerDecision> + Send {
        let observed_tls_proto = Arc::clone(&self.observed_tls_proto);
        let observed_tls_sni = Arc::clone(&self.observed_tls_sni);
        let tls_info = request.connection_meta.tls_info.clone();
        async move {
            let mut proto_guard = observed_tls_proto.lock().expect("proto lock");
            let mut sni_guard = observed_tls_sni.lock().expect("sni lock");
            *proto_guard = tls_info
                .as_ref()
                .and_then(|value| value.negotiated_proto.clone());
            *sni_guard = tls_info.and_then(|value| value.sni);
            HandlerDecision::Allow
        }
    }
}

#[derive(Debug)]
struct CancellableRequestHandler {
    drop_seen: Arc<AtomicBool>,
}

#[derive(Debug)]
struct DropProbe {
    drop_seen: Arc<AtomicBool>,
}

impl Drop for DropProbe {
    fn drop(&mut self) {
        self.drop_seen.store(true, Ordering::Relaxed);
    }
}

impl InterceptHandler for CancellableRequestHandler {
    fn on_request(
        &self,
        _request: &RawRequest,
    ) -> impl std::future::Future<Output = HandlerDecision> + Send {
        let drop_seen = Arc::clone(&self.drop_seen);
        async move {
            let _probe = DropProbe { drop_seen };
            tokio::time::sleep(Duration::from_secs(60)).await;
            HandlerDecision::Block {
                status: 403,
                body: Bytes::from_static(b"late"),
            }
        }
    }
}
