use crate::config::MitmConfig;
use crate::handler::InterceptHandler;
use crate::process::{PlatformProcessAttributor, ProcessLookupService};
use crate::types::{
    ConnectionInfo, ConnectionMeta, FrameKind, ProcessInfo, RawRequest, RawResponse, SocketFamily,
    StreamChunk,
};
use crate::HandlerDecision;
use bytes::Bytes;
use mitm_observe::FlowContext;
use mitm_sidecar::{
    FlowHooks, RawRequest as SidecarRawRequest, RawResponse as SidecarRawResponse, RequestDecision,
    StreamChunk as SidecarStreamChunk, StreamFrameKind,
};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;
#[derive(Debug)]
struct HandlerFlowHooks<H: InterceptHandler> {
    handler: Arc<H>,
    process_lookup: Option<Arc<ProcessLookupService<PlatformProcessAttributor>>>,
    stream_sequences: Arc<Mutex<HashMap<u64, u64>>>,
    connection_meta_by_flow: Arc<Mutex<HashMap<u64, ConnectionMeta>>>,
}
impl<H: InterceptHandler> HandlerFlowHooks<H> {
    fn new(
        handler: Arc<H>,
        process_lookup: Option<Arc<ProcessLookupService<PlatformProcessAttributor>>>,
    ) -> Self {
        Self {
            handler,
            process_lookup,
            stream_sequences: Arc::new(Mutex::new(HashMap::new())),
            connection_meta_by_flow: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
impl<H: InterceptHandler> FlowHooks for HandlerFlowHooks<H> {
    fn resolve_process_info(
        &self,
        context: FlowContext,
    ) -> Pin<Box<dyn Future<Output = Option<mitm_policy::ProcessInfo>> + Send>> {
        let process_lookup = self.process_lookup.clone();
        Box::pin(async move {
            let Some(lookup) = process_lookup.as_ref() else {
                return None;
            };
            if let Some(uds_process_info) = process_info_from_unix_client_addr(&context.client_addr)
            {
                return Some(policy_process_info_from_runtime(&uds_process_info));
            }
            let lookup_info = lookup
                .bind_connection_info(&lookup_connection_info_from_flow_context(&context))
                .await;
            lookup_info
                .process_info
                .as_ref()
                .map(policy_process_info_from_runtime)
        })
    }
    fn on_connection_open(
        &self,
        context: FlowContext,
        process_info: Option<mitm_policy::ProcessInfo>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = Arc::clone(&self.handler);
        let connection_meta_by_flow = Arc::clone(&self.connection_meta_by_flow);
        Box::pin(async move {
            let connection_meta = connection_meta_from_accept_context(
                &context,
                process_info.map(runtime_process_info_from_policy),
            );
            let mut guard = connection_meta_by_flow.lock().await;
            guard.insert(context.flow_id, connection_meta);
            drop(guard);
            handler.on_connection_open(Uuid::from_u128(context.flow_id as u128));
        })
    }
    fn should_intercept_tls(
        &self,
        context: FlowContext,
    ) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        let handler = Arc::clone(&self.handler);
        Box::pin(async move { handler.should_intercept_tls(&context.server_host) })
    }
    fn on_tls_failure(
        &self,
        context: FlowContext,
        error: String,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = Arc::clone(&self.handler);
        Box::pin(async move { handler.on_tls_failure(&context.server_host, &error) })
    }
    fn on_request(
        &self,
        context: FlowContext,
        request: SidecarRawRequest,
    ) -> Pin<Box<dyn Future<Output = RequestDecision> + Send>> {
        let handler = Arc::clone(&self.handler);
        let connection_meta_by_flow = Arc::clone(&self.connection_meta_by_flow);
        Box::pin(async move {
            let Some(connection_meta) =
                connection_meta_for_context(&context, &connection_meta_by_flow).await
            else {
                return RequestDecision::Block {
                    status: 500,
                    body: Bytes::from_static(b"missing ConnectionMeta"),
                };
            };
            let raw_request = RawRequest {
                method: request.method,
                path: request.path,
                headers: request.headers,
                body: request.body,
                connection_meta,
            };
            match handler.on_request(&raw_request) {
                HandlerDecision::Allow => RequestDecision::Allow,
                HandlerDecision::Block { status, body } => RequestDecision::Block { status, body },
            }
        })
    }
    fn on_response(
        &self,
        context: FlowContext,
        response: SidecarRawResponse,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = Arc::clone(&self.handler);
        let connection_meta_by_flow = Arc::clone(&self.connection_meta_by_flow);
        Box::pin(async move {
            let Some(connection_meta) =
                connection_meta_for_context(&context, &connection_meta_by_flow).await
            else {
                return;
            };
            let raw_response = RawResponse {
                status: response.status,
                headers: response.headers,
                body: response.body,
                connection_meta,
            };
            handler.on_response(&raw_response);
        })
    }
    fn on_stream_chunk(
        &self,
        context: FlowContext,
        chunk: SidecarStreamChunk,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = Arc::clone(&self.handler);
        let stream_sequences = Arc::clone(&self.stream_sequences);
        let connection_meta_by_flow = Arc::clone(&self.connection_meta_by_flow);
        Box::pin(async move {
            let Some(frame_kind) = map_stream_frame_kind(chunk.frame_kind) else {
                return;
            };
            let Some(connection_meta) =
                connection_meta_for_context(&context, &connection_meta_by_flow).await
            else {
                return;
            };
            let sequence = {
                let mut guard = stream_sequences.lock().await;
                let next = guard.entry(context.flow_id).or_insert(0);
                let value = *next;
                *next += 1;
                value
            };
            let translated = StreamChunk {
                connection_id: Uuid::from_u128(context.flow_id as u128),
                payload: chunk.payload,
                sequence,
                frame_kind,
                connection_meta,
            };
            handler.on_stream_chunk(&translated);
        })
    }
    fn on_stream_end(&self, context: FlowContext) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = Arc::clone(&self.handler);
        let stream_sequences = Arc::clone(&self.stream_sequences);
        let connection_meta_by_flow = Arc::clone(&self.connection_meta_by_flow);
        let process_lookup = self.process_lookup.clone();
        Box::pin(async move {
            let mut guard = stream_sequences.lock().await;
            guard.remove(&context.flow_id);
            drop(guard);
            let mut connection_guard = connection_meta_by_flow.lock().await;
            connection_guard.remove(&context.flow_id);
            drop(connection_guard);
            if let Some(lookup) = process_lookup.as_ref() {
                lookup
                    .remove_connection(Uuid::from_u128(context.flow_id as u128))
                    .await;
            }
            handler.on_stream_end(Uuid::from_u128(context.flow_id as u128));
        })
    }
}
pub(crate) fn build_handler_flow_hooks<H: InterceptHandler>(
    config: &MitmConfig,
    handler: Arc<H>,
) -> Arc<dyn FlowHooks> {
    let process_lookup = if config.tls.process_info {
        Some(Arc::new(ProcessLookupService::new(
            Arc::new(PlatformProcessAttributor),
            Duration::from_millis(config.handler.timeout_ms.max(1)),
        )))
    } else {
        None
    };
    Arc::new(HandlerFlowHooks::new(handler, process_lookup))
}
fn map_stream_frame_kind(kind: StreamFrameKind) -> Option<FrameKind> {
    match kind {
        StreamFrameKind::SseData => Some(FrameKind::SseData),
        StreamFrameKind::NdjsonLine => Some(FrameKind::NdjsonLine),
        StreamFrameKind::GrpcMessage => Some(FrameKind::GrpcMessage),
        StreamFrameKind::WebSocketText => Some(FrameKind::WebSocketText),
        StreamFrameKind::WebSocketBinary => Some(FrameKind::WebSocketBinary),
        StreamFrameKind::WebSocketClose => Some(FrameKind::WebSocketClose),
    }
}
fn connection_meta_from_accept_context(
    context: &FlowContext,
    process_info: Option<ProcessInfo>,
) -> ConnectionMeta {
    ConnectionMeta {
        connection_id: Uuid::from_u128(context.flow_id as u128),
        socket_family: socket_family_from_flow_context(context),
        process_info,
        tls_info: None,
    }
}
fn socket_family_from_flow_context(context: &FlowContext) -> SocketFamily {
    if let Some(meta) = parse_unix_client_addr_meta(&context.client_addr) {
        return SocketFamily::UnixDomain { path: meta.path };
    }
    let local = context.client_addr.parse::<SocketAddr>().ok();
    match local {
        Some(SocketAddr::V4(local_v4)) => SocketFamily::TcpV4 {
            local: local_v4,
            remote: SocketAddrV4::new(
                context
                    .server_host
                    .parse::<Ipv4Addr>()
                    .unwrap_or(Ipv4Addr::UNSPECIFIED),
                context.server_port,
            ),
        },
        Some(SocketAddr::V6(local_v6)) => SocketFamily::TcpV6 {
            local: local_v6,
            remote: SocketAddrV6::new(
                context
                    .server_host
                    .parse::<Ipv6Addr>()
                    .unwrap_or(Ipv6Addr::UNSPECIFIED),
                context.server_port,
                0,
                0,
            ),
        },
        None => SocketFamily::TcpV4 {
            local: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            remote: SocketAddrV4::new(
                context
                    .server_host
                    .parse::<Ipv4Addr>()
                    .unwrap_or(Ipv4Addr::UNSPECIFIED),
                context.server_port,
            ),
        },
    }
}
fn lookup_connection_info_from_flow_context(context: &FlowContext) -> ConnectionInfo {
    let socket_family = socket_family_from_flow_context(context);
    let (source_ip, source_port) = match &socket_family {
        SocketFamily::TcpV4 { local, .. } => (IpAddr::V4(*local.ip()), local.port()),
        SocketFamily::TcpV6 { local, .. } => (IpAddr::V6(*local.ip()), local.port()),
        SocketFamily::UnixDomain { .. } => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    ConnectionInfo {
        connection_id: Uuid::from_u128(context.flow_id as u128),
        source_ip,
        source_port,
        destination_host: context.server_host.clone(),
        destination_port: context.server_port,
        socket_family,
        tls_fingerprint: None,
        alpn_protocol: None,
        is_http2: false,
        process_info: None,
        connected_at: std::time::SystemTime::now(),
        request_count: 0,
    }
}
fn policy_process_info_from_runtime(process_info: &ProcessInfo) -> mitm_policy::ProcessInfo {
    let process_name = process_info.exe_name.clone().or_else(|| {
        process_info
            .exe_path
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .map(|value| value.to_string())
    });
    mitm_policy::ProcessInfo {
        pid: process_info.pid,
        bundle_id: process_info.bundle_id.clone(),
        process_name,
    }
}
fn runtime_process_info_from_policy(process_info: mitm_policy::ProcessInfo) -> ProcessInfo {
    ProcessInfo {
        pid: process_info.pid,
        bundle_id: process_info.bundle_id,
        exe_name: process_info.process_name,
        exe_path: None,
        parent_pid: None,
    }
}
async fn connection_meta_for_context(
    context: &FlowContext,
    connection_meta_by_flow: &Arc<Mutex<HashMap<u64, ConnectionMeta>>>,
) -> Option<ConnectionMeta> {
    let guard = connection_meta_by_flow.lock().await;
    let Some(connection_meta) = guard.get(&context.flow_id).cloned() else {
        debug_assert!(
            false,
            "connection {} missing ConnectionMeta in flow map",
            context.flow_id
        );
        eprintln!(
            "missing ConnectionMeta for flow_id={} host={} port={}",
            context.flow_id, context.server_host, context.server_port
        );
        return None;
    };
    Some(connection_meta)
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnixClientAddrMeta {
    pid: Option<u32>,
    path: Option<PathBuf>,
}
fn parse_unix_client_addr_meta(client_addr: &str) -> Option<UnixClientAddrMeta> {
    let raw = client_addr.strip_prefix("unix:")?;
    if raw.is_empty() {
        return Some(UnixClientAddrMeta {
            pid: None,
            path: None,
        });
    }
    let mut pid = None;
    let mut path = None;
    for part in raw
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        if let Some(raw_pid) = part.strip_prefix("pid=") {
            if let Ok(parsed) = raw_pid.trim().parse::<u32>() {
                pid = Some(parsed);
            }
            continue;
        }
        if let Some(raw_path) = part.strip_prefix("path=") {
            let value = raw_path.trim();
            if !value.is_empty() {
                path = Some(PathBuf::from(value));
            }
        }
    }
    Some(UnixClientAddrMeta { pid, path })
}
fn process_info_from_unix_client_addr(client_addr: &str) -> Option<ProcessInfo> {
    let meta = parse_unix_client_addr_meta(client_addr)?;
    let pid = meta.pid?;
    Some(ProcessInfo {
        pid,
        bundle_id: None,
        exe_name: None,
        exe_path: None,
        parent_pid: None,
    })
}

#[cfg(test)]
#[path = "flow_hooks_tests.rs"]
mod tests;
