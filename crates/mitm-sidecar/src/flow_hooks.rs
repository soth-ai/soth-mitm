use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use http::HeaderMap;
use mitm_observe::FlowContext;
use mitm_policy::ProcessInfo as PolicyProcessInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFrameKind {
    SseData,
    NdjsonLine,
    GrpcMessage,
    WebSocketText,
    WebSocketBinary,
    WebSocketClose,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRequest {
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestDecision {
    Allow,
    Block { status: u16, body: Bytes },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamChunk {
    pub payload: Bytes,
    pub sequence: u64,
    pub frame_kind: StreamFrameKind,
}

pub trait FlowHooks: Send + Sync + 'static {
    fn resolve_process_info(
        &self,
        _context: FlowContext,
    ) -> Pin<Box<dyn Future<Output = Option<PolicyProcessInfo>> + Send>> {
        Box::pin(async { None })
    }

    fn should_intercept_tls(
        &self,
        _context: FlowContext,
    ) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        Box::pin(async { true })
    }

    fn on_tls_failure(
        &self,
        _context: FlowContext,
        _error: String,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {})
    }

    fn on_connection_open(
        &self,
        _context: FlowContext,
        _process_info: Option<PolicyProcessInfo>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {})
    }

    fn on_request(
        &self,
        _context: FlowContext,
        _request: RawRequest,
    ) -> Pin<Box<dyn Future<Output = RequestDecision> + Send>> {
        Box::pin(async { RequestDecision::Allow })
    }

    fn on_response(
        &self,
        _context: FlowContext,
        _response: RawResponse,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {})
    }

    fn on_stream_chunk(
        &self,
        _context: FlowContext,
        _chunk: StreamChunk,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {})
    }

    fn on_stream_end(&self, _context: FlowContext) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {})
    }
}

#[derive(Debug, Default)]
pub struct NoopFlowHooks;

impl FlowHooks for NoopFlowHooks {}
