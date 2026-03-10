use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use http::HeaderMap;
use crate::actions::HandlerDecision;
use crate::observe::FlowContext;
use crate::types::{FrameKind, ProcessInfo};

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
pub struct StreamChunk {
    pub payload: Bytes,
    pub sequence: u64,
    pub frame_kind: FrameKind,
}

pub trait FlowHooks: Send + Sync + 'static {
    fn resolve_process_info(
        &self,
        _context: FlowContext,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessInfo>> + Send>> {
        Box::pin(async { None })
    }

    fn should_intercept_tls(
        &self,
        _context: FlowContext,
        _process_info: Option<ProcessInfo>,
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
        _process_info: Option<ProcessInfo>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {})
    }

    fn on_request(
        &self,
        _context: FlowContext,
        _request: RawRequest,
    ) -> Pin<Box<dyn Future<Output = HandlerDecision> + Send>> {
        Box::pin(async { HandlerDecision::Allow })
    }

    fn on_request_observe(
        &self,
        _context: FlowContext,
        _request: RawRequest,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {})
    }

    fn on_response(
        &self,
        _context: FlowContext,
        _response: RawResponse,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {})
    }

    fn on_websocket_start(
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
