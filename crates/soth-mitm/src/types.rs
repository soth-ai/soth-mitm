use std::net::IpAddr;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use http::HeaderMap;
use uuid::Uuid;

/// Newtype wrapping a `u64` flow identifier for type-safe flow tracking.
///
/// # Examples
///
/// ```
/// use soth_mitm::FlowId;
///
/// let id = FlowId(42);
/// assert_eq!(id.as_u64(), 42);
/// assert_eq!(format!("{id}"), "42");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub struct FlowId(pub u64);

impl FlowId {
    /// Returns the inner `u64` value.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for FlowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl TlsVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tls12 => "tls1.2",
            Self::Tls13 => "tls1.3",
        }
    }
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRequest {
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub connection_meta: Arc<ConnectionMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub connection_meta: Arc<ConnectionMeta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    SseData,
    NdjsonLine,
    GrpcMessage,
    WebSocketText,
    WebSocketBinary,
    WebSocketClose,
}

impl FrameKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SseData => "sse_data",
            Self::NdjsonLine => "ndjson_line",
            Self::GrpcMessage => "grpc_message",
            Self::WebSocketText => "websocket_text",
            Self::WebSocketBinary => "websocket_binary",
            Self::WebSocketClose => "websocket_close",
        }
    }
}

impl std::fmt::Display for FrameKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamChunk {
    pub connection_id: Uuid,
    pub payload: Bytes,
    pub sequence: u64,
    pub frame_kind: FrameKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    pub sni: Option<String>,
    pub negotiated_proto: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionMeta {
    pub connection_id: Uuid,
    pub socket_family: SocketFamily,
    pub process_info: Option<ProcessInfo>,
    pub tls_info: Option<TlsInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketFamily {
    TcpV4 {
        local: SocketAddrV4,
        remote: SocketAddrV4,
    },
    TcpV6 {
        local: SocketAddrV6,
        remote: SocketAddrV6,
    },
    UnixDomain {
        path: Option<PathBuf>,
    },
}

impl SocketFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TcpV4 { .. } => "tcp_v4",
            Self::TcpV6 { .. } => "tcp_v6",
            Self::UnixDomain { .. } => "unix_domain",
        }
    }
}

impl std::fmt::Display for SocketFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub connection_id: Uuid,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_host: String,
    pub destination_port: u16,
    pub socket_family: SocketFamily,
    pub tls_fingerprint: Option<TlsClientFingerprint>,
    pub alpn_protocol: Option<String>,
    pub is_http2: bool,
    pub process_info: Option<ProcessInfo>,
    pub connected_at: SystemTime,
    pub request_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientFingerprint {
    pub ja4: String,
    pub ja3: String,
    pub tls_version: TlsVersion,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub bundle_id: Option<String>,
    pub exe_name: Option<String>,
    pub exe_path: Option<PathBuf>,
    pub parent_pid: Option<u32>,
    pub parent_process_name: Option<String>,
}
