use std::net::IpAddr;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use http::HeaderMap;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
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
}
