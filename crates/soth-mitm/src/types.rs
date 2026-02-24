use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::HeaderMap;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptedRequest {
    pub method: String,
    pub path: String,
    pub version: HttpVersion,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub body_truncated: bool,
    pub body_original_size: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptedResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub is_streaming: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub connection_id: Uuid,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_host: String,
    pub destination_port: u16,
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
    pub process_name: String,
    pub process_path: PathBuf,
    pub bundle_id: Option<String>,
    pub code_signature: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionStats {
    pub request_count: u32,
    pub bytes_sent_upstream: u64,
    pub bytes_received_upstream: u64,
    pub duration: Duration,
}
