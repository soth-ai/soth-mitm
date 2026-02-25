use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;

use mitm_http::ApplicationProtocol;
use mitm_observe::FlowContext;

use crate::runtime::connection_id::connection_id_for_flow_id;
use crate::types::{ConnectionInfo, ConnectionMeta, ProcessInfo, SocketFamily, TlsInfo};

pub(crate) fn connection_meta_from_accept_context(
    context: &FlowContext,
    process_info: Option<ProcessInfo>,
) -> ConnectionMeta {
    ConnectionMeta {
        connection_id: connection_id_for_flow_id(context.flow_id),
        socket_family: socket_family_from_flow_context(context),
        process_info,
        tls_info: tls_info_from_flow_context(context),
    }
}

pub(crate) fn socket_family_from_flow_context(context: &FlowContext) -> SocketFamily {
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

pub(crate) fn lookup_connection_info_from_flow_context(context: &FlowContext) -> ConnectionInfo {
    let socket_family = socket_family_from_flow_context(context);
    let (alpn_protocol, is_http2) = protocol_hints_from_flow_context(context);
    let (source_ip, source_port) = match &socket_family {
        SocketFamily::TcpV4 { local, .. } => (IpAddr::V4(*local.ip()), local.port()),
        SocketFamily::TcpV6 { local, .. } => (IpAddr::V6(*local.ip()), local.port()),
        SocketFamily::UnixDomain { .. } => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    ConnectionInfo {
        connection_id: connection_id_for_flow_id(context.flow_id),
        source_ip,
        source_port,
        destination_host: context.server_host.clone(),
        destination_port: context.server_port,
        socket_family,
        tls_fingerprint: None,
        alpn_protocol,
        is_http2,
        process_info: None,
        connected_at: std::time::SystemTime::now(),
        request_count: 0,
    }
}

pub(crate) fn tls_info_from_flow_context(context: &FlowContext) -> Option<TlsInfo> {
    const COMMON_TLS_PORTS: [u16; 4] = [443, 8443, 4433, 9443];
    let likely_tls = context.protocol == ApplicationProtocol::Http2
        || COMMON_TLS_PORTS.contains(&context.server_port);
    if !likely_tls {
        return None;
    }

    let sni = normalize_sni(&context.server_host);
    let negotiated_proto = match context.protocol {
        ApplicationProtocol::Http2 => Some("h2".to_string()),
        ApplicationProtocol::Http1
        | ApplicationProtocol::WebSocket
        | ApplicationProtocol::Sse
        | ApplicationProtocol::StreamableHttp => Some("http/1.1".to_string()),
        ApplicationProtocol::Tunnel => None,
    };

    if sni.is_none() && negotiated_proto.is_none() {
        None
    } else {
        Some(TlsInfo {
            sni,
            negotiated_proto,
        })
    }
}

fn protocol_hints_from_flow_context(context: &FlowContext) -> (Option<String>, bool) {
    match context.protocol {
        ApplicationProtocol::Http2 => (Some("h2".to_string()), true),
        ApplicationProtocol::Http1
        | ApplicationProtocol::WebSocket
        | ApplicationProtocol::Sse
        | ApplicationProtocol::StreamableHttp => (Some("http/1.1".to_string()), false),
        ApplicationProtocol::Tunnel => (None, false),
    }
}

fn normalize_sni(server_host: &str) -> Option<String> {
    let trimmed = server_host.trim();
    if trimmed.is_empty() || trimmed == "<unknown>" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(crate) fn policy_process_info_from_runtime(
    process_info: &ProcessInfo,
) -> mitm_policy::ProcessInfo {
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

pub(crate) fn runtime_process_info_from_policy(
    process_info: mitm_policy::ProcessInfo,
) -> ProcessInfo {
    ProcessInfo {
        pid: process_info.pid,
        bundle_id: process_info.bundle_id,
        exe_name: process_info.process_name,
        exe_path: None,
        parent_pid: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnixClientAddrMeta {
    pub(crate) pid: Option<u32>,
    pub(crate) path: Option<PathBuf>,
}

pub(crate) fn parse_unix_client_addr_meta(client_addr: &str) -> Option<UnixClientAddrMeta> {
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

pub(crate) fn process_info_from_unix_client_addr(client_addr: &str) -> Option<ProcessInfo> {
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
mod tests {
    use super::{lookup_connection_info_from_flow_context, tls_info_from_flow_context};
    use mitm_http::ApplicationProtocol;
    use mitm_observe::FlowContext;

    #[test]
    fn tls_info_is_populated_for_http2_context() {
        let context = FlowContext {
            flow_id: 7,
            client_addr: "127.0.0.1:5000".to_string(),
            server_host: "api.example.com".to_string(),
            server_port: 443,
            protocol: ApplicationProtocol::Http2,
        };
        let tls_info = tls_info_from_flow_context(&context).expect("tls info");
        assert_eq!(tls_info.sni.as_deref(), Some("api.example.com"));
        assert_eq!(tls_info.negotiated_proto.as_deref(), Some("h2"));
    }

    #[test]
    fn connection_info_protocol_hints_follow_flow_protocol() {
        let context = FlowContext {
            flow_id: 8,
            client_addr: "127.0.0.1:5001".to_string(),
            server_host: "api.example.com".to_string(),
            server_port: 443,
            protocol: ApplicationProtocol::Http2,
        };
        let info = lookup_connection_info_from_flow_context(&context);
        assert!(info.is_http2);
        assert_eq!(info.alpn_protocol.as_deref(), Some("h2"));
    }
}
