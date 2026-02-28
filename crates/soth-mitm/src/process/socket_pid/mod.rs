use std::net::IpAddr;

use super::ConnectionInfo;
use crate::types::SocketFamily;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[derive(Debug, Clone, Copy)]
struct SocketQuery {
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

impl SocketQuery {
    fn from_connection(connection: &ConnectionInfo) -> Option<Self> {
        match connection.socket_family {
            SocketFamily::TcpV4 { local, remote } => Some(Self {
                local_ip: IpAddr::V4(*local.ip()),
                local_port: local.port(),
                remote_ip: IpAddr::V4(*remote.ip()),
                remote_port: remote.port(),
            }),
            SocketFamily::TcpV6 { local, remote } => Some(Self {
                local_ip: IpAddr::V6(*local.ip()),
                local_port: local.port(),
                remote_ip: IpAddr::V6(*remote.ip()),
                remote_port: remote.port(),
            }),
            SocketFamily::UnixDomain { .. } => None,
        }
    }
}

pub(crate) fn lookup_established_tcp_pid(connection: &ConnectionInfo) -> Option<u32> {
    let query = SocketQuery::from_connection(connection)?;

    #[cfg(target_os = "macos")]
    {
        return macos::lookup_established_tcp_pid_macos(query);
    }

    #[cfg(target_os = "linux")]
    {
        return linux::lookup_established_tcp_pid_linux(query);
    }

    #[cfg(target_os = "windows")]
    {
        return windows::lookup_established_tcp_pid_windows(query);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = query;
        None
    }
}

fn ip_matches(candidate: IpAddr, expected: IpAddr) -> bool {
    if candidate == expected || is_unspecified_ip(expected) {
        return true;
    }

    match (candidate, expected) {
        (IpAddr::V6(v6), IpAddr::V4(v4)) | (IpAddr::V4(v4), IpAddr::V6(v6)) => {
            v6.to_ipv4().map(|mapped| mapped == v4).unwrap_or(false)
        }
        _ => false,
    }
}

fn is_unspecified_ip(value: IpAddr) -> bool {
    match value {
        IpAddr::V4(ip) => ip.is_unspecified(),
        IpAddr::V6(ip) => ip.is_unspecified(),
    }
}

fn push_unique_pid(candidates: &mut Vec<u32>, pid: u32) {
    if !candidates.contains(&pid) {
        candidates.push(pid);
    }
}

fn select_unique_pid(candidates: Vec<u32>) -> Option<u32> {
    if candidates.len() == 1 {
        Some(candidates[0])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{ip_matches, select_unique_pid};

    #[test]
    fn ip_match_requires_exact_value_when_expected_is_not_unspecified() {
        assert!(ip_matches(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
        assert!(!ip_matches(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        ));
    }

    #[test]
    fn unspecified_expected_ip_matches_any_candidate() {
        assert!(ip_matches(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        ));
        assert!(ip_matches(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        ));
    }

    #[test]
    fn ipv4_mapped_ipv6_comparison_is_supported() {
        let mapped = IpAddr::V6(Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped());
        assert!(ip_matches(mapped, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn unique_pid_selection_rejects_ambiguous_candidates() {
        assert_eq!(select_unique_pid(vec![10, 20]), None);
    }

    #[test]
    fn unique_pid_selection_accepts_single_candidate() {
        assert_eq!(select_unique_pid(vec![42]), Some(42));
    }
}
