use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{ip_matches, push_unique_pid, select_unique_pid, SocketQuery};

#[derive(Debug, Clone, Copy)]
struct LinuxSocketEntry {
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    established: bool,
    inode: u64,
}

pub(super) fn lookup_established_tcp_pid_linux(query: SocketQuery) -> Option<u32> {
    let mut entries = linux_read_tcp_entries("/proc/net/tcp", false);
    entries.extend(linux_read_tcp_entries("/proc/net/tcp6", true));

    let mut fallback_inodes = Vec::new();

    for entry in entries {
        if !entry.established || entry.local_port != query.local_port {
            continue;
        }
        if !ip_matches(entry.local_ip, query.local_ip) {
            continue;
        }

        if entry.remote_port == query.remote_port && ip_matches(entry.remote_ip, query.remote_ip) {
            if let Some(pid) = linux_find_pid_by_inode(entry.inode) {
                return Some(pid);
            }
            continue;
        }

        if !fallback_inodes.contains(&entry.inode) {
            fallback_inodes.push(entry.inode);
        }
    }

    resolve_unique_linux_fallback_pid(fallback_inodes)
}

fn linux_read_tcp_entries(path: &str, is_v6: bool) -> Vec<LinuxSocketEntry> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    contents
        .lines()
        .skip(1)
        .filter_map(|line| linux_parse_tcp_entry(line, is_v6))
        .collect()
}

fn linux_parse_tcp_entry(line: &str, is_v6: bool) -> Option<LinuxSocketEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }

    let (local_ip, local_port) = linux_parse_socket_endpoint(fields[1], is_v6)?;
    let (remote_ip, remote_port) = linux_parse_socket_endpoint(fields[2], is_v6)?;
    let established = fields[3] == "01";
    let inode = fields[9].parse::<u64>().ok()?;

    Some(LinuxSocketEntry {
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        established,
        inode,
    })
}

fn linux_parse_socket_endpoint(value: &str, is_v6: bool) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = value.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if is_v6 {
        linux_parse_ipv6(addr_hex)?
    } else {
        linux_parse_ipv4(addr_hex)?
    };
    Some((ip, port))
}

fn linux_parse_ipv4(hex: &str) -> Option<IpAddr> {
    if hex.len() != 8 {
        return None;
    }
    let value = u32::from_str_radix(hex, 16).ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(value.to_le_bytes())))
}

fn linux_parse_ipv6(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }

    let mut octets = [0u8; 16];
    for index in 0..4 {
        let start = index * 8;
        let end = start + 8;
        let chunk = &hex[start..end];
        let word = u32::from_str_radix(chunk, 16).ok()?;
        octets[index * 4..(index + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}

fn linux_find_pid_by_inode(target_inode: u64) -> Option<u32> {
    for proc_entry in std::fs::read_dir("/proc").ok()? {
        let proc_entry = proc_entry.ok()?;
        let pid = proc_entry.file_name().to_str()?.parse::<u32>().ok()?;

        let fd_dir = proc_entry.path().join("fd");
        let Ok(fd_entries) = std::fs::read_dir(fd_dir) else {
            continue;
        };

        for fd_entry in fd_entries {
            let Ok(fd_entry) = fd_entry else {
                continue;
            };
            let Ok(link_target) = std::fs::read_link(fd_entry.path()) else {
                continue;
            };
            let link_text = link_target.to_string_lossy();
            if linux_parse_socket_inode(link_text.as_ref()) == Some(target_inode) {
                return Some(pid);
            }
        }
    }

    None
}

fn linux_parse_socket_inode(link_text: &str) -> Option<u64> {
    let prefix = "socket:[";
    let suffix = "]";
    if !link_text.starts_with(prefix) || !link_text.ends_with(suffix) {
        return None;
    }

    link_text[prefix.len()..link_text.len() - suffix.len()]
        .parse::<u64>()
        .ok()
}

fn resolve_unique_linux_fallback_pid(inodes: Vec<u64>) -> Option<u32> {
    let mut fallback_pids = Vec::new();
    for inode in inodes {
        let pid = linux_find_pid_by_inode(inode)?;
        push_unique_pid(&mut fallback_pids, pid);
        if fallback_pids.len() > 1 {
            return None;
        }
    }
    select_unique_pid(fallback_pids)
}
