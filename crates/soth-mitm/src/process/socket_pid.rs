use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::ConnectionInfo;
use crate::types::SocketFamily;

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
        return lookup_established_tcp_pid_macos(query);
    }

    #[cfg(target_os = "linux")]
    {
        return lookup_established_tcp_pid_linux(query);
    }

    #[cfg(target_os = "windows")]
    {
        return lookup_established_tcp_pid_windows(query);
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

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
struct LinuxSocketEntry {
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    established: bool,
    inode: u64,
}

#[cfg(target_os = "linux")]
fn lookup_established_tcp_pid_linux(query: SocketQuery) -> Option<u32> {
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn linux_parse_ipv4(hex: &str) -> Option<IpAddr> {
    if hex.len() != 8 {
        return None;
    }
    let value = u32::from_str_radix(hex, 16).ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(value.to_le_bytes())))
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "macos")]
fn lookup_established_tcp_pid_macos(query: SocketQuery) -> Option<u32> {
    let self_pid = std::process::id();
    let pids = macos_list_all_pids()?;
    let mut fallback_pids = Vec::new();

    for pid in pids {
        if pid == 0 || pid == self_pid {
            continue;
        }

        let Some(fds) = macos_list_process_fds(pid) else {
            continue;
        };

        for fd in fds {
            if fd.proc_fdtype != macos_native::PROX_FDTYPE_SOCKET {
                continue;
            }
            let Some(socket_info) = macos_socket_fdinfo(pid, fd.proc_fd) else {
                continue;
            };
            let Some((local_ip, local_port, remote_ip, remote_port)) =
                macos_extract_socket_endpoints(&socket_info)
            else {
                continue;
            };

            if local_port != query.local_port {
                continue;
            }
            if !ip_matches(local_ip, query.local_ip) {
                continue;
            }

            if remote_port == query.remote_port && ip_matches(remote_ip, query.remote_ip) {
                return Some(pid);
            }

            push_unique_pid(&mut fallback_pids, pid);
        }
    }

    select_unique_pid(fallback_pids)
}

#[cfg(target_os = "macos")]
fn macos_list_all_pids() -> Option<Vec<u32>> {
    use libc::{c_int, c_void};

    let mut capacity = 4096usize;
    loop {
        let mut pids = vec![0i32; capacity];
        // SAFETY: `pids` points to writable memory of the declared length.
        let count = unsafe {
            macos_native::proc_listallpids(
                pids.as_mut_ptr() as *mut c_void,
                (pids.len() * std::mem::size_of::<c_int>()) as c_int,
            )
        };
        if count <= 0 {
            return None;
        }

        if count as usize >= capacity {
            capacity = capacity.saturating_mul(2);
            continue;
        }

        pids.truncate(count as usize);
        return Some(
            pids.into_iter()
                .filter(|pid| *pid > 0)
                .map(|pid| pid as u32)
                .collect(),
        );
    }
}

#[cfg(target_os = "macos")]
fn macos_list_process_fds(pid: u32) -> Option<Vec<macos_native::ProcFdInfo>> {
    use libc::c_int;

    let mut capacity = 128usize;
    loop {
        let mut entries = vec![macos_native::ProcFdInfo::default(); capacity];
        // SAFETY: `entries` points to writable memory of the declared length.
        let written = unsafe {
            macos_native::proc_pidinfo(
                pid as c_int,
                macos_native::PROC_PIDLISTFDS,
                0,
                entries.as_mut_ptr().cast(),
                (entries.len() * std::mem::size_of::<macos_native::ProcFdInfo>()) as c_int,
            )
        };

        if written <= 0 {
            return None;
        }

        let count = written as usize / std::mem::size_of::<macos_native::ProcFdInfo>();
        if count >= capacity {
            capacity = capacity.saturating_mul(2);
            continue;
        }

        entries.truncate(count);
        return Some(entries);
    }
}

#[cfg(target_os = "macos")]
fn macos_socket_fdinfo(pid: u32, fd: i32) -> Option<macos_native::SocketFdInfoPrefix> {
    use libc::c_int;

    let mut raw = [0u8; 2048];
    // SAFETY: `raw` is a valid output buffer for the C API call.
    let written = unsafe {
        macos_native::proc_pidfdinfo(
            pid as c_int,
            fd,
            macos_native::PROC_PIDFDSOCKETINFO,
            raw.as_mut_ptr().cast(),
            raw.len() as c_int,
        )
    };

    if written < std::mem::size_of::<macos_native::SocketFdInfoPrefix>() as c_int {
        return None;
    }

    // SAFETY: `raw` has enough bytes for `SocketFdInfoPrefix` as checked above.
    Some(unsafe { (raw.as_ptr() as *const macos_native::SocketFdInfoPrefix).read_unaligned() })
}

#[cfg(target_os = "macos")]
fn macos_extract_socket_endpoints(
    info: &macos_native::SocketFdInfoPrefix,
) -> Option<(IpAddr, u16, IpAddr, u16)> {
    // SAFETY: Accessing union fields based on `soi_kind` tag.
    let sock = unsafe {
        match info.psi.soi_kind {
            macos_native::SOCKINFO_IN => info.psi.soi_proto.pri_in,
            macos_native::SOCKINFO_TCP => info.psi.soi_proto.pri_tcp.tcpsi_ini,
            _ => return None,
        }
    };

    let local_port = u16::from_be(sock.insi_lport as u16);
    if local_port == 0 {
        return None;
    }
    let remote_port = u16::from_be(sock.insi_fport as u16);

    if sock.insi_vflag & macos_native::INI_IPV4 != 0 {
        // SAFETY: Accessing IPv4 fields when INI_IPV4 is set.
        let local_addr = unsafe { sock.insi_laddr.ina_46.i46a_addr4.s_addr };
        // SAFETY: Accessing IPv4 fields when INI_IPV4 is set.
        let remote_addr = unsafe { sock.insi_faddr.ina_46.i46a_addr4.s_addr };
        return Some((
            IpAddr::V4(Ipv4Addr::from(u32::from_be(local_addr))),
            local_port,
            IpAddr::V4(Ipv4Addr::from(u32::from_be(remote_addr))),
            remote_port,
        ));
    }

    if sock.insi_vflag & macos_native::INI_IPV6 != 0 {
        // SAFETY: Accessing IPv6 fields when INI_IPV6 is set.
        let local_addr = unsafe { sock.insi_laddr.ina_6.s6_addr };
        // SAFETY: Accessing IPv6 fields when INI_IPV6 is set.
        let remote_addr = unsafe { sock.insi_faddr.ina_6.s6_addr };
        return Some((
            IpAddr::V6(Ipv6Addr::from(local_addr)),
            local_port,
            IpAddr::V6(Ipv6Addr::from(remote_addr)),
            remote_port,
        ));
    }

    None
}

#[cfg(target_os = "macos")]
mod macos_native {
    use libc::{c_int, c_void, gid_t, in6_addr, in_addr, off_t, uid_t, MAXCOMLEN};

    pub const PROC_PIDLISTFDS: c_int = 1;
    pub const PROC_PIDFDSOCKETINFO: c_int = 3;
    pub const PROX_FDTYPE_SOCKET: u32 = 2;
    pub const SOCKINFO_IN: i32 = 1;
    pub const SOCKINFO_TCP: i32 = 2;
    pub const INI_IPV4: u8 = 0x1;
    pub const INI_IPV6: u8 = 0x2;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct ProcFdInfo {
        pub proc_fd: i32,
        pub proc_fdtype: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct ProcFileInfo {
        pub fi_openflags: u32,
        pub fi_status: u32,
        pub fi_offset: off_t,
        pub fi_type: i32,
        pub fi_guardflags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct VinfoStat {
        pub vst_dev: u32,
        pub vst_mode: u16,
        pub vst_nlink: u16,
        pub vst_ino: u64,
        pub vst_uid: uid_t,
        pub vst_gid: gid_t,
        pub vst_atime: i64,
        pub vst_atimensec: i64,
        pub vst_mtime: i64,
        pub vst_mtimensec: i64,
        pub vst_ctime: i64,
        pub vst_ctimensec: i64,
        pub vst_birthtime: i64,
        pub vst_birthtimensec: i64,
        pub vst_size: off_t,
        pub vst_blocks: i64,
        pub vst_blksize: i32,
        pub vst_flags: u32,
        pub vst_gen: u32,
        pub vst_rdev: u32,
        pub vst_qspare: [i64; 2],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct SockbufInfo {
        pub sbi_cc: u32,
        pub sbi_hiwat: u32,
        pub sbi_mbcnt: u32,
        pub sbi_mbmax: u32,
        pub sbi_lowat: u32,
        pub sbi_flags: i16,
        pub sbi_timeo: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct In4In6Addr {
        pub i46a_pad32: [u32; 3],
        pub i46a_addr4: in_addr,
    }

    impl Default for In4In6Addr {
        fn default() -> Self {
            Self {
                i46a_pad32: [0; 3],
                i46a_addr4: in_addr { s_addr: 0 },
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union InSockAddrUnion {
        pub ina_46: In4In6Addr,
        pub ina_6: in6_addr,
    }

    impl Default for InSockAddrUnion {
        fn default() -> Self {
            Self {
                ina_46: In4In6Addr::default(),
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct InSockInfo {
        pub insi_fport: i32,
        pub insi_lport: i32,
        pub insi_gencnt: u64,
        pub insi_flags: u32,
        pub insi_flow: u32,
        pub insi_vflag: u8,
        pub insi_ip_ttl: u8,
        pub rfu_1: u32,
        pub insi_faddr: InSockAddrUnion,
        pub insi_laddr: InSockAddrUnion,
        pub insi_v4: InSockInfoV4,
        pub insi_v6: InSockInfoV6,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct InSockInfoV4 {
        pub in4_tos: u8,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct InSockInfoV6 {
        pub in6_hlim: u8,
        pub in6_cksum: i32,
        pub in6_ifindex: u16,
        pub in6_hops: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct TcpSockInfo {
        pub tcpsi_ini: InSockInfo,
        pub tcpsi_state: i32,
        pub tcpsi_timer: [i32; 4],
        pub tcpsi_mss: i32,
        pub tcpsi_flags: u32,
        pub rfu_1: u32,
        pub tcpsi_tp: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union SocketProtoPrefix {
        pub pri_in: InSockInfo,
        pub pri_tcp: TcpSockInfo,
    }

    impl Default for SocketProtoPrefix {
        fn default() -> Self {
            Self {
                pri_in: InSockInfo::default(),
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct SocketInfoPrefix {
        pub soi_stat: VinfoStat,
        pub soi_so: u64,
        pub soi_pcb: u64,
        pub soi_type: i32,
        pub soi_protocol: i32,
        pub soi_family: i32,
        pub soi_options: i16,
        pub soi_linger: i16,
        pub soi_state: i16,
        pub soi_qlen: i16,
        pub soi_incqlen: i16,
        pub soi_qlimit: i16,
        pub soi_timeo: i16,
        pub soi_error: u16,
        pub soi_oobmark: u32,
        pub soi_rcv: SockbufInfo,
        pub soi_snd: SockbufInfo,
        pub soi_kind: i32,
        pub rfu_1: u32,
        pub soi_proto: SocketProtoPrefix,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct SocketFdInfoPrefix {
        pub pfi: ProcFileInfo,
        pub psi: SocketInfoPrefix,
    }

    unsafe extern "C" {
        pub fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int;
        pub fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
        pub fn proc_pidfdinfo(
            pid: c_int,
            fd: c_int,
            flavor: c_int,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
    }

    #[allow(dead_code)]
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ProcBsdInfo {
        pub pbi_flags: u32,
        pub pbi_status: u32,
        pub pbi_xstatus: u32,
        pub pbi_pid: u32,
        pub pbi_ppid: u32,
        pub pbi_uid: uid_t,
        pub pbi_gid: gid_t,
        pub pbi_ruid: uid_t,
        pub pbi_rgid: gid_t,
        pub pbi_svuid: uid_t,
        pub pbi_svgid: gid_t,
        pub rfu_1: u32,
        pub pbi_comm: [i8; MAXCOMLEN as usize],
        pub pbi_name: [i8; (2 * MAXCOMLEN) as usize],
        pub pbi_nfiles: u32,
        pub pbi_pgid: u32,
        pub pbi_pjobc: u32,
        pub e_tdev: u32,
        pub e_tpgid: u32,
        pub pbi_nice: i32,
        pub pbi_start_tvsec: u64,
        pub pbi_start_tvusec: u64,
    }
}

#[cfg(target_os = "windows")]
fn lookup_established_tcp_pid_windows(query: SocketQuery) -> Option<u32> {
    let mut candidate_pids = Vec::new();

    for row in windows_query_tcp4_rows().unwrap_or_default() {
        if row.dw_state != windows_native::MIB_TCP_STATE_ESTAB {
            continue;
        }
        let local_port = u16::from_be(row.dw_local_port as u16);
        if local_port != query.local_port {
            continue;
        }

        let local_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dw_local_addr)));
        let remote_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dw_remote_addr)));
        let remote_port = u16::from_be(row.dw_remote_port as u16);

        if ip_matches(local_ip, query.local_ip) {
            if remote_port == query.remote_port && ip_matches(remote_ip, query.remote_ip) {
                return Some(row.dw_owning_pid);
            }
            push_unique_pid(&mut candidate_pids, row.dw_owning_pid);
        }
    }

    for row in windows_query_tcp6_rows().unwrap_or_default() {
        if row.dw_state != windows_native::MIB_TCP_STATE_ESTAB {
            continue;
        }
        let local_port = u16::from_be(row.dw_local_port as u16);
        if local_port != query.local_port {
            continue;
        }

        let local_ip = IpAddr::V6(Ipv6Addr::from(row.uc_local_addr));
        let remote_ip = IpAddr::V6(Ipv6Addr::from(row.uc_remote_addr));
        let remote_port = u16::from_be(row.dw_remote_port as u16);

        if ip_matches(local_ip, query.local_ip) {
            if remote_port == query.remote_port && ip_matches(remote_ip, query.remote_ip) {
                return Some(row.dw_owning_pid);
            }
            push_unique_pid(&mut candidate_pids, row.dw_owning_pid);
        }
    }

    select_unique_pid(candidate_pids)
}

#[cfg(target_os = "windows")]
fn windows_query_tcp4_rows() -> Option<Vec<windows_native::MibTcpRowOwnerPid>> {
    windows_query_tcp_table::<windows_native::MibTcpRowOwnerPid>(windows_native::AF_INET)
}

#[cfg(target_os = "windows")]
fn windows_query_tcp6_rows() -> Option<Vec<windows_native::MibTcp6RowOwnerPid>> {
    windows_query_tcp_table::<windows_native::MibTcp6RowOwnerPid>(windows_native::AF_INET6)
}

#[cfg(target_os = "windows")]
fn windows_query_tcp_table<Row: Copy>(address_family: u32) -> Option<Vec<Row>> {
    let mut size: u32 = 0;
    // SAFETY: Initial query with null buffer asks API for required size.
    let mut result = unsafe {
        windows_native::GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            address_family,
            windows_native::TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != windows_native::ERROR_INSUFFICIENT_BUFFER && result != windows_native::NO_ERROR {
        return None;
    }

    if size == 0 {
        return Some(Vec::new());
    }

    let mut buffer = vec![0u8; size as usize];
    // SAFETY: Buffer is allocated with reported size and writable.
    result = unsafe {
        windows_native::GetExtendedTcpTable(
            buffer.as_mut_ptr().cast(),
            &mut size,
            0,
            address_family,
            windows_native::TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if result != windows_native::NO_ERROR {
        return None;
    }

    if buffer.len() < std::mem::size_of::<u32>() {
        return None;
    }

    // SAFETY: Checked that buffer contains at least a u32 element count.
    let entry_count = unsafe { (buffer.as_ptr() as *const u32).read_unaligned() } as usize;
    let row_offset = std::mem::size_of::<u32>();
    let row_size = std::mem::size_of::<Row>();
    let required = row_offset.checked_add(entry_count.checked_mul(row_size)?)?;
    if required > buffer.len() {
        return None;
    }

    let mut rows = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let start = row_offset + index * row_size;
        // SAFETY: Bounds checked above for each fixed-size row read.
        let row = unsafe { (buffer.as_ptr().add(start) as *const Row).read_unaligned() };
        rows.push(row);
    }

    Some(rows)
}

#[cfg(target_os = "windows")]
mod windows_native {
    use std::ffi::c_void;

    pub const AF_INET: u32 = 2;
    pub const AF_INET6: u32 = 23;

    pub const TCP_TABLE_OWNER_PID_ALL: u32 = 5;

    pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    pub const NO_ERROR: u32 = 0;
    pub const MIB_TCP_STATE_ESTAB: u32 = 5;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct MibTcpRowOwnerPid {
        pub dw_state: u32,
        pub dw_local_addr: u32,
        pub dw_local_port: u32,
        pub dw_remote_addr: u32,
        pub dw_remote_port: u32,
        pub dw_owning_pid: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct MibTcp6RowOwnerPid {
        pub uc_local_addr: [u8; 16],
        pub dw_local_scope_id: u32,
        pub dw_local_port: u32,
        pub uc_remote_addr: [u8; 16],
        pub dw_remote_scope_id: u32,
        pub dw_remote_port: u32,
        pub dw_state: u32,
        pub dw_owning_pid: u32,
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        pub fn GetExtendedTcpTable(
            tcp_table: *mut c_void,
            tcp_table_size: *mut u32,
            order: i32,
            address_family: u32,
            table_class: u32,
            reserved: u32,
        ) -> u32;
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
