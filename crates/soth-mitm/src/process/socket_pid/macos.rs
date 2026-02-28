use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{ip_matches, push_unique_pid, select_unique_pid, SocketQuery};

pub(super) fn lookup_established_tcp_pid_macos(query: SocketQuery) -> Option<u32> {
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
