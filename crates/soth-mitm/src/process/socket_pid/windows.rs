use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{ip_matches, push_unique_pid, select_unique_pid, SocketQuery};

pub(super) fn lookup_established_tcp_pid_windows(query: SocketQuery) -> Option<u32> {
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

fn windows_query_tcp4_rows() -> Option<Vec<windows_native::MibTcpRowOwnerPid>> {
    windows_query_tcp_table::<windows_native::MibTcpRowOwnerPid>(windows_native::AF_INET)
}

fn windows_query_tcp6_rows() -> Option<Vec<windows_native::MibTcp6RowOwnerPid>> {
    windows_query_tcp_table::<windows_native::MibTcp6RowOwnerPid>(windows_native::AF_INET6)
}

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
