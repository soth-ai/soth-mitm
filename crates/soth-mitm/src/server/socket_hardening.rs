use super::SidecarConfig;
use std::io;
use tokio::net::{TcpListener, TcpStream};

pub(crate) async fn bind_listener_with_socket_hardening(
    config: &SidecarConfig,
) -> io::Result<TcpListener> {
    const LISTENER_BIND_RETRY_ATTEMPTS: u32 = 8;

    let resolved = tokio::net::lookup_host((config.listen_addr.as_str(), config.listen_port))
        .await
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "failed to resolve listen address {}:{}: {error}",
                    config.listen_addr, config.listen_port
                ),
            )
        })?;
    let mut listen_addrs: Vec<std::net::SocketAddr> = resolved.collect();
    if listen_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!(
                "no resolved socket address for {}:{}",
                config.listen_addr, config.listen_port
            ),
        ));
    }
    order_listen_addrs_for_dual_stack(&mut listen_addrs);

    let retry_delay = std::time::Duration::from_millis(config.accept_retry_backoff_ms.max(1));
    let mut last_error: Option<io::Error> = None;
    for attempt in 1..=LISTENER_BIND_RETRY_ATTEMPTS {
        let mut saw_retryable_error = false;
        for listen_addr in listen_addrs.iter().copied() {
            match bind_single_listener_socket(listen_addr) {
                Ok(listener) => return Ok(listener),
                Err(error) => {
                    if should_retry_listener_bind(&error) {
                        saw_retryable_error = true;
                    }
                    last_error = Some(error);
                }
            }
        }

        if !saw_retryable_error || attempt >= LISTENER_BIND_RETRY_ATTEMPTS {
            break;
        }
        tracing::warn!(
            listen_addr = %config.listen_addr,
            listen_port = config.listen_port,
            attempt,
            max_attempts = LISTENER_BIND_RETRY_ATTEMPTS,
            backoff_ms = retry_delay.as_millis() as u64,
            "transient listener bind failure; retrying"
        );
        tokio::time::sleep(retry_delay).await;
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!(
                "failed to bind resolved socket addresses for {}:{}",
                config.listen_addr, config.listen_port
            ),
        )
    }))
}

fn should_retry_listener_bind(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse
    )
}

fn bind_single_listener_socket(listen_addr: std::net::SocketAddr) -> io::Result<TcpListener> {
    if is_dual_stack_candidate(&listen_addr) {
        match bind_dual_stack_listener_socket(listen_addr) {
            Ok(listener) => return Ok(listener),
            Err(error) => {
                tracing::debug!(
                    addr = %listen_addr,
                    error = %error,
                    "dual-stack bind path failed; falling back to default bind"
                );
            }
        }
    }
    bind_listener_with_tokio_socket(listen_addr)
}

fn bind_listener_with_tokio_socket(listen_addr: std::net::SocketAddr) -> io::Result<TcpListener> {
    let socket = if listen_addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    // Unix: SO_REUSEADDR is required to rebind past TIME_WAIT sockets and is
    // safe (it cannot bind over a live listener). Windows: SO_REUSEADDR means
    // "allow binding over an actively listening socket" (port stealing) —
    // during supervisor child rotation that produced two listeners on the
    // same port with nondeterministic delivery. Use SO_EXCLUSIVEADDRUSE
    // instead so a conflicting bind fails deterministically with AddrInUse,
    // which the retry loop above handles.
    #[cfg(not(windows))]
    let _ = socket.set_reuseaddr(true);
    #[cfg(windows)]
    set_exclusive_addr_use(&socket);
    socket.bind(listen_addr)?;
    socket.listen(1024)
}

fn bind_dual_stack_listener_socket(listen_addr: std::net::SocketAddr) -> io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    // See bind_listener_with_tokio_socket for the platform split rationale.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    #[cfg(windows)]
    set_exclusive_addr_use(&socket);
    let _ = socket.set_only_v6(false);
    socket.bind(&socket2::SockAddr::from(listen_addr))?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// Set SO_EXCLUSIVEADDRUSE (best-effort). socket2 0.5 does not expose this
/// option, so call `setsockopt` directly. Failure is non-fatal: the socket
/// still binds with default (non-stealable-by-default) semantics.
#[cfg(windows)]
fn set_exclusive_addr_use<S: std::os::windows::io::AsRawSocket>(socket: &S) {
    // Values from winsock2.h: SOL_SOCKET = 0xFFFF,
    // SO_EXCLUSIVEADDRUSE = ((int)(~SO_REUSEADDR)) with SO_REUSEADDR = 0x0004.
    const SOL_SOCKET: i32 = 0xFFFF;
    const SO_EXCLUSIVEADDRUSE: i32 = !0x0004;
    #[link(name = "ws2_32")]
    extern "system" {
        fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
    }
    let enable: i32 = 1;
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            std::ptr::addr_of!(enable).cast(),
            std::mem::size_of::<i32>() as i32,
        )
    };
    if result != 0 {
        tracing::warn!("failed to set SO_EXCLUSIVEADDRUSE on listener socket (non-fatal)");
    }
}

fn is_dual_stack_candidate(listen_addr: &std::net::SocketAddr) -> bool {
    matches!(listen_addr, std::net::SocketAddr::V6(v6) if v6.ip().is_unspecified())
}

fn order_listen_addrs_for_dual_stack(listen_addrs: &mut [std::net::SocketAddr]) {
    fn priority(addr: &std::net::SocketAddr) -> u8 {
        match addr {
            std::net::SocketAddr::V6(v6) if v6.ip().is_unspecified() => 0,
            std::net::SocketAddr::V4(v4) if v4.ip().is_unspecified() => 1,
            std::net::SocketAddr::V6(_) => 2,
            std::net::SocketAddr::V4(_) => 3,
        }
    }
    listen_addrs.sort_by_key(priority);
}

#[cfg(unix)]
pub(crate) async fn bind_unix_listener_with_socket_hardening(
    socket_path: &str,
) -> io::Result<tokio::net::UnixListener> {
    let path = std::path::Path::new(socket_path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    tokio::net::UnixListener::bind(path)
}

/// Apply TCP keepalive + no-delay to a downstream (client-facing) connection.
/// Keepalive on the downstream side is what reaps a client that vanished
/// without a RST — sleep/hibernate, Wi-Fi→cellular handoff, radio drop. Until
/// this was added, only upstream sockets had keepalive, so a disappeared
/// client left its flow (and, on intercepted h2, a runtime permit) pinned
/// until the multi-minute idle watchdog fired. Same 15s/5s cadence as
/// upstream so both directions detect a dead peer on the same timescale.
pub(crate) fn apply_per_connection_socket_hardening(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    apply_tcp_keepalive(stream);
}

/// Apply TCP keepalive and no-delay to upstream connections.
/// Keepalive detects dead connections that the remote closed without
/// sending a TCP RST (e.g., server-side idle timeout, LB eviction) — and,
/// on flaky links (hotspot handoffs), sockets whose gateway silently
/// vanished. This must work on every platform: without it, a half-open
/// upstream socket hangs until the idle watchdog (minutes) instead of
/// erroring within ~keepalive time.
pub(crate) fn apply_upstream_socket_hardening(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    apply_tcp_keepalive(stream);
}

/// Set a 15s-idle / 5s-interval TCP keepalive on a live tokio `TcpStream`,
/// cross-platform. Best-effort (errors ignored). Uses `mem::forget` so the
/// borrowed `socket2::Socket` view doesn't close the underlying fd/socket.
fn apply_tcp_keepalive(stream: &TcpStream) {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(15))
        .with_interval(std::time::Duration::from_secs(5));
    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let fd = stream.as_raw_fd();
        let socket = unsafe { socket2::Socket::from_raw_fd(fd) };
        let _ = socket.set_tcp_keepalive(&keepalive);
        std::mem::forget(socket);
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};
        let raw = stream.as_raw_socket();
        let socket = unsafe { socket2::Socket::from_raw_socket(raw) };
        let _ = socket.set_tcp_keepalive(&keepalive);
        std::mem::forget(socket);
    }
}

pub(crate) fn is_benign_socket_close_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
    )
}

#[cfg(test)]
mod socket_hardening_tests {
    use super::{
        is_benign_socket_close_error, is_dual_stack_candidate, order_listen_addrs_for_dual_stack,
        should_retry_listener_bind,
    };
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn benign_socket_close_error_kinds_are_classified() {
        assert!(is_benign_socket_close_error(&io::Error::new(
            io::ErrorKind::NotConnected,
            "not connected",
        )));
        assert!(is_benign_socket_close_error(&io::Error::new(
            io::ErrorKind::ConnectionReset,
            "reset",
        )));
        assert!(!is_benign_socket_close_error(&io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid",
        )));
    }

    #[test]
    fn dual_stack_listener_prefers_ipv6_unspecified_first() {
        let mut addrs = vec![
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 8080, 0, 0)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8080)),
        ];
        order_listen_addrs_for_dual_stack(&mut addrs);
        assert!(matches!(addrs[0], SocketAddr::V6(v6) if v6.ip().is_unspecified()));
        assert!(matches!(addrs[1], SocketAddr::V4(v4) if v4.ip().is_unspecified()));
    }

    #[test]
    fn dual_stack_candidate_only_matches_ipv6_unspecified() {
        let ipv6_unspecified = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 8080, 0, 0));
        let ipv6_loopback = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0));
        let ipv4_unspecified = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8080));
        assert!(is_dual_stack_candidate(&ipv6_unspecified));
        assert!(!is_dual_stack_candidate(&ipv6_loopback));
        assert!(!is_dual_stack_candidate(&ipv4_unspecified));
    }

    #[test]
    fn bind_retry_classifier_only_marks_transient_bind_errors() {
        assert!(should_retry_listener_bind(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "operation not permitted",
        )));
        assert!(should_retry_listener_bind(&io::Error::new(
            io::ErrorKind::AddrInUse,
            "address in use",
        )));
        assert!(!should_retry_listener_bind(&io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid address",
        )));
    }
}
