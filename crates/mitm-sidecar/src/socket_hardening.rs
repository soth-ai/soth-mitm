async fn bind_listener_with_socket_hardening(config: &SidecarConfig) -> io::Result<TcpListener> {
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

    let mut last_error: Option<io::Error> = None;
    for listen_addr in listen_addrs {
        match bind_single_listener_socket(listen_addr) {
            Ok(listener) => return Ok(listener),
            Err(error) => {
                last_error = Some(error);
            }
        }
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
    let _ = socket.set_reuseaddr(true);
    socket.bind(listen_addr)?;
    socket.listen(1024)
}

fn bind_dual_stack_listener_socket(listen_addr: std::net::SocketAddr) -> io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    let _ = socket.set_only_v6(false);
    socket.bind(&socket2::SockAddr::from(listen_addr))?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
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
async fn bind_unix_listener_with_socket_hardening(
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

fn apply_per_connection_socket_hardening(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}

fn is_benign_socket_close_error(error: &io::Error) -> bool {
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
    use super::{is_benign_socket_close_error, is_dual_stack_candidate, order_listen_addrs_for_dual_stack};
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
}
