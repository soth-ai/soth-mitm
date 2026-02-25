async fn bind_listener_with_socket_hardening(config: &SidecarConfig) -> io::Result<TcpListener> {
    let mut resolved = tokio::net::lookup_host((config.listen_addr.as_str(), config.listen_port))
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
    let listen_addr = resolved.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!(
                "no resolved socket address for {}:{}",
                config.listen_addr, config.listen_port
            ),
        )
    })?;

    let socket = if listen_addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    let _ = socket.set_reuseaddr(true);
    socket.bind(listen_addr)?;
    socket.listen(1024)
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
    use super::is_benign_socket_close_error;
    use std::io;

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
}
