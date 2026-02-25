async fn connect_via_route(route: &RouteBinding, intent: RouteConnectIntent) -> io::Result<TcpStream> {
    let mut stream =
        connect_with_upstream_timeout(&route.next_hop_host, route.next_hop_port, "upstream_connect")
            .await?;
    apply_per_connection_socket_hardening(&stream);
    match route.mode {
        mitm_core::RouteMode::Direct | mitm_core::RouteMode::Reverse => Ok(stream),
        mitm_core::RouteMode::UpstreamHttp => {
            if intent == RouteConnectIntent::TargetTunnel {
                establish_http_proxy_connect_tunnel(&mut stream, route).await?;
            }
            Ok(stream)
        }
        mitm_core::RouteMode::UpstreamSocks5 => {
            establish_socks5_connect_tunnel(&mut stream, route).await?;
            Ok(stream)
        }
    }
}

async fn establish_http_proxy_connect_tunnel(
    stream: &mut TcpStream,
    route: &RouteBinding,
) -> io::Result<()> {
    let connect = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: keep-alive\r\n\r\n",
        route.target_host, route.target_port, route.target_host, route.target_port
    );
    write_all_with_idle_timeout(
        stream,
        connect.as_bytes(),
        "upstream_http_proxy_connect_write",
    )
    .await?;

    let response_head = read_head_until_terminator(
        stream,
        "upstream_http_proxy_connect_read",
        MAX_PROXY_HEAD_BYTES,
    )
    .await?;
    let status = parse_proxy_status_code(&response_head)?;
    if (status / 100) != 2 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("upstream HTTP proxy CONNECT failed with status {status}"),
        ));
    }
    Ok(())
}

async fn establish_socks5_connect_tunnel(
    stream: &mut TcpStream,
    route: &RouteBinding,
) -> io::Result<()> {
    write_all_with_idle_timeout(stream, &[0x05, 0x01, 0x00], "upstream_socks5_greeting_write")
        .await?;

    let mut greeting = [0_u8; 2];
    read_exact_with_idle_timeout(stream, &mut greeting, "upstream_socks5_greeting_read").await?;
    if greeting[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("upstream SOCKS5 replied with invalid version {}", greeting[0]),
        ));
    }
    if greeting[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("upstream SOCKS5 requires unsupported auth method {}", greeting[1]),
        ));
    }

    let connect_request = build_socks5_connect_request(route)?;
    write_all_with_idle_timeout(
        stream,
        &connect_request,
        "upstream_socks5_connect_request_write",
    )
    .await?;

    let mut reply_header = [0_u8; 4];
    read_exact_with_idle_timeout(
        stream,
        &mut reply_header,
        "upstream_socks5_connect_reply_header_read",
    )
    .await?;
    if reply_header[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream SOCKS5 connect reply version mismatch {}",
                reply_header[0]
            ),
        ));
    }
    if reply_header[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "upstream SOCKS5 connect rejected: {}",
                socks5_reply_code_label(reply_header[1])
            ),
        ));
    }

    let mut trailing = match reply_header[3] {
        0x01 => vec![0_u8; 4 + 2],
        0x03 => {
            let mut len = [0_u8; 1];
            read_exact_with_idle_timeout(
                stream,
                &mut len,
                "upstream_socks5_connect_reply_domain_len_read",
            )
            .await?;
            vec![0_u8; (len[0] as usize) + 2]
        }
        0x04 => vec![0_u8; 16 + 2],
        atyp => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("upstream SOCKS5 connect reply ATYP {atyp} is unsupported"),
            ));
        }
    };
    read_exact_with_idle_timeout(
        stream,
        &mut trailing,
        "upstream_socks5_connect_reply_trailing_read",
    )
    .await?;
    Ok(())
}

fn build_socks5_connect_request(route: &RouteBinding) -> io::Result<Vec<u8>> {
    let mut request = vec![0x05, 0x01, 0x00];
    append_socks5_address(&mut request, &route.target_host)?;
    request.extend_from_slice(&route.target_port.to_be_bytes());
    Ok(request)
}

fn append_socks5_address(request: &mut Vec<u8>, host: &str) -> io::Result<()> {
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        match addr {
            std::net::IpAddr::V4(v4) => {
                request.push(0x01);
                request.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                request.push(0x04);
                request.extend_from_slice(&v6.octets());
            }
        }
        return Ok(());
    }

    if host.len() > (u8::MAX as usize) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target host length exceeds SOCKS5 domain limit",
        ));
    }
    request.push(0x03);
    request.push(host.len() as u8);
    request.extend_from_slice(host.as_bytes());
    Ok(())
}

fn socks5_reply_code_label(code: u8) -> &'static str {
    match code {
        0x01 => "general_failure",
        0x02 => "ruleset_blocked",
        0x03 => "network_unreachable",
        0x04 => "host_unreachable",
        0x05 => "connection_refused",
        0x06 => "ttl_expired",
        0x07 => "command_unsupported",
        0x08 => "address_type_unsupported",
        _ => "unknown",
    }
}

fn parse_proxy_status_code(head: &[u8]) -> io::Result<u16> {
    let text = std::str::from_utf8(head)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proxy response was not UTF-8"))?;
    let line = text
        .split("\r\n")
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proxy response was empty"))?;
    let mut parts = line.split_whitespace();
    let _http_version = parts.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "proxy status line missing version")
    })?;
    let status = parts.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "proxy status line missing status")
    })?;
    status.parse::<u16>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("proxy status code was invalid: {status}"),
        )
    })
}

async fn read_head_until_terminator(
    stream: &mut TcpStream,
    stage: &'static str,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        if out.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy response headers exceeded max bytes",
            ));
        }
        let read = read_with_idle_timeout(stream, &mut chunk, stage).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed before complete response headers",
            ));
        }
        out.extend_from_slice(&chunk[..read]);
        if out.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(out);
        }
    }
}

async fn read_exact_with_idle_timeout<R>(
    stream: &mut R,
    mut buffer: &mut [u8],
    stage: &'static str,
) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    while !buffer.is_empty() {
        let read = read_with_idle_timeout(stream, buffer, stage).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading exact bytes",
            ));
        }
        let (_, rest) = buffer.split_at_mut(read);
        buffer = rest;
    }
    Ok(())
}
