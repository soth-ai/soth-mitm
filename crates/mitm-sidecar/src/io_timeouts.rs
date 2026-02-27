const IDLE_TIMEOUT_ERROR_PREFIX: &str = "idle_watchdog_timeout";
const STREAM_STAGE_TIMEOUT_ERROR_PREFIX: &str = "stream_stage_timeout";
const HAPPY_EYEBALLS_STAGGER: std::time::Duration = std::time::Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IoTimeoutConfig {
    idle_watchdog_timeout: std::time::Duration,
    upstream_connect_timeout: std::time::Duration,
    stream_stage_timeout: std::time::Duration,
}

impl Default for IoTimeoutConfig {
    fn default() -> Self {
        Self {
            idle_watchdog_timeout: std::time::Duration::from_secs(30),
            upstream_connect_timeout: std::time::Duration::from_secs(10),
            stream_stage_timeout: std::time::Duration::from_secs(5),
        }
    }
}

static IO_TIMEOUT_CONFIG: std::sync::OnceLock<std::sync::Mutex<IoTimeoutConfig>> =
    std::sync::OnceLock::new();

fn io_timeout_config() -> IoTimeoutConfig {
    *IO_TIMEOUT_CONFIG
        .get_or_init(|| std::sync::Mutex::new(IoTimeoutConfig::default()))
        .lock()
        .expect("io timeout config lock poisoned")
}

fn timeout_error(prefix: &str, stage: &'static str, timeout: std::time::Duration) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{prefix}:{stage}:{}ms", timeout.as_millis()),
    )
}

fn ignored_shutdown_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
    )
}

fn as_non_zero_duration(
    duration: std::time::Duration,
    fallback: std::time::Duration,
) -> std::time::Duration {
    if duration.is_zero() {
        fallback
    } else {
        duration
    }
}

fn ensure_bounded_timeout(timeout: std::time::Duration) -> std::time::Duration {
    as_non_zero_duration(timeout, std::time::Duration::from_millis(1))
}

fn install_io_timeout_config(
    idle_watchdog_timeout: std::time::Duration,
    upstream_connect_timeout: std::time::Duration,
    stream_stage_timeout: std::time::Duration,
) {
    let config = IoTimeoutConfig {
        idle_watchdog_timeout: ensure_bounded_timeout(idle_watchdog_timeout),
        upstream_connect_timeout: ensure_bounded_timeout(upstream_connect_timeout),
        stream_stage_timeout: ensure_bounded_timeout(stream_stage_timeout),
    };
    let mut guard = IO_TIMEOUT_CONFIG
        .get_or_init(|| std::sync::Mutex::new(IoTimeoutConfig::default()))
        .lock()
        .expect("io timeout config lock poisoned");
    *guard = config;
}

async fn connect_with_upstream_timeout(
    host: &str,
    port: u16,
    stage: &'static str,
) -> std::io::Result<tokio::net::TcpStream> {
    let timeout = io_timeout_config().upstream_connect_timeout;
    let deadline = tokio::time::Instant::now() + timeout;

    let connect_result = connect_with_happy_eyeballs(host, port, deadline).await;
    if is_connect_timeout_error(&connect_result) {
        runtime_governor::mark_stream_stage_timeout_global();
        runtime_governor::mark_stuck_flow_global();
        return Err(timeout_error(STREAM_STAGE_TIMEOUT_ERROR_PREFIX, stage, timeout));
    }
    connect_result
}

fn is_connect_timeout_error(result: &std::io::Result<tokio::net::TcpStream>) -> bool {
    matches!(result, Err(error) if error.kind() == std::io::ErrorKind::TimedOut)
}

async fn connect_with_happy_eyeballs(
    host: &str,
    port: u16,
    deadline: tokio::time::Instant,
) -> std::io::Result<tokio::net::TcpStream> {
    let addrs = resolve_upstream_socket_addrs(host, port, deadline).await?;
    connect_with_happy_eyeballs_addrs(addrs, deadline).await
}

async fn resolve_upstream_socket_addrs(
    host: &str,
    port: u16,
    deadline: tokio::time::Instant,
) -> std::io::Result<Vec<std::net::SocketAddr>> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "upstream address resolution timed out",
        ));
    }

    let resolved = tokio::time::timeout(remaining, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream address resolution timed out",
            )
        })?
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("upstream address resolution failed: {error}"),
            )
        })?;

    let addrs = interleave_happy_eyeballs_addrs(resolved.collect());
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "upstream address resolution returned no socket addresses",
        ));
    }
    Ok(addrs)
}

fn interleave_happy_eyeballs_addrs(
    addrs: Vec<std::net::SocketAddr>,
) -> Vec<std::net::SocketAddr> {
    let mut ipv4 = std::collections::VecDeque::new();
    let mut ipv6 = std::collections::VecDeque::new();
    for addr in addrs {
        if addr.is_ipv6() {
            ipv6.push_back(addr);
        } else {
            ipv4.push_back(addr);
        }
    }

    let prefer_ipv6 = !ipv6.is_empty();
    let mut ordered = Vec::with_capacity(ipv4.len() + ipv6.len());
    while !ipv4.is_empty() || !ipv6.is_empty() {
        if prefer_ipv6 {
            if let Some(addr) = ipv6.pop_front() {
                ordered.push(addr);
            }
            if let Some(addr) = ipv4.pop_front() {
                ordered.push(addr);
            }
        } else {
            if let Some(addr) = ipv4.pop_front() {
                ordered.push(addr);
            }
            if let Some(addr) = ipv6.pop_front() {
                ordered.push(addr);
            }
        }
    }
    ordered
}

async fn connect_with_happy_eyeballs_addrs(
    addrs: Vec<std::net::SocketAddr>,
    deadline: tokio::time::Instant,
) -> std::io::Result<tokio::net::TcpStream> {
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no upstream addresses provided",
        ));
    }

    let mut connect_tasks = tokio::task::JoinSet::new();
    let mut start_at = tokio::time::Instant::now();
    for addr in addrs {
        let attempt_start = start_at;
        connect_tasks.spawn(async move {
            if tokio::time::Instant::now() < attempt_start {
                tokio::time::sleep_until(attempt_start).await;
            }
            tokio::net::TcpStream::connect(addr).await
        });
        start_at = start_at
            .checked_add(HAPPY_EYEBALLS_STAGGER)
            .unwrap_or(start_at);
    }

    let mut last_error: Option<std::io::Error> = None;
    while !connect_tasks.is_empty() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            connect_tasks.abort_all();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream connect timed out",
            ));
        }
        match tokio::time::timeout(remaining, connect_tasks.join_next()).await {
            Ok(Some(Ok(Ok(stream)))) => {
                connect_tasks.abort_all();
                return Ok(stream);
            }
            Ok(Some(Ok(Err(error)))) => {
                last_error = Some(error);
            }
            Ok(Some(Err(join_error))) => {
                last_error = Some(std::io::Error::other(format!(
                    "upstream connect attempt join failed: {join_error}"
                )));
            }
            Ok(None) => break,
            Err(_) => {
                connect_tasks.abort_all();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "upstream connect timed out",
                ));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "all upstream connect attempts failed",
        )
    }))
}

fn is_idle_watchdog_timeout(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::TimedOut
        && error
            .to_string()
            .starts_with(IDLE_TIMEOUT_ERROR_PREFIX)
}

fn is_stream_stage_timeout(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::TimedOut
        && error
            .to_string()
            .starts_with(STREAM_STAGE_TIMEOUT_ERROR_PREFIX)
}

async fn read_with_idle_timeout<R>(
    stream: &mut R,
    buf: &mut [u8],
    stage: &'static str,
) -> std::io::Result<usize>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let timeout = io_timeout_config().idle_watchdog_timeout;
    match tokio::time::timeout(timeout, tokio::io::AsyncReadExt::read(stream, buf)).await {
        Ok(result) => result,
        Err(_) => {
            runtime_governor::mark_idle_timeout_global();
            runtime_governor::mark_stuck_flow_global();
            Err(timeout_error(IDLE_TIMEOUT_ERROR_PREFIX, stage, timeout))
        }
    }
}

async fn write_all_with_idle_timeout<W>(
    stream: &mut W,
    bytes: &[u8],
    stage: &'static str,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let timeout = io_timeout_config().idle_watchdog_timeout;
    match tokio::time::timeout(timeout, tokio::io::AsyncWriteExt::write_all(stream, bytes)).await {
        Ok(result) => result,
        Err(_) => {
            runtime_governor::mark_idle_timeout_global();
            runtime_governor::mark_stuck_flow_global();
            Err(timeout_error(IDLE_TIMEOUT_ERROR_PREFIX, stage, timeout))
        }
    }
}

async fn flush_with_idle_timeout<W>(
    stream: &mut W,
    stage: &'static str,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let timeout = io_timeout_config().idle_watchdog_timeout;
    match tokio::time::timeout(timeout, tokio::io::AsyncWriteExt::flush(stream)).await {
        Ok(result) => result,
        Err(_) => {
            runtime_governor::mark_idle_timeout_global();
            runtime_governor::mark_stuck_flow_global();
            Err(timeout_error(IDLE_TIMEOUT_ERROR_PREFIX, stage, timeout))
        }
    }
}

async fn shutdown_with_idle_timeout<W>(
    stream: &mut W,
    stage: &'static str,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let timeout = io_timeout_config().idle_watchdog_timeout;
    match tokio::time::timeout(timeout, tokio::io::AsyncWriteExt::shutdown(stream)).await {
        Ok(result) => match result {
            Ok(()) => Ok(()),
            Err(error) if ignored_shutdown_error(&error) => Ok(()),
            Err(error) => Err(error),
        },
        Err(_) => {
            runtime_governor::mark_idle_timeout_global();
            runtime_governor::mark_stuck_flow_global();
            Err(timeout_error(IDLE_TIMEOUT_ERROR_PREFIX, stage, timeout))
        }
    }
}

async fn with_stream_stage_timeout<T, F>(
    stage: &'static str,
    future: F,
) -> std::io::Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    let timeout = io_timeout_config().stream_stage_timeout;
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| {
            runtime_governor::mark_stream_stage_timeout_global();
            runtime_governor::mark_stuck_flow_global();
            timeout_error(STREAM_STAGE_TIMEOUT_ERROR_PREFIX, stage, timeout)
        })?
}

async fn copy_bidirectional_with_idle_timeout<A, B>(
    side_a: &mut A,
    side_b: &mut B,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut a_to_b = [0_u8; IO_CHUNK_SIZE];
    let mut b_to_a = [0_u8; IO_CHUNK_SIZE];
    let mut bytes_from_a = 0_u64;
    let mut bytes_from_b = 0_u64;
    let mut a_closed = false;
    let mut b_closed = false;

    loop {
        if a_closed && b_closed {
            return Ok((bytes_from_a, bytes_from_b));
        }

        tokio::select! {
            result = read_with_idle_timeout(side_a, &mut a_to_b, "copy_bidirectional_read_a"), if !a_closed => {
                let read = result?;
                if read == 0 {
                    a_closed = true;
                    let _ = shutdown_with_idle_timeout(side_b, "copy_bidirectional_shutdown_b").await;
                } else {
                    write_all_with_idle_timeout(side_b, &a_to_b[..read], "copy_bidirectional_write_b").await?;
                    bytes_from_a += read as u64;
                }
            }
            result = read_with_idle_timeout(side_b, &mut b_to_a, "copy_bidirectional_read_b"), if !b_closed => {
                let read = result?;
                if read == 0 {
                    b_closed = true;
                    let _ = shutdown_with_idle_timeout(side_a, "copy_bidirectional_shutdown_a").await;
                } else {
                    write_all_with_idle_timeout(side_a, &b_to_a[..read], "copy_bidirectional_write_a").await?;
                    bytes_from_b += read as u64;
                }
            }
        }

    }
}

#[cfg(test)]
mod io_timeout_happy_eyeballs_tests {
    use super::{connect_with_happy_eyeballs_addrs, interleave_happy_eyeballs_addrs};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn interleave_addrs_alternates_ip_families() {
        let addrs = vec![
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 444, 0, 0)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 81)),
        ];

        let ordered = interleave_happy_eyeballs_addrs(addrs);
        assert_eq!(
            ordered,
            vec![
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)),
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 444, 0, 0)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 81)),
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn happy_eyeballs_falls_back_when_first_address_refuses() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind v4 listener");
        let port = listener.local_addr().expect("listener addr").port();
        let accept_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept stream");
            let mut one = [0_u8; 1];
            let _ = stream.read(&mut one).await;
        });

        let addrs = vec![
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        ];

        let stream = connect_with_happy_eyeballs_addrs(
            addrs,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .expect("happy-eyeballs connect should succeed");
        drop(stream);
        accept_task.await.expect("accept task join");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn happy_eyeballs_rejects_empty_address_list() {
        let error = connect_with_happy_eyeballs_addrs(
            Vec::new(),
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("empty address list must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
