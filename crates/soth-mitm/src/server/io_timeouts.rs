use super::{runtime_governor, IO_CHUNK_SIZE};
use crate::config::H2ResponseOverflowMode;

const IDLE_TIMEOUT_ERROR_PREFIX: &str = "idle_watchdog_timeout";
const STREAM_STAGE_TIMEOUT_ERROR_PREFIX: &str = "stream_stage_timeout";
const HAPPY_EYEBALLS_STAGGER: std::time::Duration = std::time::Duration::from_millis(200);
/// Last-resort idle ceiling for blind tunnels. Blind tunnels deliberately have
/// no aggressive idle watchdog (they carry legitimately-idle SSH / IMAP / DB
/// sessions), relying on TCP keepalive to reap a peer that vanished without a
/// RST. But keepalive is best-effort and cannot apply to non-TCP transports,
/// and can be swallowed by a middlebox — leaving no reaper. This ceiling is
/// the unconditional backstop: high enough (1h) that no legitimate idle
/// session is severed, low enough that a dead-without-RST flow can't pin a
/// task and its admission slot forever.
const TUNNEL_IDLE_CEILING: std::time::Duration = std::time::Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IoTimeoutConfig {
    idle_watchdog_timeout: std::time::Duration,
    websocket_idle_watchdog_timeout: std::time::Duration,
    upstream_connect_timeout: std::time::Duration,
    stream_stage_timeout: std::time::Duration,
    h2_body_idle_timeout: std::time::Duration,
    h2_response_overflow_mode: H2ResponseOverflowMode,
    /// `Some(delay)` enables a single connect retry after `delay` for
    /// transient failures (refused / unreachable / reset). `None` disables.
    upstream_connect_retry_delay: Option<std::time::Duration>,
}

impl Default for IoTimeoutConfig {
    fn default() -> Self {
        Self {
            idle_watchdog_timeout: std::time::Duration::from_secs(30),
            websocket_idle_watchdog_timeout: std::time::Duration::from_secs(600),
            upstream_connect_timeout: std::time::Duration::from_secs(10),
            stream_stage_timeout: std::time::Duration::from_secs(5),
            h2_body_idle_timeout: std::time::Duration::from_secs(5),
            h2_response_overflow_mode: H2ResponseOverflowMode::TruncateContinue,
            upstream_connect_retry_delay: None,
        }
    }
}

/// Lock-free, poison-free global read via `ArcSwap` (same pattern as the DNS
/// resolver). Previously this was a `std::sync::Mutex` read with
/// `.expect("… poisoned")` on *every* proxy read/write/connect/flush — so a
/// single panic while any thread held the lock would poison it and make every
/// subsequent I/O timeout lookup panic, killing every connection in the proxy
/// until restart. `ArcSwap` has neither a lock nor a poison state.
static IO_TIMEOUT_CONFIG: std::sync::LazyLock<arc_swap::ArcSwap<IoTimeoutConfig>> =
    std::sync::LazyLock::new(|| arc_swap::ArcSwap::from_pointee(IoTimeoutConfig::default()));

fn io_timeout_config() -> IoTimeoutConfig {
    // IoTimeoutConfig is Copy, so this is a cheap value read.
    **IO_TIMEOUT_CONFIG.load()
}

fn timeout_error(
    prefix: &str,
    stage: &'static str,
    timeout: std::time::Duration,
) -> std::io::Error {
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn install_io_timeout_config(
    idle_watchdog_timeout: std::time::Duration,
    websocket_idle_watchdog_timeout: std::time::Duration,
    upstream_connect_timeout: std::time::Duration,
    stream_stage_timeout: std::time::Duration,
    h2_body_idle_timeout: std::time::Duration,
    h2_response_overflow_mode: H2ResponseOverflowMode,
    upstream_connect_retry_delay: Option<std::time::Duration>,
) {
    let config = IoTimeoutConfig {
        idle_watchdog_timeout: ensure_bounded_timeout(idle_watchdog_timeout),
        websocket_idle_watchdog_timeout: ensure_bounded_timeout(websocket_idle_watchdog_timeout),
        upstream_connect_timeout: ensure_bounded_timeout(upstream_connect_timeout),
        stream_stage_timeout: ensure_bounded_timeout(stream_stage_timeout),
        h2_body_idle_timeout: ensure_bounded_timeout(h2_body_idle_timeout),
        h2_response_overflow_mode,
        upstream_connect_retry_delay,
    };
    IO_TIMEOUT_CONFIG.store(std::sync::Arc::new(config));
}

pub(crate) async fn connect_with_upstream_timeout(
    host: &str,
    port: u16,
    stage: &'static str,
) -> std::io::Result<tokio::net::TcpStream> {
    let config = io_timeout_config();
    let timeout = config.upstream_connect_timeout;
    let deadline = tokio::time::Instant::now() + timeout;

    let start = std::time::Instant::now();
    let connect_result = connect_with_retry(
        host,
        port,
        stage,
        deadline,
        config.upstream_connect_retry_delay,
    )
    .await;
    if is_connect_timeout_error(&connect_result) {
        let elapsed = start.elapsed();
        tracing::warn!(
            host,
            port,
            stage,
            elapsed_ms = elapsed.as_millis() as u64,
            timeout_ms = timeout.as_millis() as u64,
            "upstream connect timed out"
        );
        runtime_governor::mark_stream_stage_timeout_global();
        runtime_governor::mark_stuck_flow_global();
        return Err(timeout_error(
            STREAM_STAGE_TIMEOUT_ERROR_PREFIX,
            stage,
            timeout,
        ));
    }
    connect_result
}

fn is_connect_timeout_error(result: &std::io::Result<tokio::net::TcpStream>) -> bool {
    matches!(result, Err(error) if error.kind() == std::io::ErrorKind::TimedOut)
}

/// Connect with a single retry for transient failures (hotspot handoffs,
/// gateway blips). Timeouts are excluded — they already consumed the whole
/// budget — and the retry only runs when enough budget remains past the
/// retry delay. `retry_delay: None` disables retrying entirely.
async fn connect_with_retry(
    host: &str,
    port: u16,
    stage: &'static str,
    deadline: tokio::time::Instant,
    retry_delay: Option<std::time::Duration>,
) -> std::io::Result<tokio::net::TcpStream> {
    let connect_result = connect_with_happy_eyeballs(host, port, deadline).await;
    let Some(retry_delay) = retry_delay else {
        return connect_result;
    };
    if !is_transient_connect_error(&connect_result) {
        return connect_result;
    }
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining <= retry_delay {
        return connect_result;
    }
    tracing::debug!(
        host,
        port,
        stage,
        retry_delay_ms = retry_delay.as_millis() as u64,
        "upstream connect failed transiently; retrying once"
    );
    tokio::time::sleep(retry_delay).await;
    connect_with_happy_eyeballs(host, port, deadline).await
}

/// Transient network errors worth one retry: connection-level rejections and
/// route/DNS failures that a mid-handoff network produces for a few hundred
/// milliseconds. Timeouts and permanent errors (invalid input, not found)
/// are excluded.
fn is_transient_connect_error(result: &std::io::Result<tokio::net::TcpStream>) -> bool {
    use std::io::ErrorKind;
    matches!(
        result,
        Err(error) if matches!(
            error.kind(),
            ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::NetworkUnreachable
                | ErrorKind::HostUnreachable
                | ErrorKind::NetworkDown
                | ErrorKind::AddrNotAvailable
        )
    )
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

    let resolved = tokio::time::timeout(remaining, super::dns_resolver::resolve_host(host, port))
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

    let addrs = interleave_happy_eyeballs_addrs(resolved);
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "upstream address resolution returned no socket addresses",
        ));
    }
    Ok(addrs)
}

fn interleave_happy_eyeballs_addrs(addrs: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
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

pub(crate) fn is_idle_watchdog_timeout(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::TimedOut
        && error.to_string().starts_with(IDLE_TIMEOUT_ERROR_PREFIX)
}

pub(crate) fn is_stream_stage_timeout(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::TimedOut
        && error
            .to_string()
            .starts_with(STREAM_STAGE_TIMEOUT_ERROR_PREFIX)
}

pub(crate) async fn read_with_idle_timeout<R>(
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

pub(crate) async fn write_all_with_idle_timeout<W>(
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

pub(crate) async fn read_with_websocket_idle_timeout<R>(
    stream: &mut R,
    buf: &mut [u8],
    stage: &'static str,
) -> std::io::Result<usize>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let timeout = io_timeout_config().websocket_idle_watchdog_timeout;
    match tokio::time::timeout(timeout, tokio::io::AsyncReadExt::read(stream, buf)).await {
        Ok(result) => result,
        Err(_) => {
            runtime_governor::mark_idle_timeout_global();
            runtime_governor::mark_stuck_flow_global();
            Err(timeout_error(IDLE_TIMEOUT_ERROR_PREFIX, stage, timeout))
        }
    }
}

pub(crate) async fn write_all_with_websocket_idle_timeout<W>(
    stream: &mut W,
    bytes: &[u8],
    stage: &'static str,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let timeout = io_timeout_config().websocket_idle_watchdog_timeout;
    match tokio::time::timeout(timeout, tokio::io::AsyncWriteExt::write_all(stream, bytes)).await {
        Ok(result) => result,
        Err(_) => {
            runtime_governor::mark_idle_timeout_global();
            runtime_governor::mark_stuck_flow_global();
            Err(timeout_error(IDLE_TIMEOUT_ERROR_PREFIX, stage, timeout))
        }
    }
}

pub(crate) async fn flush_with_idle_timeout<W>(
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

pub(crate) async fn flush_with_websocket_idle_timeout<W>(
    stream: &mut W,
    stage: &'static str,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let timeout = io_timeout_config().websocket_idle_watchdog_timeout;
    match tokio::time::timeout(timeout, tokio::io::AsyncWriteExt::flush(stream)).await {
        Ok(result) => result,
        Err(_) => {
            runtime_governor::mark_idle_timeout_global();
            runtime_governor::mark_stuck_flow_global();
            Err(timeout_error(IDLE_TIMEOUT_ERROR_PREFIX, stage, timeout))
        }
    }
}

pub(crate) async fn shutdown_with_idle_timeout<W>(
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

pub(crate) async fn shutdown_with_websocket_idle_timeout<W>(
    stream: &mut W,
    stage: &'static str,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let timeout = io_timeout_config().websocket_idle_watchdog_timeout;
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

pub(crate) async fn with_stream_stage_timeout<T, F>(
    stage: &'static str,
    future: F,
) -> std::io::Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    let timeout = io_timeout_config().stream_stage_timeout;
    tokio::time::timeout(timeout, future).await.map_err(|_| {
        runtime_governor::mark_stream_stage_timeout_global();
        runtime_governor::mark_stuck_flow_global();
        timeout_error(STREAM_STAGE_TIMEOUT_ERROR_PREFIX, stage, timeout)
    })?
}

pub(crate) async fn with_h2_body_idle_timeout<T, F>(
    stage: &'static str,
    future: F,
) -> std::io::Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    let timeout = io_timeout_config().h2_body_idle_timeout;
    tokio::time::timeout(timeout, future).await.map_err(|_| {
        runtime_governor::mark_stream_stage_timeout_global();
        runtime_governor::mark_stuck_flow_global();
        timeout_error(STREAM_STAGE_TIMEOUT_ERROR_PREFIX, stage, timeout)
    })?
}

/// Blind-tunnel byte pump with **no application idle timeout**.
///
/// Blind tunnels carry arbitrary long-lived protocols — SSH, IMAP IDLE,
/// database keepalives, RDP, MQTT — that are legitimately silent for minutes
/// or hours while both endpoints stay alive. The application idle watchdog
/// used for intercepted flows and websockets would sever those (the previous
/// behavior: a tunnel silent for the ~10-minute watchdog window was force-
/// closed even though both peers were healthy — a breakage the user never
/// sees natively). Dead-peer detection is instead delegated to TCP keepalive
/// (set on both sockets in `socket_hardening`) plus natural connection
/// errors, exactly as a plain TCP proxy behaves. Using tokio's
/// `copy_bidirectional` also avoids the head-of-line stall the hand-rolled
/// copy had, where a slow write in one direction blocked reads in the other.
pub(crate) async fn copy_bidirectional_tunnel<A, B>(
    side_a: &mut A,
    side_b: &mut B,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut a_to_b = [0_u8; IO_CHUNK_SIZE];
    let mut b_to_a = [0_u8; IO_CHUNK_SIZE];
    let mut bytes_from_a = 0_u64;
    let mut bytes_from_b = 0_u64;
    let mut a_closed = false;
    let mut b_closed = false;

    // Each read is bounded by the large TUNNEL_IDLE_CEILING backstop only —
    // there is no aggressive idle watchdog, so legitimately-idle tunnels
    // survive; a dead-without-RST peer that keepalive fails to reap is
    // eventually reaped here instead of leaking forever.
    loop {
        if a_closed && b_closed {
            return Ok((bytes_from_a, bytes_from_b));
        }
        tokio::select! {
            result = tokio::time::timeout(TUNNEL_IDLE_CEILING, side_a.read(&mut a_to_b)), if !a_closed => {
                let read = result.map_err(|_| tunnel_idle_ceiling_error())??;
                if read == 0 {
                    a_closed = true;
                    let _ = side_b.shutdown().await;
                } else {
                    side_b.write_all(&a_to_b[..read]).await?;
                    bytes_from_a += read as u64;
                }
            }
            result = tokio::time::timeout(TUNNEL_IDLE_CEILING, side_b.read(&mut b_to_a)), if !b_closed => {
                let read = result.map_err(|_| tunnel_idle_ceiling_error())??;
                if read == 0 {
                    b_closed = true;
                    let _ = side_a.shutdown().await;
                } else {
                    side_a.write_all(&b_to_a[..read]).await?;
                    bytes_from_b += read as u64;
                }
            }
        }
    }
}

fn tunnel_idle_ceiling_error() -> std::io::Error {
    runtime_governor::mark_idle_timeout_global();
    runtime_governor::mark_stuck_flow_global();
    timeout_error(
        IDLE_TIMEOUT_ERROR_PREFIX,
        "tunnel_idle_ceiling",
        TUNNEL_IDLE_CEILING,
    )
}

pub(crate) async fn copy_bidirectional_with_websocket_idle_timeout<A, B>(
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
            result = read_with_websocket_idle_timeout(side_a, &mut a_to_b, "copy_bidirectional_read_a"), if !a_closed => {
                let read = result?;
                if read == 0 {
                    a_closed = true;
                    let _ = shutdown_with_websocket_idle_timeout(side_b, "copy_bidirectional_shutdown_b").await;
                } else {
                    write_all_with_websocket_idle_timeout(side_b, &a_to_b[..read], "copy_bidirectional_write_b").await?;
                    bytes_from_a += read as u64;
                }
            }
            result = read_with_websocket_idle_timeout(side_b, &mut b_to_a, "copy_bidirectional_read_b"), if !b_closed => {
                let read = result?;
                if read == 0 {
                    b_closed = true;
                    let _ = shutdown_with_websocket_idle_timeout(side_a, "copy_bidirectional_shutdown_a").await;
                } else {
                    write_all_with_websocket_idle_timeout(side_a, &b_to_a[..read], "copy_bidirectional_write_a").await?;
                    bytes_from_b += read as u64;
                }
            }
        }
    }
}

#[cfg(test)]
mod io_timeout_happy_eyeballs_tests {
    use super::{
        connect_with_happy_eyeballs_addrs, connect_with_retry, interleave_happy_eyeballs_addrs,
        is_transient_connect_error,
    };
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tunnel_copy_pumps_both_directions_and_reports_counts() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Echo server on side_b; side_a is the client half of a loopback pair.
        let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
            s.shutdown().await.unwrap();
        });

        let (mut a_client, mut a_server) = tokio::io::duplex(1024);
        let mut b = tokio::net::TcpStream::connect(echo_addr).await.unwrap();

        let copy =
            tokio::spawn(
                async move { super::copy_bidirectional_tunnel(&mut a_server, &mut b).await },
            );

        a_client.write_all(b"ping").await.unwrap();
        a_client.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        a_client.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        let (from_a, from_b) = copy.await.unwrap().unwrap();
        assert_eq!(from_a, 4);
        assert_eq!(from_b, 4);
        echo_task.await.unwrap();
    }

    #[test]
    fn io_timeout_config_swaps_without_lock() {
        use super::{install_io_timeout_config, io_timeout_config};
        use crate::config::H2ResponseOverflowMode;
        install_io_timeout_config(
            Duration::from_secs(31),
            Duration::from_secs(601),
            Duration::from_secs(11),
            Duration::from_secs(7),
            Duration::from_secs(9),
            H2ResponseOverflowMode::TruncateContinue,
            Some(Duration::from_millis(250)),
        );
        let cfg = io_timeout_config();
        assert_eq!(cfg.upstream_connect_timeout, Duration::from_secs(11));
        assert_eq!(
            cfg.upstream_connect_retry_delay,
            Some(Duration::from_millis(250))
        );
    }

    #[test]
    fn transient_connect_error_classification() {
        let transient = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        assert!(is_transient_connect_error(&Err(transient)));
        let timeout = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        assert!(!is_transient_connect_error(&Err(timeout)));
        let invalid = std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad input");
        assert!(!is_transient_connect_error(&Err(invalid)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_with_retry_recovers_after_transient_refusal() {
        // Reserve a port, then close the listener so the first attempt is
        // refused; rebind shortly after so the retry succeeds.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind probe listener");
        let addr = listener.local_addr().expect("listener addr");
        drop(listener);

        let rebind = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            let listener = TcpListener::bind(addr).await.expect("rebind listener");
            let (mut stream, _) = listener.accept().await.expect("accept retried connect");
            let mut one = [0_u8; 1];
            let _ = stream.read(&mut one).await;
        });

        let stream = connect_with_retry(
            "127.0.0.1",
            addr.port(),
            "test_retry",
            tokio::time::Instant::now() + Duration::from_secs(5),
            Some(Duration::from_millis(100)),
        )
        .await
        .expect("retry should recover after listener rebinds");
        drop(stream);
        rebind.await.expect("rebind task join");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_with_retry_disabled_fails_immediately() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind probe listener");
        let addr = listener.local_addr().expect("listener addr");
        drop(listener);

        let error = connect_with_retry(
            "127.0.0.1",
            addr.port(),
            "test_no_retry",
            tokio::time::Instant::now() + Duration::from_secs(5),
            None,
        )
        .await
        .expect_err("closed port must refuse without retry");
        assert!(is_transient_connect_error(&Err(error)));
    }
}
