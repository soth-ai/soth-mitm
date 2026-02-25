const IDLE_TIMEOUT_ERROR_PREFIX: &str = "idle_watchdog_timeout";
const STREAM_STAGE_TIMEOUT_ERROR_PREFIX: &str = "stream_stage_timeout";

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
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port))).await {
        Ok(result) => result,
        Err(_) => {
            runtime_governor::mark_stream_stage_timeout_global();
            runtime_governor::mark_stuck_flow_global();
            Err(timeout_error(STREAM_STAGE_TIMEOUT_ERROR_PREFIX, stage, timeout))
        }
    }
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
