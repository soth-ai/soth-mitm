mod common;

use std::env;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use soth_mitm::{
    generate_ca, HandlerDecision, InterceptHandler, MitmConfig, MitmProxyBuilder, MitmProxyHandle,
    RawRequest,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Instant};

use crate::common::{
    free_loopback_port, parse_path_arg, parse_u128_arg, parse_usize_arg, print_result_stdout,
    summarize_latency, write_result_file,
};

const DEFAULT_ITERATIONS: usize = 200;
const DEFAULT_WARMUP: usize = 20;
const DEFAULT_P50_THRESHOLD_US: u128 = 1_000;
const DEFAULT_P95_THRESHOLD_US: u128 = 5_000;
const DEFAULT_P99_THRESHOLD_US: u128 = 15_000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
struct BenchConfig {
    iterations: usize,
    warmup: usize,
    p50_threshold_us: u128,
    p95_threshold_us: u128,
    p99_threshold_us: u128,
    result_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct BenchResult {
    summary: common::LatencySummary,
    pass: bool,
}

#[derive(Debug, Clone, Copy)]
struct ForwardHandler;

impl InterceptHandler for ForwardHandler {
    fn on_request(&self, _request: &RawRequest) -> HandlerDecision {
        HandlerDecision::Allow
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let config = BenchConfig {
        iterations: parse_usize_arg(&args, "--iterations", DEFAULT_ITERATIONS)?,
        warmup: parse_usize_arg(&args, "--warmup", DEFAULT_WARMUP)?,
        p50_threshold_us: parse_u128_arg(&args, "--threshold-p50-us", DEFAULT_P50_THRESHOLD_US)?,
        p95_threshold_us: parse_u128_arg(&args, "--threshold-p95-us", DEFAULT_P95_THRESHOLD_US)?,
        p99_threshold_us: parse_u128_arg(&args, "--threshold-p99-us", DEFAULT_P99_THRESHOLD_US)?,
        result_file: parse_path_arg(&args, "--result-file"),
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()?;
    let result = runtime.block_on(run_benchmark(config.clone()))?;

    let rows = vec![
        ("bench", "forwarding_latency".to_string()),
        ("iterations", config.iterations.to_string()),
        ("warmup", config.warmup.to_string()),
        ("p50_us", result.summary.p50_us.to_string()),
        ("p95_us", result.summary.p95_us.to_string()),
        ("p99_us", result.summary.p99_us.to_string()),
        ("min_us", result.summary.min_us.to_string()),
        ("max_us", result.summary.max_us.to_string()),
        ("mean_us", result.summary.mean_us.to_string()),
        ("samples", result.summary.samples.to_string()),
        ("threshold_p50_us", config.p50_threshold_us.to_string()),
        ("threshold_p95_us", config.p95_threshold_us.to_string()),
        ("threshold_p99_us", config.p99_threshold_us.to_string()),
        ("pass", result.pass.to_string()),
    ];
    print_result_stdout(&rows);
    write_result_file(config.result_file, &rows)?;

    if !result.pass {
        return Err("forwarding latency thresholds exceeded".into());
    }
    Ok(())
}

async fn run_benchmark(config: BenchConfig) -> io::Result<BenchResult> {
    let (upstream_addr, upstream_task) = start_plain_http_upstream().await?;
    let (proxy_addr, proxy_handle, temp_dir) = start_proxy(upstream_addr).await?;

    for _ in 0..config.warmup {
        run_direct_request(upstream_addr).await?;
        run_proxy_request(proxy_addr, upstream_addr).await?;
    }

    let mut added_latencies = Vec::with_capacity(config.iterations);
    for _ in 0..config.iterations {
        let direct_started = Instant::now();
        run_direct_request(upstream_addr).await?;
        let direct_elapsed = direct_started.elapsed();

        let proxy_started = Instant::now();
        run_proxy_request(proxy_addr, upstream_addr).await?;
        let proxy_elapsed = proxy_started.elapsed();

        let added = proxy_elapsed
            .checked_sub(direct_elapsed)
            .unwrap_or_else(|| Duration::from_micros(0));
        added_latencies.push(added);
    }

    proxy_handle
        .shutdown(Duration::from_secs(2))
        .await
        .map_err(|error| io::Error::other(format!("proxy shutdown failed: {error}")))?;
    upstream_task.abort();
    let _ = upstream_task.await;
    let _ = fs::remove_dir_all(temp_dir);

    let summary = summarize_latency(&added_latencies);
    let pass = summary.p50_us <= config.p50_threshold_us
        && summary.p95_us <= config.p95_threshold_us
        && summary.p99_us <= config.p99_threshold_us;
    Ok(BenchResult { summary, pass })
}

async fn start_plain_http_upstream() -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let _ = read_http_head(&mut socket).await;
                let response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = socket.write_all(response).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    Ok((addr, task))
}

async fn start_proxy(
    upstream_addr: SocketAddr,
) -> io::Result<(SocketAddr, MitmProxyHandle, PathBuf)> {
    let proxy_port = free_loopback_port()?;
    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| io::Error::other(format!("clock error: {error}")))?
        .as_nanos();
    let temp_dir = env::temp_dir().join(format!("soth-mitm-forward-bench-{nonce}"));
    fs::create_dir_all(&temp_dir)?;

    let mut config = MitmConfig::default();
    config.bind = proxy_addr;
    config.interception.destinations = vec![format!("127.0.0.1:{}", upstream_addr.port())];
    config.interception.passthrough_unlisted = true;
    config.upstream.verify_upstream_tls = false;
    config.tls.ca_cert_path = temp_dir.join("ca-cert.pem");
    config.tls.ca_key_path = temp_dir.join("ca-key.pem");

    let ca = generate_ca().map_err(|error| io::Error::other(format!("generate ca: {error}")))?;
    let proxy = MitmProxyBuilder::new(config, ForwardHandler)
        .with_ca(ca)
        .build()
        .map_err(|error| io::Error::other(format!("build proxy: {error}")))?;
    let handle = proxy
        .start()
        .await
        .map_err(|error| io::Error::other(format!("start proxy: {error}")))?;

    wait_for_proxy_ready(proxy_addr).await?;
    Ok((proxy_addr, handle, temp_dir))
}

async fn wait_for_proxy_ready(proxy_addr: SocketAddr) -> io::Result<()> {
    for _ in 0..50 {
        match TcpStream::connect(proxy_addr).await {
            Ok(mut stream) => {
                let _ = stream.shutdown().await;
                return Ok(());
            }
            Err(_) => sleep(Duration::from_millis(25)).await,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "proxy did not start listening within deadline",
    ))
}

async fn run_direct_request(upstream_addr: SocketAddr) -> io::Result<()> {
    timeout(REQUEST_TIMEOUT, async move {
        let mut stream = TcpStream::connect(upstream_addr).await?;
        let request = format!(
            "GET /bench HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            upstream_addr.port()
        );
        stream.write_all(request.as_bytes()).await?;
        let response = read_to_end(&mut stream).await?;
        if !response.starts_with(b"HTTP/1.1 200 OK") {
            return Err(io::Error::other("direct request received non-200 response"));
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct request timed out"))?
}

async fn run_proxy_request(proxy_addr: SocketAddr, upstream_addr: SocketAddr) -> io::Result<()> {
    timeout(REQUEST_TIMEOUT, async move {
        let mut stream = TcpStream::connect(proxy_addr).await?;
        let request = format!(
            "GET http://127.0.0.1:{}/bench HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        );
        stream.write_all(request.as_bytes()).await?;
        let response = read_to_end(&mut stream).await?;
        if !response.starts_with(b"HTTP/1.1 200 OK") {
            return Err(io::Error::other("proxy request received non-200 response"));
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy request timed out"))?
}

async fn read_http_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 1024];
    while !out.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        out.extend_from_slice(&buf[..read]);
    }
    Ok(out)
}

async fn read_to_end(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 2048];
    loop {
        let read = stream.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        out.extend_from_slice(&buf[..read]);
    }
    Ok(out)
}
