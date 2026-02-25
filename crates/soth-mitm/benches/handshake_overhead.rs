mod common;

use std::env;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use soth_mitm::{
    generate_ca, HandlerDecision, InterceptHandler, MitmConfig, MitmProxyBuilder, MitmProxyHandle,
    RawRequest,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout, Instant};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::common::{
    free_loopback_port, parse_path_arg, parse_u128_arg, parse_usize_arg, print_result_stdout,
    summarize_latency, write_result_file,
};

const DEFAULT_ITERATIONS: usize = 120;
const DEFAULT_WARMUP: usize = 12;
const DEFAULT_OVERHEAD_P95_THRESHOLD_US: u128 = 10_000;
const DEFAULT_SCALE_TARGET: usize = 1000;
const DEFAULT_SCALE_MAX_IN_FLIGHT: usize = 192;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Debug, Clone)]
struct BenchConfig {
    iterations: usize,
    warmup: usize,
    overhead_p95_threshold_us: u128,
    scale_target: usize,
    scale_max_in_flight: usize,
    result_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct BenchResult {
    overhead_summary: common::LatencySummary,
    direct_summary: common::LatencySummary,
    proxy_summary: common::LatencySummary,
    scale_successes: usize,
    scale_failures: usize,
    pass: bool,
}

#[derive(Debug, Clone, Copy)]
struct ForwardHandler;

impl InterceptHandler for ForwardHandler {
    async fn on_request(&self, _request: &RawRequest) -> HandlerDecision {
        HandlerDecision::Allow
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let config = BenchConfig {
        iterations: parse_usize_arg(&args, "--iterations", DEFAULT_ITERATIONS)?,
        warmup: parse_usize_arg(&args, "--warmup", DEFAULT_WARMUP)?,
        overhead_p95_threshold_us: parse_u128_arg(
            &args,
            "--threshold-overhead-p95-us",
            DEFAULT_OVERHEAD_P95_THRESHOLD_US,
        )?,
        scale_target: parse_usize_arg(&args, "--scale-target", DEFAULT_SCALE_TARGET)?,
        scale_max_in_flight: parse_usize_arg(
            &args,
            "--scale-max-in-flight",
            DEFAULT_SCALE_MAX_IN_FLIGHT,
        )?
        .max(1),
        result_file: parse_path_arg(&args, "--result-file"),
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()?;
    let result = runtime.block_on(run_benchmark(config.clone()))?;

    let rows = vec![
        ("bench", "handshake_overhead".to_string()),
        ("iterations", config.iterations.to_string()),
        ("warmup", config.warmup.to_string()),
        ("direct_p50_us", result.direct_summary.p50_us.to_string()),
        ("direct_p95_us", result.direct_summary.p95_us.to_string()),
        ("direct_p99_us", result.direct_summary.p99_us.to_string()),
        ("proxy_p50_us", result.proxy_summary.p50_us.to_string()),
        ("proxy_p95_us", result.proxy_summary.p95_us.to_string()),
        ("proxy_p99_us", result.proxy_summary.p99_us.to_string()),
        (
            "overhead_p50_us",
            result.overhead_summary.p50_us.to_string(),
        ),
        (
            "overhead_p95_us",
            result.overhead_summary.p95_us.to_string(),
        ),
        (
            "overhead_p99_us",
            result.overhead_summary.p99_us.to_string(),
        ),
        (
            "threshold_overhead_p95_us",
            config.overhead_p95_threshold_us.to_string(),
        ),
        ("scale_target", config.scale_target.to_string()),
        (
            "scale_max_in_flight",
            config.scale_max_in_flight.to_string(),
        ),
        ("scale_successes", result.scale_successes.to_string()),
        ("scale_failures", result.scale_failures.to_string()),
        ("pass", result.pass.to_string()),
    ];
    print_result_stdout(&rows);
    write_result_file(config.result_file, &rows)?;

    if !result.pass {
        return Err("handshake overhead thresholds exceeded or scale baseline failed".into());
    }
    Ok(())
}

async fn run_benchmark(config: BenchConfig) -> io::Result<BenchResult> {
    let (upstream_addr, upstream_task) = start_tls_upstream().await?;
    let (proxy_addr, proxy_handle, temp_dir) = start_proxy(upstream_addr).await?;

    let tls_connector = TlsConnector::from(mitm_tls::build_http1_client_config(true));
    for _ in 0..config.warmup {
        run_direct_tls_request(upstream_addr, tls_connector.clone()).await?;
        run_proxy_tls_request(proxy_addr, upstream_addr, tls_connector.clone()).await?;
    }

    let mut direct_samples = Vec::with_capacity(config.iterations);
    let mut proxy_samples = Vec::with_capacity(config.iterations);
    let mut overhead_samples = Vec::with_capacity(config.iterations);
    for _ in 0..config.iterations {
        let direct_started = Instant::now();
        run_direct_tls_request(upstream_addr, tls_connector.clone()).await?;
        let direct_elapsed = direct_started.elapsed();
        direct_samples.push(direct_elapsed);

        let proxy_started = Instant::now();
        run_proxy_tls_request(proxy_addr, upstream_addr, tls_connector.clone()).await?;
        let proxy_elapsed = proxy_started.elapsed();
        proxy_samples.push(proxy_elapsed);

        overhead_samples.push(
            proxy_elapsed
                .checked_sub(direct_elapsed)
                .unwrap_or_else(|| Duration::from_micros(0)),
        );
    }

    let (scale_successes, scale_failures) = run_scale_baseline(
        proxy_addr,
        upstream_addr,
        config.scale_target,
        config.scale_max_in_flight,
        tls_connector,
    )
    .await;

    proxy_handle
        .shutdown(Duration::from_secs(2))
        .await
        .map_err(|error| io::Error::other(format!("proxy shutdown failed: {error}")))?;
    upstream_task.abort();
    let _ = upstream_task.await;
    let _ = fs::remove_dir_all(temp_dir);

    let direct_summary = summarize_latency(&direct_samples);
    let proxy_summary = summarize_latency(&proxy_samples);
    let overhead_summary = summarize_latency(&overhead_samples);
    let pass = overhead_summary.p95_us <= config.overhead_p95_threshold_us
        && scale_failures == 0
        && scale_successes == config.scale_target;
    Ok(BenchResult {
        overhead_summary,
        direct_summary,
        proxy_summary,
        scale_successes,
        scale_failures,
        pass,
    })
}

async fn start_tls_upstream() -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server_config = mitm_tls::build_http1_server_config_for_host("127.0.0.1")
        .map_err(|error| io::Error::other(format!("build upstream TLS config: {error}")))?;
    let acceptor = TlsAcceptor::from(server_config);
    let task = tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let _ = read_http_head(&mut tls).await;
                let response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = tls.write_all(response).await;
                let _ = tls.flush().await;
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
    let temp_dir = env::temp_dir().join(format!("soth-mitm-handshake-bench-{nonce}"));
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
    for _ in 0..80 {
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

async fn run_direct_tls_request(
    upstream_addr: SocketAddr,
    connector: TlsConnector,
) -> io::Result<()> {
    timeout(REQUEST_TIMEOUT, async move {
        let tcp = TcpStream::connect(upstream_addr).await?;
        let server_name = ServerName::try_from("127.0.0.1".to_string())
            .map_err(|error| io::Error::other(format!("invalid server name: {error}")))?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|error| io::Error::other(format!("direct tls handshake failed: {error}")))?;
        let request = b"GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        tls.write_all(request).await?;
        tls.flush().await?;
        let response = read_to_end(&mut tls).await?;
        if !response.starts_with(b"HTTP/1.1 200 OK") {
            return Err(io::Error::other(
                "direct TLS request received non-200 response",
            ));
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct TLS request timed out"))?
}

async fn run_proxy_tls_request(
    proxy_addr: SocketAddr,
    upstream_addr: SocketAddr,
    connector: TlsConnector,
) -> io::Result<()> {
    timeout(REQUEST_TIMEOUT, async move {
        let mut tcp = TcpStream::connect(proxy_addr).await?;
        let connect = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        );
        tcp.write_all(connect.as_bytes()).await?;
        let connect_response = read_http_head(&mut tcp).await?;
        if !connect_response.starts_with(b"HTTP/1.1 200 Connection Established") {
            return Err(io::Error::other(
                "proxy CONNECT did not return 200 Connection Established",
            ));
        }

        let server_name = ServerName::try_from("127.0.0.1".to_string())
            .map_err(|error| io::Error::other(format!("invalid server name: {error}")))?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|error| io::Error::other(format!("proxy tls handshake failed: {error}")))?;
        let request = b"GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        tls.write_all(request).await?;
        tls.flush().await?;
        let response = read_to_end(&mut tls).await?;
        if !response.starts_with(b"HTTP/1.1 200 OK") {
            return Err(io::Error::other(
                "proxy TLS request received non-200 response",
            ));
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy TLS request timed out"))?
}

async fn run_scale_baseline(
    proxy_addr: SocketAddr,
    upstream_addr: SocketAddr,
    target: usize,
    max_in_flight: usize,
    connector: TlsConnector,
) -> (usize, usize) {
    let limiter = Arc::new(Semaphore::new(max_in_flight));
    let mut tasks = JoinSet::new();
    for _ in 0..target {
        let limiter = Arc::clone(&limiter);
        let connector = connector.clone();
        tasks.spawn(async move {
            let permit = limiter
                .acquire_owned()
                .await
                .map_err(|error| io::Error::other(format!("scale semaphore closed: {error}")))?;
            let result = run_proxy_tls_request(proxy_addr, upstream_addr, connector).await;
            drop(permit);
            result
        });
    }

    let mut successes = 0_usize;
    let mut failures = 0_usize;
    while let Some(join_result) = tasks.join_next().await {
        match join_result {
            Ok(Ok(())) => successes += 1,
            Ok(Err(_)) | Err(_) => failures += 1,
        }
    }
    (successes, failures)
}

async fn read_http_head<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
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

async fn read_to_end<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 2048];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(read) => out.extend_from_slice(&buf[..read]),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break,
            Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => break,
            Err(error) => return Err(error),
        }
    }
    Ok(out)
}
