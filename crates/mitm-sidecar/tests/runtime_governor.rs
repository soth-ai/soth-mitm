use std::time::Duration;

use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::{EventType, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep, timeout};

fn build_engine(
    config: MitmConfig,
    sink: VecEventConsumer,
) -> MitmEngine<DefaultPolicyEngine, VecEventConsumer> {
    let policy =
        DefaultPolicyEngine::new(config.ignore_hosts.clone(), config.blocked_hosts.clone());
    MitmEngine::new(config, policy, sink)
}

async fn read_response_head(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !data.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.expect("read response");
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8_lossy(&data).to_string()
}

fn should_retry_bind(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrInUse
    )
}

async fn bind_loopback_listener_with_retry(label: &str) -> TcpListener {
    let retries = 20_u32;
    let retry_delay = Duration::from_millis(25);
    for attempt in 0..=retries {
        match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => return listener,
            Err(error) if should_retry_bind(&error) && attempt < retries => {
                sleep(retry_delay).await;
            }
            Err(error) => panic!("{label}: {error}"),
        }
    }
    unreachable!("bind retries exhausted unexpectedly")
}

fn runtime_governor_test_gate() -> &'static std::sync::Arc<Semaphore> {
    static TEST_GATE: std::sync::OnceLock<std::sync::Arc<Semaphore>> = std::sync::OnceLock::new();
    TEST_GATE.get_or_init(|| std::sync::Arc::new(Semaphore::new(1)))
}

async fn acquire_runtime_governor_test_permit() -> OwnedSemaphorePermit {
    runtime_governor_test_gate()
        .clone()
        .acquire_owned()
        .await
        .expect("runtime-governor test gate closed")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runtime_governor_enforces_concurrent_flow_limit_and_records_metrics() {
    let _serial_permit = acquire_runtime_governor_test_permit().await;
    let upstream = bind_loopback_listener_with_retry("bind upstream").await;
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("accept upstream");
        let mut request = [0_u8; 4];
        stream
            .read_exact(&mut request)
            .await
            .expect("read tunneled bytes");
        assert_eq!(&request, b"ping");
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream
            .write_all(b"pong")
            .await
            .expect("write tunneled response");
    });

    let sink = VecEventConsumer::default();
    let config = MitmConfig {
        ignore_hosts: vec!["127.0.0.1".to_string()],
        max_concurrent_flows: 1,
        max_in_flight_bytes: 8 * 1024,
        ..MitmConfig::default()
    };
    let sidecar_config = SidecarConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        max_connect_head_bytes: 4 * 1024,
        max_http_head_bytes: 4 * 1024,
        idle_watchdog_timeout: std::time::Duration::from_secs(30),
        stream_stage_timeout: std::time::Duration::from_secs(5),
        unix_socket_path: None,
    };
    let engine = build_engine(config, sink);
    let server = SidecarServer::new(sidecar_config, engine).expect("build sidecar");
    let observability = server.runtime_observability_handle();
    let listener = bind_loopback_listener_with_retry("bind sidecar").await;
    let proxy_addr = listener.local_addr().expect("proxy addr");
    let proxy_task = tokio::spawn(server.run_with_listener(listener));

    let mut first = TcpStream::connect(proxy_addr).await.expect("connect first");
    let connect_first = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    );
    first
        .write_all(connect_first.as_bytes())
        .await
        .expect("write first CONNECT");
    let first_head = read_response_head(&mut first).await;
    assert!(first_head.starts_with("HTTP/1.1 200"), "{first_head}");

    let mut second = TcpStream::connect(proxy_addr)
        .await
        .expect("connect second");
    second
        .write_all(connect_first.as_bytes())
        .await
        .expect("write second CONNECT");
    let second_head = read_response_head(&mut second).await;
    assert!(
        second_head.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{second_head}"
    );

    first
        .write_all(b"ping")
        .await
        .expect("write tunnel payload");
    let mut pong = [0_u8; 4];
    first
        .read_exact(&mut pong)
        .await
        .expect("read tunnel response");
    assert_eq!(&pong, b"pong");

    upstream_task.await.expect("upstream task");
    first
        .shutdown()
        .await
        .expect("shutdown first tunnel socket");
    drop(first);
    drop(second);

    timeout(Duration::from_secs(1), async {
        loop {
            if observability.snapshot().flow_count >= 1 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("runtime governor should observe at least one completed flow");

    proxy_task.abort();

    let snapshot = observability.snapshot();
    assert!(snapshot.max_active_flows >= 1);
    assert!(snapshot.flow_count >= 1);
    assert!(snapshot.flow_duration_max_ms > 0);
    assert!(snapshot.in_flight_bytes_watermark > 0);
    assert!(
        snapshot.budget_denial_count >= 1,
        "expected at least one budget denial from flow-capacity saturation"
    );
    assert!(
        snapshot.backpressure_activation_count >= 1,
        "expected backpressure activation to track denied capacity"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_watchdog_timeout_closes_stuck_tunnel_and_records_metrics() {
    let _serial_permit = acquire_runtime_governor_test_permit().await;
    let upstream = bind_loopback_listener_with_retry("bind upstream").await;
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        let (_stream, _) = upstream.accept().await.expect("accept upstream");
        sleep(Duration::from_secs(1)).await;
    });

    let sink = VecEventConsumer::default();
    let sink_for_assertions = sink.clone();
    let config = MitmConfig {
        ignore_hosts: vec!["127.0.0.1".to_string()],
        max_concurrent_flows: 8,
        max_in_flight_bytes: 32 * 1024,
        ..MitmConfig::default()
    };
    let sidecar_config = SidecarConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0,
        max_connect_head_bytes: 4 * 1024,
        max_http_head_bytes: 4 * 1024,
        idle_watchdog_timeout: Duration::from_millis(120),
        stream_stage_timeout: Duration::from_secs(1),
        unix_socket_path: None,
    };
    let engine = build_engine(config, sink);
    let server = SidecarServer::new(sidecar_config, engine).expect("build sidecar");
    let observability = server.runtime_observability_handle();
    let listener = bind_loopback_listener_with_retry("bind sidecar").await;
    let proxy_addr = listener.local_addr().expect("proxy addr");
    let proxy_task = tokio::spawn(server.run_with_listener(listener));

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect client");
    let connect_request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    );
    client
        .write_all(connect_request.as_bytes())
        .await
        .expect("write CONNECT");
    let connect_head = read_response_head(&mut client).await;
    assert!(connect_head.starts_with("HTTP/1.1 200"), "{connect_head}");

    timeout(Duration::from_secs(2), async {
        let mut probe = [0_u8; 1];
        loop {
            match client.read(&mut probe).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("unexpected read error: {error}"),
            }
        }
    })
    .await
    .expect("idle watchdog should close stalled tunnel");

    timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = observability.snapshot();
            if snapshot.idle_timeout_count >= 1 && snapshot.stuck_flow_count >= 1 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timeout counters should be observed");

    let snapshot = observability.snapshot();
    assert!(
        snapshot.idle_timeout_count >= 1,
        "expected idle timeout counter increment"
    );
    assert!(
        snapshot.stuck_flow_count >= 1,
        "expected stuck flow counter increment"
    );
    assert!(
        sink_for_assertions.snapshot().iter().any(|event| {
            event.kind == EventType::StreamClosed
                && event.attributes.get("reason_code").map(String::as_str)
                    == Some("idle_watchdog_timeout")
        }),
        "expected stream_closed reason_code=idle_watchdog_timeout"
    );

    proxy_task.abort();
    upstream_task.abort();
}
