use std::time::Duration;

use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::VecEventConsumer;
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runtime_governor_enforces_concurrent_flow_limit_and_records_metrics() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
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
    };
    let engine = build_engine(config, sink);
    let server = SidecarServer::new(sidecar_config, engine).expect("build sidecar");
    let observability = server.runtime_observability_handle();
    let listener = server.bind_listener().await.expect("bind sidecar");
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
}
