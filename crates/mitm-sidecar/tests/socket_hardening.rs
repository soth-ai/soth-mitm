use std::time::Duration;

use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::VecEventConsumer;
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};
use tokio::net::TcpStream;

fn build_engine(
    config: MitmConfig,
    sink: VecEventConsumer,
) -> MitmEngine<DefaultPolicyEngine, VecEventConsumer> {
    let policy =
        DefaultPolicyEngine::new(config.ignore_hosts.clone(), config.blocked_hosts.clone());
    MitmEngine::new(config, policy, sink)
}

fn sidecar_config_for_addr(listen_addr: &str) -> SidecarConfig {
    SidecarConfig {
        listen_addr: listen_addr.to_string(),
        listen_port: 0,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: 64 * 1024,
        idle_watchdog_timeout: Duration::from_secs(5),
        stream_stage_timeout: Duration::from_secs(5),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_supports_ipv6_loopback_when_available() {
    let sink = VecEventConsumer::default();
    let engine = build_engine(MitmConfig::default(), sink);
    let server = SidecarServer::new(sidecar_config_for_addr("::1"), engine).expect("sidecar");
    match server.bind_listener().await {
        Ok(listener) => {
            let addr = listener.local_addr().expect("listener addr");
            assert!(addr.is_ipv6(), "expected ipv6 listener, got {addr}");
        }
        Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => {}
        Err(error) => panic!("unexpected ipv6 bind failure: {error}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dual_stack_ipv6_listener_accepts_ipv4_when_available() {
    let sink = VecEventConsumer::default();
    let engine = build_engine(MitmConfig::default(), sink);
    let server = SidecarServer::new(sidecar_config_for_addr("::"), engine).expect("sidecar");
    let listener = match server.bind_listener().await {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => return,
        Err(error) => panic!("unexpected dual-stack bind failure: {error}"),
    };
    let listen_addr = listener.local_addr().expect("listener addr");
    if !listen_addr.is_ipv6() {
        return;
    }

    let port = listen_addr.port();
    let accept_task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_millis(600), listener.accept()).await
    });
    let connect_result = tokio::time::timeout(
        Duration::from_millis(400),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await;
    let Ok(Ok(client)) = connect_result else {
        accept_task.abort();
        return;
    };

    let accepted = accept_task
        .await
        .expect("accept task join")
        .expect("accept timeout")
        .expect("accept connection");
    drop(client);
    drop(accepted.0);
}
