use std::sync::Arc;

use mitm_core::server::run_flow_lifecycle_server;
use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::{EventType, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

const CONNECTIONS: usize = 500;

fn build_engine(
    config: MitmConfig,
    sink: VecEventConsumer,
) -> MitmEngine<DefaultPolicyEngine, VecEventConsumer> {
    let policy =
        DefaultPolicyEngine::new(config.ignore_hosts.clone(), config.blocked_hosts.clone());
    MitmEngine::new(config, policy, sink)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flow_lifecycle_server_handles_500_parallel_short_lived_connections() {
    let sink = VecEventConsumer::default();
    let engine = Arc::new(build_engine(MitmConfig::default(), sink.clone()));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind lifecycle listener");
    let addr = listener.local_addr().expect("listener local addr");

    let server_task = tokio::spawn(run_flow_lifecycle_server(
        Arc::clone(&engine),
        listener,
        CONNECTIONS,
    ));

    let mut clients = JoinSet::new();
    for _ in 0..CONNECTIONS {
        clients.spawn(async move {
            let _stream = TcpStream::connect(addr)
                .await
                .expect("connect lifecycle server");
        });
    }
    while let Some(result) = clients.join_next().await {
        result.expect("client join");
    }

    let summary = server_task
        .await
        .expect("server task join")
        .expect("server result");
    assert_eq!(summary.accepted_connections, CONNECTIONS as u64);
    assert_eq!(summary.completed_connections, CONNECTIONS as u64);
    assert_eq!(summary.failed_connections, 0);

    let events = sink.snapshot();
    let connect_received = events
        .iter()
        .filter(|event| event.kind == EventType::ConnectReceived)
        .count();
    let connect_decision = events
        .iter()
        .filter(|event| event.kind == EventType::ConnectDecision)
        .count();
    let stream_closed = events
        .iter()
        .filter(|event| event.kind == EventType::StreamClosed)
        .count();
    assert_eq!(connect_received, CONNECTIONS);
    assert_eq!(connect_decision, CONNECTIONS);
    assert_eq!(stream_closed, CONNECTIONS);
}
