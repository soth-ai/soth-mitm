use std::sync::Arc;
use std::{env, io};

use mitm_core::server::run_flow_lifecycle_server;
use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::{EventType, VecEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

const DEFAULT_CONNECTIONS: usize = 500;

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
    let connections = configured_connections();
    let sink = VecEventConsumer::default();
    let engine = Arc::new(build_engine(MitmConfig::default(), sink.clone()));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind lifecycle listener");
    let addr = listener.local_addr().expect("listener local addr");

    let server_task = tokio::spawn(run_flow_lifecycle_server(
        Arc::clone(&engine),
        listener,
        connections,
    ));

    let mut clients = JoinSet::new();
    for _ in 0..connections {
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
    assert_eq!(summary.accepted_connections, connections as u64);
    assert_eq!(summary.completed_connections, connections as u64);
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
    assert_eq!(connect_received, connections);
    assert_eq!(connect_decision, connections);
    assert_eq!(stream_closed, connections);
}

fn configured_connections() -> usize {
    match env::var("MITM_CORE_CONCURRENCY") {
        Ok(raw) => parse_connections(&raw).unwrap_or(DEFAULT_CONNECTIONS),
        Err(_) => DEFAULT_CONNECTIONS,
    }
}

fn parse_connections(raw: &str) -> Result<usize, io::Error> {
    let value = raw.parse::<usize>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid MITM_CORE_CONCURRENCY value: {error}"),
        )
    })?;
    if value == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MITM_CORE_CONCURRENCY must be greater than zero",
        ));
    }
    Ok(value)
}
