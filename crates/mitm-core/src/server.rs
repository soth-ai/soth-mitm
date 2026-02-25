use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use mitm_http::ApplicationProtocol;
use mitm_observe::{Event, EventConsumer, EventType, FlowContext};
use mitm_policy::PolicyEngine;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

use crate::MitmEngine;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServerRunSummary {
    pub accepted_connections: u64,
    pub completed_connections: u64,
    pub failed_connections: u64,
}

pub async fn run_flow_lifecycle_server<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    listener: TcpListener,
    max_connections: usize,
) -> io::Result<ServerRunSummary>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut summary = ServerRunSummary::default();
    let mut tasks = JoinSet::new();

    for _ in 0..max_connections {
        let (stream, peer_addr) = listener.accept().await?;
        summary.accepted_connections += 1;
        let engine = Arc::clone(&engine);
        tasks
            .spawn(async move { close_connection_with_lifecycle(engine, stream, peer_addr).await });
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => summary.completed_connections += 1,
            Ok(Err(_)) | Err(_) => summary.failed_connections += 1,
        }
    }

    Ok(summary)
}

async fn close_connection_with_lifecycle<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    mut stream: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let client_addr = peer_addr.to_string();
    let flow_id = engine.allocate_flow_id();
    let outcome = engine.decide_connect(flow_id, client_addr.clone(), "<accepted>", 0, None, None);
    let context = FlowContext {
        flow_id: outcome.flow_id,
        client_addr,
        server_host: "<accepted>".to_string(),
        server_port: 0,
        protocol: ApplicationProtocol::Tunnel,
    };

    stream.shutdown().await?;

    let mut stream_closed = Event::new(EventType::StreamClosed, context);
    stream_closed.attributes =
        BTreeMap::from([("reason_code".to_string(), "accept_loop_closed".to_string())]);
    engine.emit_event(stream_closed);
    Ok(())
}
