use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use crate::engine::MitmEngine;
use crate::observe::{EventConsumer, FlowContext};
use crate::policy::PolicyEngine;
use crate::protocol::ApplicationProtocol;
use super::{BufferedConn};
use super::runtime_governor;
use super::flow_hooks::FlowHooks;
use super::close_codes::CloseReasonCode;
use super::event_emitters::emit_stream_closed;
use super::io_timeouts::{is_idle_watchdog_timeout, is_stream_stage_timeout};
use super::websocket_relay::relay_websocket_connection;

pub(crate) async fn finalize_websocket_upgrade<P, S, D, U>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    tunnel_context: &FlowContext,
    downstream: BufferedConn<D>,
    upstream: BufferedConn<U>,
    mut bytes_from_client: u64,
    mut bytes_from_server: u64,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let websocket_context = FlowContext {
        protocol: ApplicationProtocol::WebSocket,
        ..tunnel_context.clone()
    };
    match relay_websocket_connection(
        Arc::clone(&engine),
        runtime_governor,
        flow_hooks,
        websocket_context.clone(),
        downstream,
        upstream,
    )
    .await
    {
        Ok(outcome) => {
            bytes_from_client += outcome.bytes_from_client;
            bytes_from_server += outcome.bytes_from_server;
            emit_stream_closed(
                &engine,
                websocket_context,
                CloseReasonCode::WebSocketCompleted,
                None,
                Some(bytes_from_client),
                Some(bytes_from_server),
            );
        }
        Err(error) => {
            let reason = if is_idle_watchdog_timeout(&error) {
                CloseReasonCode::IdleWatchdogTimeout
            } else if is_stream_stage_timeout(&error) {
                CloseReasonCode::StreamStageTimeout
            } else {
                CloseReasonCode::WebSocketError
            };
            emit_stream_closed(
                &engine,
                websocket_context,
                reason,
                Some(error.to_string()),
                Some(bytes_from_client),
                Some(bytes_from_server),
            );
        }
    }
    Ok(())
}

