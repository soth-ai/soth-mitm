async fn finalize_websocket_upgrade<P, S, D, U>(
    engine: Arc<MitmEngine<P, S>>,
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
            emit_stream_closed(
                &engine,
                websocket_context,
                CloseReasonCode::WebSocketError,
                Some(error.to_string()),
                Some(bytes_from_client),
                Some(bytes_from_server),
            );
        }
    }
    Ok(())
}

fn map_joined_direction_result(
    label: &str,
    joined: Result<io::Result<WebSocketDirectionOutcome>, tokio::task::JoinError>,
) -> io::Result<WebSocketDirectionOutcome> {
    match joined {
        Ok(result) => result,
        Err(join_error) => Err(io::Error::other(format!(
            "websocket {label} task join failed: {join_error}"
        ))),
    }
}

fn websocket_final_flush_reason(
    client_result: &io::Result<WebSocketDirectionOutcome>,
    server_result: &io::Result<WebSocketDirectionOutcome>,
) -> &'static str {
    if client_result.is_err() || server_result.is_err() {
        return "error";
    }

    let close_frame_seen = client_result
        .as_ref()
        .map(|outcome| outcome.close_frame_seen)
        .unwrap_or(false)
        || server_result
            .as_ref()
            .map(|outcome| outcome.close_frame_seen)
            .unwrap_or(false);
    if close_frame_seen {
        "close_frame"
    } else {
        "eof"
    }
}

fn websocket_now_unix_ms() -> u128 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    }
}
