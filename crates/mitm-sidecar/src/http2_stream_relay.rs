use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

const H2_MAX_CONCURRENT_STREAMS: u32 = 128;
const H2_INITIAL_WINDOW_SIZE: u32 = 65_535;
const H2_INITIAL_CONNECTION_WINDOW_SIZE: u32 = 262_144;
const H2_MAX_SEND_BUFFER_SIZE: usize = 128 * 1024;
const H2_FORWARD_CHUNK_LIMIT: usize = 16 * 1024;
static H2_RELAY_DEBUG_ENABLED: OnceLock<bool> = OnceLock::new();

fn h2_relay_debug_enabled() -> bool {
    *H2_RELAY_DEBUG_ENABLED.get_or_init(|| {
        std::env::var("SOTH_MITM_H2_RELAY_DEBUG")
            .ok()
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

fn h2_relay_debug(message: impl AsRef<str>) {
    if h2_relay_debug_enabled() {
        tracing::debug!("{}", message.as_ref());
    }
}

#[derive(Clone)]
struct H2ByteCounters {
    request_bytes: Arc<AtomicU64>,
    response_bytes: Arc<AtomicU64>,
}

async fn relay_http2_connection<P, S, D, U>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    tunnel_context: FlowContext,
    process_info: Option<mitm_policy::ProcessInfo>,
    downstream_tls: D,
    upstream_tls: U,
    max_header_list_size: u32,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut downstream_builder = h2::server::Builder::new();
    configure_h2_server(&mut downstream_builder, max_header_list_size);
    let mut downstream_connection = match downstream_builder.handshake(downstream_tls).await {
        Ok(connection) => connection,
        Err(error) => {
            emit_stream_closed(
                &engine,
                FlowContext {
                    protocol: ApplicationProtocol::Http2,
                    ..tunnel_context
                },
                CloseReasonCode::MitmHttpError,
                Some(format!("downstream HTTP/2 handshake failed: {error}")),
                None,
                None,
            );
            return Ok(());
        }
    };

    let mut upstream_builder = h2::client::Builder::new();
    configure_h2_client(&mut upstream_builder, max_header_list_size);
    let (upstream_sender, upstream_connection) = match upstream_builder.handshake(upstream_tls).await {
        Ok(connection_parts) => connection_parts,
        Err(error) => {
            emit_stream_closed(
                &engine,
                FlowContext {
                    protocol: ApplicationProtocol::Http2,
                    ..tunnel_context
                },
                CloseReasonCode::MitmHttpError,
                Some(format!("upstream HTTP/2 handshake failed: {error}")),
                None,
                None,
            );
            return Ok(());
        }
    };
    let upstream_connection_task = tokio::spawn(upstream_connection);

    let http2_context = FlowContext {
        protocol: ApplicationProtocol::Http2,
        ..tunnel_context.clone()
    };
    let byte_counters = H2ByteCounters {
        request_bytes: Arc::new(AtomicU64::new(0)),
        response_bytes: Arc::new(AtomicU64::new(0)),
    };
    let mut stream_tasks = tokio::task::JoinSet::new();
    let mut first_error: Option<io::Error> = None;

    while let Some(next_stream) = downstream_connection.accept().await {
        match next_stream {
            Ok((request, respond)) => {
                let stream_engine = Arc::clone(&engine);
                let stream_runtime_governor = Arc::clone(&runtime_governor);
                let stream_context = FlowContext {
                    flow_id: stream_engine.allocate_flow_id(),
                    ..http2_context.clone()
                };
                let stream_upstream_sender = upstream_sender.clone();
                let stream_byte_counters = byte_counters.clone();
                let stream_flow_hooks = Arc::clone(&flow_hooks);
                let stream_process_info = process_info.clone();
                stream_tasks.spawn(async move {
                    stream_flow_hooks
                        .on_connection_open(stream_context.clone(), stream_process_info)
                        .await;
                    relay_http2_stream(
                        stream_engine,
                        stream_runtime_governor,
                        stream_flow_hooks,
                        stream_context,
                        stream_upstream_sender,
                        request,
                        respond,
                        max_header_list_size,
                        stream_byte_counters,
                    )
                    .await
                });
            }
            Err(error) => {
                if !is_h2_nonfatal_stream_error(&error) && first_error.is_none() {
                    first_error = Some(h2_error_to_io("downstream HTTP/2 accept failed", error));
                }
                break;
            }
        }
    }

    while let Some(task_result) = stream_tasks.join_next().await {
        match task_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if !is_benign_h2_stream_io_error(&error) && first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(join_error) => {
                if first_error.is_none() {
                    first_error = Some(io::Error::other(format!(
                        "HTTP/2 stream task join failed: {join_error}"
                    )));
                }
            }
        }
    }

    drop(upstream_sender);

    match upstream_connection_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            if !is_h2_nonfatal_stream_error(&error) && first_error.is_none() {
                first_error = Some(h2_error_to_io("upstream HTTP/2 driver failed", error));
            }
        }
        Err(join_error) => {
            if first_error.is_none() {
                first_error = Some(io::Error::other(format!(
                    "HTTP/2 upstream task join failed: {join_error}"
                )));
            }
        }
    }

    let bytes_from_client = byte_counters.request_bytes.load(Ordering::Relaxed);
    let bytes_from_server = byte_counters.response_bytes.load(Ordering::Relaxed);

    if let Some(error) = first_error {
        let close_reason = if is_stream_stage_timeout(&error) {
            CloseReasonCode::StreamStageTimeout
        } else if is_idle_watchdog_timeout(&error) {
            CloseReasonCode::IdleWatchdogTimeout
        } else {
            CloseReasonCode::MitmHttpError
        };
        emit_stream_closed(
            &engine,
            http2_context,
            close_reason,
            Some(error.to_string()),
            Some(bytes_from_client),
            Some(bytes_from_server),
        );
    } else {
        emit_stream_closed(
            &engine,
            http2_context,
            CloseReasonCode::MitmHttpCompleted,
            None,
            Some(bytes_from_client),
            Some(bytes_from_server),
        );
    }

    Ok(())
}

include!("http2_stream_relay_body.rs");
