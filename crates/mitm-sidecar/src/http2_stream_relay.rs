use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

const H2_MAX_CONCURRENT_STREAMS: u32 = 128;
const H2_INITIAL_WINDOW_SIZE: u32 = 65_535;
const H2_INITIAL_CONNECTION_WINDOW_SIZE: u32 = 262_144;
const H2_MAX_SEND_BUFFER_SIZE: usize = 128 * 1024;
const H2_FORWARD_CHUNK_LIMIT: usize = 16 * 1024;
const H2_END_STREAM_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);
const H2_TRAILERS_WAIT_TIMEOUT: Duration = Duration::from_secs(2);
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
        eprintln!("{}", message.as_ref());
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
    tunnel_context: FlowContext,
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
                let stream_context = http2_context.clone();
                let stream_upstream_sender = upstream_sender.clone();
                let stream_byte_counters = byte_counters.clone();
                stream_tasks.spawn(async move {
                    relay_http2_stream(
                        stream_engine,
                        stream_runtime_governor,
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

async fn relay_http2_stream<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    stream_context: FlowContext,
    upstream_sender: h2::client::SendRequest<bytes::Bytes>,
    downstream_request: http::Request<h2::RecvStream>,
    mut downstream_respond: h2::server::SendResponse<bytes::Bytes>,
    max_header_list_size: u32,
    byte_counters: H2ByteCounters,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let (mut request_parts, mut downstream_request_body) = downstream_request.into_parts();
    if let Err(error) = enforce_h2_request_header_limit(&request_parts, max_header_list_size) {
        h2_relay_debug(format!(
            "[h2-relay:request] request header limit exceeded; resetting stream: {error}"
        ));
        downstream_respond.send_reset(h2::Reason::PROTOCOL_ERROR);
        return Ok(());
    }

    let grpc_observation = detect_grpc_request(&request_parts);
    if let Some(observation) = grpc_observation.as_ref() {
        emit_grpc_request_headers_event(
            &engine,
            stream_context.clone(),
            observation,
            &request_parts.headers,
        );
    }

    request_parts.version = http::Version::HTTP_2;
    let upstream_request = http::Request::from_parts(request_parts, ());
    let request_end_stream = downstream_request_body.is_end_stream();

    let mut ready_upstream_sender = match upstream_sender.ready().await {
        Ok(sender) => sender,
        Err(error) => {
            if is_h2_nonfatal_stream_error(&error) {
                downstream_respond.send_reset(h2_reason_for_downstream_reset(&error));
                return Ok(());
            }
            return Err(h2_error_to_io("upstream HTTP/2 sender not ready", error));
        }
    };
    let (upstream_response_future, mut upstream_request_stream) =
        match ready_upstream_sender.send_request(upstream_request, request_end_stream) {
            Ok(parts) => parts,
            Err(error) => {
                if is_h2_nonfatal_stream_error(&error) {
                    downstream_respond.send_reset(h2_reason_for_downstream_reset(&error));
                    return Ok(());
                }
                return Err(h2_error_to_io("forwarding HTTP/2 request failed", error));
            }
        };

    if !request_end_stream {
        let request_outcome = match with_stream_stage_timeout(
            "http2_request_body_relay",
            relay_h2_body(
                &mut downstream_request_body,
                &mut upstream_request_stream,
                &runtime_governor,
                "request",
            ),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                if is_benign_h2_stream_io_error(&error) {
                    upstream_request_stream.send_reset(h2::Reason::CANCEL);
                    downstream_respond.send_reset(h2::Reason::CANCEL);
                    return Ok(());
                }
                return Err(error);
            }
        };
        byte_counters
            .request_bytes
            .fetch_add(request_outcome.bytes_forwarded, Ordering::Relaxed);
    }

    let upstream_response_result = with_stream_stage_timeout(
        "http2_upstream_response_headers",
        async { Ok(upstream_response_future.await) },
    )
    .await?;
    let upstream_response = match upstream_response_result {
        Ok(response) => response,
        Err(error) => {
            if is_h2_nonfatal_stream_error(&error) {
                downstream_respond.send_reset(h2_reason_for_downstream_reset(&error));
                return Ok(());
            }
            return Err(h2_error_to_io(
                "awaiting upstream HTTP/2 response failed",
                error,
            ));
        }
    };
    let (response_parts, mut upstream_response_body) = upstream_response.into_parts();
    if enforce_h2_response_header_limit(&response_parts, max_header_list_size).is_err() {
        h2_relay_debug("[h2-relay:response] response header limit exceeded; resetting stream");
        downstream_respond.send_reset(h2::Reason::PROTOCOL_ERROR);
        return Ok(());
    }

    if let Some(observation) = grpc_observation.as_ref() {
        emit_grpc_response_headers_event(
            &engine,
            stream_context.clone(),
            observation,
            &response_parts,
        );
    }

    let response_end_stream = upstream_response_body.is_end_stream();
    let downstream_response = http::Response::from_parts(response_parts, ());
    let mut downstream_response_stream =
        match downstream_respond.send_response(downstream_response, response_end_stream) {
            Ok(stream) => stream,
            Err(error) => {
                if is_h2_nonfatal_stream_error(&error) {
                    return Ok(());
                }
                return Err(h2_error_to_io(
                    "sending downstream HTTP/2 response headers failed",
                    error,
                ));
            }
        };

    if !response_end_stream {
        let response_outcome = match with_stream_stage_timeout(
            "http2_response_body_relay",
            relay_h2_body(
                &mut upstream_response_body,
                &mut downstream_response_stream,
                &runtime_governor,
                "response",
            ),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                if is_benign_h2_stream_io_error(&error) {
                    downstream_response_stream.send_reset(h2::Reason::CANCEL);
                    return Ok(());
                }
                return Err(error);
            }
        };
        byte_counters
            .response_bytes
            .fetch_add(response_outcome.bytes_forwarded, Ordering::Relaxed);
        if let (Some(observation), Some(trailers)) = (
            grpc_observation.as_ref(),
            response_outcome.trailers.as_ref(),
        ) {
            emit_grpc_response_trailers_event(
                &engine,
                stream_context.clone(),
                observation,
                trailers,
            );
        }
    }

    Ok(())
}

include!("http2_stream_relay_body.rs");
