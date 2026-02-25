const WS_FRAME_COPY_CHUNK_SIZE: usize = 8 * 1024;
const WS_MAX_FRAME_HEADER_BYTES: usize = 14;
const WS_OPCODE_CLOSE: u8 = 0x8;
const WS_OPCODE_PING: u8 = 0x9;
const WS_OPCODE_PONG: u8 = 0xA;
const WS_CONTROL_MAX_PAYLOAD_BYTES: u64 = 125;
const WS_TURN_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(750);
const WS_OBSERVER_CHANNEL_CAPACITY: usize = 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WebSocketRelayOutcome {
    bytes_from_client: u64,
    bytes_from_server: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WebSocketDirectionOutcome {
    bytes_forwarded: u64,
    close_frame_seen: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct WebSocketFrameObservation {
    direction: mitm_http::WsDirection,
    kind: mitm_http::WsFrameKind,
    sequence_no: u64,
    opcode: u8,
    fin: bool,
    masked: bool,
    payload_len: u64,
    frame_len: u64,
    payload: bytes::Bytes,
    observed_at_unix_ms: u128,
}
enum WebSocketObserverMessage {
    Frame(WebSocketFrameObservation),
    FinalFlushReason(&'static str),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WebSocketTurnTrackerState {
    next_turn_id: u64,
    next_chunk_sequence: u64,
    active_turn_id: Option<u64>,
    closing: bool,
}

impl Default for WebSocketTurnTrackerState {
    fn default() -> Self {
        Self {
            next_turn_id: 1,
            next_chunk_sequence: 0,
            active_turn_id: None,
            closing: false,
        }
    }
}
async fn relay_websocket_connection<P, S, D, U>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    websocket_context: FlowContext,
    downstream: BufferedConn<D>,
    upstream: BufferedConn<U>,
) -> io::Result<WebSocketRelayOutcome>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    emit_websocket_opened_event(&engine, websocket_context.clone());
    let BufferedConn {
        stream: downstream_stream,
        read_buf: downstream_prefetch,
    } = downstream;
    let BufferedConn {
        stream: upstream_stream,
        read_buf: upstream_prefetch,
    } = upstream;
    let (observer_tx, observer_rx) = tokio::sync::mpsc::channel(WS_OBSERVER_CHANNEL_CAPACITY);
    let observer_engine = Arc::clone(&engine);
    let observer_context = websocket_context.clone();
    let observer_hooks = Arc::clone(&flow_hooks);
    let observer_task = tokio::spawn(async move {
        observe_websocket_frames(
            observer_engine,
            observer_context,
            observer_hooks,
            observer_rx,
        )
        .await
    });
    let (downstream_read, downstream_write) = tokio::io::split(downstream_stream);
    let (upstream_read, upstream_write) = tokio::io::split(upstream_stream);
    let downstream_write = Arc::new(tokio::sync::Mutex::new(downstream_write));
    let upstream_write = Arc::new(tokio::sync::Mutex::new(upstream_write));
    let frame_sequence = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let max_payload_capture_bytes = engine.config.max_flow_decoder_buffer_bytes.max(1);
    let client_task = tokio::spawn(relay_websocket_direction(
        mitm_http::WsDirection::ClientToServer,
        PrefixedReader::new(downstream_prefetch, downstream_read),
        Arc::clone(&upstream_write),
        Arc::clone(&downstream_write),
        Arc::clone(&runtime_governor),
        Arc::clone(&frame_sequence),
        observer_tx.clone(),
        max_payload_capture_bytes,
    ));
    let server_task = tokio::spawn(relay_websocket_direction(
        mitm_http::WsDirection::ServerToClient,
        PrefixedReader::new(upstream_prefetch, upstream_read),
        downstream_write,
        upstream_write,
        runtime_governor,
        Arc::clone(&frame_sequence),
        observer_tx.clone(),
        max_payload_capture_bytes,
    ));
    let (client_join, server_join) = tokio::join!(client_task, server_task);
    let client_result = map_joined_direction_result("client_to_server", client_join);
    let server_result = map_joined_direction_result("server_to_client", server_join);

    let bytes_from_client = client_result
        .as_ref()
        .map(|outcome| outcome.bytes_forwarded)
        .unwrap_or_default();
    let bytes_from_server = server_result
        .as_ref()
        .map(|outcome| outcome.bytes_forwarded)
        .unwrap_or_default();
    let final_flush_reason = websocket_final_flush_reason(&client_result, &server_result);
    let _ = observer_tx
        .send(WebSocketObserverMessage::FinalFlushReason(
            final_flush_reason,
        ))
        .await;
    drop(observer_tx);
    let observer_result = match observer_task.await {
        Ok(result) => result,
        Err(join_error) => Err(io::Error::other(format!(
            "websocket observer task join failed: {join_error}"
        ))),
    };
    if client_result.is_ok() && server_result.is_ok() && observer_result.is_ok() {
        emit_websocket_closed_event(
            &engine,
            websocket_context,
            final_flush_reason,
            None,
            bytes_from_client,
            bytes_from_server,
        );
        return Ok(WebSocketRelayOutcome {
            bytes_from_client,
            bytes_from_server,
        });
    }
    let mut error_detail_parts = Vec::new();
    if let Err(error) = &client_result {
        error_detail_parts.push(format!("client_to_server={error}"));
    }
    if let Err(error) = &server_result {
        error_detail_parts.push(format!("server_to_client={error}"));
    }
    if let Err(error) = &observer_result {
        error_detail_parts.push(format!("observer={error}"));
    }
    emit_websocket_closed_event(
        &engine,
        websocket_context,
        "error",
        Some(error_detail_parts.join("; ")),
        bytes_from_client,
        bytes_from_server,
    );
    client_result?;
    server_result?;
    observer_result?;

    Err(io::Error::other("websocket relay failed"))
}

async fn relay_websocket_direction<R, WF, WC>(
    direction: mitm_http::WsDirection,
    mut source: PrefixedReader<R>,
    forward_sink: Arc<tokio::sync::Mutex<WF>>,
    control_sink: Arc<tokio::sync::Mutex<WC>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    frame_sequence: Arc<std::sync::atomic::AtomicU64>,
    observer_tx: tokio::sync::mpsc::Sender<WebSocketObserverMessage>,
    max_payload_capture_bytes: usize,
) -> io::Result<WebSocketDirectionOutcome>
where
    R: AsyncRead + Unpin,
    WF: AsyncWrite + Unpin + Send + 'static,
    WC: AsyncWrite + Unpin + Send + 'static,
{
    let mut bytes_forwarded = 0_u64;
    loop {
        let mut initial_header = [0_u8; 2];
        let has_frame = source.read_exact_or_eof(&mut initial_header).await?;
        if !has_frame {
            let mut sink = forward_sink.lock().await;
            shutdown_with_idle_timeout(&mut *sink, "websocket_sink_shutdown").await?;
            return Ok(WebSocketDirectionOutcome {
                bytes_forwarded,
                close_frame_seen: false,
            });
        }

        let mut frame_header = Vec::with_capacity(WS_MAX_FRAME_HEADER_BYTES);
        frame_header.extend_from_slice(&initial_header);
        let fin = (initial_header[0] & 0b1000_0000) != 0;
        let opcode = initial_header[0] & 0b0000_1111;
        let masked = (initial_header[1] & 0b1000_0000) != 0;
        let mut payload_len = (initial_header[1] & 0b0111_1111) as u64;
        if (opcode & 0b1000) != 0 {
            if !fin {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fragmented websocket control frame",
                ));
            }
            if payload_len > WS_CONTROL_MAX_PAYLOAD_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "websocket control frame payload exceeds 125 bytes",
                ));
            }
        }
        let mut masking_key: Option<[u8; 4]> = None;
        if payload_len == 126 {
            let mut ext_len = [0_u8; 2];
            source
                .read_exact_required(&mut ext_len, "extended payload length")
                .await?;
            frame_header.extend_from_slice(&ext_len);
            payload_len = u16::from_be_bytes(ext_len) as u64;
        } else if payload_len == 127 {
            let mut ext_len = [0_u8; 8];
            source
                .read_exact_required(&mut ext_len, "extended payload length")
                .await?;
            frame_header.extend_from_slice(&ext_len);
            payload_len = u64::from_be_bytes(ext_len);
            if (payload_len & (1_u64 << 63)) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "websocket payload length used reserved high bit",
                ));
            }
        }
        if masked {
            let mut key = [0_u8; 4];
            source.read_exact_required(&mut key, "masking key").await?;
            frame_header.extend_from_slice(&key);
            masking_key = Some(key);
        }

        let payload = if opcode == WS_OPCODE_PING || opcode == WS_OPCODE_PONG {
            let payload = read_websocket_payload_captured(
                &mut source,
                payload_len,
                masking_key,
                max_payload_capture_bytes,
            )
            .await?;
            if opcode == WS_OPCODE_PING {
                send_websocket_pong(
                    direction,
                    &control_sink,
                    &runtime_governor,
                    payload.as_ref(),
                )
                .await?;
            }
            payload
        } else {
            {
                let _in_flight_lease = runtime_governor.reserve_in_flight_or_error(
                    frame_header.len(),
                    "websocket_frame_header_write",
                )?;
                let mut sink = forward_sink.lock().await;
                write_all_with_idle_timeout(
                    &mut *sink,
                    &frame_header,
                    "websocket_frame_header_write",
                )
                .await?;
            }
            bytes_forwarded += frame_header.len() as u64;
            let payload = {
                let mut sink = forward_sink.lock().await;
                relay_websocket_payload(
                    &mut source,
                    &mut *sink,
                    &runtime_governor,
                    payload_len,
                    masking_key,
                    max_payload_capture_bytes,
                )
                .await?
            };
            bytes_forwarded += payload_len;
            payload
        };

        let frame_kind = if (opcode & 0b1000) != 0 {
            mitm_http::WsFrameKind::Control
        } else {
            mitm_http::WsFrameKind::Data
        };
        let sequence_no = frame_sequence.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        let observation = WebSocketFrameObservation {
            direction,
            kind: frame_kind,
            sequence_no,
            opcode,
            fin,
            masked,
            payload_len,
            frame_len: frame_header.len() as u64 + payload_len,
            payload,
            observed_at_unix_ms: websocket_now_unix_ms(),
        };
        match observer_tx.try_send(WebSocketObserverMessage::Frame(observation)) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(message)) => {
                runtime_governor.mark_backpressure_activation();
                observer_tx.send(message).await.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "websocket observer channel closed",
                    )
                })?;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "websocket observer channel closed",
                ));
            }
        }

        if opcode == WS_OPCODE_CLOSE {
            let mut sink = forward_sink.lock().await;
            flush_with_idle_timeout(&mut *sink, "websocket_close_flush").await?;
            return Ok(WebSocketDirectionOutcome {
                bytes_forwarded,
                close_frame_seen: true,
            });
        }
    }
}
