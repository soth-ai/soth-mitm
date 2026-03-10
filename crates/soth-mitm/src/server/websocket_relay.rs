use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use crate::engine::MitmEngine;
use crate::observe::{EventConsumer, FlowContext};
use crate::policy::PolicyEngine;
use super::{BufferedConn};
use super::runtime_governor;
use super::flow_hooks::FlowHooks;
use super::io_timeouts::{
    write_all_with_websocket_idle_timeout, flush_with_websocket_idle_timeout,
    shutdown_with_websocket_idle_timeout,
};
use super::websocket_relay_io::{PrefixedReader, read_websocket_frame_header, relay_websocket_payload};
use super::websocket_codec::validate_websocket_mask_direction;
use super::websocket_events::{emit_websocket_opened_event, emit_websocket_closed_event};

pub(crate) const WS_FRAME_COPY_CHUNK_SIZE: usize = 8 * 1024;
pub(crate) const WS_OPCODE_CLOSE: u8 = 0x8;
pub(crate) const WS_TURN_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(750);
const WS_OBSERVER_CHANNEL_CAPACITY: usize = 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WebSocketRelayOutcome {
    pub(crate) bytes_from_client: u64,
    pub(crate) bytes_from_server: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WebSocketDirectionOutcome {
    pub(crate) bytes_forwarded: u64,
    pub(crate) close_frame_seen: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WebSocketFrameObservation {
    pub(crate) direction: crate::protocol::WsDirection,
    pub(crate) kind: crate::protocol::WsFrameKind,
    pub(crate) sequence_no: u64,
    pub(crate) opcode: u8,
    pub(crate) fin: bool,
    pub(crate) masked: bool,
    pub(crate) payload_len: u64,
    pub(crate) frame_len: u64,
    pub(crate) payload: bytes::Bytes,
    pub(crate) observed_at_unix_ms: u128,
}
pub(crate) enum WebSocketObserverMessage {
    Frame(WebSocketFrameObservation),
    FinalFlushReason(&'static str),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WebSocketTurnTrackerState {
    pub(crate) next_turn_id: u64,
    pub(crate) next_chunk_sequence: u64,
    pub(crate) active_turn_id: Option<u64>,
    pub(crate) closing: bool,
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
pub(crate) async fn relay_websocket_connection<P, S, D, U>(
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
        super::websocket_turn_tracker::observe_websocket_frames(
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
    let max_frame_payload_bytes = engine.config.max_flow_body_buffer_bytes.max(1);
    let client_task = tokio::spawn(relay_websocket_direction(
        crate::protocol::WsDirection::ClientToServer,
        PrefixedReader::new(downstream_prefetch, downstream_read),
        Arc::clone(&upstream_write),
        Arc::clone(&runtime_governor),
        Arc::clone(&frame_sequence),
        observer_tx.clone(),
        max_payload_capture_bytes,
        max_frame_payload_bytes,
    ));
    let server_task = tokio::spawn(relay_websocket_direction(
        crate::protocol::WsDirection::ServerToClient,
        PrefixedReader::new(upstream_prefetch, upstream_read),
        downstream_write,
        runtime_governor,
        Arc::clone(&frame_sequence),
        observer_tx.clone(),
        max_payload_capture_bytes,
        max_frame_payload_bytes,
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

async fn relay_websocket_direction<R, WF>(
    direction: crate::protocol::WsDirection,
    mut source: PrefixedReader<R>,
    forward_sink: Arc<tokio::sync::Mutex<WF>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    frame_sequence: Arc<std::sync::atomic::AtomicU64>,
    observer_tx: tokio::sync::mpsc::Sender<WebSocketObserverMessage>,
    max_payload_capture_bytes: usize,
    max_frame_payload_bytes: usize,
) -> io::Result<WebSocketDirectionOutcome>
where
    R: AsyncRead + Unpin,
    WF: AsyncWrite + Unpin + Send + 'static,
{
    let mut bytes_forwarded = 0_u64;
    let mut frame_codec = soketto::base::Codec::new();
        frame_codec.set_max_data_size(max_frame_payload_bytes);
    loop {
        let next_frame =
            read_websocket_frame_header(&mut source, &frame_codec, max_frame_payload_bytes)
                .await?;
        let Some((frame_header, header_view)) = next_frame
        else {
            let mut sink = forward_sink.lock().await;
            shutdown_with_websocket_idle_timeout(&mut *sink, "websocket_sink_shutdown").await?;
            return Ok(WebSocketDirectionOutcome {
                bytes_forwarded,
                close_frame_seen: false,
            });
        };
        let fin = header_view.fin;
        let opcode = header_view.opcode;
        let masked = header_view.masked;
        validate_websocket_mask_direction(direction, masked)?;
        let payload_len = header_view.payload_len as u64;
        let masking_key = header_view.mask.map(|value| value.to_be_bytes());

        {
            let _in_flight_lease = runtime_governor.reserve_in_flight_or_error(
                frame_header.len(),
                "websocket_frame_header_write",
            )?;
            let mut sink = forward_sink.lock().await;
            write_all_with_websocket_idle_timeout(
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

        let frame_kind = if (opcode & 0b1000) != 0 {
            crate::protocol::WsFrameKind::Control
        } else {
            crate::protocol::WsFrameKind::Data
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
            flush_with_websocket_idle_timeout(&mut *sink, "websocket_close_flush").await?;
            return Ok(WebSocketDirectionOutcome {
                bytes_forwarded,
                close_frame_seen: true,
            });
        }
    }
}

pub(crate) fn map_joined_direction_result(
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

pub(crate) fn websocket_final_flush_reason(
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

pub(crate) fn websocket_now_unix_ms() -> u128 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    }
}
