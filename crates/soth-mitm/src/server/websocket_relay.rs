use super::flow_hooks::FlowHooks;
use super::io_timeouts::{
    flush_with_websocket_idle_timeout, shutdown_with_websocket_idle_timeout,
    write_all_with_websocket_idle_timeout,
};
use super::runtime_governor;
use super::websocket_codec::validate_websocket_mask_direction;
use super::websocket_events::{emit_websocket_closed_event, emit_websocket_opened_event};
use super::websocket_relay_io::{
    read_websocket_frame_header, relay_websocket_payload, PrefixedReader,
};
use super::BufferedConn;
use crate::engine::MitmEngine;
use crate::observe::{EventConsumer, FlowContext};
use crate::policy::PolicyEngine;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) const WS_FRAME_COPY_CHUNK_SIZE: usize = 8 * 1024;
pub(crate) const WS_OPCODE_CLOSE: u8 = 0x8;
pub(crate) const WS_TURN_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(750);

/// Negotiated permessage-deflate parameters parsed from the
/// `Sec-WebSocket-Extensions` response header (RFC 7692).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeflateConfig {
    /// Server resets compression context after each message.
    pub(crate) server_no_context_takeover: bool,
    /// Client resets compression context after each message.
    pub(crate) client_no_context_takeover: bool,
    /// Server max window bits (default 15).
    pub(crate) server_max_window_bits: u8,
    /// Client max window bits (default 15).
    pub(crate) client_max_window_bits: u8,
}

/// Parse `DeflateConfig` from a 101 response's `Sec-WebSocket-Extensions` header.
/// Returns `None` if permessage-deflate was not negotiated.
pub(crate) fn parse_deflate_config(headers: &[super::HttpHeader]) -> Option<DeflateConfig> {
    for h in headers {
        if !h.name.eq_ignore_ascii_case("sec-websocket-extensions") {
            continue;
        }
        let value = h.value.to_ascii_lowercase();
        if !value.contains("permessage-deflate") {
            continue;
        }
        let server_bits = parse_window_bits(&value, "server_max_window_bits");
        let client_bits = parse_window_bits(&value, "client_max_window_bits");
        return Some(DeflateConfig {
            server_no_context_takeover: value.contains("server_no_context_takeover"),
            client_no_context_takeover: value.contains("client_no_context_takeover"),
            server_max_window_bits: server_bits,
            client_max_window_bits: client_bits,
        });
    }
    None
}
/// Parse `server_max_window_bits=N` or `client_max_window_bits=N` from the extension header.
/// Returns 15 (default) if not specified or invalid.
fn parse_window_bits(header: &str, param: &str) -> u8 {
    if let Some(pos) = header.find(param) {
        let rest = &header[pos + param.len()..];
        if let Some(rest) = rest.strip_prefix('=') {
            let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(bits) = num.parse::<u8>() {
                if (8..=15).contains(&bits) {
                    return bits;
                }
            }
        }
    }
    15
}

/// Maximum time to wait for the reverse close frame after forwarding a close
/// frame from the peer. Per RFC 6455 Section 5.5.1, the remote endpoint MUST
/// reply with a close frame, but we bound the wait to avoid hanging forever.
const WS_CLOSE_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
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
    /// RSV1 bit — set on the first frame of a compressed message (permessage-deflate).
    pub(crate) rsv1: bool,
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
    deflate_config: Option<DeflateConfig>,
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
            deflate_config,
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
    // Shared close-handshake signaling: when one direction forwards a close
    // frame, it notifies the peer direction so it can apply a bounded timeout
    // for the reverse close frame (RFC 6455 Section 5.5.1).
    let (close_tx, close_rx) = tokio::sync::watch::channel(false);
    let close_tx = Arc::new(close_tx);
    let client_task = tokio::spawn(relay_websocket_direction(
        crate::protocol::WsDirection::ClientToServer,
        PrefixedReader::new(downstream_prefetch, downstream_read),
        Arc::clone(&upstream_write),
        Arc::clone(&runtime_governor),
        Arc::clone(&frame_sequence),
        observer_tx.clone(),
        max_payload_capture_bytes,
        max_frame_payload_bytes,
        Arc::clone(&close_tx),
        close_rx.clone(),
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
        close_tx,
        close_rx,
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
    close_tx: Arc<tokio::sync::watch::Sender<bool>>,
    mut close_rx: tokio::sync::watch::Receiver<bool>,
) -> io::Result<WebSocketDirectionOutcome>
where
    R: AsyncRead + Unpin,
    WF: AsyncWrite + Unpin + Send + 'static,
{
    let mut bytes_forwarded = 0_u64;
    let mut frame_codec = soketto::base::Codec::new();
    frame_codec.set_max_data_size(max_frame_payload_bytes);
    loop {
        // If the peer direction already forwarded a close frame, apply a
        // bounded timeout for the reverse close frame from this source.
        let peer_closed = *close_rx.borrow_and_update();
        let next_frame = if peer_closed {
            match tokio::time::timeout(
                WS_CLOSE_HANDSHAKE_TIMEOUT,
                read_websocket_frame_header(&mut source, &frame_codec, max_frame_payload_bytes),
            )
            .await
            {
                Ok(result) => result?,
                Err(_elapsed) => {
                    tracing::trace!(
                        ?direction,
                        "websocket close handshake timed out waiting for reverse close frame"
                    );
                    let mut sink = forward_sink.lock().await;
                    let _ = shutdown_with_websocket_idle_timeout(
                        &mut *sink,
                        "websocket_close_handshake_timeout_shutdown",
                    )
                    .await;
                    return Ok(WebSocketDirectionOutcome {
                        bytes_forwarded,
                        close_frame_seen: false,
                    });
                }
            }
        } else {
            read_websocket_frame_header(&mut source, &frame_codec, max_frame_payload_bytes).await?
        };
        let Some((frame_header, header_view)) = next_frame else {
            let mut sink = forward_sink.lock().await;
            shutdown_with_websocket_idle_timeout(&mut *sink, "websocket_sink_shutdown").await?;
            return Ok(WebSocketDirectionOutcome {
                bytes_forwarded,
                close_frame_seen: false,
            });
        };
        let fin = header_view.fin;
        let rsv1 = header_view.rsv1;
        let opcode = header_view.opcode;
        let masked = header_view.masked;
        validate_websocket_mask_direction(direction, masked)?;
        super::websocket_codec::validate_websocket_frame_rfc6455(fin, opcode)?;
        let payload_len = header_view.payload_len as u64;
        let masking_key = header_view.mask.map(|value| value.to_be_bytes());

        {
            let _in_flight_lease = runtime_governor
                .reserve_in_flight_or_error(frame_header.len(), "websocket_frame_header_write")?;
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
            rsv1,
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
            // Signal the peer direction that a close frame was forwarded so it
            // can start a bounded wait for the reverse close frame.
            let _ = close_tx.send(true);
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

/// Inflate a permessage-deflate compressed WebSocket message payload.
///
/// Per RFC 7692, the compressed payload has the 4-byte trailer
/// `0x00 0x00 0xff 0xff` stripped. We re-append it before decompressing.
///
/// `max_output_bytes` caps the decompressed size to prevent zip-bomb DoS.
/// Called after message assembly (all fragments concatenated), so the input
/// is a complete compressed message.
pub(crate) fn inflate_permessage_deflate(
    compressed: &[u8],
    decompressor: &mut flate2::Decompress,
    max_output_bytes: usize,
) -> Option<bytes::Bytes> {
    if compressed.is_empty() {
        return Some(bytes::Bytes::new());
    }

    let mut input = Vec::with_capacity(compressed.len() + 4);
    input.extend_from_slice(compressed);
    input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);

    let cap = max_output_bytes.min(16 * 1024 * 1024); // hard cap 16 MB
    let mut output = Vec::with_capacity(compressed.len().saturating_mul(4).min(cap));

    // decompress_vec makes a single inflate() call — loop until all input
    // is consumed or the output cap is reached.
    let mut consumed = 0usize;
    loop {
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let result = decompressor.decompress_vec(
            &input[consumed..],
            &mut output,
            flate2::FlushDecompress::Sync,
        );
        let ate = (decompressor.total_in() - before_in) as usize;
        let produced = (decompressor.total_out() - before_out) as usize;
        consumed += ate;

        match result {
            Ok(flate2::Status::Ok | flate2::Status::StreamEnd) => {
                if output.len() > cap {
                    output.truncate(cap);
                }
                return Some(bytes::Bytes::from(output));
            }
            Ok(flate2::Status::BufError) => {
                if output.len() >= cap {
                    output.truncate(cap);
                    return Some(bytes::Bytes::from(output));
                }
                if ate == 0 && produced == 0 {
                    // No progress — avoid infinite loop.
                    output.reserve(4096.min(cap - output.len()));
                    if output.capacity() == output.len() {
                        return Some(bytes::Bytes::from(output));
                    }
                } else {
                    output.reserve(compressed.len().saturating_mul(2).min(cap - output.len()));
                }
            }
            Err(error) => {
                tracing::debug!(
                    compressed_len = compressed.len(),
                    consumed,
                    output_len = output.len(),
                    error = %error,
                    "permessage-deflate inflate failed"
                );
                // Reset the decompressor to prevent cascade failures —
                // after an error the internal zlib state is invalid and
                // every subsequent call would also fail.
                decompressor.reset(false);
                // Return partial output if we got any — partial decompression
                // is better than nothing for content inspection (WebSocket
                // message parsing can work with incomplete JSON).
                if !output.is_empty() {
                    return Some(bytes::Bytes::from(output));
                }
                return None;
            }
        }
    }
}
