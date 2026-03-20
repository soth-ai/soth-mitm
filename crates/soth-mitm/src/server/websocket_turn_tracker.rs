use super::flow_hooks::{FlowHooks, StreamChunk};
use crate::types::FrameDirection;

fn ws_direction_to_frame(dir: crate::protocol::WsDirection) -> Option<FrameDirection> {
    match dir {
        crate::protocol::WsDirection::ClientToServer => Some(FrameDirection::ClientToServer),
        crate::protocol::WsDirection::ServerToClient => Some(FrameDirection::ServerToClient),
    }
}
use super::websocket_events::{
    emit_websocket_frame_event, emit_websocket_turn_completed_event,
    emit_websocket_turn_started_event,
};
use super::websocket_relay::{
    DeflateConfig, WebSocketFrameObservation, WebSocketObserverMessage, WebSocketTurnTrackerState,
    WS_OPCODE_CLOSE, WS_TURN_IDLE_TIMEOUT,
};
use crate::engine::MitmEngine;
use crate::observe::{EventConsumer, FlowContext};
use crate::policy::PolicyEngine;
use crate::types::FrameKind;
use std::io;
use std::sync::Arc;

pub(crate) async fn observe_websocket_frames<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    websocket_context: FlowContext,
    flow_hooks: Arc<dyn FlowHooks>,
    mut observer_rx: tokio::sync::mpsc::Receiver<WebSocketObserverMessage>,
    deflate_config: Option<DeflateConfig>,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut turn_aggregator = crate::protocol::WebSocketTurnAggregator::new();
    let mut turn_state = WebSocketTurnTrackerState::default();
    let mut message_assemblers = WebSocketMessageAssemblers::default();
    // Per-direction inflate state for permessage-deflate decompression.
    let mut client_inflate = if deflate_config.is_some() {
        Some(flate2::Decompress::new(false))
    } else {
        None
    };
    let mut server_inflate = if deflate_config.is_some() {
        Some(flate2::Decompress::new(false))
    } else {
        None
    };
    let mut final_flush_reason: Option<&'static str> = None;
    let idle_deadline = tokio::time::Instant::now() + WS_TURN_IDLE_TIMEOUT;
    let idle_sleep = tokio::time::sleep_until(idle_deadline);
    tokio::pin!(idle_sleep);
    let mut idle_armed = false;

    loop {
        tokio::select! {
            message = observer_rx.recv() => {
                match message {
                    Some(WebSocketObserverMessage::Frame(frame)) => {
                        let inflate = match frame.direction {
                            crate::protocol::WsDirection::ClientToServer => client_inflate.as_mut(),
                            crate::protocol::WsDirection::ServerToClient => server_inflate.as_mut(),
                        };
                        track_websocket_frame(
                            &engine,
                            websocket_context.clone(),
                            &flow_hooks,
                            &mut turn_aggregator,
                            &mut turn_state,
                            &mut message_assemblers,
                            frame,
                            inflate,
                            deflate_config,
                        )
                        .await;

                        if turn_state.active_turn_id.is_some() && !turn_state.closing {
                            idle_sleep.as_mut().reset(tokio::time::Instant::now() + WS_TURN_IDLE_TIMEOUT);
                            idle_armed = true;
                        } else {
                            idle_armed = false;
                        }
                    }
                    Some(WebSocketObserverMessage::FinalFlushReason(reason)) => {
                        final_flush_reason = Some(reason);
                        if reason == "error" {
                            flush_pending_turn(
                                &engine,
                                websocket_context.clone(),
                                &mut turn_aggregator,
                                &mut turn_state,
                                reason,
                            );
                            idle_armed = false;
                        }
                    }
                    None => break,
                }
            }
            _ = &mut idle_sleep, if idle_armed => {
                flush_pending_turn(
                    &engine,
                    websocket_context.clone(),
                    &mut turn_aggregator,
                    &mut turn_state,
                    "idle_timeout",
                );
                idle_armed = false;
            }
        }
    }

    flush_pending_turn(
        &engine,
        websocket_context.clone(),
        &mut turn_aggregator,
        &mut turn_state,
        final_flush_reason.unwrap_or("eof"),
    );
    flow_hooks.on_stream_end(websocket_context).await;

    Ok(())
}

#[derive(Debug, Default)]
struct WebSocketMessageAssemblers {
    client_to_server: WebSocketMessageAssembler,
    server_to_client: WebSocketMessageAssembler,
}

#[derive(Debug, Default)]
struct WebSocketMessageAssembler {
    frame_kind: Option<FrameKind>,
    payload: Vec<u8>,
    /// True if the first frame of this message had RSV1 set (permessage-deflate).
    rsv1_compressed: bool,
}

fn assembler_for_direction_mut(
    assemblers: &mut WebSocketMessageAssemblers,
    direction: crate::protocol::WsDirection,
) -> &mut WebSocketMessageAssembler {
    match direction {
        crate::protocol::WsDirection::ClientToServer => &mut assemblers.client_to_server,
        crate::protocol::WsDirection::ServerToClient => &mut assemblers.server_to_client,
    }
}

/// Inflate a compressed message if an inflate state is available.
/// Falls back to passing the raw bytes if decompression fails.
/// When `reset_after` is true (no_context_takeover), resets the
/// decompressor after each successful decompression.
fn maybe_inflate(
    compressed: &[u8],
    inflate: Option<&mut flate2::Decompress>,
    max_output_bytes: usize,
    reset_after: bool,
) -> bytes::Bytes {
    let Some(decompressor) = inflate else {
        return bytes::Bytes::from(compressed.to_vec());
    };
    let result = super::websocket_relay::inflate_permessage_deflate(
        compressed,
        decompressor,
        max_output_bytes,
    );
    match result {
        Some(bytes) => {
            if reset_after {
                decompressor.reset(false);
            }
            bytes
        }
        None => {
            // inflate_permessage_deflate already resets the decompressor on error.
            bytes::Bytes::from(compressed.to_vec())
        }
    }
}

fn append_with_cap(buffer: &mut Vec<u8>, payload: &[u8], cap: usize) {
    if buffer.len() >= cap {
        return;
    }
    let take = (cap - buffer.len()).min(payload.len());
    buffer.extend_from_slice(&payload[..take]);
}

async fn track_websocket_frame<P, S>(
    engine: &MitmEngine<P, S>,
    websocket_context: FlowContext,
    flow_hooks: &Arc<dyn FlowHooks>,
    turn_aggregator: &mut crate::protocol::WebSocketTurnAggregator,
    turn_state: &mut WebSocketTurnTrackerState,
    message_assemblers: &mut WebSocketMessageAssemblers,
    frame: WebSocketFrameObservation,
    inflate: Option<&mut flate2::Decompress>,
    deflate_config: Option<DeflateConfig>,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    emit_websocket_frame_event(
        engine,
        websocket_context.clone(),
        frame.direction,
        frame.kind,
        frame.sequence_no,
        frame.opcode,
        frame.fin,
        frame.masked,
        frame.payload_len,
        frame.frame_len,
    );

    let max_message_bytes = engine.config.max_flow_decoder_buffer_bytes.max(1);
    // Determine if the decompressor should be reset after this message
    // (RFC 7692 no_context_takeover — sender resets context per message,
    // so our decompressor must also reset to stay in sync).
    let reset_after_inflate = deflate_config
        .map(|cfg| match frame.direction {
            crate::protocol::WsDirection::ServerToClient => cfg.server_no_context_takeover,
            crate::protocol::WsDirection::ClientToServer => cfg.client_no_context_takeover,
        })
        .unwrap_or(false);
    let assembler = assembler_for_direction_mut(message_assemblers, frame.direction);
    match frame.opcode {
        0x1 | 0x2 => {
            let frame_kind = if frame.opcode == 0x1 {
                FrameKind::WebSocketText
            } else {
                FrameKind::WebSocketBinary
            };
            if frame.fin {
                // Single-frame complete message — decompress if RSV1 set.
                let payload = if frame.rsv1 {
                    maybe_inflate(
                        frame.payload.as_ref(),
                        inflate,
                        max_message_bytes,
                        reset_after_inflate,
                    )
                } else {
                    frame.payload.clone()
                };
                let sequence = turn_state.next_chunk_sequence;
                turn_state.next_chunk_sequence += 1;
                flow_hooks
                    .on_stream_chunk(
                        websocket_context.clone(),
                        StreamChunk {
                            payload,
                            sequence,
                            frame_kind,
                            direction: ws_direction_to_frame(frame.direction),
                        },
                    )
                    .await;
                assembler.frame_kind = None;
                assembler.payload.clear();
            } else {
                assembler.frame_kind = Some(frame_kind);
                assembler.rsv1_compressed = frame.rsv1;
                assembler.payload.clear();
                append_with_cap(
                    &mut assembler.payload,
                    frame.payload.as_ref(),
                    max_message_bytes,
                );
            }
        }
        0x0 => {
            if let Some(frame_kind) = assembler.frame_kind {
                append_with_cap(
                    &mut assembler.payload,
                    frame.payload.as_ref(),
                    max_message_bytes,
                );
                if frame.fin {
                    // Multi-frame assembled message — decompress if first frame had RSV1.
                    let raw = std::mem::take(&mut assembler.payload);
                    let payload = if assembler.rsv1_compressed {
                        maybe_inflate(&raw, inflate, max_message_bytes, reset_after_inflate)
                    } else {
                        bytes::Bytes::from(raw)
                    };
                    let sequence = turn_state.next_chunk_sequence;
                    turn_state.next_chunk_sequence += 1;
                    flow_hooks
                        .on_stream_chunk(
                            websocket_context.clone(),
                            StreamChunk {
                                payload,
                                sequence,
                                frame_kind,
                                direction: ws_direction_to_frame(frame.direction),
                            },
                        )
                        .await;
                    assembler.frame_kind = None;
                    assembler.rsv1_compressed = false;
                }
            }
        }
        0x9 => {}
        0x8 => {
            let sequence = turn_state.next_chunk_sequence;
            turn_state.next_chunk_sequence += 1;
            flow_hooks
                .on_stream_chunk(
                    websocket_context.clone(),
                    StreamChunk {
                        payload: frame.payload.clone(),
                        sequence,
                        frame_kind: FrameKind::WebSocketClose,
                        direction: ws_direction_to_frame(frame.direction),
                    },
                )
                .await;
        }
        _ => {}
    }

    if turn_state.closing {
        return;
    }

    if turn_state.active_turn_id.is_none() {
        start_turn(engine, websocket_context.clone(), turn_state, &frame);
    }

    let payload_len = usize::try_from(frame.payload_len).unwrap_or(usize::MAX);
    if let Some(turn) = turn_aggregator.on_frame(
        frame.direction,
        frame.kind,
        payload_len,
        frame.observed_at_unix_ms,
    ) {
        emit_websocket_turn_completed_event(engine, websocket_context.clone(), &turn, "rollover");
        turn_state.active_turn_id = None;
        start_turn(engine, websocket_context.clone(), turn_state, &frame);
    }

    if frame.opcode == WS_OPCODE_CLOSE {
        flush_pending_turn(
            engine,
            websocket_context,
            turn_aggregator,
            turn_state,
            "close_frame",
        );
        turn_state.closing = true;
    }
}

fn start_turn<P, S>(
    engine: &MitmEngine<P, S>,
    websocket_context: FlowContext,
    turn_state: &mut WebSocketTurnTrackerState,
    frame: &WebSocketFrameObservation,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let turn_id = turn_state.next_turn_id;
    turn_state.next_turn_id += 1;
    turn_state.active_turn_id = Some(turn_id);
    emit_websocket_turn_started_event(
        engine,
        websocket_context,
        turn_id,
        frame.direction,
        frame.sequence_no,
        frame.observed_at_unix_ms,
    );
}

fn flush_pending_turn<P, S>(
    engine: &MitmEngine<P, S>,
    websocket_context: FlowContext,
    turn_aggregator: &mut crate::protocol::WebSocketTurnAggregator,
    turn_state: &mut WebSocketTurnTrackerState,
    reason: &str,
) where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    if let Some(turn) = turn_aggregator.flush() {
        emit_websocket_turn_completed_event(engine, websocket_context, &turn, reason);
    }
    turn_state.active_turn_id = None;
}
