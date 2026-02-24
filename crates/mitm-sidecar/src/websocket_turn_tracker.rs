async fn observe_websocket_frames<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    websocket_context: FlowContext,
    mut observer_rx: tokio::sync::mpsc::Receiver<WebSocketObserverMessage>,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut turn_aggregator = mitm_http::WebSocketTurnAggregator::new();
    let mut turn_state = WebSocketTurnTrackerState::default();
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
                        track_websocket_frame(
                            &engine,
                            websocket_context.clone(),
                            &mut turn_aggregator,
                            &mut turn_state,
                            frame,
                        );

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
        websocket_context,
        &mut turn_aggregator,
        &mut turn_state,
        final_flush_reason.unwrap_or("eof"),
    );

    Ok(())
}

fn track_websocket_frame<P, S>(
    engine: &MitmEngine<P, S>,
    websocket_context: FlowContext,
    turn_aggregator: &mut mitm_http::WebSocketTurnAggregator,
    turn_state: &mut WebSocketTurnTrackerState,
    frame: WebSocketFrameObservation,
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
    turn_aggregator: &mut mitm_http::WebSocketTurnAggregator,
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
