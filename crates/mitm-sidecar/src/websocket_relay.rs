const WS_FRAME_COPY_CHUNK_SIZE: usize = 8 * 1024;
const WS_MAX_FRAME_HEADER_BYTES: usize = 14;
const WS_OPCODE_CLOSE: u8 = 0x8;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WebSocketFrameObservation {
    direction: mitm_http::WsDirection,
    kind: mitm_http::WsFrameKind,
    sequence_no: u64,
    opcode: u8,
    fin: bool,
    masked: bool,
    payload_len: u64,
    frame_len: u64,
    observed_at_unix_ms: u128,
}

enum WebSocketObserverMessage {
    Frame(WebSocketFrameObservation),
    FinalFlushReason(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WebSocketTurnTrackerState {
    next_turn_id: u64,
    active_turn_id: Option<u64>,
    closing: bool,
}

impl Default for WebSocketTurnTrackerState {
    fn default() -> Self {
        Self {
            next_turn_id: 1,
            active_turn_id: None,
            closing: false,
        }
    }
}

struct PrefixedReader<R> {
    prefix: Vec<u8>,
    prefix_offset: usize,
    source: R,
}

impl<R> PrefixedReader<R> {
    fn new(prefix: Vec<u8>, source: R) -> Self {
        Self {
            prefix,
            prefix_offset: 0,
            source,
        }
    }
}

impl<R> PrefixedReader<R>
where
    R: AsyncRead + Unpin,
{
    async fn read_exact_or_eof(&mut self, out: &mut [u8]) -> io::Result<bool> {
        let mut written = 0_usize;
        while written < out.len() {
            if self.prefix_offset < self.prefix.len() {
                let available = self.prefix.len() - self.prefix_offset;
                let take = available.min(out.len() - written);
                out[written..written + take]
                    .copy_from_slice(&self.prefix[self.prefix_offset..self.prefix_offset + take]);
                self.prefix_offset += take;
                written += take;
                continue;
            }

            let read = self.source.read(&mut out[written..]).await?;
            if read == 0 {
                if written == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "websocket frame ended before expected bytes were read",
                ));
            }
            written += read;
        }
        Ok(true)
    }

    async fn read_exact_required(&mut self, out: &mut [u8], label: &str) -> io::Result<()> {
        if self.read_exact_or_eof(out).await? {
            return Ok(());
        }

        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("connection closed while reading websocket {label}"),
        ))
    }
}

async fn relay_websocket_connection<P, S, D, U>(
    engine: Arc<MitmEngine<P, S>>,
    websocket_context: FlowContext,
    downstream: BufferedConn<D>,
    upstream: BufferedConn<U>,
) -> io::Result<WebSocketRelayOutcome>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
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
    let observer_task = tokio::spawn(async move {
        observe_websocket_frames(observer_engine, observer_context, observer_rx).await
    });

    let (downstream_read, downstream_write) = tokio::io::split(downstream_stream);
    let (upstream_read, upstream_write) = tokio::io::split(upstream_stream);
    let frame_sequence = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let client_task = tokio::spawn(relay_websocket_direction(
        mitm_http::WsDirection::ClientToServer,
        PrefixedReader::new(downstream_prefetch, downstream_read),
        upstream_write,
        Arc::clone(&frame_sequence),
        observer_tx.clone(),
    ));
    let server_task = tokio::spawn(relay_websocket_direction(
        mitm_http::WsDirection::ServerToClient,
        PrefixedReader::new(upstream_prefetch, upstream_read),
        downstream_write,
        Arc::clone(&frame_sequence),
        observer_tx.clone(),
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
        .send(WebSocketObserverMessage::FinalFlushReason(final_flush_reason))
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

async fn relay_websocket_direction<R, W>(
    direction: mitm_http::WsDirection,
    mut source: PrefixedReader<R>,
    mut sink: W,
    frame_sequence: Arc<std::sync::atomic::AtomicU64>,
    observer_tx: tokio::sync::mpsc::Sender<WebSocketObserverMessage>,
) -> io::Result<WebSocketDirectionOutcome>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut bytes_forwarded = 0_u64;
    loop {
        let mut initial_header = [0_u8; 2];
        let has_frame = source.read_exact_or_eof(&mut initial_header).await?;
        if !has_frame {
            sink.shutdown().await?;
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
            let mut masking_key = [0_u8; 4];
            source
                .read_exact_required(&mut masking_key, "masking key")
                .await?;
            frame_header.extend_from_slice(&masking_key);
        }

        sink.write_all(&frame_header).await?;
        bytes_forwarded += frame_header.len() as u64;
        relay_websocket_payload(&mut source, &mut sink, payload_len).await?;
        bytes_forwarded += payload_len;

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
            observed_at_unix_ms: websocket_now_unix_ms(),
        };
        observer_tx
            .send(WebSocketObserverMessage::Frame(observation))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "websocket observer channel closed")
            })?;

        if opcode == WS_OPCODE_CLOSE {
            sink.flush().await?;
            return Ok(WebSocketDirectionOutcome {
                bytes_forwarded,
                close_frame_seen: true,
            });
        }
    }
}

async fn relay_websocket_payload<R, W>(
    source: &mut PrefixedReader<R>,
    sink: &mut W,
    mut payload_len: u64,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if payload_len == 0 {
        return Ok(());
    }

    let mut chunk = [0_u8; WS_FRAME_COPY_CHUNK_SIZE];
    while payload_len > 0 {
        let read_len = (chunk.len() as u64).min(payload_len) as usize;
        source
            .read_exact_required(&mut chunk[..read_len], "payload")
            .await?;
        sink.write_all(&chunk[..read_len]).await?;
        payload_len -= read_len as u64;
    }
    Ok(())
}
