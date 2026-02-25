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

            let read = read_with_idle_timeout(
                &mut self.source,
                &mut out[written..],
                "websocket_frame_read",
            )
            .await?;
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

async fn relay_websocket_payload<R, W>(
    source: &mut PrefixedReader<R>,
    sink: &mut W,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    mut payload_len: u64,
    masking_key: Option<[u8; 4]>,
    max_payload_capture_bytes: usize,
) -> io::Result<bytes::Bytes>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if payload_len == 0 {
        return Ok(bytes::Bytes::new());
    }

    let mut chunk = [0_u8; WS_FRAME_COPY_CHUNK_SIZE];
    let mut captured = Vec::new();
    let mut mask_offset = 0_usize;
    while payload_len > 0 {
        let read_len = (chunk.len() as u64).min(payload_len) as usize;
        let _in_flight_lease =
            runtime_governor.reserve_in_flight_or_error(read_len, "websocket_payload_write")?;
        source
            .read_exact_required(&mut chunk[..read_len], "payload")
            .await?;
        write_all_with_idle_timeout(&mut *sink, &chunk[..read_len], "websocket_payload_write")
            .await?;
        if captured.len() < max_payload_capture_bytes {
            let take = (max_payload_capture_bytes - captured.len()).min(read_len);
            if let Some(mask) = masking_key {
                for (index, byte) in chunk[..take].iter().enumerate() {
                    captured.push(*byte ^ mask[(mask_offset + index) % 4]);
                }
            } else {
                captured.extend_from_slice(&chunk[..take]);
            }
        }
        if masking_key.is_some() {
            mask_offset = (mask_offset + read_len) % 4;
        }
        payload_len -= read_len as u64;
    }
    Ok(bytes::Bytes::from(captured))
}

async fn read_websocket_payload_captured<R>(
    source: &mut PrefixedReader<R>,
    mut payload_len: u64,
    masking_key: Option<[u8; 4]>,
    max_payload_capture_bytes: usize,
) -> io::Result<bytes::Bytes>
where
    R: AsyncRead + Unpin,
{
    if payload_len == 0 {
        return Ok(bytes::Bytes::new());
    }

    let mut chunk = [0_u8; WS_FRAME_COPY_CHUNK_SIZE];
    let mut captured = Vec::new();
    let mut mask_offset = 0_usize;
    while payload_len > 0 {
        let read_len = (chunk.len() as u64).min(payload_len) as usize;
        source
            .read_exact_required(&mut chunk[..read_len], "payload")
            .await?;
        if captured.len() < max_payload_capture_bytes {
            let take = (max_payload_capture_bytes - captured.len()).min(read_len);
            if let Some(mask) = masking_key {
                for (index, byte) in chunk[..take].iter().enumerate() {
                    captured.push(*byte ^ mask[(mask_offset + index) % 4]);
                }
            } else {
                captured.extend_from_slice(&chunk[..take]);
            }
        }
        if masking_key.is_some() {
            mask_offset = (mask_offset + read_len) % 4;
        }
        payload_len -= read_len as u64;
    }
    Ok(bytes::Bytes::from(captured))
}

async fn send_websocket_pong<W>(
    direction: mitm_http::WsDirection,
    sink: &Arc<tokio::sync::Mutex<W>>,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    payload: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mask_payload = matches!(direction, mitm_http::WsDirection::ServerToClient);
    let pong_frame = encode_websocket_control_frame(WS_OPCODE_PONG, payload, mask_payload)?;
    let _in_flight_lease =
        runtime_governor.reserve_in_flight_or_error(pong_frame.len(), "websocket_pong_write")?;
    let mut sink = sink.lock().await;
    write_all_with_idle_timeout(&mut *sink, &pong_frame, "websocket_pong_write").await?;
    flush_with_idle_timeout(&mut *sink, "websocket_pong_flush").await?;
    Ok(())
}

fn encode_websocket_control_frame(
    opcode: u8,
    payload: &[u8],
    mask_payload: bool,
) -> io::Result<Vec<u8>> {
    if payload.len() > (WS_CONTROL_MAX_PAYLOAD_BYTES as usize) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket control frame payload exceeds 125 bytes",
        ));
    }
    let mut frame = Vec::with_capacity(2 + if mask_payload { 4 } else { 0 } + payload.len());
    frame.push(0x80 | (opcode & 0x0F));
    if mask_payload {
        let mask = websocket_control_masking_key(payload);
        frame.push(0x80 | (payload.len() as u8));
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(*byte ^ mask[index % 4]);
        }
    } else {
        frame.push(payload.len() as u8);
        frame.extend_from_slice(payload);
    }
    Ok(frame)
}

fn websocket_control_masking_key(payload: &[u8]) -> [u8; 4] {
    let seed = 0xA5D3_9C17_u32 ^ (payload.len() as u32);
    seed.to_be_bytes()
}
