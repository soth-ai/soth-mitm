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

            let read = read_with_websocket_idle_timeout(
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

async fn read_websocket_frame_header<R>(
    source: &mut PrefixedReader<R>,
    codec: &soketto::base::Codec,
    max_frame_payload_bytes: usize,
) -> io::Result<Option<(Vec<u8>, WebSocketHeaderView)>>
where
    R: AsyncRead + Unpin,
{
    const WS_MAX_FRAME_HEADER_BYTES: usize = 14;
    let mut frame_header = Vec::with_capacity(WS_MAX_FRAME_HEADER_BYTES);

    loop {
        match decode_websocket_header_soketto(codec, &frame_header)? {
            WebSocketHeaderDecodeResult::NeedMore(_) => {
                if frame_header.len() >= WS_MAX_FRAME_HEADER_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "websocket frame header exceeds {WS_MAX_FRAME_HEADER_BYTES} bytes"
                        ),
                    ));
                }
                let mut next_byte = [0_u8; 1];
                if !source.read_exact_or_eof(&mut next_byte).await? {
                    if frame_header.is_empty() {
                        return Ok(None);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed while reading websocket frame header",
                    ));
                }
                frame_header.push(next_byte[0]);
            }
            WebSocketHeaderDecodeResult::Complete(header_view) => {
                websocket_payload_len_within_limit(header_view.payload_len, max_frame_payload_bytes)?;
                if header_view.header_len != frame_header.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "websocket frame header offset mismatch: decoded={} buffered={}",
                            header_view.header_len,
                            frame_header.len()
                        ),
                    ));
                }
                return Ok(Some((frame_header, header_view)));
            }
        }
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
        write_all_with_websocket_idle_timeout(
            &mut *sink,
            &chunk[..read_len],
            "websocket_payload_write",
        )
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
