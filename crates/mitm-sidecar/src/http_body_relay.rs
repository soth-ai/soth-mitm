async fn relay_http_body<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
    mode: HttpBodyMode,
    max_http_head_bytes: usize,
) -> io::Result<u64>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    match mode {
        HttpBodyMode::None => Ok(0),
        HttpBodyMode::ContentLength(length) => {
            relay_exact(engine, context, event_kind, source, sink, length).await
        }
        HttpBodyMode::Chunked => {
            relay_chunked(
                engine,
                context,
                event_kind,
                source,
                sink,
                max_http_head_bytes,
            )
            .await
        }
        HttpBodyMode::CloseDelimited => {
            relay_until_eof(engine, context, event_kind, source, sink).await
        }
    }
}

async fn relay_exact<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
    mut length: u64,
) -> io::Result<u64>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut total = 0_u64;

    if !source.read_buf.is_empty() && length > 0 {
        let take = std::cmp::min(length as usize, source.read_buf.len());
        sink.write_all(&source.read_buf[..take]).await?;
        source.read_buf.drain(..take);
        length -= take as u64;
        total += take as u64;
        emit_body_chunk_event(engine, context.clone(), event_kind, take as u64);
    }

    let mut chunk = [0_u8; IO_CHUNK_SIZE];
    while length > 0 {
        let read = source
            .stream
            .read(&mut chunk[..std::cmp::min(IO_CHUNK_SIZE, length as usize)])
            .await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before body completed",
            ));
        }
        sink.write_all(&chunk[..read]).await?;
        length -= read as u64;
        total += read as u64;
        emit_body_chunk_event(engine, context.clone(), event_kind, read as u64);
    }

    Ok(total)
}

async fn relay_chunked<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
    max_http_head_bytes: usize,
) -> io::Result<u64>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut total = 0_u64;
    loop {
        let line = read_chunk_line(source).await?;
        sink.write_all(&line).await?;
        let chunk_len = parse_chunk_len(&line)?;
        if chunk_len == 0 {
            let trailers = read_until_pattern(source, b"\r\n\r\n", max_http_head_bytes)
                .await?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed before chunked trailers completed",
                    )
                })?;
            sink.write_all(&trailers).await?;
            return Ok(total);
        }

        total += relay_exact(engine, context, event_kind, source, sink, chunk_len).await?;

        let chunk_terminator = read_exact_from_source(source, 2).await?;
        if chunk_terminator.as_slice() != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunk terminator",
            ));
        }
        sink.write_all(&chunk_terminator).await?;
    }
}

async fn relay_until_eof<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
) -> io::Result<u64>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventSink + Send + Sync + 'static,
{
    let mut total = 0_u64;
    if !source.read_buf.is_empty() {
        sink.write_all(&source.read_buf).await?;
        total += source.read_buf.len() as u64;
        emit_body_chunk_event(
            engine,
            context.clone(),
            event_kind,
            source.read_buf.len() as u64,
        );
        source.read_buf.clear();
    }

    let mut chunk = [0_u8; IO_CHUNK_SIZE];
    loop {
        let read = source.stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        sink.write_all(&chunk[..read]).await?;
        total += read as u64;
        emit_body_chunk_event(engine, context.clone(), event_kind, read as u64);
    }
    Ok(total)
}

async fn read_chunk_line<S: AsyncRead + Unpin>(
    source: &mut BufferedConn<S>,
) -> io::Result<Vec<u8>> {
    let line = read_until_pattern(source, b"\r\n", CHUNK_LINE_LIMIT)
        .await?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before chunk size line was read",
            )
        })?;
    Ok(line)
}

fn parse_chunk_len(line: &[u8]) -> io::Result<u64> {
    let text = std::str::from_utf8(line).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "chunk size line had invalid UTF-8",
        )
    })?;
    let trimmed = text.trim();
    let size_text = trimmed.split(';').next().unwrap_or(trimmed).trim();
    u64::from_str_radix(size_text, 16).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "chunk size line had invalid hex length",
        )
    })
}

async fn read_exact_from_source<S: AsyncRead + Unpin>(
    source: &mut BufferedConn<S>,
    exact_len: usize,
) -> io::Result<Vec<u8>> {
    while source.read_buf.len() < exact_len {
        let mut chunk = [0_u8; IO_CHUNK_SIZE];
        let read = source.stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before fixed-length body completed",
            ));
        }
        source.read_buf.extend_from_slice(&chunk[..read]);
    }
    Ok(source.read_buf.drain(..exact_len).collect::<Vec<_>>())
}

async fn write_proxy_response(stream: &mut TcpStream, status: &str, body: &str) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}
