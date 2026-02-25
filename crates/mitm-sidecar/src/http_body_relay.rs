trait HttpBodyObserver: Send {
    fn on_chunk<'a>(
        &'a mut self,
        chunk: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>>;
    fn on_complete<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_http_body<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
    mode: HttpBodyMode,
    max_http_head_bytes: usize,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    observer: &mut dyn HttpBodyObserver,
) -> io::Result<u64>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let total = match mode {
        HttpBodyMode::None => Ok(0),
        HttpBodyMode::ContentLength(length) => relay_exact(
            engine,
            context,
            event_kind,
            source,
            sink,
            length,
            runtime_governor,
            observer,
        )
        .await,
        HttpBodyMode::Chunked => {
            relay_chunked(
                engine,
                context,
                event_kind,
                source,
                sink,
                max_http_head_bytes,
                runtime_governor,
                observer,
            )
            .await
        }
        HttpBodyMode::CloseDelimited => relay_until_eof(
            engine,
            context,
            event_kind,
            source,
            sink,
            runtime_governor,
            observer,
        )
        .await,
    }?;
    observer.on_complete().await?;
    Ok(total)
}

async fn relay_exact<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
    mut length: u64,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    observer: &mut dyn HttpBodyObserver,
) -> io::Result<u64>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut total = 0_u64;

    if !source.read_buf.is_empty() && length > 0 {
        let take = std::cmp::min(length as usize, source.read_buf.len());
        let _in_flight_lease = runtime_governor
            .reserve_in_flight_or_error(take, "http1_body_prefetch_write")?;
        write_all_with_idle_timeout(sink, &source.read_buf[..take], "http1_body_prefetch_write")
            .await?;
        observer.on_chunk(&source.read_buf[..take]).await?;
        source.read_buf.drain(..take);
        length -= take as u64;
        total += take as u64;
        emit_body_chunk_event(engine, context.clone(), event_kind, take as u64);
    }

    let mut chunk = [0_u8; IO_CHUNK_SIZE];
    while length > 0 {
        let read = read_with_idle_timeout(
            &mut source.stream,
            &mut chunk[..std::cmp::min(IO_CHUNK_SIZE, length as usize)],
            "http1_body_chunk_read",
        )
        .await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before body completed",
            ));
        }
        let _in_flight_lease = runtime_governor
            .reserve_in_flight_or_error(read, "http1_body_chunk_write")?;
        write_all_with_idle_timeout(sink, &chunk[..read], "http1_body_chunk_write").await?;
        observer.on_chunk(&chunk[..read]).await?;
        length -= read as u64;
        total += read as u64;
        emit_body_chunk_event(engine, context.clone(), event_kind, read as u64);
    }

    Ok(total)
}

#[allow(clippy::too_many_arguments)]
async fn relay_chunked<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
    max_http_head_bytes: usize,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    observer: &mut dyn HttpBodyObserver,
) -> io::Result<u64>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut total = 0_u64;
    loop {
        let line = read_chunk_line(source, runtime_governor).await?;
        let _in_flight_lease =
            runtime_governor.reserve_in_flight_or_error(line.len(), "http1_chunk_line_write")?;
        write_all_with_idle_timeout(sink, &line, "http1_chunk_line_write").await?;
        let chunk_len = parse_chunk_len(&line)?;
        if chunk_len == 0 {
            let trailers = read_until_pattern(
                source,
                b"\r\n\r\n",
                max_http_head_bytes,
                runtime_governor,
            )
                .await?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed before chunked trailers completed",
                    )
                })?;
            let _in_flight_lease = runtime_governor
                .reserve_in_flight_or_error(trailers.len(), "http1_chunk_trailers_write")?;
            write_all_with_idle_timeout(sink, &trailers, "http1_chunk_trailers_write").await?;
            return Ok(total);
        }

        total += relay_exact(
            engine,
            context,
            event_kind,
            source,
            sink,
            chunk_len,
            runtime_governor,
            observer,
        )
        .await?;

        let chunk_terminator = read_exact_from_source(source, 2, runtime_governor).await?;
        if chunk_terminator.as_slice() != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunk terminator",
            ));
        }
        let _in_flight_lease = runtime_governor
            .reserve_in_flight_or_error(chunk_terminator.len(), "http1_chunk_terminator_write")?;
        write_all_with_idle_timeout(
            sink,
            &chunk_terminator,
            "http1_chunk_terminator_write",
        )
        .await?;
    }
}

async fn relay_until_eof<RS, WS, P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    context: &FlowContext,
    event_kind: EventType,
    source: &mut BufferedConn<RS>,
    sink: &mut WS,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    observer: &mut dyn HttpBodyObserver,
) -> io::Result<u64>
where
    RS: AsyncRead + Unpin,
    WS: AsyncWrite + Unpin,
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut total = 0_u64;
    if !source.read_buf.is_empty() {
        let _in_flight_lease = runtime_governor.reserve_in_flight_or_error(
            source.read_buf.len(),
            "http1_close_delimited_prefetch_write",
        )?;
        write_all_with_idle_timeout(
            sink,
            &source.read_buf,
            "http1_close_delimited_prefetch_write",
        )
        .await?;
        observer.on_chunk(&source.read_buf).await?;
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
        let read =
            read_with_idle_timeout(&mut source.stream, &mut chunk, "http1_close_delimited_read")
                .await?;
        if read == 0 {
            break;
        }
        let _in_flight_lease = runtime_governor
            .reserve_in_flight_or_error(read, "http1_close_delimited_chunk_write")?;
        write_all_with_idle_timeout(sink, &chunk[..read], "http1_close_delimited_write").await?;
        observer.on_chunk(&chunk[..read]).await?;
        total += read as u64;
        emit_body_chunk_event(engine, context.clone(), event_kind, read as u64);
    }
    Ok(total)
}

async fn read_chunk_line<S: AsyncRead + Unpin>(
    source: &mut BufferedConn<S>,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
) -> io::Result<Vec<u8>> {
    let line = read_until_pattern(source, b"\r\n", CHUNK_LINE_LIMIT, runtime_governor)
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
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
) -> io::Result<Vec<u8>> {
    let _in_flight_lease = runtime_governor
        .reserve_in_flight_or_error(exact_len, "http1_fixed_read_exact")?;
    while source.read_buf.len() < exact_len {
        let mut chunk = [0_u8; IO_CHUNK_SIZE];
        let read = read_with_idle_timeout(
            &mut source.stream,
            &mut chunk,
            "http1_fixed_read_exact_chunk",
        )
        .await?;
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
    write_all_with_idle_timeout(stream, response.as_bytes(), "proxy_error_response_write").await
}
