async fn write_http1_request_body_from_h2_capture<U>(
    upstream_stream: &mut U,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    captured: &H2CapturedBody,
) -> io::Result<()>
where
    U: AsyncWrite + Unpin,
{
    if captured.bytes.is_empty() && captured.trailers.is_none() {
        return Ok(());
    }

    if captured.trailers.is_none() {
        let _in_flight_lease = runtime_governor
            .reserve_in_flight_or_error(captured.bytes.len(), "http2_to_http1_request_body_write")?;
        return write_all_with_idle_timeout(
            upstream_stream,
            &captured.bytes,
            "http2_to_http1_request_body_write",
        )
        .await;
    }

    let mut remaining = captured.bytes.clone();
    while !remaining.is_empty() {
        let send_len = remaining.len().min(H2_FORWARD_CHUNK_LIMIT);
        let chunk = remaining.split_to(send_len);
        let chunk_header = format!("{send_len:X}\r\n");
        let _header_lease = runtime_governor
            .reserve_in_flight_or_error(chunk_header.len(), "http2_to_http1_chunk_header_write")?;
        write_all_with_idle_timeout(
            upstream_stream,
            chunk_header.as_bytes(),
            "http2_to_http1_chunk_header_write",
        )
        .await?;
        let _chunk_lease =
            runtime_governor.reserve_in_flight_or_error(send_len, "http2_to_http1_chunk_data_write")?;
        write_all_with_idle_timeout(upstream_stream, &chunk, "http2_to_http1_chunk_data_write")
            .await?;
        let _tail_lease =
            runtime_governor.reserve_in_flight_or_error(2, "http2_to_http1_chunk_tail_write")?;
        write_all_with_idle_timeout(upstream_stream, b"\r\n", "http2_to_http1_chunk_tail_write")
            .await?;
    }

    let _zero_lease =
        runtime_governor.reserve_in_flight_or_error(3, "http2_to_http1_zero_chunk_write")?;
    write_all_with_idle_timeout(upstream_stream, b"0\r\n", "http2_to_http1_zero_chunk_write")
        .await?;
    if let Some(trailers) = captured.trailers.as_ref() {
        let trailer_bytes = serialize_http1_trailers(trailers);
        if !trailer_bytes.is_empty() {
            let _trailers_lease = runtime_governor.reserve_in_flight_or_error(
                trailer_bytes.len(),
                "http2_to_http1_trailers_write",
            )?;
            write_all_with_idle_timeout(
                upstream_stream,
                &trailer_bytes,
                "http2_to_http1_trailers_write",
            )
            .await?;
        }
    }
    let _final_lease =
        runtime_governor.reserve_in_flight_or_error(2, "http2_to_http1_final_crlf_write")?;
    write_all_with_idle_timeout(upstream_stream, b"\r\n", "http2_to_http1_final_crlf_write").await
}

fn serialize_http1_trailers(trailers: &http::HeaderMap) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in trailers {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

async fn read_http1_response_body_for_h2<U>(
    source: &mut BufferedConn<U>,
    mode: HttpBodyMode,
    max_http_head_bytes: usize,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    max_body_bytes: usize,
) -> io::Result<H2CapturedBody>
where
    U: AsyncRead + Unpin,
{
    let mut total = 0_u64;
    let mut body = Vec::new();
    let mut trailers: Option<http::HeaderMap> = None;

    match mode {
        HttpBodyMode::None => {}
        HttpBodyMode::ContentLength(length) => {
            let mut remaining = length;
            while remaining > 0 {
                let read_len = remaining.min(IO_CHUNK_SIZE as u64) as usize;
                let chunk = read_exact_from_source(source, read_len, runtime_governor).await?;
                append_http1_body_chunk_with_budget(
                    &mut body,
                    &chunk,
                    &mut total,
                    max_body_bytes as u64,
                )?;
                remaining -= read_len as u64;
            }
        }
        HttpBodyMode::Chunked => {
            let mut trailer_bytes = 0_usize;
            loop {
                let line = read_chunk_line(source, runtime_governor).await?;
                let chunk_len = parse_chunk_len(&line)?;
                if chunk_len == 0 {
                    let mut parsed_trailers = http::HeaderMap::new();
                    loop {
                        let trailer_line = read_chunk_line(source, runtime_governor).await?;
                        trailer_bytes += trailer_line.len();
                        if trailer_bytes > max_http_head_bytes {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "chunked trailers exceeded configured header limit",
                            ));
                        }
                        if trailer_line == b"\r\n" {
                            break;
                        }
                        let (name, value) = parse_http1_trailer_line(&trailer_line)?;
                        parsed_trailers.append(name, value);
                    }
                    if !parsed_trailers.is_empty() {
                        trailers = Some(parsed_trailers);
                    }
                    break;
                }

                let mut remaining = chunk_len;
                while remaining > 0 {
                    let read_len = remaining.min(IO_CHUNK_SIZE as u64) as usize;
                    let chunk = read_exact_from_source(source, read_len, runtime_governor).await?;
                    append_http1_body_chunk_with_budget(
                        &mut body,
                        &chunk,
                        &mut total,
                        max_body_bytes as u64,
                    )?;
                    remaining -= read_len as u64;
                }
                let terminator = read_exact_from_source(source, 2, runtime_governor).await?;
                if terminator.as_slice() != b"\r\n" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid chunk terminator",
                    ));
                }
            }
        }
        HttpBodyMode::CloseDelimited => {
            if !source.read_buf.is_empty() {
                let prefetch = source.read_buf.split_off(0);
                append_http1_body_chunk_with_budget(
                    &mut body,
                    &prefetch,
                    &mut total,
                    max_body_bytes as u64,
                )?;
            }
            let mut chunk = [0_u8; IO_CHUNK_SIZE];
            loop {
                let read = read_with_idle_timeout(
                    &mut source.stream,
                    &mut chunk,
                    "http2_to_http1_close_delimited_read",
                )
                .await?;
                if read == 0 {
                    break;
                }
                append_http1_body_chunk_with_budget(
                    &mut body,
                    &chunk[..read],
                    &mut total,
                    max_body_bytes as u64,
                )?;
            }
        }
    }

    Ok(H2CapturedBody {
        bytes: bytes::Bytes::from(body),
        bytes_forwarded: total,
        trailers,
        body_truncated: false,
    })
}

fn append_http1_body_chunk_with_budget(
    body: &mut Vec<u8>,
    chunk: &[u8],
    total: &mut u64,
    max_body_bytes: u64,
) -> io::Result<()> {
    *total += chunk.len() as u64;
    if *total > max_body_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "response body exceeded flow body budget (limit={max_body_bytes}, observed={total})"
            ),
        ));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

fn parse_http1_trailer_line(line: &[u8]) -> io::Result<(http::header::HeaderName, http::HeaderValue)> {
    let line = line.strip_suffix(b"\r\n").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid trailer line terminator")
    })?;
    let Some(split_at) = line.iter().position(|byte| *byte == b':') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed trailer header line",
        ));
    };
    let name = http::header::HeaderName::from_bytes(&line[..split_at]).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid trailer header name")
    })?;
    let mut value_bytes = &line[split_at + 1..];
    while let Some(first) = value_bytes.first() {
        if *first == b' ' || *first == b'\t' {
            value_bytes = &value_bytes[1..];
        } else {
            break;
        }
    }
    let value = http::HeaderValue::from_bytes(value_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid trailer header value"))?;
    Ok((name, value))
}

fn build_h2_response_parts_from_http1(
    response: &HttpResponseHead,
) -> io::Result<http::response::Parts> {
    let status = http::StatusCode::from_u16(response.status_code).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid upstream status code {}: {error}", response.status_code),
        )
    })?;
    let mut headers = http::HeaderMap::new();
    for header in &response.headers {
        let name = http::header::HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid upstream response header name")
        })?;
        let value = http::HeaderValue::from_str(&header.value).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid upstream response header value")
        })?;
        headers.append(name, value);
    }
    strip_hop_by_hop_and_transport_headers(&mut headers);
    let mut builder = http::Response::builder().status(status);
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    let response = builder.body(()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("build downstream HTTP/2 response failed: {error}"),
        )
    })?;
    Ok(response.into_parts().0)
}

async fn send_h2_text_response(
    downstream_respond: &mut h2::server::SendResponse<bytes::Bytes>,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    status: u16,
    body: bytes::Bytes,
) -> io::Result<()> {
    let status = sanitize_block_status(status);
    let mut builder = http::Response::builder().status(status);
    builder = builder.header("content-type", "text/plain");
    builder = builder.header("content-length", body.len().to_string());
    let response = builder.body(()).map_err(|error| {
        io::Error::other(format!("build HTTP/2 text response failed: {error}"))
    })?;
    let mut stream = match downstream_respond.send_response(response, body.is_empty()) {
        Ok(stream) => stream,
        Err(error) => {
            if is_h2_nonfatal_stream_error(&error) {
                return Ok(());
            }
            return Err(h2_error_to_io("send HTTP/2 text response failed", error));
        }
    };
    if !body.is_empty() {
        send_h2_data_with_backpressure(&mut stream, runtime_governor, body, true).await?;
    }
    Ok(())
}

async fn respond_h2_error_and_end(
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: FlowContext,
    downstream_respond: &mut h2::server::SendResponse<bytes::Bytes>,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    status: u16,
    body: &str,
) -> io::Result<()> {
    let _ =
        send_h2_text_response(downstream_respond, runtime_governor, status, bytes::Bytes::copy_from_slice(body.as_bytes()))
            .await;
    flow_hooks.on_stream_end(stream_context).await;
    Ok(())
}
