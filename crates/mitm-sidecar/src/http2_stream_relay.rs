use std::sync::atomic::{AtomicU64, Ordering};

const H2_MAX_CONCURRENT_STREAMS: u32 = 128;
const H2_INITIAL_WINDOW_SIZE: u32 = 65_535;
const H2_INITIAL_CONNECTION_WINDOW_SIZE: u32 = 262_144;
const H2_MAX_SEND_BUFFER_SIZE: usize = 128 * 1024;
const H2_FORWARD_CHUNK_LIMIT: usize = 16 * 1024;

#[derive(Clone)]
struct H2ByteCounters {
    request_bytes: Arc<AtomicU64>,
    response_bytes: Arc<AtomicU64>,
}

async fn relay_http2_connection<P, S, D, U>(
    engine: Arc<MitmEngine<P, S>>,
    tunnel_context: FlowContext,
    downstream_tls: D,
    upstream_tls: U,
    max_header_list_size: u32,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut downstream_builder = h2::server::Builder::new();
    configure_h2_server(&mut downstream_builder, max_header_list_size);
    let mut downstream_connection = match downstream_builder.handshake(downstream_tls).await {
        Ok(connection) => connection,
        Err(error) => {
            emit_stream_closed(
                &engine,
                FlowContext {
                    protocol: ApplicationProtocol::Http2,
                    ..tunnel_context
                },
                CloseReasonCode::MitmHttpError,
                Some(format!("downstream HTTP/2 handshake failed: {error}")),
                None,
                None,
            );
            return Ok(());
        }
    };

    let mut upstream_builder = h2::client::Builder::new();
    configure_h2_client(&mut upstream_builder, max_header_list_size);
    let (upstream_sender, upstream_connection) = match upstream_builder.handshake(upstream_tls).await {
        Ok(connection_parts) => connection_parts,
        Err(error) => {
            emit_stream_closed(
                &engine,
                FlowContext {
                    protocol: ApplicationProtocol::Http2,
                    ..tunnel_context
                },
                CloseReasonCode::MitmHttpError,
                Some(format!("upstream HTTP/2 handshake failed: {error}")),
                None,
                None,
            );
            return Ok(());
        }
    };
    let upstream_connection_task = tokio::spawn(upstream_connection);

    let http2_context = FlowContext {
        protocol: ApplicationProtocol::Http2,
        ..tunnel_context.clone()
    };
    let byte_counters = H2ByteCounters {
        request_bytes: Arc::new(AtomicU64::new(0)),
        response_bytes: Arc::new(AtomicU64::new(0)),
    };
    let mut stream_tasks = tokio::task::JoinSet::new();
    let mut first_error: Option<io::Error> = None;

    while let Some(next_stream) = downstream_connection.accept().await {
        match next_stream {
            Ok((request, respond)) => {
                let stream_engine = Arc::clone(&engine);
                let stream_context = http2_context.clone();
                let stream_upstream_sender = upstream_sender.clone();
                let stream_byte_counters = byte_counters.clone();
                stream_tasks.spawn(async move {
                    relay_http2_stream(
                        stream_engine,
                        stream_context,
                        stream_upstream_sender,
                        request,
                        respond,
                        max_header_list_size,
                        stream_byte_counters,
                    )
                    .await
                });
            }
            Err(error) => {
                if !is_h2_transport_close_error(&error) && first_error.is_none() {
                    first_error = Some(h2_error_to_io("downstream HTTP/2 accept failed", error));
                }
                break;
            }
        }
    }

    while let Some(task_result) = stream_tasks.join_next().await {
        match task_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(join_error) => {
                if first_error.is_none() {
                    first_error = Some(io::Error::other(format!(
                        "HTTP/2 stream task join failed: {join_error}"
                    )));
                }
            }
        }
    }

    drop(upstream_sender);

    match upstream_connection_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            if !is_h2_transport_close_error(&error) && first_error.is_none() {
                first_error = Some(h2_error_to_io("upstream HTTP/2 driver failed", error));
            }
        }
        Err(join_error) => {
            if first_error.is_none() {
                first_error = Some(io::Error::other(format!(
                    "HTTP/2 upstream task join failed: {join_error}"
                )));
            }
        }
    }

    let bytes_from_client = byte_counters.request_bytes.load(Ordering::Relaxed);
    let bytes_from_server = byte_counters.response_bytes.load(Ordering::Relaxed);

    if let Some(error) = first_error {
        emit_stream_closed(
            &engine,
            http2_context,
            CloseReasonCode::MitmHttpError,
            Some(error.to_string()),
            Some(bytes_from_client),
            Some(bytes_from_server),
        );
    } else {
        emit_stream_closed(
            &engine,
            http2_context,
            CloseReasonCode::MitmHttpCompleted,
            None,
            Some(bytes_from_client),
            Some(bytes_from_server),
        );
    }

    Ok(())
}

async fn relay_http2_stream<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    stream_context: FlowContext,
    upstream_sender: h2::client::SendRequest<bytes::Bytes>,
    downstream_request: http::Request<h2::RecvStream>,
    mut downstream_respond: h2::server::SendResponse<bytes::Bytes>,
    max_header_list_size: u32,
    byte_counters: H2ByteCounters,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let (mut request_parts, mut downstream_request_body) = downstream_request.into_parts();
    enforce_h2_request_header_limit(&request_parts, max_header_list_size)?;

    let grpc_observation = detect_grpc_request(&request_parts);
    if let Some(observation) = grpc_observation.as_ref() {
        emit_grpc_request_headers_event(
            &engine,
            stream_context.clone(),
            observation,
            &request_parts.headers,
        );
    }

    request_parts.version = http::Version::HTTP_2;
    let upstream_request = http::Request::from_parts(request_parts, ());
    let request_end_stream = downstream_request_body.is_end_stream();

    let mut ready_upstream_sender = upstream_sender
        .ready()
        .await
        .map_err(|error| h2_error_to_io("upstream HTTP/2 sender not ready", error))?;
    let (upstream_response_future, mut upstream_request_stream) = ready_upstream_sender
        .send_request(upstream_request, request_end_stream)
        .map_err(|error| h2_error_to_io("forwarding HTTP/2 request failed", error))?;

    if !request_end_stream {
        let request_outcome =
            relay_h2_body(&mut downstream_request_body, &mut upstream_request_stream).await?;
        byte_counters
            .request_bytes
            .fetch_add(request_outcome.bytes_forwarded, Ordering::Relaxed);
    }

    let upstream_response = upstream_response_future
        .await
        .map_err(|error| h2_error_to_io("awaiting upstream HTTP/2 response failed", error))?;
    let (response_parts, mut upstream_response_body) = upstream_response.into_parts();
    enforce_h2_response_header_limit(&response_parts, max_header_list_size)?;

    if let Some(observation) = grpc_observation.as_ref() {
        emit_grpc_response_headers_event(
            &engine,
            stream_context.clone(),
            observation,
            &response_parts,
        );
    }

    let response_end_stream = upstream_response_body.is_end_stream();
    let downstream_response = http::Response::from_parts(response_parts, ());
    let mut downstream_response_stream =
        downstream_respond
            .send_response(downstream_response, response_end_stream)
            .map_err(|error| {
                h2_error_to_io("sending downstream HTTP/2 response headers failed", error)
            })?;

    if !response_end_stream {
        let response_outcome =
            relay_h2_body(&mut upstream_response_body, &mut downstream_response_stream).await?;
        byte_counters
            .response_bytes
            .fetch_add(response_outcome.bytes_forwarded, Ordering::Relaxed);
        if let (Some(observation), Some(trailers)) = (
            grpc_observation.as_ref(),
            response_outcome.trailers.as_ref(),
        ) {
            emit_grpc_response_trailers_event(
                &engine,
                stream_context.clone(),
                observation,
                trailers,
            );
        }
    }

    Ok(())
}

async fn relay_h2_body(
    source: &mut h2::RecvStream,
    sink: &mut h2::SendStream<bytes::Bytes>,
) -> io::Result<H2BodyRelayOutcome> {
    let mut total = 0_u64;

    while let Some(next_data) = source.data().await {
        let data = next_data.map_err(|error| h2_error_to_io("reading HTTP/2 body frame failed", error))?;
        let frame_len = data.len();
        if frame_len == 0 {
            continue;
        }

        send_h2_data_with_backpressure(sink, data, false).await?;
        source
            .flow_control()
            .release_capacity(frame_len)
            .map_err(|error| h2_error_to_io("releasing HTTP/2 receive capacity failed", error))?;
        total += frame_len as u64;
    }

    let trailers = match source
        .trailers()
        .await
        .map_err(|error| h2_error_to_io("reading HTTP/2 trailers failed", error))?
    {
        Some(trailers) => {
            let observation_copy = trailers.clone();
            sink.send_trailers(trailers)
                .map_err(|error| h2_error_to_io("sending HTTP/2 trailers failed", error))?;
            Some(observation_copy)
        }
        None => {
            send_h2_data_with_backpressure(sink, bytes::Bytes::new(), true).await?;
            None
        }
    };

    Ok(H2BodyRelayOutcome {
        bytes_forwarded: total,
        trailers,
    })
}

async fn send_h2_data_with_backpressure(
    sink: &mut h2::SendStream<bytes::Bytes>,
    mut data: bytes::Bytes,
    end_stream: bool,
) -> io::Result<()> {
    if data.is_empty() {
        sink.send_data(data, end_stream)
            .map_err(|error| h2_error_to_io("sending HTTP/2 data frame failed", error))?;
        return Ok(());
    }

    while !data.is_empty() {
        let available_capacity = wait_for_h2_capacity(sink, data.len()).await?;
        let send_len = available_capacity.min(data.len()).min(H2_FORWARD_CHUNK_LIMIT);
        if send_len == 0 {
            continue;
        }
        let chunk = data.split_to(send_len);
        let is_last = data.is_empty();
        sink.send_data(chunk, end_stream && is_last)
            .map_err(|error| h2_error_to_io("sending HTTP/2 data frame failed", error))?;
    }

    Ok(())
}

async fn wait_for_h2_capacity(
    sink: &mut h2::SendStream<bytes::Bytes>,
    desired: usize,
) -> io::Result<usize> {
    runtime_governor::mark_backpressure_activation_global();
    sink.reserve_capacity(desired);
    loop {
        match std::future::poll_fn(|cx| sink.poll_capacity(cx)).await {
            Some(Ok(capacity)) if capacity > 0 => return Ok(capacity),
            Some(Ok(_)) => {
                runtime_governor::mark_backpressure_activation_global();
                continue;
            }
            Some(Err(error)) => return Err(h2_error_to_io("polling HTTP/2 send capacity failed", error)),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "HTTP/2 send stream closed before capacity became available",
                ));
            }
        }
    }
}
