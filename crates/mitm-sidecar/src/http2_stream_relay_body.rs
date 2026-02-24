async fn relay_h2_body(
    source: &mut h2::RecvStream,
    sink: &mut h2::SendStream<bytes::Bytes>,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    direction: &'static str,
) -> io::Result<H2BodyRelayOutcome> {
    let mut total = 0_u64;
    let mut end_stream_sent_on_data = false;
    h2_relay_debug(format!("[h2-relay:{direction}] start"));

    while let Some(next_data) = source.data().await {
        let data =
            next_data.map_err(|error| h2_error_to_io("reading HTTP/2 body frame failed", error))?;
        let is_end_stream = source.is_end_stream();
        let frame_len = data.len();
        h2_relay_debug(format!(
            "[h2-relay:{direction}] data frame len={frame_len} end_stream_now={}",
            is_end_stream
        ));
        if frame_len == 0 {
            if is_end_stream {
                send_h2_data_with_backpressure(sink, runtime_governor, bytes::Bytes::new(), true)
                    .await?;
                end_stream_sent_on_data = true;
                break;
            }
            continue;
        }

        send_h2_data_with_backpressure(sink, runtime_governor, data, is_end_stream).await?;
        source
            .flow_control()
            .release_capacity(frame_len)
            .map_err(|error| h2_error_to_io("releasing HTTP/2 receive capacity failed", error))?;
        total += frame_len as u64;
        if is_end_stream {
            end_stream_sent_on_data = true;
            break;
        }
    }
    h2_relay_debug(format!(
        "[h2-relay:{direction}] data stream exhausted; source_end_stream={}",
        source.is_end_stream()
    ));

    if end_stream_sent_on_data {
        h2_relay_debug(format!(
            "[h2-relay:{direction}] end-stream already sent on data frame"
        ));
        if tokio::time::timeout(H2_END_STREAM_DRAIN_TIMEOUT, source.trailers())
            .await
            .is_err()
        {
            h2_relay_debug(format!(
                "[h2-relay:{direction}] timed out draining post-end-stream trailers"
            ));
        }
        return Ok(H2BodyRelayOutcome {
            bytes_forwarded: total,
            trailers: None,
        });
    }

    let trailers_result = match tokio::time::timeout(H2_TRAILERS_WAIT_TIMEOUT, source.trailers()).await
    {
        Ok(result) => result,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "timed out waiting for HTTP/2 {direction} trailers or end-of-stream signal"
                ),
            ));
        }
    };
    let trailers = match trailers_result
        .map_err(|error| h2_error_to_io("reading HTTP/2 trailers failed", error))?
    {
        Some(trailers) => {
            h2_relay_debug(format!("[h2-relay:{direction}] forwarding trailers"));
            let observation_copy = trailers.clone();
            let trailers_size = estimate_header_map_size(&trailers);
            let _in_flight_lease = runtime_governor
                .reserve_in_flight_or_error(trailers_size.max(1), "http2_trailers_write")?;
            sink.send_trailers(trailers)
                .map_err(|error| h2_error_to_io("sending HTTP/2 trailers failed", error))?;
            Some(observation_copy)
        }
        None => {
            h2_relay_debug(format!("[h2-relay:{direction}] no trailers; sending EOS"));
            send_h2_data_with_backpressure(sink, runtime_governor, bytes::Bytes::new(), true)
                .await?;
            None
        }
    };
    h2_relay_debug(format!("[h2-relay:{direction}] complete bytes={total}"));

    Ok(H2BodyRelayOutcome {
        bytes_forwarded: total,
        trailers,
    })
}

async fn send_h2_data_with_backpressure(
    sink: &mut h2::SendStream<bytes::Bytes>,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
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
        let _in_flight_lease = runtime_governor
            .reserve_in_flight_or_error(send_len, "http2_data_frame_write")?;
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
            Some(Err(error)) => {
                return Err(h2_error_to_io(
                    "polling HTTP/2 send capacity failed",
                    error,
                ));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "HTTP/2 send stream closed before capacity became available",
                ));
            }
        }
    }
}
