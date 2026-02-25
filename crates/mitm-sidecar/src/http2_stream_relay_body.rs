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
