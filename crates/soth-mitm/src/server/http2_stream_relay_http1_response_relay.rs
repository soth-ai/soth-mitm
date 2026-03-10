use std::io;
use std::sync::Arc;
use tokio::io::AsyncRead;
use crate::config::H2ResponseOverflowMode;
use crate::observe::FlowContext;
use super::{BufferedConn, HttpBodyMode, IO_CHUNK_SIZE};
use super::runtime_governor;
use super::flow_hooks::FlowHooks;
use super::io_timeouts::with_h2_body_idle_timeout;
use super::http2_relay_support::h2_error_to_io;
use super::http2_stream_relay_body::send_h2_data_with_backpressure;
use super::http2_stream_relay_http1_body::{
    read_http1_response_chunk_non_eof, read_http1_response_chunk_allow_eof,
    read_http1_chunked_trailers_as_header_map,
};
use super::http_body_relay::{read_chunk_line, parse_chunk_len, read_exact_from_source};
use super::http2_stream_hook_dispatch::H2CapturedBody;
use super::http2_stream_response_relay::H2ResponseStreamHookDispatcher;
use super::flow_hook_http_helpers::strip_trailer_forbidden_and_transport_headers;

pub(crate) struct Http1ToH2ResponseRelayOutcome {
    pub(crate) captured: H2CapturedBody,
    pub(crate) observed_trailers: Option<http::HeaderMap>,
}

struct Http1ResponseCaptureState {
    total_forwarded: u64,
    captured: Vec<u8>,
    body_truncated: bool,
}

impl Http1ResponseCaptureState {
    fn new() -> Self {
        Self {
            total_forwarded: 0,
            captured: Vec::new(),
            body_truncated: false,
        }
    }

    fn observe_chunk(&mut self, chunk: &[u8], max_handler_body: usize) -> bool {
        self.total_forwarded += chunk.len() as u64;
        if self.body_truncated {
            return false;
        }
        let remaining = max_handler_body.saturating_sub(self.captured.len());
        if remaining >= chunk.len() {
            self.captured.extend_from_slice(chunk);
            return false;
        }
        if remaining > 0 {
            self.captured.extend_from_slice(&chunk[..remaining]);
        }
        self.body_truncated = true;
        true
    }

    fn into_captured(self, trailers: Option<http::HeaderMap>) -> H2CapturedBody {
        H2CapturedBody {
            bytes: bytes::Bytes::from(self.captured),
            bytes_forwarded: self.total_forwarded,
            trailers,
            body_truncated: self.body_truncated,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_http1_response_body_with_incremental_forwarding<U>(
    source: &mut BufferedConn<U>,
    mode: HttpBodyMode,
    max_http_head_bytes: usize,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    downstream_response_stream: &mut h2::SendStream<bytes::Bytes>,
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: &FlowContext,
    stream_dispatcher: &mut Option<H2ResponseStreamHookDispatcher>,
    max_handler_body: usize,
    h2_response_overflow_strict: bool,
) -> io::Result<Http1ToH2ResponseRelayOutcome>
where
    U: AsyncRead + Unpin,
{
    let overflow_mode = if h2_response_overflow_strict {
        H2ResponseOverflowMode::StrictFail
    } else {
        H2ResponseOverflowMode::TruncateContinue
    };
    let mut capture_state = Http1ResponseCaptureState::new();
    let mut trailers = match mode {
        HttpBodyMode::None => None,
        HttpBodyMode::ContentLength(length) => {
            relay_http1_content_length_body(
                source,
                length,
                runtime_governor,
                downstream_response_stream,
                flow_hooks,
                stream_context,
                stream_dispatcher,
                &mut capture_state,
                max_handler_body,
                overflow_mode,
            )
            .await?;
            None
        }
        HttpBodyMode::Chunked => {
            relay_http1_chunked_body(
                source,
                max_http_head_bytes,
                runtime_governor,
                downstream_response_stream,
                flow_hooks,
                stream_context,
                stream_dispatcher,
                &mut capture_state,
                max_handler_body,
                overflow_mode,
            )
            .await?
        }
        HttpBodyMode::CloseDelimited => {
            relay_http1_close_delimited_body(
                source,
                runtime_governor,
                downstream_response_stream,
                flow_hooks,
                stream_context,
                stream_dispatcher,
                &mut capture_state,
                max_handler_body,
                overflow_mode,
            )
            .await?;
            None
        }
    };

    if let Some(candidate) = trailers.as_mut() {
        strip_trailer_forbidden_and_transport_headers(candidate);
        if candidate.is_empty() {
            trailers = None;
        }
    }

    let observed_trailers = if let Some(trailers_to_send) = trailers.clone() {
        downstream_response_stream
            .send_trailers(trailers_to_send.clone())
            .map_err(|error| h2_error_to_io("sending HTTP/2 trailers failed", error))?;
        Some(trailers_to_send)
    } else {
        send_h2_data_with_backpressure(
            downstream_response_stream,
            runtime_governor,
            bytes::Bytes::new(),
            true,
        )
        .await?;
        None
    };

    if let Some(dispatcher) = stream_dispatcher.as_mut() {
        dispatcher.finish(flow_hooks, stream_context).await;
    }

    Ok(Http1ToH2ResponseRelayOutcome {
        captured: capture_state.into_captured(trailers),
        observed_trailers,
    })
}

#[allow(clippy::too_many_arguments)]
async fn relay_http1_content_length_body<U>(
    source: &mut BufferedConn<U>,
    length: u64,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    downstream_response_stream: &mut h2::SendStream<bytes::Bytes>,
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: &FlowContext,
    stream_dispatcher: &mut Option<H2ResponseStreamHookDispatcher>,
    capture_state: &mut Http1ResponseCaptureState,
    max_handler_body: usize,
    overflow_mode: H2ResponseOverflowMode,
) -> io::Result<()>
where
    U: AsyncRead + Unpin,
{
    let mut remaining = length;
    while remaining > 0 {
        let read_len = remaining.min(IO_CHUNK_SIZE as u64) as usize;
        let chunk = read_http1_response_chunk_non_eof(
            source,
            read_len,
            "http2_to_http1_response_body_next_chunk",
        )
        .await?;
        remaining = remaining.checked_sub(chunk.len() as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream sent more bytes than declared content-length",
            )
        })?;
        forward_http1_response_chunk(
            chunk,
            runtime_governor,
            downstream_response_stream,
            flow_hooks,
            stream_context,
            stream_dispatcher,
            capture_state,
            max_handler_body,
            overflow_mode,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn relay_http1_chunked_body<U>(
    source: &mut BufferedConn<U>,
    max_http_head_bytes: usize,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    downstream_response_stream: &mut h2::SendStream<bytes::Bytes>,
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: &FlowContext,
    stream_dispatcher: &mut Option<H2ResponseStreamHookDispatcher>,
    capture_state: &mut Http1ResponseCaptureState,
    max_handler_body: usize,
    overflow_mode: H2ResponseOverflowMode,
) -> io::Result<Option<http::HeaderMap>>
where
    U: AsyncRead + Unpin,
{
    loop {
        let line =
            with_h2_body_idle_timeout("http2_to_http1_response_body_chunk_line", async {
                read_chunk_line(source, runtime_governor).await
            })
            .await?;
        let chunk_len = parse_chunk_len(&line)?;
        if chunk_len == 0 {
            return read_http1_chunked_trailers_as_header_map(
                source,
                max_http_head_bytes,
                runtime_governor,
            )
            .await;
        }

        let mut remaining = chunk_len;
        while remaining > 0 {
            let read_len = remaining.min(IO_CHUNK_SIZE as u64) as usize;
            let chunk = read_http1_response_chunk_non_eof(
                source,
                read_len,
                "http2_to_http1_response_body_next_chunk",
            )
            .await
            .map_err(|error| {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed before chunked response body completed",
                    )
                } else {
                    error
                }
            })?;
            remaining = remaining.checked_sub(chunk.len() as u64).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream chunk exceeded declared chunk length",
                )
            })?;
            forward_http1_response_chunk(
                chunk,
                runtime_governor,
                downstream_response_stream,
                flow_hooks,
                stream_context,
                stream_dispatcher,
                capture_state,
                max_handler_body,
                overflow_mode,
            )
            .await?;
        }

        let terminator =
            with_h2_body_idle_timeout("http2_to_http1_response_body_chunk_terminator", async {
                read_exact_from_source(source, 2, runtime_governor).await
            })
            .await?;
        if terminator.as_slice() != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunk terminator",
            ));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_http1_close_delimited_body<U>(
    source: &mut BufferedConn<U>,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    downstream_response_stream: &mut h2::SendStream<bytes::Bytes>,
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: &FlowContext,
    stream_dispatcher: &mut Option<H2ResponseStreamHookDispatcher>,
    capture_state: &mut Http1ResponseCaptureState,
    max_handler_body: usize,
    overflow_mode: H2ResponseOverflowMode,
) -> io::Result<()>
where
    U: AsyncRead + Unpin,
{
    loop {
        let Some(chunk) = read_http1_response_chunk_allow_eof(
            source,
            IO_CHUNK_SIZE,
            "http2_to_http1_close_delimited_read",
        )
        .await?
        else {
            break;
        };
        forward_http1_response_chunk(
            chunk,
            runtime_governor,
            downstream_response_stream,
            flow_hooks,
            stream_context,
            stream_dispatcher,
            capture_state,
            max_handler_body,
            overflow_mode,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn forward_http1_response_chunk(
    chunk: Vec<u8>,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    downstream_response_stream: &mut h2::SendStream<bytes::Bytes>,
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: &FlowContext,
    stream_dispatcher: &mut Option<H2ResponseStreamHookDispatcher>,
    capture_state: &mut Http1ResponseCaptureState,
    max_handler_body: usize,
    overflow_mode: H2ResponseOverflowMode,
) -> io::Result<()> {
    if chunk.is_empty() {
        return Ok(());
    }
    let truncated_now = capture_state.observe_chunk(&chunk, max_handler_body);
    if truncated_now && matches!(overflow_mode, H2ResponseOverflowMode::StrictFail) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream response body exceeded flow body budget (strict overflow mode)",
        ));
    }
    let chunk = bytes::Bytes::from(chunk);
    let hook_chunk = stream_dispatcher.as_ref().map(|_| chunk.clone());
    send_h2_data_with_backpressure(downstream_response_stream, runtime_governor, chunk, false).await?;
    if let (Some(dispatcher), Some(chunk)) = (stream_dispatcher.as_mut(), hook_chunk.as_ref()) {
        dispatcher
            .on_chunk(flow_hooks, stream_context, chunk.as_ref())
            .await;
    }
    Ok(())
}
