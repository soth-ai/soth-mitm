use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use crate::engine::MitmEngine;
use crate::observe::{EventConsumer, FlowContext};
use crate::policy::PolicyEngine;
use crate::config::InterceptMode;
use super::runtime_governor;
use crate::actions::HandlerDecision;
use super::flow_hooks::{FlowHooks, RawRequest};
use super::io_timeouts::with_stream_stage_timeout;
use super::http2_relay_support::{
    GrpcRequestObservation, enforce_h2_request_header_limit, enforce_h2_response_header_limit,
    h2_error_to_io, is_h2_nonfatal_stream_error, h2_reason_for_downstream_reset, detect_grpc_request,
};
use super::http2_stream_relay::{H2ByteCounters, h2_relay_debug};
use super::http2_stream_relay_body::send_h2_data_with_backpressure;
use super::http2_stream_hook_dispatch::{
    H2CapturedBody, capture_h2_body, tee_h2_request_body, dispatch_h2_response_hooks,
    send_h2_captured_body, is_sse_h2_response, is_ndjson_h2_response, is_grpc_h2_response,
};
use super::http2_stream_response_relay::{
    relay_h2_response_body_with_incremental_forwarding, h2_response_stream_hook_dispatcher,
};
use super::event_emitters_protocol::{emit_grpc_request_headers_event, emit_grpc_response_headers_event, emit_grpc_response_trailers_event};
use super::flow_hook_http_helpers::{
    build_handler_header_map_from_h2, ensure_handler_host_header_from_uri,
    normalize_h2_path_for_handler, normalize_grpc_request_body_for_handler,
    normalize_request_body_for_handler, mark_body_truncated, sanitize_block_status,
    strip_hop_by_hop_and_transport_headers,
};

pub(crate) async fn relay_http2_stream<P, S>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
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
    let (mut request_parts, downstream_request_body) = downstream_request.into_parts();
    if let Err(error) = enforce_h2_request_header_limit(&request_parts, max_header_list_size) {
        h2_relay_debug(format!(
            "[h2-relay:request] request header limit exceeded; resetting stream: {error}"
        ));
        downstream_respond.send_reset(h2::Reason::PROTOCOL_ERROR);
        flow_hooks.on_stream_end(stream_context).await;
        return Ok(());
    }

    let grpc_observation = detect_grpc_request(&request_parts);
    if let Some(observation) = grpc_observation.as_ref() {
        emit_grpc_request_headers_event(
            &engine,
            stream_context.clone(),
            observation,
            &request_parts.headers,
        );
    }

    // Extract handler-relevant info from request parts BEFORE consuming them for upstream.
    let max_handler_body = engine.config.max_flow_body_buffer_bytes.max(1);
    let mut handler_request_headers = build_handler_header_map_from_h2(&request_parts.headers);
    ensure_handler_host_header_from_uri(
        &mut handler_request_headers,
        &stream_context,
        &request_parts.uri,
    );
    let handler_method = request_parts.method.to_string();
    let handler_path = normalize_h2_path_for_handler(&request_parts.uri);

    // Pre-check: if content-length is known and exceeds the handler body budget,
    // reject immediately without forwarding the request upstream.
    let request_end_stream = downstream_request_body.is_end_stream();
    if !request_end_stream {
        if let Some(content_length) = request_parts
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
        {
            if content_length > max_handler_body {
                let body = bytes::Bytes::from_static(b"request body exceeded flow body budget");
                let mut builder = http::Response::builder().status(413);
                builder = builder.header("content-type", "text/plain");
                builder = builder.header("content-length", body.len().to_string());
                let response = builder.body(()).map_err(|error| {
                    io::Error::other(format!("build oversized HTTP/2 response: {error}"))
                })?;
                let mut stream = downstream_respond
                    .send_response(response, body.is_empty())
                    .map_err(|error| {
                        h2_error_to_io("sending oversized HTTP/2 response failed", error)
                    })?;
                if !body.is_empty() {
                    send_h2_data_with_backpressure(&mut stream, &runtime_governor, body, true)
                        .await?;
                }
                flow_hooks.on_stream_end(stream_context).await;
                return Ok(());
            }
        }
    }

    // Build upstream request (consumes request_parts).
    request_parts.version = http::Version::HTTP_2;
    let upstream_request = http::Request::from_parts(request_parts, ());

    // Get upstream sender ready and send request headers BEFORE body capture.
    let ready_upstream_sender_result =
        with_stream_stage_timeout("http2_upstream_sender_ready", async {
            Ok(upstream_sender.ready().await)
        })
        .await?;
    let mut ready_upstream_sender = match ready_upstream_sender_result {
        Ok(sender) => sender,
        Err(error) => {
            if is_h2_nonfatal_stream_error(&error) {
                downstream_respond.send_reset(h2_reason_for_downstream_reset(&error));
                flow_hooks.on_stream_end(stream_context).await;
                return Ok(());
            }
            return Err(h2_error_to_io("upstream HTTP/2 sender not ready", error));
        }
    };
    let (upstream_response_future, upstream_request_stream) =
        match ready_upstream_sender.send_request(upstream_request, request_end_stream) {
            Ok(parts) => parts,
            Err(error) => {
                if is_h2_nonfatal_stream_error(&error) {
                    downstream_respond.send_reset(h2_reason_for_downstream_reset(&error));
                    flow_hooks.on_stream_end(stream_context).await;
                    return Ok(());
                }
                return Err(h2_error_to_io("forwarding HTTP/2 request failed", error));
            }
        };

    // Run body tee and response await concurrently using select!.
    //
    // Two scenarios:
    // 1. Tee finishes first (normal): upstream processes the full body, then responds.
    //    We relay the response body incrementally via the live RecvStream.
    // 2. Response arrives first (early response, e.g. 401 before body is fully sent):
    //    For non-streaming responses with known content-length, eagerly capture the
    //    body before the upstream connection might close. For streaming responses
    //    (SSE, gRPC, NDJSON), wait for tee and relay incrementally.
    //
    // Biased toward tee-first: for small bodies (< H2 window size), the tee completes
    // before the response arrives (network latency), ensuring the streaming relay path.
    enum UpstreamResponseCapture {
        /// RecvStream is live, use incremental relay.
        Streaming(http::response::Parts, h2::RecvStream),
        /// Body was captured eagerly before upstream connection died.
        Buffered(http::response::Parts, H2CapturedBody),
    }

    let (request_captured, response_capture) = if request_end_stream {
        let captured = H2CapturedBody {
            bytes: bytes::Bytes::new(),
            bytes_forwarded: 0,
            trailers: None,
            body_truncated: false,
        };
        let resp = with_stream_stage_timeout("http2_upstream_response_headers", async {
            Ok(upstream_response_future.await)
        })
        .await?;
        let response = match resp {
            Ok(response) => response,
            Err(error) => {
                if is_h2_nonfatal_stream_error(&error) {
                    downstream_respond.send_reset(h2_reason_for_downstream_reset(&error));
                    flow_hooks.on_stream_end(stream_context).await;
                    return Ok(());
                }
                return Err(h2_error_to_io(
                    "awaiting upstream HTTP/2 response failed",
                    error,
                ));
            }
        };
        let (parts, body) = response.into_parts();
        (captured, UpstreamResponseCapture::Streaming(parts, body))
    } else {
        let mut tee_fut = std::pin::pin!(tee_h2_request_body(
            downstream_request_body,
            upstream_request_stream,
            Arc::clone(&runtime_governor),
            max_handler_body,
        ));
        let mut resp_fut = std::pin::pin!(with_stream_stage_timeout(
            "http2_upstream_response_headers",
            async { Ok(upstream_response_future.await) },
        ));

        tokio::select! {
            biased;

            // Tee finished first — normal case. Use streaming relay.
            tee_result = &mut tee_fut => {
                let request_captured = tee_result?;
                let resp = resp_fut.await?;
                let response = match resp {
                    Ok(response) => response,
                    Err(error) => {
                        if is_h2_nonfatal_stream_error(&error) {
                            downstream_respond.send_reset(h2_reason_for_downstream_reset(&error));
                            flow_hooks.on_stream_end(stream_context).await;
                            return Ok(());
                        }
                        return Err(h2_error_to_io(
                            "awaiting upstream HTTP/2 response failed",
                            error,
                        ));
                    }
                };
                let (parts, body) = response.into_parts();
                (request_captured, UpstreamResponseCapture::Streaming(parts, body))
            }

            // Response arrived before tee finished — early response scenario.
            resp_result = &mut resp_fut => {
                let resp = resp_result?;
                let response = match resp {
                    Ok(response) => response,
                    Err(error) => {
                        // Let tee finish before returning.
                        let _ = tee_fut.await;
                        if is_h2_nonfatal_stream_error(&error) {
                            downstream_respond.send_reset(h2_reason_for_downstream_reset(&error));
                            flow_hooks.on_stream_end(stream_context).await;
                            return Ok(());
                        }
                        return Err(h2_error_to_io(
                            "awaiting upstream HTTP/2 response failed",
                            error,
                        ));
                    }
                };
                let (parts, mut recv_body) = response.into_parts();

                // For streaming responses (SSE, NDJSON, gRPC) or responses without
                // a known content-length, use incremental relay — don't try to buffer
                // the entire stream. Wait for tee to finish, then relay live.
                let is_streaming_response = is_sse_h2_response(&parts)
                    || is_ndjson_h2_response(&parts)
                    || is_grpc_h2_response(&parts)
                    || !has_finite_content_length(&parts);

                if is_streaming_response {
                    let request_captured = tee_fut.await?;
                    (request_captured, UpstreamResponseCapture::Streaming(parts, recv_body))
                } else {
                    // Non-streaming early response (e.g. 401 with small body).
                    // Capture body eagerly before the upstream connection closes.
                    let response_captured = capture_h2_body(&mut recv_body, max_handler_body)
                        .await
                        .unwrap_or_else(|_| H2CapturedBody {
                            bytes: bytes::Bytes::new(),
                            bytes_forwarded: 0,
                            trailers: None,
                            body_truncated: false,
                        });
                    let request_captured = tee_fut.await?;
                    (request_captured, UpstreamResponseCapture::Buffered(parts, response_captured))
                }
            }
        }
    };
    byte_counters
        .request_bytes
        .fetch_add(request_captured.bytes_forwarded, Ordering::Relaxed);

    if request_captured.body_truncated {
        let body = bytes::Bytes::from_static(b"request body exceeded flow body budget");
        let mut builder = http::Response::builder().status(413);
        builder = builder.header("content-type", "text/plain");
        builder = builder.header("content-length", body.len().to_string());
        let response = builder
            .body(())
            .map_err(|error| io::Error::other(format!("build oversized HTTP/2 response: {error}")))?;
        let mut stream = downstream_respond
            .send_response(response, body.is_empty())
            .map_err(|error| h2_error_to_io("sending oversized HTTP/2 response failed", error))?;
        if !body.is_empty() {
            send_h2_data_with_backpressure(&mut stream, &runtime_governor, body, true).await?;
        }
        flow_hooks.on_stream_end(stream_context).await;
        return Ok(());
    }

    // Build handler body and call handler.
    if request_captured.body_truncated {
        mark_body_truncated(&mut handler_request_headers);
    }
    let mut handler_request_body = if request_captured.body_truncated {
        request_captured
            .bytes
            .slice(..max_handler_body.min(request_captured.bytes.len()))
    } else {
        request_captured.bytes.clone()
    };
    handler_request_body =
        normalize_request_body_for_handler(&mut handler_request_headers, handler_request_body);
    if grpc_observation.is_some() {
        handler_request_body = normalize_grpc_request_body_for_handler(
            &mut handler_request_headers,
            handler_request_body,
        );
    }

    if engine.config.intercept_mode == InterceptMode::Monitor {
        flow_hooks
            .on_request_observe(
                stream_context.clone(),
                RawRequest {
                    method: handler_method,
                    path: handler_path,
                    headers: handler_request_headers,
                    body: handler_request_body,
                },
            )
            .await;
    } else {
        let request_decision = flow_hooks
            .on_request(
                stream_context.clone(),
                RawRequest {
                    method: handler_method,
                    path: handler_path,
                    headers: handler_request_headers,
                    body: handler_request_body,
                },
            )
            .await;
        if let HandlerDecision::Block { status, body } = request_decision {
            let status = sanitize_block_status(status);
            let mut builder = http::Response::builder().status(status);
            builder = builder.header("content-type", "text/plain");
            builder = builder.header("content-length", body.len().to_string());
            let block_response = builder.body(()).map_err(|error| {
                io::Error::other(format!("build blocked HTTP/2 response: {error}"))
            })?;
            let mut stream = downstream_respond
                .send_response(block_response, body.is_empty())
                .map_err(|error| {
                    h2_error_to_io("sending blocked HTTP/2 response failed", error)
                })?;
            if !body.is_empty() {
                send_h2_data_with_backpressure(&mut stream, &runtime_governor, body, true)
                    .await?;
            }
            flow_hooks.on_stream_end(stream_context).await;
            return Ok(());
        }
    }

    // Forward upstream response to downstream.
    match response_capture {
        UpstreamResponseCapture::Streaming(response_parts, mut upstream_response_body) => {
            relay_upstream_response_streaming(
                &engine,
                &runtime_governor,
                &flow_hooks,
                &stream_context,
                &grpc_observation,
                downstream_respond,
                response_parts,
                &mut upstream_response_body,
                max_header_list_size,
                max_handler_body,
                &byte_counters,
            )
            .await
        }
        UpstreamResponseCapture::Buffered(response_parts, captured_response) => {
            relay_upstream_response_buffered(
                &engine,
                &runtime_governor,
                &flow_hooks,
                &stream_context,
                &grpc_observation,
                downstream_respond,
                response_parts,
                captured_response,
                max_header_list_size,
                max_handler_body,
                &byte_counters,
            )
            .await
        }
    }
}

/// Returns true if the response has a finite content-length header (non-streaming).
fn has_finite_content_length(parts: &http::response::Parts) -> bool {
    parts
        .headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some()
}

/// Forward a live upstream response body incrementally (normal case).
#[allow(clippy::too_many_arguments)]
async fn relay_upstream_response_streaming<P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: &FlowContext,
    grpc_observation: &Option<GrpcRequestObservation>,
    mut downstream_respond: h2::server::SendResponse<bytes::Bytes>,
    response_parts: http::response::Parts,
    upstream_response_body: &mut h2::RecvStream,
    max_header_list_size: u32,
    max_handler_body: usize,
    byte_counters: &H2ByteCounters,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut downstream_response_parts = response_parts.clone();
    strip_hop_by_hop_and_transport_headers(&mut downstream_response_parts.headers);
    if enforce_h2_response_header_limit(&downstream_response_parts, max_header_list_size).is_err() {
        h2_relay_debug("[h2-relay:response] response header limit exceeded; resetting stream");
        downstream_respond.send_reset(h2::Reason::PROTOCOL_ERROR);
        flow_hooks.on_stream_end(stream_context.clone()).await;
        return Ok(());
    }

    if let Some(observation) = grpc_observation.as_ref() {
        emit_grpc_response_headers_event(engine, stream_context.clone(), observation, &response_parts);
    }

    let mut stream_dispatcher = h2_response_stream_hook_dispatcher(&response_parts);
    let downstream_response = http::Response::from_parts(downstream_response_parts.clone(), ());
    let mut downstream_response_stream =
        match downstream_respond.send_response(downstream_response, false) {
            Ok(stream) => stream,
            Err(error) => {
                if is_h2_nonfatal_stream_error(&error) {
                    flow_hooks.on_stream_end(stream_context.clone()).await;
                    return Ok(());
                }
                return Err(h2_error_to_io(
                    "sending downstream HTTP/2 response headers failed",
                    error,
                ));
            }
        };

    let relay_outcome = relay_h2_response_body_with_incremental_forwarding(
        upstream_response_body,
        &mut downstream_response_stream,
        runtime_governor,
        flow_hooks,
        stream_context,
        &mut stream_dispatcher,
        max_handler_body,
        engine.config.h2_response_overflow_strict,
    )
    .await?;
    byte_counters
        .response_bytes
        .fetch_add(relay_outcome.captured.bytes_forwarded, Ordering::Relaxed);

    if let (Some(observation), Some(trailers)) = (
        grpc_observation.as_ref(),
        relay_outcome.observed_trailers.as_ref(),
    ) {
        emit_grpc_response_trailers_event(engine, stream_context.clone(), observation, trailers);
    }

    if stream_dispatcher.is_none() {
        dispatch_h2_response_hooks(
            flow_hooks,
            stream_context.clone(),
            &response_parts,
            &relay_outcome.captured,
            max_handler_body,
        )
        .await;
    }
    Ok(())
}

/// Forward a buffered upstream response (early response case where body was
/// eagerly captured before the upstream connection died).
#[allow(clippy::too_many_arguments)]
async fn relay_upstream_response_buffered<P, S>(
    engine: &Arc<MitmEngine<P, S>>,
    runtime_governor: &Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: &Arc<dyn FlowHooks>,
    stream_context: &FlowContext,
    grpc_observation: &Option<GrpcRequestObservation>,
    mut downstream_respond: h2::server::SendResponse<bytes::Bytes>,
    response_parts: http::response::Parts,
    captured_response: H2CapturedBody,
    max_header_list_size: u32,
    max_handler_body: usize,
    byte_counters: &H2ByteCounters,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    let mut downstream_response_parts = response_parts.clone();
    strip_hop_by_hop_and_transport_headers(&mut downstream_response_parts.headers);
    if enforce_h2_response_header_limit(&downstream_response_parts, max_header_list_size).is_err() {
        h2_relay_debug("[h2-relay:response] response header limit exceeded; resetting stream");
        downstream_respond.send_reset(h2::Reason::PROTOCOL_ERROR);
        flow_hooks.on_stream_end(stream_context.clone()).await;
        return Ok(());
    }

    if let Some(observation) = grpc_observation.as_ref() {
        emit_grpc_response_headers_event(engine, stream_context.clone(), observation, &response_parts);
    }

    let has_body = !captured_response.bytes.is_empty() || captured_response.trailers.is_some();
    let downstream_response = http::Response::from_parts(downstream_response_parts.clone(), ());
    let mut downstream_response_stream =
        match downstream_respond.send_response(downstream_response, !has_body) {
            Ok(stream) => stream,
            Err(error) => {
                if is_h2_nonfatal_stream_error(&error) {
                    flow_hooks.on_stream_end(stream_context.clone()).await;
                    return Ok(());
                }
                return Err(h2_error_to_io(
                    "sending downstream HTTP/2 response headers failed",
                    error,
                ));
            }
        };

    byte_counters
        .response_bytes
        .fetch_add(captured_response.bytes_forwarded, Ordering::Relaxed);

    if has_body {
        let observed_trailers = send_h2_captured_body(
            &mut downstream_response_stream,
            runtime_governor,
            H2CapturedBody {
                bytes: captured_response.bytes.clone(),
                bytes_forwarded: captured_response.bytes_forwarded,
                trailers: captured_response.trailers.clone(),
                body_truncated: captured_response.body_truncated,
            },
        )
        .await?;

        if let (Some(observation), Some(trailers)) = (
            grpc_observation.as_ref(),
            observed_trailers.as_ref(),
        ) {
            emit_grpc_response_trailers_event(engine, stream_context.clone(), observation, trailers);
        }
    }

    dispatch_h2_response_hooks(
        flow_hooks,
        stream_context.clone(),
        &response_parts,
        &captured_response,
        max_handler_body,
    )
    .await;

    Ok(())
}
