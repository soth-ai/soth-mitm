use super::close_codes::CloseReasonCode;
use super::event_emitters::emit_stream_closed;
use super::flow_forward_proxy_http1_helpers::{
    is_self_listener_target, resolve_forward_http_route,
};
use super::flow_hook_http_helpers::{
    build_handler_header_map, mark_body_truncated, normalize_request_body_for_handler,
    normalize_request_path_for_handler, relay_http_body_with_capture, sanitize_block_status,
    strip_hop_by_hop_and_transport_headers,
};
use super::flow_hooks::FlowHooks;
use super::flow_intercept_http1::relay_http1_mitm_loop;
use super::flow_policy_snapshot::resolve_flow_policy_snapshot;
use super::http_head_parser::parse_http_request_head;
use super::io_timeouts::{
    copy_bidirectional_with_websocket_idle_timeout, is_idle_watchdog_timeout,
    is_stream_stage_timeout, shutdown_with_idle_timeout, write_all_with_idle_timeout,
};
use super::route_planner_model::{FlowRoutePlanner, RouteConnectIntent};
use super::route_planner_transport::connect_via_route;
use super::runtime_governor;
use super::BufferedConn;
use crate::engine::MitmEngine;
use crate::observe::{EventConsumer, EventType, FlowContext};
use crate::policy::{FlowAction, PolicyEngine};
use crate::protocol::ApplicationProtocol;
use crate::types::ProcessInfo;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_forward_http1_proxy_request<P, S, D>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    downstream: D,
    client_addr: String,
    flow_id: crate::types::FlowId,
    process_info: Option<ProcessInfo>,
    initial_head: Vec<u8>,
    max_http_head_bytes: usize,
    listener_addr: Option<std::net::SocketAddr>,
    _flow_guard: &mut Option<crate::server::runtime_governor::FlowRuntimeGuard>,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut downstream = downstream;
    let request = match parse_http_request_head(&initial_head) {
        Ok(parsed) => parsed,
        Err(error) => {
            let context = FlowContext {
                flow_id,
                client_addr,
                server_host: "<unknown>".to_string(),
                server_port: 0,
                protocol: ApplicationProtocol::Http1,
            };
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::MitmHttpError,
                Some(format!("invalid forward-proxy request: {error}")),
                None,
                None,
            );
            write_forward_proxy_error_response(
                &mut downstream,
                "400 Bad Request",
                "invalid HTTP proxy request",
            )
            .await?;
            return Ok(());
        }
    };

    let target = match resolve_forward_http_route(&request) {
        Ok(value) => value,
        Err(error) => {
            let context = FlowContext {
                flow_id,
                client_addr,
                server_host: "<unknown>".to_string(),
                server_port: 0,
                protocol: ApplicationProtocol::Http1,
            };
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::MitmHttpError,
                Some(format!("invalid forward-proxy route: {error}")),
                None,
                None,
            );
            write_forward_proxy_error_response(
                &mut downstream,
                "400 Bad Request",
                "invalid HTTP proxy target",
            )
            .await?;
            return Ok(());
        }
    };

    let (listen_addr, listen_port) = listener_addr
        .map(|addr| (addr.ip().to_string(), addr.port()))
        .unwrap_or_else(|| (engine.config.listen_addr.clone(), engine.config.listen_port));

    if is_self_listener_target(&target.host, target.port, &listen_addr, listen_port) {
        let context = FlowContext {
            flow_id,
            client_addr,
            server_host: target.host.clone(),
            server_port: target.port,
            protocol: ApplicationProtocol::Http1,
        };
        if flow_hooks.handles_local_requests() {
            if let Some((bytes_from_client, bytes_from_server)) = try_handle_local_http1_request(
                Arc::clone(&engine),
                Arc::clone(&runtime_governor),
                Arc::clone(&flow_hooks),
                &context,
                &request,
                &mut downstream,
                max_http_head_bytes,
            )
            .await?
            {
                emit_stream_closed(
                    &engine,
                    context,
                    CloseReasonCode::MitmHttpCompleted,
                    Some("local self-target request handled".to_string()),
                    Some(bytes_from_client),
                    Some(bytes_from_server),
                );
                return Ok(());
            }
        }
        emit_stream_closed(
            &engine,
            context,
            CloseReasonCode::RoutePlannerFailed,
            Some(format!(
                "forward-proxy self-target loop detected: {}:{} matches listener {}:{}",
                target.host, target.port, listen_addr, listen_port
            )),
            None,
            None,
        );
        write_forward_proxy_error_response(
            &mut downstream,
            "508 Loop Detected",
            "forward proxy self-target not allowed",
        )
        .await?;
        return Ok(());
    }

    let mut route_planner = FlowRoutePlanner::default();
    let route = match route_planner.bind_once(&engine.config, target) {
        Ok(value) => value,
        Err(error) => {
            let context = FlowContext {
                flow_id,
                client_addr,
                server_host: "<unknown>".to_string(),
                server_port: 0,
                protocol: ApplicationProtocol::Http1,
            };
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::RoutePlannerFailed,
                Some(format!("forward-proxy route planner failed: {error}")),
                None,
                None,
            );
            write_forward_proxy_error_response(
                &mut downstream,
                "502 Bad Gateway",
                "route planner failed for forward proxy request",
            )
            .await?;
            return Ok(());
        }
    };

    let policy_snapshot = resolve_flow_policy_snapshot(
        &engine,
        flow_id,
        client_addr.clone(),
        route.target_host.clone(),
        route.target_port,
        route.policy_path.clone(),
        process_info,
    );
    let context = FlowContext {
        flow_id: policy_snapshot.flow_id,
        client_addr,
        server_host: route.target_host.clone(),
        server_port: route.target_port,
        protocol: ApplicationProtocol::Http1,
    };

    if policy_snapshot.action == FlowAction::Block {
        write_forward_proxy_error_response(
            &mut downstream,
            "403 Forbidden",
            &policy_snapshot.reason,
        )
        .await?;
        emit_stream_closed(
            &engine,
            context,
            CloseReasonCode::Blocked,
            Some(policy_snapshot.reason),
            None,
            None,
        );
        return Ok(());
    }

    let upstream_tcp = match connect_via_route(&route, RouteConnectIntent::ForwardHttpRequest).await
    {
        Ok(stream) => stream,
        Err(error) => {
            write_forward_proxy_error_response(
                &mut downstream,
                "502 Bad Gateway",
                &format!(
                    "upstream_connect_failed[{}]: {error}",
                    route.route_mode_label()
                ),
            )
            .await?;
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::UpstreamConnectFailed,
                Some(error.to_string()),
                None,
                None,
            );
            return Ok(());
        }
    };

    if policy_snapshot.action == FlowAction::Tunnel {
        // No permit needed for tunnel — never acquired.
        return tunnel_http1_forward_stream(
            engine,
            context,
            downstream,
            upstream_tcp,
            initial_head,
        )
        .await;
    }

    let mut downstream_conn = BufferedConn::new(downstream);
    downstream_conn.read_buf = initial_head;
    let upstream_conn = BufferedConn::new(upstream_tcp);
    relay_http1_mitm_loop(
        engine,
        runtime_governor,
        flow_hooks,
        context,
        route.request_target_mode,
        downstream_conn,
        upstream_conn,
        max_http_head_bytes,
        policy_snapshot.override_state.strict_header_mode,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn try_handle_local_http1_request<P, S, D>(
    engine: Arc<MitmEngine<P, S>>,
    runtime_governor: Arc<runtime_governor::RuntimeGovernor>,
    flow_hooks: Arc<dyn FlowHooks>,
    context: &FlowContext,
    request: &super::HttpRequestHead,
    downstream: &mut D,
    max_http_head_bytes: usize,
) -> io::Result<Option<(u64, u64)>>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut downstream_conn = BufferedConn::new(downstream);
    let mut request_sink = tokio::io::sink();
    let (request_body_bytes, request_body, request_body_truncated) = relay_http_body_with_capture(
        &engine,
        context,
        EventType::RequestBodyChunk,
        &mut downstream_conn,
        &mut request_sink,
        request.body_mode,
        max_http_head_bytes,
        &runtime_governor,
        engine.config.max_flow_body_buffer_bytes,
    )
    .await?;

    let mut headers = build_handler_header_map(&request.headers);
    if request_body_truncated {
        mark_body_truncated(&mut headers);
    }
    let body = normalize_request_body_for_handler(&mut headers, request_body);
    let local_response = flow_hooks
        .on_local_request(
            context.clone(),
            super::flow_hooks::RawRequest {
                method: request.method.clone(),
                path: normalize_request_path_for_handler(&request.target),
                headers,
                body,
            },
        )
        .await;

    let Some(response) = local_response else {
        return Ok(None);
    };

    let bytes_from_server =
        write_local_http1_response(downstream_conn.stream, &request.method, response).await?;
    Ok(Some((
        request.raw.len() as u64 + request_body_bytes,
        bytes_from_server,
    )))
}

async fn write_local_http1_response<D>(
    mut downstream: D,
    request_method: &str,
    response: super::flow_hooks::RawResponse,
) -> io::Result<u64>
where
    D: AsyncWrite + Unpin,
{
    let status = sanitize_block_status(response.status);
    let reason = status_reason(status);
    let mut headers = response.headers;
    strip_hop_by_hop_and_transport_headers(&mut headers);
    headers.remove(http::header::CONTENT_LENGTH);

    let content_length_allowed = !((100..200).contains(&status) || status == 204 || status == 304);
    let body_allowed = content_length_allowed && !request_method.eq_ignore_ascii_case("HEAD");

    let mut head = Vec::new();
    head.extend_from_slice(format!("HTTP/1.1 {status} {reason}\r\n").as_bytes());
    for (name, value) in headers.iter() {
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    if content_length_allowed {
        head.extend_from_slice(format!("Content-Length: {}\r\n", response.body.len()).as_bytes());
    }
    // Local responses terminate the self-target request without entering the
    // normal forward-proxy relay loop, so close the connection deterministically.
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    let mut bytes_written = head.len() as u64;
    write_all_with_idle_timeout(&mut downstream, &head, "local_http1_response_head_write").await?;
    if body_allowed && !response.body.is_empty() {
        bytes_written += response.body.len() as u64;
        write_all_with_idle_timeout(
            &mut downstream,
            &response.body,
            "local_http1_response_body_write",
        )
        .await?;
    }
    shutdown_with_idle_timeout(&mut downstream, "local_http1_response_shutdown").await?;
    Ok(bytes_written)
}

fn status_reason(status: u16) -> &'static str {
    http::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("Unknown")
}

async fn tunnel_http1_forward_stream<P, S, D>(
    engine: Arc<MitmEngine<P, S>>,
    context: FlowContext,
    mut downstream: D,
    mut upstream: TcpStream,
    initial_head: Vec<u8>,
) -> io::Result<()>
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let first_request = match parse_http_request_head(&initial_head) {
        Ok(value) => value,
        Err(error) => {
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::MitmHttpError,
                Some(format!(
                    "invalid first HTTP request in tunnel mode: {error}"
                )),
                None,
                None,
            );
            return Ok(());
        }
    };
    if let Err(error) = write_all_with_idle_timeout(
        &mut upstream,
        &first_request.raw,
        "forward_tunnel_initial_request_write",
    )
    .await
    {
        emit_stream_closed(
            &engine,
            context,
            CloseReasonCode::RelayError,
            Some(format!("forward initial request failed: {error}")),
            None,
            None,
        );
        return Ok(());
    }

    match copy_bidirectional_with_websocket_idle_timeout(&mut downstream, &mut upstream).await {
        Ok((from_client, from_server)) => {
            // Forward-proxy tunnel: blind TCP passthrough, no body budget applies.
            emit_stream_closed(
                &engine,
                context,
                CloseReasonCode::RelayEof,
                None,
                Some(from_client + (initial_head.len() as u64)),
                Some(from_server),
            );
            Ok(())
        }
        Err(error) => {
            let reason = if is_idle_watchdog_timeout(&error) {
                CloseReasonCode::IdleWatchdogTimeout
            } else if is_stream_stage_timeout(&error) {
                CloseReasonCode::StreamStageTimeout
            } else {
                CloseReasonCode::RelayError
            };
            emit_stream_closed(
                &engine,
                context,
                reason,
                Some(error.to_string()),
                None,
                None,
            );
            if error.kind() == io::ErrorKind::InvalidData
                && error.to_string().contains("copy_bidirectional")
            {
                let _ = write_forward_proxy_error_response(
                    &mut downstream,
                    "400 Bad Request",
                    "HTTP proxy stream relay failed",
                )
                .await;
            }
            Ok(())
        }
    }
}

pub(crate) async fn write_forward_proxy_error_response<D>(
    downstream: &mut D,
    status: &str,
    body: &str,
) -> io::Result<()>
where
    D: AsyncWrite + Unpin,
{
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    write_all_with_idle_timeout(
        downstream,
        response.as_bytes(),
        "forward_proxy_error_response_write",
    )
    .await?;
    shutdown_with_idle_timeout(downstream, "forward_proxy_error_response_shutdown").await
}
