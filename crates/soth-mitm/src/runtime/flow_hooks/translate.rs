use std::sync::Arc;

use dashmap::{DashMap, DashSet};
use mitm_observe::FlowContext;
use mitm_sidecar::StreamFrameKind;

use crate::runtime::connection_meta::tls_info_from_intercept_decision;
use crate::types::{ConnectionMeta, FrameKind};

pub(super) fn map_stream_frame_kind(kind: StreamFrameKind) -> Option<FrameKind> {
    match kind {
        StreamFrameKind::SseData => Some(FrameKind::SseData),
        StreamFrameKind::NdjsonLine => Some(FrameKind::NdjsonLine),
        StreamFrameKind::GrpcMessage => Some(FrameKind::GrpcMessage),
        StreamFrameKind::WebSocketText => Some(FrameKind::WebSocketText),
        StreamFrameKind::WebSocketBinary => Some(FrameKind::WebSocketBinary),
        StreamFrameKind::WebSocketClose => Some(FrameKind::WebSocketClose),
    }
}

pub(super) async fn connection_meta_for_context(
    context: &FlowContext,
    connection_meta_by_flow: &Arc<DashMap<u64, Arc<ConnectionMeta>>>,
    closed_flow_live: &Arc<DashSet<u64>>,
    tls_intercepted_flow_ids: &Arc<DashMap<u64, ()>>,
) -> Option<Arc<ConnectionMeta>> {
    let Some(connection_meta) = connection_meta_by_flow
        .get(&context.flow_id)
        .map(|value| Arc::clone(value.value()))
    else {
        if closed_flow_live.contains(&context.flow_id) {
            return None;
        }
        debug_assert!(
            false,
            "connection {} missing ConnectionMeta in flow map",
            context.flow_id
        );
        tracing::error!(
            flow_id = context.flow_id,
            host = %context.server_host,
            port = context.server_port,
            "missing ConnectionMeta in flow map"
        );
        return None;
    };
    if connection_meta.tls_info.is_some() {
        return Some(connection_meta);
    }

    let intercepted_tls = tls_intercepted_flow_ids.contains_key(&context.flow_id);
    let Some(tls_info) = tls_info_from_intercept_decision(context, intercepted_tls) else {
        return Some(connection_meta);
    };

    let mut enriched = (*connection_meta).clone();
    enriched.tls_info = Some(tls_info);
    let enriched = Arc::new(enriched);
    connection_meta_by_flow.insert(context.flow_id, Arc::clone(&enriched));
    Some(enriched)
}
