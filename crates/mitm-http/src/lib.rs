mod anti_hijack;
mod decoder_chain;
mod grpc_envelope;
mod sse_parser;

pub use anti_hijack::{
    sanitize_anti_hijack_prefix, sanitize_anti_hijack_prefixes, AntiHijackPrefix,
    AntiHijackSanitizationStage, AntiHijackSanitizeResult, KNOWN_ANTI_HIJACK_PREFIXES,
    SANITIZED_ATTRIBUTE, SANITIZED_PREFIX_ATTRIBUTE, SANITIZED_PROVENANCE_ATTRIBUTE,
};
pub use decoder_chain::{
    validate_stage_order, DecoderFailureCode, DecoderFrame, DecoderPipelineRegistry,
    DecoderPipelineResult, DecoderStage, DecoderStageFailure, DecoderStageProcessor,
    DecoderStageReport, DecoderStageStatus, LayeredDecoderPipeline, StageProcessOutcome,
};
pub use grpc_envelope::{
    GrpcEnvelopeFrame, GrpcEnvelopeMalformed, GrpcEnvelopeMalformedCode, GrpcEnvelopeParser,
    GrpcEnvelopeParserLimits, GrpcEnvelopeRecord,
};
pub use sse_parser::{SseEvent, SseParser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationProtocol {
    Http1,
    Http2,
    WebSocket,
    Sse,
    StreamableHttp,
    Tunnel,
}

pub const ALPN_HTTP_11: &[u8] = b"http/1.1";
pub const ALPN_H2: &[u8] = b"h2";

pub fn configured_http_alpn_protocols(http2_enabled: bool) -> Vec<Vec<u8>> {
    if http2_enabled {
        vec![ALPN_H2.to_vec(), ALPN_HTTP_11.to_vec()]
    } else {
        vec![ALPN_HTTP_11.to_vec()]
    }
}

pub fn protocol_from_negotiated_alpn(
    negotiated_alpn: Option<&[u8]>,
    http2_enabled: bool,
) -> ApplicationProtocol {
    if http2_enabled && matches!(negotiated_alpn, Some(value) if value == ALPN_H2) {
        ApplicationProtocol::Http2
    } else {
        ApplicationProtocol::Http1
    }
}

pub fn negotiated_alpn_label(negotiated_alpn: Option<&[u8]>) -> Option<&'static str> {
    match negotiated_alpn {
        Some(value) if value == ALPN_H2 => Some("h2"),
        Some(value) if value == ALPN_HTTP_11 => Some("http/1.1"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpLimits {
    pub http2_enabled: bool,
    pub http2_max_header_list_size: u32,
    pub http3_passthrough: bool,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            http2_enabled: true,
            http2_max_header_list_size: 64 * 1024,
            http3_passthrough: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsFrameKind {
    Data,
    Control,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketFrameMeta {
    pub sequence_no: u64,
    pub direction: WsDirection,
    pub kind: WsFrameKind,
    pub payload_len: usize,
    pub timestamp_unix_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketTurn {
    pub turn_id: u64,
    pub initiated_by: WsDirection,
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: u128,
    pub first_frame_sequence_no: u64,
    pub last_frame_sequence_no: u64,
    pub client_frame_count: u32,
    pub server_frame_count: u32,
    pub client_payload_bytes: u64,
    pub server_payload_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InProgressTurn {
    turn_id: u64,
    initiated_by: WsDirection,
    started_at_unix_ms: u128,
    last_frame_sequence_no: u64,
    last_frame_timestamp_unix_ms: u128,
    first_frame_sequence_no: u64,
    client_frame_count: u32,
    server_frame_count: u32,
    client_payload_bytes: u64,
    server_payload_bytes: u64,
    opposite_data_seen: bool,
}

#[derive(Debug, Default)]
pub struct WebSocketTurnAggregator {
    current: Option<InProgressTurn>,
    next_turn_id: u64,
    next_frame_sequence_no: u64,
}

impl WebSocketTurnAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on_frame(
        &mut self,
        direction: WsDirection,
        kind: WsFrameKind,
        payload_len: usize,
        timestamp_unix_ms: u128,
    ) -> Option<WebSocketTurn> {
        let sequence_no = self.next_sequence_no();
        let frame = WebSocketFrameMeta {
            sequence_no,
            direction,
            kind,
            payload_len,
            timestamp_unix_ms,
        };

        if self.current.is_none() {
            self.current = Some(self.start_turn(&frame));
            return None;
        }

        let should_roll = {
            let current = self.current.as_ref().expect("current turn must exist");
            current.opposite_data_seen
                && frame.kind == WsFrameKind::Data
                && frame.direction == current.initiated_by
        };

        if should_roll {
            let completed = self.finish_current_turn();
            self.current = Some(self.start_turn(&frame));
            return completed;
        }

        self.append_frame(frame);
        None
    }

    pub fn flush(&mut self) -> Option<WebSocketTurn> {
        self.finish_current_turn()
    }

    fn start_turn(&mut self, frame: &WebSocketFrameMeta) -> InProgressTurn {
        let turn_id = self.next_turn_id();
        let mut turn = InProgressTurn {
            turn_id,
            initiated_by: frame.direction,
            started_at_unix_ms: frame.timestamp_unix_ms,
            last_frame_sequence_no: frame.sequence_no,
            last_frame_timestamp_unix_ms: frame.timestamp_unix_ms,
            first_frame_sequence_no: frame.sequence_no,
            client_frame_count: 0,
            server_frame_count: 0,
            client_payload_bytes: 0,
            server_payload_bytes: 0,
            opposite_data_seen: false,
        };
        Self::apply_frame(&mut turn, frame);
        turn
    }

    fn append_frame(&mut self, frame: WebSocketFrameMeta) {
        if let Some(current) = self.current.as_mut() {
            Self::apply_frame(current, &frame);
        }
    }

    fn apply_frame(turn: &mut InProgressTurn, frame: &WebSocketFrameMeta) {
        turn.last_frame_sequence_no = frame.sequence_no;
        turn.last_frame_timestamp_unix_ms = frame.timestamp_unix_ms;

        match frame.direction {
            WsDirection::ClientToServer => {
                turn.client_frame_count += 1;
                turn.client_payload_bytes += frame.payload_len as u64;
            }
            WsDirection::ServerToClient => {
                turn.server_frame_count += 1;
                turn.server_payload_bytes += frame.payload_len as u64;
            }
        }

        if frame.kind == WsFrameKind::Data && frame.direction != turn.initiated_by {
            turn.opposite_data_seen = true;
        }
    }

    fn finish_current_turn(&mut self) -> Option<WebSocketTurn> {
        self.current.take().map(|turn| WebSocketTurn {
            turn_id: turn.turn_id,
            initiated_by: turn.initiated_by,
            started_at_unix_ms: turn.started_at_unix_ms,
            ended_at_unix_ms: turn.last_frame_timestamp_unix_ms,
            first_frame_sequence_no: turn.first_frame_sequence_no,
            last_frame_sequence_no: turn.last_frame_sequence_no,
            client_frame_count: turn.client_frame_count,
            server_frame_count: turn.server_frame_count,
            client_payload_bytes: turn.client_payload_bytes,
            server_payload_bytes: turn.server_payload_bytes,
        })
    }

    fn next_sequence_no(&mut self) -> u64 {
        let next = self.next_frame_sequence_no + 1;
        self.next_frame_sequence_no = next;
        next
    }

    fn next_turn_id(&mut self) -> u64 {
        let next = self.next_turn_id + 1;
        self.next_turn_id = next;
        next
    }
}

#[cfg(test)]
mod tests {
    use super::{
        configured_http_alpn_protocols, negotiated_alpn_label, protocol_from_negotiated_alpn,
        ApplicationProtocol, WebSocketTurnAggregator, WsDirection, WsFrameKind, ALPN_H2,
        ALPN_HTTP_11,
    };

    #[test]
    fn rolls_turn_after_response_when_client_speaks_again() {
        let mut agg = WebSocketTurnAggregator::new();
        assert!(agg
            .on_frame(WsDirection::ClientToServer, WsFrameKind::Data, 10, 1_000)
            .is_none());
        assert!(agg
            .on_frame(WsDirection::ClientToServer, WsFrameKind::Data, 5, 1_001)
            .is_none());
        assert!(agg
            .on_frame(WsDirection::ServerToClient, WsFrameKind::Data, 20, 1_002)
            .is_none());
        assert!(agg
            .on_frame(WsDirection::ServerToClient, WsFrameKind::Control, 0, 1_003)
            .is_none());

        let completed = agg
            .on_frame(WsDirection::ClientToServer, WsFrameKind::Data, 1, 1_004)
            .expect("turn should complete");
        assert_eq!(completed.turn_id, 1);
        assert_eq!(completed.client_frame_count, 2);
        assert_eq!(completed.server_frame_count, 2);
        assert_eq!(completed.client_payload_bytes, 15);
        assert_eq!(completed.server_payload_bytes, 20);
        assert_eq!(completed.first_frame_sequence_no, 1);
        assert_eq!(completed.last_frame_sequence_no, 4);
        assert_eq!(completed.started_at_unix_ms, 1_000);
        assert_eq!(completed.ended_at_unix_ms, 1_003);

        let second = agg.flush().expect("second turn should flush");
        assert_eq!(second.turn_id, 2);
        assert_eq!(second.client_frame_count, 1);
        assert_eq!(second.server_frame_count, 0);
        assert_eq!(second.first_frame_sequence_no, 5);
        assert_eq!(second.last_frame_sequence_no, 5);
    }

    #[test]
    fn supports_server_initiated_turns() {
        let mut agg = WebSocketTurnAggregator::new();
        assert!(agg
            .on_frame(WsDirection::ServerToClient, WsFrameKind::Data, 8, 2_000)
            .is_none());
        assert!(agg
            .on_frame(WsDirection::ClientToServer, WsFrameKind::Data, 2, 2_001)
            .is_none());

        let completed = agg
            .on_frame(WsDirection::ServerToClient, WsFrameKind::Data, 3, 2_002)
            .expect("server-initiated turn should complete");
        assert_eq!(completed.turn_id, 1);
        assert_eq!(completed.client_frame_count, 1);
        assert_eq!(completed.server_frame_count, 1);
        assert_eq!(completed.client_payload_bytes, 2);
        assert_eq!(completed.server_payload_bytes, 8);

        let second = agg.flush().expect("remaining turn should flush");
        assert_eq!(second.turn_id, 2);
        assert_eq!(second.client_frame_count, 0);
        assert_eq!(second.server_frame_count, 1);
        assert_eq!(second.server_payload_bytes, 3);
    }

    #[test]
    fn alpn_configuration_is_deterministic() {
        assert_eq!(
            configured_http_alpn_protocols(false),
            vec![ALPN_HTTP_11.to_vec()]
        );
        assert_eq!(
            configured_http_alpn_protocols(true),
            vec![ALPN_H2.to_vec(), ALPN_HTTP_11.to_vec()]
        );
    }

    #[test]
    fn negotiated_alpn_maps_to_application_protocol() {
        assert_eq!(
            protocol_from_negotiated_alpn(Some(ALPN_H2), true),
            ApplicationProtocol::Http2
        );
        assert_eq!(
            protocol_from_negotiated_alpn(Some(ALPN_H2), false),
            ApplicationProtocol::Http1
        );
        assert_eq!(
            protocol_from_negotiated_alpn(Some(ALPN_HTTP_11), true),
            ApplicationProtocol::Http1
        );
        assert_eq!(
            protocol_from_negotiated_alpn(None, true),
            ApplicationProtocol::Http1
        );
    }

    #[test]
    fn negotiated_alpn_label_only_marks_supported_http_protocols() {
        assert_eq!(negotiated_alpn_label(Some(ALPN_H2)), Some("h2"));
        assert_eq!(negotiated_alpn_label(Some(ALPN_HTTP_11)), Some("http/1.1"));
        assert_eq!(negotiated_alpn_label(Some(b"h3")), None);
        assert_eq!(negotiated_alpn_label(None), None);
    }
}
