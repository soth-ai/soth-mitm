#![no_main]

use libfuzzer_sys::fuzz_target;
use mitm_http::{WebSocketTurn, WebSocketTurnAggregator, WsDirection, WsFrameKind};

fn assert_turn_invariants(turn: &WebSocketTurn) {
    assert!(turn.first_frame_sequence_no <= turn.last_frame_sequence_no);
    assert!(turn.started_at_unix_ms <= turn.ended_at_unix_ms);
    assert!(turn.client_payload_bytes <= u64::MAX);
    assert!(turn.server_payload_bytes <= u64::MAX);
    assert!(turn.client_frame_count > 0 || turn.server_frame_count > 0);
}

fuzz_target!(|data: &[u8]| {
    let mut agg = WebSocketTurnAggregator::new();
    let mut timestamp_unix_ms = 0_u128;

    for chunk in data.chunks_exact(6) {
        let direction = if (chunk[0] & 0x01) == 0 {
            WsDirection::ClientToServer
        } else {
            WsDirection::ServerToClient
        };
        let kind = if (chunk[0] & 0x02) == 0 {
            WsFrameKind::Data
        } else {
            WsFrameKind::Control
        };
        let payload_len = u16::from_be_bytes([chunk[1], chunk[2]]) as usize;
        let ts_delta = u16::from_be_bytes([chunk[3], chunk[4]]) as u128;
        timestamp_unix_ms = timestamp_unix_ms.saturating_add(ts_delta);

        if let Some(turn) = agg.on_frame(direction, kind, payload_len, timestamp_unix_ms) {
            assert_turn_invariants(&turn);
        }
    }

    if let Some(turn) = agg.flush() {
        assert_turn_invariants(&turn);
    }
});
