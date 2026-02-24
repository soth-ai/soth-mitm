use std::collections::{BTreeSet, HashSet};

use mitm_observe::{Event, EventType};

const DETERMINISTIC_CLOSE_REASONS: &[&str] = &[
    "blocked",
    "connect_parse_failed",
    "tls_handshake_failed",
    "route_planner_failed",
    "upstream_connect_failed",
    "relay_eof",
    "relay_error",
    "idle_watchdog_timeout",
    "stream_stage_timeout",
    "mitm_http_completed",
    "mitm_http_error",
    "websocket_completed",
    "websocket_error",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlowCloseSummary {
    pub stream_closed_count: u64,
    pub unique_flow_count: u64,
    pub duplicate_close_count: u64,
    pub missing_reason_count: u64,
    pub non_deterministic_reasons: BTreeSet<String>,
}

impl FlowCloseSummary {
    pub(crate) fn is_deterministic(&self) -> bool {
        self.duplicate_close_count == 0
            && self.missing_reason_count == 0
            && self.non_deterministic_reasons.is_empty()
    }
}

pub(crate) fn summarize_stream_closed(events: &[Event]) -> FlowCloseSummary {
    let mut seen_flow_ids = HashSet::new();
    let mut duplicate_close_count = 0_u64;
    let mut stream_closed_count = 0_u64;
    let mut missing_reason_count = 0_u64;
    let mut non_deterministic_reasons = BTreeSet::new();

    for event in events {
        if event.kind != EventType::StreamClosed {
            continue;
        }
        stream_closed_count += 1;

        if !seen_flow_ids.insert(event.context.flow_id) {
            duplicate_close_count += 1;
        }

        match event.attributes.get("reason_code") {
            Some(reason) if is_deterministic_close_reason(reason) => {}
            Some(reason) => {
                non_deterministic_reasons.insert(reason.clone());
            }
            None => {
                missing_reason_count += 1;
            }
        }
    }

    FlowCloseSummary {
        stream_closed_count,
        unique_flow_count: seen_flow_ids.len() as u64,
        duplicate_close_count,
        missing_reason_count,
        non_deterministic_reasons,
    }
}

fn is_deterministic_close_reason(reason: &str) -> bool {
    DETERMINISTIC_CLOSE_REASONS.contains(&reason)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use mitm_http::ApplicationProtocol;
    use mitm_observe::{Event, EventType, FlowContext};

    use super::summarize_stream_closed;

    #[test]
    fn close_reason_summary_detects_nondeterminism() {
        let mut events = Vec::new();
        events.push(stream_closed_event(1, Some("relay_eof")));
        events.push(stream_closed_event(1, Some("relay_eof")));
        events.push(stream_closed_event(2, Some("unknown_close")));
        events.push(stream_closed_event(3, None));

        let summary = summarize_stream_closed(&events);
        assert_eq!(summary.stream_closed_count, 4);
        assert_eq!(summary.unique_flow_count, 3);
        assert_eq!(summary.duplicate_close_count, 1);
        assert_eq!(summary.missing_reason_count, 1);
        assert!(summary.non_deterministic_reasons.contains("unknown_close"));
        assert!(!summary.is_deterministic());
    }

    #[test]
    fn close_reason_summary_accepts_deterministic_stream_closes() {
        let events = vec![
            stream_closed_event(1, Some("relay_eof")),
            stream_closed_event(2, Some("mitm_http_completed")),
            stream_closed_event(3, Some("stream_stage_timeout")),
        ];
        let summary = summarize_stream_closed(&events);
        assert!(summary.is_deterministic());
    }

    fn stream_closed_event(flow_id: u64, reason_code: Option<&str>) -> Event {
        let mut event = Event::new(
            EventType::StreamClosed,
            FlowContext {
                flow_id,
                client_addr: "127.0.0.1:50000".to_string(),
                server_host: "api.example.com".to_string(),
                server_port: 443,
                protocol: ApplicationProtocol::Tunnel,
            },
        );
        let mut attributes = BTreeMap::new();
        if let Some(reason_code) = reason_code {
            attributes.insert("reason_code".to_string(), reason_code.to_string());
        }
        event.attributes = attributes;
        event
    }
}
