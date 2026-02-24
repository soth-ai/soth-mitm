use std::collections::BTreeSet;

use mitm_http::ApplicationProtocol;
use mitm_observe::{Event, EventType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Http2ResilienceSummary {
    pub stream_closed_count: u64,
    pub completed_close_count: u64,
    pub error_close_count: u64,
    pub non_deterministic_close_reasons: BTreeSet<String>,
}

impl Http2ResilienceSummary {
    pub(crate) fn has_stable_close_semantics(&self) -> bool {
        self.stream_closed_count > 0 && self.non_deterministic_close_reasons.is_empty()
    }
}

pub(crate) fn summarize_http2_close_semantics(events: &[Event]) -> Http2ResilienceSummary {
    let mut stream_closed_count = 0_u64;
    let mut completed_close_count = 0_u64;
    let mut error_close_count = 0_u64;
    let mut non_deterministic_close_reasons = BTreeSet::new();

    for event in events {
        if event.kind != EventType::StreamClosed
            || event.context.protocol != ApplicationProtocol::Http2
        {
            continue;
        }
        stream_closed_count += 1;
        match event.attributes.get("reason_code").map(String::as_str) {
            Some("mitm_http_completed") => {
                completed_close_count += 1;
            }
            Some("mitm_http_error" | "stream_stage_timeout" | "relay_error") => {
                error_close_count += 1;
            }
            Some(other) => {
                non_deterministic_close_reasons.insert(other.to_string());
            }
            None => {
                non_deterministic_close_reasons.insert("<missing>".to_string());
            }
        }
    }

    Http2ResilienceSummary {
        stream_closed_count,
        completed_close_count,
        error_close_count,
        non_deterministic_close_reasons,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use mitm_http::ApplicationProtocol;
    use mitm_observe::{Event, EventType, FlowContext};

    use super::summarize_http2_close_semantics;

    #[test]
    fn http2_close_summary_detects_non_deterministic_reason() {
        let events = vec![
            http2_stream_closed(11, "mitm_http_completed"),
            http2_stream_closed(12, "mitm_http_error"),
            http2_stream_closed(13, "unexpected_reason"),
        ];
        let summary = summarize_http2_close_semantics(&events);
        assert_eq!(summary.stream_closed_count, 3);
        assert_eq!(summary.completed_close_count, 1);
        assert_eq!(summary.error_close_count, 1);
        assert!(summary
            .non_deterministic_close_reasons
            .contains("unexpected_reason"));
        assert!(!summary.has_stable_close_semantics());
    }

    #[test]
    fn http2_close_summary_accepts_stable_reasons() {
        let events = vec![
            http2_stream_closed(21, "mitm_http_completed"),
            http2_stream_closed(22, "mitm_http_error"),
            http2_stream_closed(23, "stream_stage_timeout"),
        ];
        let summary = summarize_http2_close_semantics(&events);
        assert!(summary.has_stable_close_semantics());
    }

    fn http2_stream_closed(flow_id: u64, reason_code: &str) -> Event {
        let mut event = Event::new(
            EventType::StreamClosed,
            FlowContext {
                flow_id,
                client_addr: "127.0.0.1:50000".to_string(),
                server_host: "127.0.0.1".to_string(),
                server_port: 443,
                protocol: ApplicationProtocol::Http2,
            },
        );
        let mut attributes = BTreeMap::new();
        attributes.insert("reason_code".to_string(), reason_code.to_string());
        event.attributes = attributes;
        event
    }
}
