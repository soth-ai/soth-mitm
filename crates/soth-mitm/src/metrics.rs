use std::sync::atomic::{AtomicU64, Ordering};

use mitm_observe::{EventConsumer, EventEnvelope, EventType};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyMetrics {
    pub active_connections: u64,
    pub total_connections: u64,
    pub handler_panic_count: u64,
    pub handler_timeout_count: u64,
    pub upstream_connect_error_count: u64,
    pub upstream_timeout_count: u64,
    pub process_attribution_failure_count: u64,
    pub process_attribution_timeout_count: u64,
}

#[derive(Debug, Default)]
pub(crate) struct ProxyMetricsStore {
    active_connections: AtomicU64,
    total_connections: AtomicU64,
    handler_panic_count: AtomicU64,
    handler_timeout_count: AtomicU64,
    upstream_connect_error_count: AtomicU64,
    upstream_timeout_count: AtomicU64,
    process_attribution_failure_count: AtomicU64,
    process_attribution_timeout_count: AtomicU64,
}

impl ProxyMetricsStore {
    pub(crate) fn snapshot(&self) -> ProxyMetrics {
        ProxyMetrics {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            handler_panic_count: self.handler_panic_count.load(Ordering::Relaxed),
            handler_timeout_count: self.handler_timeout_count.load(Ordering::Relaxed),
            upstream_connect_error_count: self.upstream_connect_error_count.load(Ordering::Relaxed),
            upstream_timeout_count: self.upstream_timeout_count.load(Ordering::Relaxed),
            process_attribution_failure_count: self
                .process_attribution_failure_count
                .load(Ordering::Relaxed),
            process_attribution_timeout_count: self
                .process_attribution_timeout_count
                .load(Ordering::Relaxed),
        }
    }

    pub(crate) fn record_connection_open(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_connection_close(&self) {
        let _ =
            self.active_connections
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_sub(1))
                });
    }

    pub(crate) fn record_handler_panic(&self) {
        self.handler_panic_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_handler_timeout(&self) {
        self.handler_timeout_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_upstream_connect_error(&self) {
        self.upstream_connect_error_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_upstream_timeout(&self) {
        self.upstream_timeout_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_process_attribution_failure(&self) {
        self.process_attribution_failure_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_process_attribution_timeout(&self) {
        self.process_attribution_timeout_count
            .fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub(crate) struct MetricsEventConsumer {
    store: std::sync::Arc<ProxyMetricsStore>,
}

impl MetricsEventConsumer {
    pub(crate) fn new(store: std::sync::Arc<ProxyMetricsStore>) -> Self {
        Self { store }
    }
}

impl EventConsumer for MetricsEventConsumer {
    fn consume(&self, envelope: EventEnvelope) {
        match envelope.event.kind {
            EventType::ConnectReceived => self.store.record_connection_open(),
            EventType::StreamClosed => {
                self.store.record_connection_close();
                let reason_code = envelope
                    .event
                    .attributes
                    .get("reason_code")
                    .map(std::string::String::as_str);
                let reason_detail = envelope
                    .event
                    .attributes
                    .get("reason_detail")
                    .map(std::string::String::as_str)
                    .unwrap_or_default();
                match reason_code {
                    Some("upstream_connect_failed") => {
                        self.store.record_upstream_connect_error();
                        if is_timeout_reason(reason_detail) {
                            self.store.record_upstream_timeout();
                        }
                    }
                    Some("stream_stage_timeout") => {
                        self.store.record_upstream_timeout();
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

fn is_timeout_reason(reason_detail: &str) -> bool {
    let lower = reason_detail.to_ascii_lowercase();
    lower.contains("timed out") || lower.contains("timeout")
}

#[cfg(test)]
mod tests {
    use mitm_http::ApplicationProtocol;
    use mitm_observe::{Event, EventConsumer, EventEnvelope, EventType, FlowContext};

    use super::ProxyMetricsStore;

    #[test]
    fn proxy_metrics_counter_contract() {
        let store = ProxyMetricsStore::default();

        store.record_connection_open();
        store.record_connection_open();
        store.record_connection_close();
        store.record_handler_timeout();
        store.record_handler_panic();

        let snapshot = store.snapshot();
        assert_eq!(snapshot.total_connections, 2);
        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(snapshot.handler_timeout_count, 1);
        assert_eq!(snapshot.handler_panic_count, 1);
        assert_eq!(snapshot.upstream_connect_error_count, 0);
        assert_eq!(snapshot.upstream_timeout_count, 0);
        assert_eq!(snapshot.process_attribution_failure_count, 0);
        assert_eq!(snapshot.process_attribution_timeout_count, 0);
    }

    #[test]
    fn upstream_failure_metrics_are_wired_from_stream_closed_events() {
        let store = std::sync::Arc::new(ProxyMetricsStore::default());
        let consumer = super::MetricsEventConsumer::new(std::sync::Arc::clone(&store));

        consumer.consume(EventEnvelope::from_event(Event::new(
            EventType::ConnectReceived,
            sample_context(1),
        )));

        let mut connect_failed = Event::new(EventType::StreamClosed, sample_context(1));
        connect_failed.attributes.insert(
            "reason_code".to_string(),
            "upstream_connect_failed".to_string(),
        );
        connect_failed
            .attributes
            .insert("reason_detail".to_string(), "connect timeout".to_string());
        consumer.consume(EventEnvelope::from_event(connect_failed));

        consumer.consume(EventEnvelope::from_event(Event::new(
            EventType::ConnectReceived,
            sample_context(2),
        )));
        let mut stage_timeout = Event::new(EventType::StreamClosed, sample_context(2));
        stage_timeout.attributes.insert(
            "reason_code".to_string(),
            "stream_stage_timeout".to_string(),
        );
        consumer.consume(EventEnvelope::from_event(stage_timeout));

        let snapshot = store.snapshot();
        assert_eq!(snapshot.active_connections, 0);
        assert_eq!(snapshot.total_connections, 2);
        assert_eq!(snapshot.upstream_connect_error_count, 1);
        assert_eq!(snapshot.upstream_timeout_count, 2);
    }

    fn sample_context(flow_id: u64) -> FlowContext {
        FlowContext {
            flow_id,
            client_addr: "127.0.0.1:1234".to_string(),
            server_host: "api.example.com".to_string(),
            server_port: 443,
            protocol: ApplicationProtocol::Http1,
        }
    }
}
