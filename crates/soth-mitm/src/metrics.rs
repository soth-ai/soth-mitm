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
}

#[derive(Debug, Default)]
pub(crate) struct ProxyMetricsStore {
    active_connections: AtomicU64,
    total_connections: AtomicU64,
    handler_panic_count: AtomicU64,
    handler_timeout_count: AtomicU64,
    upstream_connect_error_count: AtomicU64,
    upstream_timeout_count: AtomicU64,
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

    #[allow(dead_code)]
    pub(crate) fn record_upstream_connect_error(&self) {
        self.upstream_connect_error_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub(crate) fn record_upstream_timeout(&self) {
        self.upstream_timeout_count.fetch_add(1, Ordering::Relaxed);
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
            EventType::StreamClosed => self.store.record_connection_close(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProxyMetricsStore;

    #[test]
    fn proxy_metrics_counter_contract() {
        let store = ProxyMetricsStore::default();

        store.record_connection_open();
        store.record_connection_open();
        store.record_connection_close();
        store.record_handler_timeout();
        store.record_handler_panic();
        store.record_upstream_connect_error();
        store.record_upstream_timeout();

        let snapshot = store.snapshot();
        assert_eq!(snapshot.total_connections, 2);
        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(snapshot.handler_timeout_count, 1);
        assert_eq!(snapshot.handler_panic_count, 1);
        assert_eq!(snapshot.upstream_connect_error_count, 1);
        assert_eq!(snapshot.upstream_timeout_count, 1);
    }
}
