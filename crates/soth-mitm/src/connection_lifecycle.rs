use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::task::JoinHandle;

use crate::handler::InterceptHandler;
use crate::types::{ConnectionInfo, ConnectionStats};

#[derive(Debug, Default)]
pub(crate) struct ConnectionCloseOnce {
    closed: AtomicBool,
}

impl ConnectionCloseOnce {
    pub(crate) fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) async fn call_once<H: InterceptHandler>(
        &self,
        handler: &H,
        connection: &ConnectionInfo,
        stats: &ConnectionStats,
    ) -> bool {
        if self
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        handler.on_connection_close(connection, stats).await;
        true
    }
}

pub(crate) fn fire_connection_open_non_blocking<H: InterceptHandler>(
    handler: Arc<H>,
    connection: ConnectionInfo,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        handler.on_connection_open(&connection).await;
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use bytes::Bytes;
    use http::HeaderMap;
    use tokio::sync::Mutex;
    use uuid::Uuid;

    use super::{fire_connection_open_non_blocking, ConnectionCloseOnce};
    use crate::actions::HandlerAction;
    use crate::handler::InterceptHandler;
    use crate::types::{ConnectionInfo, ConnectionStats, HttpVersion, InterceptedRequest};

    #[derive(Default)]
    struct LifecycleHandler {
        open_calls: AtomicU64,
        close_calls: AtomicU64,
        close_stats: Mutex<Option<ConnectionStats>>,
    }

    impl InterceptHandler for LifecycleHandler {
        async fn on_request(
            &self,
            _request: &InterceptedRequest,
            _connection: &ConnectionInfo,
        ) -> HandlerAction {
            HandlerAction::Forward
        }

        async fn on_connection_open(&self, _connection: &ConnectionInfo) {
            self.open_calls.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        async fn on_connection_close(&self, _connection: &ConnectionInfo, stats: &ConnectionStats) {
            self.close_calls.fetch_add(1, Ordering::Relaxed);
            *self.close_stats.lock().await = Some(stats.clone());
        }
    }

    #[tokio::test]
    async fn on_connection_open_non_blocking() {
        let handler = Arc::new(LifecycleHandler::default());
        let connection = sample_connection();

        let started = tokio::time::Instant::now();
        let join = fire_connection_open_non_blocking(Arc::clone(&handler), connection);
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(20),
            "open callback scheduling should be non-blocking"
        );
        join.await.expect("open callback task join");
        assert_eq!(handler.open_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn on_connection_close_called_exactly_once_all_exit_paths() {
        let handler = Arc::new(LifecycleHandler::default());
        let connection = sample_connection();
        let stats = sample_stats();
        let close_once = Arc::new(ConnectionCloseOnce::new());

        let first = close_once
            .call_once(handler.as_ref(), &connection, &stats)
            .await;
        let second = close_once
            .call_once(handler.as_ref(), &connection, &stats)
            .await;

        assert!(first);
        assert!(!second);
        assert_eq!(handler.close_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn connection_stats_complete_on_close() {
        let handler = Arc::new(LifecycleHandler::default());
        let connection = sample_connection();
        let stats = sample_stats();
        let close_once = ConnectionCloseOnce::new();

        let called = close_once
            .call_once(handler.as_ref(), &connection, &stats)
            .await;
        assert!(called);

        let captured = handler
            .close_stats
            .lock()
            .await
            .clone()
            .expect("close stats should be captured");
        assert_eq!(captured.request_count, stats.request_count);
        assert_eq!(captured.bytes_sent_upstream, stats.bytes_sent_upstream);
        assert_eq!(
            captured.bytes_received_upstream,
            stats.bytes_received_upstream
        );
        assert_eq!(captured.duration, stats.duration);
    }

    fn sample_connection() -> ConnectionInfo {
        ConnectionInfo {
            connection_id: Uuid::new_v4(),
            source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            source_port: 52431,
            destination_host: "api.example.com".to_string(),
            destination_port: 443,
            tls_fingerprint: None,
            alpn_protocol: Some("h2".to_string()),
            is_http2: true,
            process_info: None,
            connected_at: SystemTime::now(),
            request_count: 3,
        }
    }

    fn sample_stats() -> ConnectionStats {
        ConnectionStats {
            request_count: 3,
            bytes_sent_upstream: 1024,
            bytes_received_upstream: 2048,
            duration: Duration::from_millis(150),
        }
    }

    #[allow(dead_code)]
    fn sample_request() -> InterceptedRequest {
        InterceptedRequest {
            method: "GET".to_string(),
            path: "/health".to_string(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            body_truncated: false,
            body_original_size: None,
        }
    }
}
