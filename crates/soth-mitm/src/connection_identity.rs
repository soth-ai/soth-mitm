use std::sync::atomic::{AtomicU32, Ordering};

use uuid::Uuid;

use crate::types::ConnectionInfo;

#[derive(Debug)]
pub(crate) struct ConnectionRequestTracker {
    connection_id: Uuid,
    request_count: AtomicU32,
}

impl ConnectionRequestTracker {
    pub(crate) fn new(connection_id: Uuid, initial_request_count: u32) -> Self {
        Self {
            connection_id,
            request_count: AtomicU32::new(initial_request_count),
        }
    }

    pub(crate) fn connection_id(&self) -> Uuid {
        self.connection_id
    }

    pub(crate) fn next_request_count(&self) -> u32 {
        self.request_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn clone_with_next_request_count(
        &self,
        connection: &ConnectionInfo,
    ) -> ConnectionInfo {
        let mut updated = connection.clone();
        updated.connection_id = self.connection_id();
        updated.request_count = self.next_request_count();
        updated
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use uuid::Uuid;

    use super::ConnectionRequestTracker;
    use crate::types::ConnectionInfo;

    #[test]
    fn h2_connection_id_stable_request_count_increments() {
        let connection_id = Uuid::new_v4();
        let tracker = ConnectionRequestTracker::new(connection_id, 0);
        let base = sample_connection(connection_id);

        let first = tracker.clone_with_next_request_count(&base);
        let second = tracker.clone_with_next_request_count(&first);
        let third = tracker.clone_with_next_request_count(&second);

        assert_eq!(first.connection_id, connection_id);
        assert_eq!(second.connection_id, connection_id);
        assert_eq!(third.connection_id, connection_id);
        assert_eq!(first.request_count, 1);
        assert_eq!(second.request_count, 2);
        assert_eq!(third.request_count, 3);
    }

    fn sample_connection(connection_id: Uuid) -> ConnectionInfo {
        ConnectionInfo {
            connection_id,
            source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            source_port: 4242,
            destination_host: "api.example.com".to_string(),
            destination_port: 443,
            tls_fingerprint: None,
            alpn_protocol: Some("h2".to_string()),
            is_http2: true,
            process_info: None,
            connected_at: SystemTime::now(),
            request_count: 0,
        }
    }
}
