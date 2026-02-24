use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::types::{ConnectionInfo, ProcessInfo};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod unsupported;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub(crate) use linux::PlatformProcessAttributor;
#[cfg(target_os = "macos")]
#[allow(unused_imports)]
pub(crate) use macos::PlatformProcessAttributor;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[allow(unused_imports)]
pub(crate) use unsupported::PlatformProcessAttributor;
#[cfg(target_os = "windows")]
#[allow(unused_imports)]
pub(crate) use windows::PlatformProcessAttributor;

pub(crate) trait ProcessAttributor: Send + Sync + 'static {
    fn lookup<'a>(
        &'a self,
        connection: &'a ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessInfo>> + Send + 'a>>;
}

#[derive(Debug)]
pub(crate) struct ProcessLookupService<A: ProcessAttributor> {
    attributor: Arc<A>,
    timeout: Duration,
    cache: Mutex<HashMap<Uuid, Option<ProcessInfo>>>,
}

impl<A: ProcessAttributor> ProcessLookupService<A> {
    pub(crate) fn new(attributor: Arc<A>, timeout: Duration) -> Self {
        Self {
            attributor,
            timeout,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn resolve(&self, connection: &ConnectionInfo) -> Option<ProcessInfo> {
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache.get(&connection.connection_id) {
            return cached.clone();
        }

        let resolved = tokio::time::timeout(self.timeout, self.attributor.lookup(connection))
            .await
            .ok()
            .flatten();
        cache.insert(connection.connection_id, resolved.clone());
        resolved
    }

    pub(crate) async fn bind_connection_info(&self, connection: &ConnectionInfo) -> ConnectionInfo {
        let mut updated = connection.clone();
        updated.process_info = self.resolve(connection).await;
        updated
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use uuid::Uuid;

    use super::{ConnectionInfo, ProcessAttributor, ProcessInfo, ProcessLookupService};

    #[derive(Debug)]
    struct SleepyAttributor {
        lookup_calls: AtomicU64,
        sleep_for: Duration,
    }

    impl SleepyAttributor {
        fn new(sleep_for: Duration) -> Self {
            Self {
                lookup_calls: AtomicU64::new(0),
                sleep_for,
            }
        }

        fn calls(&self) -> u64 {
            self.lookup_calls.load(Ordering::Relaxed)
        }
    }

    impl ProcessAttributor for SleepyAttributor {
        fn lookup<'a>(
            &'a self,
            _connection: &'a ConnectionInfo,
        ) -> Pin<Box<dyn Future<Output = Option<ProcessInfo>> + Send + 'a>> {
            self.lookup_calls.fetch_add(1, Ordering::Relaxed);
            let sleep_for = self.sleep_for;
            Box::pin(async move {
                tokio::time::sleep(sleep_for).await;
                Some(ProcessInfo {
                    pid: 4242,
                    process_name: "curl".to_string(),
                    process_path: PathBuf::from("/usr/bin/curl"),
                    bundle_id: None,
                    code_signature: None,
                    parent_pid: Some(1),
                    parent_name: Some("init".to_string()),
                })
            })
        }
    }

    #[tokio::test]
    async fn process_lookup_timeout_sets_none() {
        let attributor = Arc::new(SleepyAttributor::new(Duration::from_millis(75)));
        let service = ProcessLookupService::new(Arc::clone(&attributor), Duration::from_millis(5));
        let connection = sample_connection();

        let process = service.resolve(&connection).await;
        assert!(
            process.is_none(),
            "timed out process lookup should return None"
        );

        let second = service.resolve(&connection).await;
        assert!(
            second.is_none(),
            "once timed out and cached, repeated lookup should stay None"
        );
        assert_eq!(
            attributor.calls(),
            1,
            "lookup should run once per connection"
        );
    }

    #[tokio::test]
    async fn process_info_resolved_once_per_connection() {
        let attributor = Arc::new(SleepyAttributor::new(Duration::from_millis(1)));
        let service = ProcessLookupService::new(Arc::clone(&attributor), Duration::from_millis(50));
        let connection = sample_connection();

        let first = service.bind_connection_info(&connection).await;
        let second = service.bind_connection_info(&first).await;

        assert!(
            first.process_info.is_some(),
            "first resolve must attach process"
        );
        assert!(
            second.process_info.is_some(),
            "cached resolve must attach process"
        );
        assert_eq!(
            attributor.calls(),
            1,
            "process attribution should be resolved once per connection"
        );
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
            request_count: 1,
        }
    }
}
