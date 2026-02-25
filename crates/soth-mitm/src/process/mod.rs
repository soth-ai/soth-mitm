use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use lru::LruCache;
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedLookupResult {
    process_info: Option<ProcessInfo>,
    timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessLookupResult {
    pub(crate) process_info: Option<ProcessInfo>,
    pub(crate) timed_out: bool,
}

#[derive(Debug)]
pub(crate) struct ProcessLookupService<A: ProcessAttributor> {
    attributor: Arc<A>,
    timeout: Duration,
    cache: Mutex<LruCache<Uuid, CachedLookupResult>>,
}

impl<A: ProcessAttributor> ProcessLookupService<A> {
    pub(crate) fn new(attributor: Arc<A>, timeout: Duration) -> Self {
        let capacity = NonZeroUsize::new(4096).expect("process cache capacity must be non-zero");
        Self {
            attributor,
            timeout,
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }

    pub(crate) async fn resolve_with_status(
        &self,
        connection: &ConnectionInfo,
    ) -> ProcessLookupResult {
        let connection_id = connection.connection_id;
        let cached = {
            let mut cache = self.cache.lock().await;
            cache.get(&connection_id).cloned()
        };
        if let Some(cached) = cached {
            return ProcessLookupResult {
                process_info: cached.process_info,
                timed_out: cached.timed_out,
            };
        }

        let (resolved, timed_out) =
            match tokio::time::timeout(self.timeout, self.attributor.lookup(connection)).await {
                Ok(process_info) => (process_info, false),
                Err(_) => (None, true),
            };
        let mut cache = self.cache.lock().await;
        cache.put(
            connection_id,
            CachedLookupResult {
                process_info: resolved.clone(),
                timed_out,
            },
        );
        ProcessLookupResult {
            process_info: resolved,
            timed_out,
        }
    }

    pub(crate) async fn remove_connection(&self, connection_id: Uuid) {
        let mut cache = self.cache.lock().await;
        let _ = cache.pop(&connection_id);
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
    use crate::types::SocketFamily;

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
                    bundle_id: None,
                    exe_name: Some("curl".to_string()),
                    exe_path: Some(PathBuf::from("/usr/bin/curl")),
                    parent_pid: Some(1),
                })
            })
        }
    }

    #[tokio::test]
    async fn process_lookup_timeout_sets_none() {
        let attributor = Arc::new(SleepyAttributor::new(Duration::from_millis(75)));
        let service = ProcessLookupService::new(Arc::clone(&attributor), Duration::from_millis(5));
        let connection = sample_connection();

        let first = service.resolve_with_status(&connection).await;
        assert!(
            first.process_info.is_none(),
            "timed out process lookup should return None"
        );
        assert!(first.timed_out, "timed out lookup should be tagged");

        let second = service.resolve_with_status(&connection).await;
        assert!(
            second.process_info.is_none(),
            "once timed out and cached, repeated lookup should stay None"
        );
        assert!(second.timed_out, "cached timeout should preserve status");
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

        let first = service.resolve_with_status(&connection).await;
        let second = service.resolve_with_status(&connection).await;

        assert!(
            first.process_info.is_some(),
            "first resolve must attach process"
        );
        assert!(
            second.process_info.is_some(),
            "cached resolve must attach process"
        );
        assert!(!first.timed_out, "successful lookup should not timeout");
        assert!(!second.timed_out, "cached success should not timeout");
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
            socket_family: SocketFamily::TcpV4 {
                local: std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 52431),
                remote: std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 443),
            },
            tls_fingerprint: None,
            alpn_protocol: Some("h2".to_string()),
            is_http2: true,
            process_info: None,
            connected_at: SystemTime::now(),
            request_count: 1,
        }
    }
}
