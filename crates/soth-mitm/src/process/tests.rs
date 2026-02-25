use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use uuid::Uuid;

use super::{
    ConnectionInfo, ProcessAttributor, ProcessCachePath, ProcessIdentity, ProcessInfo,
    ProcessLookupService,
};
use crate::types::SocketFamily;

#[derive(Debug)]
struct SleepyAttributor {
    lookup_calls: AtomicU64,
    identity_calls: AtomicU64,
    identity_lookup_calls: AtomicU64,
    pid: u32,
    start_token: Option<String>,
    sleep_for: Duration,
}

impl SleepyAttributor {
    fn new(sleep_for: Duration) -> Self {
        Self {
            lookup_calls: AtomicU64::new(0),
            identity_calls: AtomicU64::new(0),
            identity_lookup_calls: AtomicU64::new(0),
            pid: 4242,
            start_token: Some("boot-1".to_string()),
            sleep_for,
        }
    }

    fn new_without_identity(sleep_for: Duration) -> Self {
        Self {
            start_token: None,
            ..Self::new(sleep_for)
        }
    }

    fn calls(&self) -> u64 {
        self.lookup_calls.load(Ordering::Relaxed)
    }

    fn identity_calls(&self) -> u64 {
        self.identity_calls.load(Ordering::Relaxed)
    }

    fn identity_lookup_calls(&self) -> u64 {
        self.identity_lookup_calls.load(Ordering::Relaxed)
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

    fn lookup_identity<'a>(
        &'a self,
        _connection: &'a ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessIdentity>> + Send + 'a>> {
        self.identity_calls.fetch_add(1, Ordering::Relaxed);
        let start_token = self.start_token.clone();
        let pid = self.pid;
        Box::pin(async move {
            start_token.map(|token| ProcessIdentity {
                pid,
                start_token: token,
            })
        })
    }

    fn lookup_by_identity<'a>(
        &'a self,
        identity: &'a ProcessIdentity,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessInfo>> + Send + 'a>> {
        self.identity_lookup_calls.fetch_add(1, Ordering::Relaxed);
        let pid = identity.pid;
        Box::pin(async move {
            Some(ProcessInfo {
                pid,
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
    let attributor = Arc::new(SleepyAttributor::new_without_identity(
        Duration::from_millis(75),
    ));
    let service = ProcessLookupService::new(Arc::clone(&attributor), Duration::from_millis(5));
    let connection = sample_connection();

    let first = service.resolve_with_status(&connection).await;
    assert!(
        first.process_info.is_none(),
        "timed out process lookup should return None"
    );
    assert!(first.timed_out, "timed out lookup should be tagged");
    assert_eq!(first.cache_path, ProcessCachePath::Miss);

    let second = service.resolve_with_status(&connection).await;
    assert!(
        second.process_info.is_none(),
        "once timed out and cached, repeated lookup should stay None"
    );
    assert!(second.timed_out, "cached timeout should preserve status");
    assert_eq!(second.cache_path, ProcessCachePath::ConnectionHit);
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
    assert_eq!(first.cache_path, ProcessCachePath::Miss);
    assert_eq!(second.cache_path, ProcessCachePath::ConnectionHit);
    assert_eq!(
        attributor.calls(),
        0,
        "identity lookup should satisfy process attribution path"
    );
    assert_eq!(
        attributor.identity_lookup_calls(),
        1,
        "identity attribution should resolve once per first connection"
    );
}

#[tokio::test]
async fn identity_cache_reused_across_connections() {
    let attributor = Arc::new(SleepyAttributor::new(Duration::from_millis(1)));
    let service = ProcessLookupService::new(Arc::clone(&attributor), Duration::from_millis(50));
    let first_connection = sample_connection();
    let mut second_connection = sample_connection();
    second_connection.connection_id = Uuid::new_v4();
    second_connection.source_port = first_connection.source_port + 1;

    let first = service.resolve_with_status(&first_connection).await;
    let second = service.resolve_with_status(&second_connection).await;

    assert_eq!(first.cache_path, ProcessCachePath::Miss);
    assert_eq!(second.cache_path, ProcessCachePath::IdentityHit);
    assert_eq!(attributor.identity_lookup_calls(), 1);
    assert_eq!(
        attributor.identity_calls(),
        2,
        "identity should be consulted for each accepted connection"
    );
}

#[tokio::test]
async fn concurrent_cold_misses_are_singleflight_per_connection() {
    let attributor = Arc::new(SleepyAttributor::new_without_identity(
        Duration::from_millis(40),
    ));
    let service = Arc::new(ProcessLookupService::new(
        Arc::clone(&attributor),
        Duration::from_millis(500),
    ));
    let connection = sample_connection();

    let mut tasks = Vec::with_capacity(8);
    for _ in 0..8 {
        let service = Arc::clone(&service);
        let connection = connection.clone();
        tasks.push(tokio::spawn(async move {
            service.resolve_with_status(&connection).await
        }));
    }

    let mut misses = 0;
    let mut hits = 0;
    for task in tasks {
        let result = task.await.expect("singleflight join should succeed");
        match result.cache_path {
            ProcessCachePath::Miss => misses += 1,
            ProcessCachePath::ConnectionHit => hits += 1,
            ProcessCachePath::IdentityHit => {}
        }
    }

    assert_eq!(misses, 1, "exactly one task should execute uncached lookup");
    assert_eq!(
        hits, 7,
        "remaining tasks should consume cached connection result"
    );
    assert_eq!(
        attributor.calls(),
        1,
        "singleflight should collapse concurrent cold misses into one lookup call"
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
