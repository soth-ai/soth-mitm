use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use lru::LruCache;
use parking_lot::Mutex as FastMutex;
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

use crate::types::{ConnectionInfo, ProcessInfo};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod socket_pid;
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ProcessIdentity {
    pub(crate) pid: u32,
    pub(crate) start_token: String,
}

pub(crate) trait ProcessAttributor: Send + Sync + 'static {
    fn lookup<'a>(
        &'a self,
        connection: &'a ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessInfo>> + Send + 'a>>;

    fn lookup_identity<'a>(
        &'a self,
        _connection: &'a ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessIdentity>> + Send + 'a>> {
        Box::pin(async { None })
    }

    fn lookup_by_identity<'a>(
        &'a self,
        _identity: &'a ProcessIdentity,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessInfo>> + Send + 'a>> {
        Box::pin(async { None })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessCachePath {
    ConnectionHit,
    IdentityHit,
    Miss,
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
    pub(crate) cache_path: ProcessCachePath,
    pub(crate) pid_reuse_detected: bool,
    pub(crate) cache_evictions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UncachedLookupOutcome {
    process_info: Option<ProcessInfo>,
    cache_path: ProcessCachePath,
    pid_reuse_detected: bool,
    cache_evictions: u32,
}

#[derive(Debug)]
pub(crate) struct ProcessLookupService<A: ProcessAttributor> {
    attributor: Arc<A>,
    timeout: Duration,
    connection_cache: Mutex<LruCache<Uuid, CachedLookupResult>>,
    identity_cache: Mutex<LruCache<ProcessIdentity, ProcessInfo>>,
    pid_start_tokens: Mutex<LruCache<u32, String>>,
    in_flight: Arc<FastMutex<HashMap<Uuid, Arc<Notify>>>>,
}

#[derive(Debug)]
struct InFlightLeaderGuard {
    in_flight: Arc<FastMutex<HashMap<Uuid, Arc<Notify>>>>,
    connection_id: Uuid,
    notify: Arc<Notify>,
}

impl InFlightLeaderGuard {
    fn new(
        in_flight: Arc<FastMutex<HashMap<Uuid, Arc<Notify>>>>,
        connection_id: Uuid,
        notify: Arc<Notify>,
    ) -> Self {
        Self {
            in_flight,
            connection_id,
            notify,
        }
    }
}

impl Drop for InFlightLeaderGuard {
    fn drop(&mut self) {
        let mut in_flight = self.in_flight.lock();
        if let Some(existing) = in_flight.get(&self.connection_id) {
            if Arc::ptr_eq(existing, &self.notify) {
                in_flight.remove(&self.connection_id);
            }
        }
        drop(in_flight);
        self.notify.notify_waiters();
    }
}

impl<A: ProcessAttributor> ProcessLookupService<A> {
    pub(crate) fn new(attributor: Arc<A>, timeout: Duration) -> Self {
        let capacity = NonZeroUsize::new(4096).expect("process cache capacity must be non-zero");
        Self {
            attributor,
            timeout,
            connection_cache: Mutex::new(LruCache::new(capacity)),
            identity_cache: Mutex::new(LruCache::new(capacity)),
            pid_start_tokens: Mutex::new(LruCache::new(capacity)),
            in_flight: Arc::new(FastMutex::new(HashMap::new())),
        }
    }

    pub(crate) async fn resolve_with_status(
        &self,
        connection: &ConnectionInfo,
    ) -> ProcessLookupResult {
        let connection_id = connection.connection_id;
        if let Some(cached) = self.cached_connection_result(connection_id).await {
            return Self::result_from_cached_connection(cached);
        }

        loop {
            let (leader, notify) = {
                let mut in_flight = self.in_flight.lock();
                if let Some(existing) = in_flight.get(&connection_id) {
                    (false, Arc::clone(existing))
                } else {
                    let notify = Arc::new(Notify::new());
                    in_flight.insert(connection_id, Arc::clone(&notify));
                    (true, notify)
                }
            };
            if leader {
                let _leader_guard = InFlightLeaderGuard::new(
                    Arc::clone(&self.in_flight),
                    connection_id,
                    Arc::clone(&notify),
                );
                return self.resolve_miss_and_cache(connection_id, connection).await;
            }

            notify.notified().await;
            if let Some(cached) = self.cached_connection_result(connection_id).await {
                return Self::result_from_cached_connection(cached);
            }
        }
    }

    async fn cached_connection_result(&self, connection_id: Uuid) -> Option<CachedLookupResult> {
        let mut cache = self.connection_cache.lock().await;
        cache.get(&connection_id).cloned()
    }

    fn result_from_cached_connection(cached: CachedLookupResult) -> ProcessLookupResult {
        ProcessLookupResult {
            process_info: cached.process_info,
            timed_out: cached.timed_out,
            cache_path: ProcessCachePath::ConnectionHit,
            pid_reuse_detected: false,
            cache_evictions: 0,
        }
    }

    async fn resolve_miss_and_cache(
        &self,
        connection_id: Uuid,
        connection: &ConnectionInfo,
    ) -> ProcessLookupResult {
        let outcome =
            match tokio::time::timeout(self.timeout, self.resolve_uncached(connection)).await {
                Ok(outcome) => outcome,
                Err(_) => {
                    let evictions = self
                        .cache_connection_result(
                            connection_id,
                            CachedLookupResult {
                                process_info: None,
                                timed_out: true,
                            },
                        )
                        .await;
                    return ProcessLookupResult {
                        process_info: None,
                        timed_out: true,
                        cache_path: ProcessCachePath::Miss,
                        pid_reuse_detected: false,
                        cache_evictions: evictions,
                    };
                }
            };
        let connection_evictions = self
            .cache_connection_result(
                connection_id,
                CachedLookupResult {
                    process_info: outcome.process_info.clone(),
                    timed_out: false,
                },
            )
            .await;
        ProcessLookupResult {
            process_info: outcome.process_info,
            timed_out: false,
            cache_path: outcome.cache_path,
            pid_reuse_detected: outcome.pid_reuse_detected,
            cache_evictions: outcome.cache_evictions + connection_evictions,
        }
    }

    async fn resolve_uncached(&self, connection: &ConnectionInfo) -> UncachedLookupOutcome {
        let mut cache_evictions = 0;
        let mut pid_reuse_detected = false;

        if let Some(identity) = self.attributor.lookup_identity(connection).await {
            let (reused, pid_token_evictions) = self.register_pid_start_token(&identity).await;
            pid_reuse_detected = reused;
            cache_evictions += pid_token_evictions;

            let identity_cached = {
                let mut cache = self.identity_cache.lock().await;
                cache.get(&identity).cloned()
            };
            if let Some(process_info) = identity_cached {
                return UncachedLookupOutcome {
                    process_info: Some(process_info),
                    cache_path: ProcessCachePath::IdentityHit,
                    pid_reuse_detected,
                    cache_evictions,
                };
            }

            let mut resolved = self.attributor.lookup_by_identity(&identity).await;
            if resolved.is_none() {
                resolved = self.attributor.lookup(connection).await;
            }

            if let Some(process_info) = resolved.as_ref() {
                cache_evictions += self
                    .cache_identity_result(identity, process_info.clone())
                    .await;
            }

            return UncachedLookupOutcome {
                process_info: resolved,
                cache_path: ProcessCachePath::Miss,
                pid_reuse_detected,
                cache_evictions,
            };
        }

        UncachedLookupOutcome {
            process_info: self.attributor.lookup(connection).await,
            cache_path: ProcessCachePath::Miss,
            pid_reuse_detected,
            cache_evictions,
        }
    }

    async fn cache_connection_result(
        &self,
        connection_id: Uuid,
        result: CachedLookupResult,
    ) -> u32 {
        cache_push_count_eviction(&self.connection_cache, connection_id, result).await
    }

    async fn cache_identity_result(
        &self,
        identity: ProcessIdentity,
        process_info: ProcessInfo,
    ) -> u32 {
        cache_push_count_eviction(&self.identity_cache, identity, process_info).await
    }

    async fn register_pid_start_token(&self, identity: &ProcessIdentity) -> (bool, u32) {
        let mut cache = self.pid_start_tokens.lock().await;
        let pid_reuse_detected = cache
            .get(&identity.pid)
            .map(|cached| cached != &identity.start_token)
            .unwrap_or(false);
        let evicted = if cache
            .push(identity.pid, identity.start_token.clone())
            .is_some()
        {
            1
        } else {
            0
        };
        (pid_reuse_detected, evicted)
    }

    pub(crate) async fn remove_connection(&self, connection_id: Uuid) {
        let mut cache = self.connection_cache.lock().await;
        let _ = cache.pop(&connection_id);
    }
}

async fn cache_push_count_eviction<K, V>(cache: &Mutex<LruCache<K, V>>, key: K, value: V) -> u32
where
    K: Eq + Hash,
{
    let mut cache = cache.lock().await;
    if cache.push(key, value).is_some() {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests;
