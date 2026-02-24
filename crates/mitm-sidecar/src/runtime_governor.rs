use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBudgetConfig {
    pub max_concurrent_flows: usize,
    pub max_in_flight_bytes: usize,
}

impl Default for RuntimeBudgetConfig {
    fn default() -> Self {
        Self {
            max_concurrent_flows: 2048,
            max_in_flight_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RuntimeObservabilitySnapshot {
    pub active_flows: u64,
    pub max_active_flows: u64,
    pub current_in_flight_bytes: u64,
    pub in_flight_bytes_watermark: u64,
    pub flow_count: u64,
    pub flow_duration_total_ms: u64,
    pub flow_duration_max_ms: u64,
    pub backpressure_activation_count: u64,
    pub decoder_failure_count: u64,
    pub event_queue_depth: u64,
    pub event_queue_depth_watermark: u64,
}

pub struct RuntimeGovernor {
    flow_permits: Arc<Semaphore>,
    max_in_flight_bytes: usize,
    current_in_flight_bytes: AtomicUsize,
    in_flight_bytes_watermark: AtomicUsize,
    active_flows: AtomicU64,
    max_active_flows: AtomicU64,
    flow_count: AtomicU64,
    flow_duration_total_ms: AtomicU64,
    flow_duration_max_ms: AtomicU64,
    backpressure_activation_count: AtomicU64,
    decoder_failure_count: AtomicU64,
    event_queue_depth: AtomicU64,
    event_queue_depth_watermark: AtomicU64,
    closed_flow_ids: Mutex<VecDeque<u64>>,
}

static GLOBAL_RUNTIME_GOVERNOR: OnceLock<Arc<RuntimeGovernor>> = OnceLock::new();

impl RuntimeGovernor {
    const RECENT_CLOSED_FLOW_IDS: usize = 16_384;

    pub fn new(config: RuntimeBudgetConfig) -> Self {
        Self {
            flow_permits: Arc::new(Semaphore::new(config.max_concurrent_flows.max(1))),
            max_in_flight_bytes: config.max_in_flight_bytes.max(1),
            current_in_flight_bytes: AtomicUsize::new(0),
            in_flight_bytes_watermark: AtomicUsize::new(0),
            active_flows: AtomicU64::new(0),
            max_active_flows: AtomicU64::new(0),
            flow_count: AtomicU64::new(0),
            flow_duration_total_ms: AtomicU64::new(0),
            flow_duration_max_ms: AtomicU64::new(0),
            backpressure_activation_count: AtomicU64::new(0),
            decoder_failure_count: AtomicU64::new(0),
            event_queue_depth: AtomicU64::new(0),
            event_queue_depth_watermark: AtomicU64::new(0),
            closed_flow_ids: Mutex::new(VecDeque::new()),
        }
    }

    pub fn try_acquire_flow_permit(self: &Arc<Self>) -> Option<OwnedSemaphorePermit> {
        self.flow_permits.clone().try_acquire_owned().ok()
    }

    pub fn begin_flow(self: &Arc<Self>, permit: OwnedSemaphorePermit) -> FlowRuntimeGuard {
        let active = self.active_flows.fetch_add(1, Ordering::SeqCst) + 1;
        update_max_u64(&self.max_active_flows, active);
        FlowRuntimeGuard {
            governor: Arc::clone(self),
            started_at: Instant::now(),
            _permit: permit,
        }
    }

    pub fn try_reserve_in_flight(self: &Arc<Self>, bytes: usize) -> Option<InFlightLease> {
        if bytes == 0 {
            return Some(InFlightLease {
                governor: Arc::clone(self),
                bytes: 0,
            });
        }
        loop {
            let current = self.current_in_flight_bytes.load(Ordering::Relaxed);
            let next = current.saturating_add(bytes);
            if next > self.max_in_flight_bytes {
                return None;
            }
            if self
                .current_in_flight_bytes
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                update_max_usize(&self.in_flight_bytes_watermark, next);
                return Some(InFlightLease {
                    governor: Arc::clone(self),
                    bytes,
                });
            }
        }
    }

    pub fn mark_backpressure_activation(&self) {
        self.backpressure_activation_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_decoder_failure(&self) {
        self.decoder_failure_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_event_queue_depth(&self, depth: u64) {
        self.event_queue_depth.store(depth, Ordering::Relaxed);
        update_max_u64(&self.event_queue_depth_watermark, depth);
    }

    pub fn register_stream_closed(&self, flow_id: u64) -> bool {
        let mut closed = self
            .closed_flow_ids
            .lock()
            .expect("runtime governor closed-flow lock poisoned");
        if closed.iter().any(|existing| *existing == flow_id) {
            return false;
        }
        closed.push_back(flow_id);
        while closed.len() > Self::RECENT_CLOSED_FLOW_IDS {
            closed.pop_front();
        }
        true
    }

    pub fn snapshot(&self) -> RuntimeObservabilitySnapshot {
        RuntimeObservabilitySnapshot {
            active_flows: self.active_flows.load(Ordering::Relaxed),
            max_active_flows: self.max_active_flows.load(Ordering::Relaxed),
            current_in_flight_bytes: self.current_in_flight_bytes.load(Ordering::Relaxed) as u64,
            in_flight_bytes_watermark: self.in_flight_bytes_watermark.load(Ordering::Relaxed)
                as u64,
            flow_count: self.flow_count.load(Ordering::Relaxed),
            flow_duration_total_ms: self.flow_duration_total_ms.load(Ordering::Relaxed),
            flow_duration_max_ms: self.flow_duration_max_ms.load(Ordering::Relaxed),
            backpressure_activation_count: self
                .backpressure_activation_count
                .load(Ordering::Relaxed),
            decoder_failure_count: self.decoder_failure_count.load(Ordering::Relaxed),
            event_queue_depth: self.event_queue_depth.load(Ordering::Relaxed),
            event_queue_depth_watermark: self.event_queue_depth_watermark.load(Ordering::Relaxed),
        }
    }
}

pub fn install_global_runtime_governor(governor: Arc<RuntimeGovernor>) {
    let _ = GLOBAL_RUNTIME_GOVERNOR.set(governor);
}

pub fn mark_backpressure_activation_global() {
    if let Some(governor) = GLOBAL_RUNTIME_GOVERNOR.get() {
        governor.mark_backpressure_activation();
    }
}

pub fn mark_decoder_failure_global() {
    if let Some(governor) = GLOBAL_RUNTIME_GOVERNOR.get() {
        governor.mark_decoder_failure();
    }
}

pub fn set_event_queue_depth_global(depth: u64) {
    if let Some(governor) = GLOBAL_RUNTIME_GOVERNOR.get() {
        governor.set_event_queue_depth(depth);
    }
}

pub struct FlowRuntimeGuard {
    governor: Arc<RuntimeGovernor>,
    started_at: Instant,
    _permit: OwnedSemaphorePermit,
}

impl Drop for FlowRuntimeGuard {
    fn drop(&mut self) {
        self.governor.active_flows.fetch_sub(1, Ordering::SeqCst);
        self.governor.flow_count.fetch_add(1, Ordering::Relaxed);

        let duration_ms = self
            .started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        self.governor
            .flow_duration_total_ms
            .fetch_add(duration_ms, Ordering::Relaxed);
        update_max_u64(&self.governor.flow_duration_max_ms, duration_ms);
    }
}

pub struct InFlightLease {
    governor: Arc<RuntimeGovernor>,
    bytes: usize,
}

impl Drop for InFlightLease {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.governor
                .current_in_flight_bytes
                .fetch_sub(self.bytes, Ordering::SeqCst);
        }
    }
}

fn update_max_u64(target: &AtomicU64, candidate: u64) {
    loop {
        let current = target.load(Ordering::Relaxed);
        if candidate <= current {
            return;
        }
        if target
            .compare_exchange(current, candidate, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

fn update_max_usize(target: &AtomicUsize, candidate: usize) {
    loop {
        let current = target.load(Ordering::Relaxed);
        if candidate <= current {
            return;
        }
        if target
            .compare_exchange(current, candidate, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{RuntimeBudgetConfig, RuntimeGovernor};

    #[test]
    fn stream_closed_is_deduplicated_per_flow_id() {
        let governor = RuntimeGovernor::new(RuntimeBudgetConfig::default());
        assert!(governor.register_stream_closed(42));
        assert!(!governor.register_stream_closed(42));
        assert!(governor.register_stream_closed(43));
    }

    #[test]
    fn in_flight_reservation_respects_global_limit() {
        let governor = Arc::new(RuntimeGovernor::new(RuntimeBudgetConfig {
            max_concurrent_flows: 2,
            max_in_flight_bytes: 16,
        }));
        let a = governor
            .try_reserve_in_flight(8)
            .expect("first reservation should succeed");
        let b = governor
            .try_reserve_in_flight(8)
            .expect("second reservation should succeed");
        assert!(governor.try_reserve_in_flight(1).is_none());
        drop(a);
        assert!(governor.try_reserve_in_flight(1).is_some());
        drop(b);
    }
}
