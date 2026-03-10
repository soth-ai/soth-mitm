use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_ROLLING_WINDOW: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHostFailureSnapshot {
    pub total_failures: u64,
    pub rolling_failures: u64,
    pub by_source: BTreeMap<String, u64>,
    pub by_reason: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsDiagnosticsSnapshot {
    pub total_failures: u64,
    pub hosts: BTreeMap<String, TlsHostFailureSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsFailureCounterUpdate {
    pub host_total_failures: u64,
    pub host_rolling_failures: u64,
    pub source_total_failures: u64,
    pub reason_total_failures: u64,
    pub global_total_failures: u64,
}

#[derive(Debug)]
pub struct TlsDiagnostics {
    rolling_window: Duration,
    state: Mutex<TlsDiagnosticsState>,
}

#[derive(Debug, Default)]
struct TlsDiagnosticsState {
    total_failures: u64,
    hosts: HashMap<String, HostCounters>,
}

#[derive(Debug, Default)]
struct HostCounters {
    total_failures: u64,
    by_source: HashMap<String, u64>,
    by_reason: HashMap<String, u64>,
    rolling_timestamps: VecDeque<Instant>,
}

impl Default for TlsDiagnostics {
    fn default() -> Self {
        Self::new(DEFAULT_ROLLING_WINDOW)
    }
}

impl TlsDiagnostics {
    pub fn new(rolling_window: Duration) -> Self {
        let window = if rolling_window.is_zero() {
            Duration::from_secs(1)
        } else {
            rolling_window
        };
        Self {
            rolling_window: window,
            state: Mutex::new(TlsDiagnosticsState::default()),
        }
    }

    pub fn record_failure(
        &self,
        host: &str,
        source: &str,
        reason: &str,
    ) -> TlsFailureCounterUpdate {
        let now = Instant::now();
        let host = normalize_host(host);

        let mut state = self.state.lock().expect("TLS diagnostics lock poisoned");
        let (host_total_failures, host_rolling_failures, source_total, reason_total) = {
            let host_counters = state.hosts.entry(host).or_default();
            prune_rolling(host_counters, now, self.rolling_window);

            host_counters.total_failures += 1;
            host_counters.rolling_timestamps.push_back(now);
            let source_total = increment_counter(&mut host_counters.by_source, source);
            let reason_total = increment_counter(&mut host_counters.by_reason, reason);
            (
                host_counters.total_failures,
                host_counters.rolling_timestamps.len() as u64,
                source_total,
                reason_total,
            )
        };

        state.total_failures += 1;

        TlsFailureCounterUpdate {
            host_total_failures,
            host_rolling_failures,
            source_total_failures: source_total,
            reason_total_failures: reason_total,
            global_total_failures: state.total_failures,
        }
    }

    pub fn snapshot(&self) -> TlsDiagnosticsSnapshot {
        let now = Instant::now();
        let mut state = self.state.lock().expect("TLS diagnostics lock poisoned");

        let mut hosts = BTreeMap::new();
        for (host, counters) in &mut state.hosts {
            prune_rolling(counters, now, self.rolling_window);
            hosts.insert(
                host.clone(),
                TlsHostFailureSnapshot {
                    total_failures: counters.total_failures,
                    rolling_failures: counters.rolling_timestamps.len() as u64,
                    by_source: counters
                        .by_source
                        .iter()
                        .map(|(source, count)| (source.clone(), *count))
                        .collect(),
                    by_reason: counters
                        .by_reason
                        .iter()
                        .map(|(reason, count)| (reason.clone(), *count))
                        .collect(),
                },
            );
        }

        TlsDiagnosticsSnapshot {
            total_failures: state.total_failures,
            hosts,
        }
    }
}

fn normalize_host(host: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(_) => host.to_string(),
        Err(_) => host.to_ascii_lowercase(),
    }
}

fn increment_counter(counters: &mut HashMap<String, u64>, key: &str) -> u64 {
    let value = counters.entry(key.to_string()).or_insert(0);
    *value += 1;
    *value
}

fn prune_rolling(counters: &mut HostCounters, now: Instant, window: Duration) {
    while let Some(timestamp) = counters.rolling_timestamps.front() {
        if now.duration_since(*timestamp) > window {
            counters.rolling_timestamps.pop_front();
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use super::TlsDiagnostics;

    #[test]
    fn records_host_scoped_source_and_reason_counts() {
        let diagnostics = TlsDiagnostics::new(Duration::from_secs(60));

        let first = diagnostics.record_failure("API.EXAMPLE.COM", "upstream", "unknown_ca");
        assert_eq!(first.host_total_failures, 1);
        assert_eq!(first.host_rolling_failures, 1);
        assert_eq!(first.source_total_failures, 1);
        assert_eq!(first.reason_total_failures, 1);
        assert_eq!(first.global_total_failures, 1);

        let second = diagnostics.record_failure("api.example.com", "upstream", "unknown_ca");
        assert_eq!(second.host_total_failures, 2);
        assert_eq!(second.host_rolling_failures, 2);
        assert_eq!(second.source_total_failures, 2);
        assert_eq!(second.reason_total_failures, 2);
        assert_eq!(second.global_total_failures, 2);

        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.total_failures, 2);
        let host = snapshot
            .hosts
            .get("api.example.com")
            .expect("host counters");
        assert_eq!(host.total_failures, 2);
        assert_eq!(host.rolling_failures, 2);
        assert_eq!(host.by_source.get("upstream"), Some(&2));
        assert_eq!(host.by_reason.get("unknown_ca"), Some(&2));
    }

    #[test]
    fn rolling_counter_expires_entries_outside_window() {
        let diagnostics = TlsDiagnostics::new(Duration::from_millis(30));
        let first = diagnostics.record_failure("service.local", "upstream", "timeout");
        assert_eq!(first.host_rolling_failures, 1);

        thread::sleep(Duration::from_millis(45));

        let second = diagnostics.record_failure("service.local", "upstream", "timeout");
        assert_eq!(second.host_total_failures, 2);
        assert_eq!(second.host_rolling_failures, 1);

        let snapshot = diagnostics.snapshot();
        let host = snapshot.hosts.get("service.local").expect("host counters");
        assert_eq!(host.total_failures, 2);
        assert_eq!(host.rolling_failures, 1);
        assert_eq!(host.by_source.get("upstream"), Some(&2));
        assert_eq!(host.by_reason.get("timeout"), Some(&2));
    }
}
