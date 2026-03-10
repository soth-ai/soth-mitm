use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;

const AUTHORITATIVE_PROVIDER: &str = "rustls";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsLearningSignal {
    pub host: String,
    pub failure_reason: String,
    pub failure_source: String,
    pub provider: String,
    pub inferred: bool,
}

impl TlsLearningSignal {
    pub fn new(
        host: impl Into<String>,
        failure_reason: impl Into<String>,
        failure_source: impl Into<String>,
        provider: impl Into<String>,
        inferred: bool,
    ) -> Self {
        Self {
            host: host.into(),
            failure_reason: failure_reason.into(),
            failure_source: failure_source.into(),
            provider: provider.into(),
            inferred,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsLearningDecision {
    Applied,
    Ignored,
}

impl TlsLearningDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Ignored => "ignored",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsLearningOutcome {
    pub decision: TlsLearningDecision,
    pub reason_code: &'static str,
    pub host_applied_total: u64,
    pub global_applied_total: u64,
    pub global_ignored_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsLearningHostSnapshot {
    pub applied_total: u64,
    pub by_reason: BTreeMap<String, u64>,
    pub last_source: String,
    pub last_provider: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsLearningSnapshot {
    pub applied_total: u64,
    pub ignored_total: u64,
    pub hosts: BTreeMap<String, TlsLearningHostSnapshot>,
}

#[derive(Debug)]
pub struct TlsLearningGuardrails {
    state: Mutex<TlsLearningState>,
}

#[derive(Debug, Default)]
struct TlsLearningState {
    applied_total: u64,
    ignored_total: u64,
    hosts: HashMap<String, HostLearningState>,
}

#[derive(Debug, Default)]
struct HostLearningState {
    applied_total: u64,
    by_reason: HashMap<String, u64>,
    last_source: String,
    last_provider: String,
}

#[derive(Debug)]
struct NormalizedSignal {
    host: String,
    failure_reason: String,
    failure_source: String,
    provider: String,
    inferred: bool,
}

impl Default for TlsLearningGuardrails {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsLearningGuardrails {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(TlsLearningState::default()),
        }
    }

    pub fn ingest(&self, signal: TlsLearningSignal) -> TlsLearningOutcome {
        let normalized = normalize_signal(signal);
        let (accepted, reason_code) = evaluate_signal_authority(&normalized);

        let mut state = self.state.lock().expect("TLS learning lock poisoned");
        if accepted {
            state.applied_total += 1;
            let host_state = state.hosts.entry(normalized.host).or_default();
            host_state.applied_total += 1;
            increment_counter(&mut host_state.by_reason, &normalized.failure_reason);
            host_state.last_source = normalized.failure_source;
            host_state.last_provider = normalized.provider;

            TlsLearningOutcome {
                decision: TlsLearningDecision::Applied,
                reason_code,
                host_applied_total: host_state.applied_total,
                global_applied_total: state.applied_total,
                global_ignored_total: state.ignored_total,
            }
        } else {
            state.ignored_total += 1;
            let host_applied_total = state
                .hosts
                .get(&normalized.host)
                .map(|host| host.applied_total)
                .unwrap_or(0);
            TlsLearningOutcome {
                decision: TlsLearningDecision::Ignored,
                reason_code,
                host_applied_total,
                global_applied_total: state.applied_total,
                global_ignored_total: state.ignored_total,
            }
        }
    }

    pub fn snapshot(&self) -> TlsLearningSnapshot {
        let state = self.state.lock().expect("TLS learning lock poisoned");
        let hosts = state
            .hosts
            .iter()
            .map(|(host, host_state)| {
                (
                    host.clone(),
                    TlsLearningHostSnapshot {
                        applied_total: host_state.applied_total,
                        by_reason: host_state
                            .by_reason
                            .iter()
                            .map(|(reason, count)| (reason.clone(), *count))
                            .collect(),
                        last_source: host_state.last_source.clone(),
                        last_provider: host_state.last_provider.clone(),
                    },
                )
            })
            .collect();

        TlsLearningSnapshot {
            applied_total: state.applied_total,
            ignored_total: state.ignored_total,
            hosts,
        }
    }
}

fn normalize_signal(signal: TlsLearningSignal) -> NormalizedSignal {
    let host = normalize_host(&signal.host);
    NormalizedSignal {
        host,
        failure_reason: signal.failure_reason.trim().to_ascii_lowercase(),
        failure_source: signal.failure_source.trim().to_ascii_lowercase(),
        provider: signal.provider.trim().to_ascii_lowercase(),
        inferred: signal.inferred,
    }
}

fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    match trimmed.parse::<IpAddr>() {
        Ok(_) => trimmed.to_string(),
        Err(_) => trimmed.to_ascii_lowercase(),
    }
}

fn evaluate_signal_authority(signal: &NormalizedSignal) -> (bool, &'static str) {
    if signal.failure_reason.is_empty() {
        return (false, "missing_failure_reason");
    }

    let from_hudsucker =
        signal.failure_source.contains("hudsucker") || signal.provider.contains("hudsucker");
    if signal.inferred && from_hudsucker {
        return (false, "inferred_hudsucker_signal");
    }
    if signal.inferred {
        return (false, "inferred_signal");
    }
    if from_hudsucker {
        return (false, "hudsucker_signal");
    }
    if signal.provider != AUTHORITATIVE_PROVIDER {
        return (false, "non_authoritative_provider");
    }
    if signal.failure_source != "upstream" && signal.failure_source != "downstream" {
        return (false, "non_authoritative_source");
    }

    (true, "authoritative")
}

fn increment_counter(counters: &mut HashMap<String, u64>, key: &str) {
    let value = counters.entry(key.to_string()).or_insert(0);
    *value += 1;
}

#[cfg(test)]
mod tests {
    use super::{TlsLearningDecision, TlsLearningGuardrails, TlsLearningSignal};

    #[test]
    fn accepts_authoritative_rustls_signal() {
        let guardrails = TlsLearningGuardrails::new();
        let outcome = guardrails.ingest(TlsLearningSignal::new(
            "API.EXAMPLE.COM",
            "unknown_ca",
            "upstream",
            "rustls",
            false,
        ));
        assert_eq!(outcome.decision, TlsLearningDecision::Applied);
        assert_eq!(outcome.reason_code, "authoritative");
        assert_eq!(outcome.host_applied_total, 1);
        assert_eq!(outcome.global_applied_total, 1);
        assert_eq!(outcome.global_ignored_total, 0);

        let snapshot = guardrails.snapshot();
        assert_eq!(snapshot.applied_total, 1);
        assert_eq!(snapshot.ignored_total, 0);
        let host = snapshot.hosts.get("api.example.com").expect("host state");
        assert_eq!(host.applied_total, 1);
        assert_eq!(host.by_reason.get("unknown_ca"), Some(&1));
        assert_eq!(host.last_source, "upstream");
        assert_eq!(host.last_provider, "rustls");
    }

    #[test]
    fn inferred_hudsucker_signal_is_ignored_and_not_learned() {
        let guardrails = TlsLearningGuardrails::new();
        let outcome = guardrails.ingest(TlsLearningSignal::new(
            "api.example.com",
            "unknown_ca",
            "hudsucker_upstream",
            "hudsucker",
            true,
        ));
        assert_eq!(outcome.decision, TlsLearningDecision::Ignored);
        assert_eq!(outcome.reason_code, "inferred_hudsucker_signal");
        assert_eq!(outcome.host_applied_total, 0);
        assert_eq!(outcome.global_applied_total, 0);
        assert_eq!(outcome.global_ignored_total, 1);

        let snapshot = guardrails.snapshot();
        assert_eq!(snapshot.applied_total, 0);
        assert_eq!(snapshot.ignored_total, 1);
        assert!(snapshot.hosts.is_empty());
    }

    #[test]
    fn non_authoritative_provider_is_ignored() {
        let guardrails = TlsLearningGuardrails::new();
        let outcome = guardrails.ingest(TlsLearningSignal::new(
            "service.local",
            "timeout",
            "upstream",
            "mitmproxy",
            false,
        ));
        assert_eq!(outcome.decision, TlsLearningDecision::Ignored);
        assert_eq!(outcome.reason_code, "non_authoritative_provider");
        assert_eq!(outcome.global_applied_total, 0);
        assert_eq!(outcome.global_ignored_total, 1);
    }
}
