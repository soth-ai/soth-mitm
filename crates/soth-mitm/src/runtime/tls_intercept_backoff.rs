use dashmap::DashMap;
use std::time::{Duration, Instant};

const DEFAULT_BYPASS_TTL: Duration = Duration::from_secs(15 * 60);

/// Number of genuine cert-trust rejections (within one TTL window) required
/// before a host/pid is bypassed. Requiring more than one raises the bar
/// against a local process that deliberately fails its own handshake to
/// evade inspection, and avoids disabling interception on a single transient
/// cert glitch. A genuinely cert-pinned host fails every handshake, so it
/// still reaches the threshold within a couple of connection attempts.
const ACTIVATION_THRESHOLD: u32 = 2;

#[derive(Debug, Clone, Copy)]
struct FailureRecord {
    count: u32,
    window_until: Instant,
}

#[derive(Debug)]
pub(crate) struct TlsInterceptBackoff {
    bypass_ttl: Duration,
    bypass_until_by_pid: DashMap<u32, Instant>,
    bypass_until_by_host: DashMap<String, Instant>,
    failures_by_pid: DashMap<u32, FailureRecord>,
    failures_by_host: DashMap<String, FailureRecord>,
}

impl Default for TlsInterceptBackoff {
    fn default() -> Self {
        Self::new(DEFAULT_BYPASS_TTL)
    }
}

impl TlsInterceptBackoff {
    pub(crate) fn new(bypass_ttl: Duration) -> Self {
        let bypass_ttl = if bypass_ttl.is_zero() {
            Duration::from_secs(1)
        } else {
            bypass_ttl
        };
        Self {
            bypass_ttl,
            bypass_until_by_pid: DashMap::new(),
            bypass_until_by_host: DashMap::new(),
            failures_by_pid: DashMap::new(),
            failures_by_host: DashMap::new(),
        }
    }

    pub(crate) fn should_bypass_for_pid(&self, pid: u32) -> bool {
        if let Some(until) = self.bypass_until_by_pid.get(&pid) {
            if *until > Instant::now() {
                return true;
            }
        }
        let _ = self.bypass_until_by_pid.remove(&pid);
        false
    }

    pub(crate) fn should_bypass_for_host(&self, host: &str) -> bool {
        let Some(host_key) = normalize_host_key(host) else {
            return false;
        };
        let now = Instant::now();
        if let Some(until) = self.bypass_until_by_host.get(&host_key) {
            if *until > now {
                return true;
            }
        }
        let _ = self.bypass_until_by_host.remove(&host_key);
        false
    }

    pub(crate) fn bypass_ttl(&self) -> Duration {
        self.bypass_ttl
    }

    pub(crate) fn register_tls_failure(
        &self,
        pid: Option<u32>,
        _process_name: Option<&str>,
        host: &str,
        detail: &str,
    ) -> bool {
        // Only genuine cert-trust rejections count. A connection reset / EOF
        // is not evidence of pinning and is trivially forgeable by any local
        // process, so it must never disable inspection.
        if !is_downstream_tls_compat_failure(detail) {
            return false;
        }

        let now = Instant::now();
        let until = now + self.bypass_ttl;
        let mut activated = false;

        if let Some(pid) = pid {
            if self.record_failure_reached_threshold(&self.failures_by_pid, pid, now) {
                activated |= register_backoff_deadline(&self.bypass_until_by_pid, pid, now, until);
            }
        }

        // Exact host only — no parent-domain widening. Widening a failure at
        // `x.co.uk` up to `co.uk` (or any eTLD) would disable inspection for
        // every sibling/host under that suffix; without a public-suffix list
        // that blast radius is unbounded, so we never widen.
        if let Some(host_key) = normalize_host_key(host) {
            if self.record_failure_reached_threshold(&self.failures_by_host, host_key.clone(), now)
            {
                activated |=
                    register_backoff_deadline(&self.bypass_until_by_host, host_key, now, until);
            }
        }

        activated
    }

    /// Record one genuine failure for `key` and report whether the activation
    /// threshold has been reached within the current window. The window is
    /// `bypass_ttl`; a failure after the window elapses starts a fresh count.
    fn record_failure_reached_threshold<K>(
        &self,
        map: &DashMap<K, FailureRecord>,
        key: K,
        now: Instant,
    ) -> bool
    where
        K: Eq + std::hash::Hash,
    {
        // Read-modify-write under the shard lock via `entry`, not a
        // get-then-insert pair. The latter has a TOCTOU gap: concurrent
        // failures for the same host (e.g. an h2 client racing several
        // connections that all reject our MITM leaf at once) would all read
        // the same count and all write count+1, advancing by 1 instead of N —
        // stalling arming for exactly the pinned host this exists to serve.
        use dashmap::mapref::entry::Entry;
        let window_until = now + self.bypass_ttl;
        match map.entry(key) {
            Entry::Occupied(mut occupied) => {
                let record = occupied.get_mut();
                if record.window_until <= now {
                    // Window expired — start a fresh count.
                    *record = FailureRecord {
                        count: 1,
                        window_until,
                    };
                } else {
                    record.count = record.count.saturating_add(1);
                }
                if record.count >= ACTIVATION_THRESHOLD {
                    // Threshold crossed — clear the counter; the bypass
                    // deadline now governs behavior.
                    occupied.remove();
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(vacant) => {
                // First failure in a fresh window. With ACTIVATION_THRESHOLD > 1
                // this never arms on its own; record and wait for the next.
                if ACTIVATION_THRESHOLD <= 1 {
                    true
                } else {
                    vacant.insert(FailureRecord {
                        count: 1,
                        window_until,
                    });
                    false
                }
            }
        }
    }
}

fn register_backoff_deadline<K>(
    map: &DashMap<K, Instant>,
    key: K,
    now: Instant,
    until: Instant,
) -> bool
where
    K: Eq + std::hash::Hash,
{
    if let Some(existing) = map.get(&key) {
        if *existing > now {
            if *existing < until {
                map.insert(key, until);
            }
            return false;
        }
    }
    map.insert(key, until);
    true
}

/// Normalize a host into a bypass-map key, or `None` for empty/unknown hosts.
fn normalize_host_key(host: &str) -> Option<String> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized == "<unknown>" || normalized == "unknown" {
        None
    } else {
        Some(normalized)
    }
}

fn is_downstream_tls_compat_failure(detail: &str) -> bool {
    let normalized = detail.to_ascii_lowercase();
    if !normalized.contains("downstream handshake failed") {
        return false;
    }

    // Only genuine certificate-trust rejections — the client validated our
    // MITM leaf and rejected it, which is the actual signal of pinning /
    // custom trust. "tls handshake eof" / "unexpected eof" / "connection
    // reset" were previously included but are NOT evidence of pinning: they
    // fire on any aborted handshake and are trivially forgeable by a local
    // process, which made this an inspection-bypass primitive. They no
    // longer arm the backoff.
    normalized.contains("unknown ca")
        || normalized.contains("unknown issuer")
        || normalized.contains("self signed")
        || normalized.contains("certificate verify failed")
        || normalized.contains("bad certificate")
        || normalized.contains("certificate required")
        || normalized.contains("certificate unknown")
}

#[cfg(test)]
mod tests {
    use super::TlsInterceptBackoff;
    use std::time::Duration;

    const CERT_FAILURE: &str =
        "downstream handshake failed: downstream rustls handshake failed: bad certificate";

    #[test]
    fn genuine_cert_failure_arms_bypass_after_threshold() {
        let backoff = TlsInterceptBackoff::new(Duration::from_secs(30));
        let host = concat!("chatg", "pt.com");
        // First genuine failure records but must NOT yet arm the bypass —
        // requiring a second failure raises the bar against forgery.
        assert!(!backoff.register_tls_failure(Some(42), Some("codex"), host, CERT_FAILURE));
        assert!(!backoff.should_bypass_for_pid(42));
        assert!(!backoff.should_bypass_for_host(host));
        // Second genuine failure crosses the threshold and arms it.
        assert!(backoff.register_tls_failure(Some(42), Some("codex"), host, CERT_FAILURE));
        assert!(backoff.should_bypass_for_pid(42));
        assert!(backoff.should_bypass_for_host(host));
    }

    #[test]
    fn eof_or_reset_never_arms_bypass() {
        let backoff = TlsInterceptBackoff::new(Duration::from_secs(30));
        let host = concat!("chatg", "pt.com");
        // Trivially-forgeable aborts must never disable inspection, no matter
        // how many times they occur — this was the bypass primitive.
        for detail in [
            "downstream handshake failed: tls handshake eof",
            "downstream handshake failed: connection reset",
            "downstream handshake failed: unexpected eof",
        ] {
            for _ in 0..5 {
                assert!(!backoff.register_tls_failure(Some(42), None, host, detail));
            }
        }
        assert!(!backoff.should_bypass_for_pid(42));
        assert!(!backoff.should_bypass_for_host(host));
    }

    #[test]
    fn upstream_failure_does_not_enable_bypass() {
        let backoff = TlsInterceptBackoff::new(Duration::from_secs(30));
        for _ in 0..3 {
            assert!(!backoff.register_tls_failure(
                Some(42),
                Some("codex"),
                concat!("chatg", "pt.com"),
                "upstream handshake failed: certificate verify failed: unknown ca"
            ));
        }
        assert!(!backoff.should_bypass_for_pid(42));
        assert!(!backoff.should_bypass_for_host(concat!("chatg", "pt.com")));
    }

    #[test]
    fn genuine_cert_failure_arms_host_bypass_without_process_info() {
        let backoff = TlsInterceptBackoff::new(Duration::from_secs(30));
        let host = concat!("chatg", "pt.com");
        assert!(!backoff.should_bypass_for_host(host));
        assert!(!backoff.register_tls_failure(None, None, host, CERT_FAILURE));
        assert!(backoff.register_tls_failure(None, None, host, CERT_FAILURE));
        assert!(backoff.should_bypass_for_host(host));
    }

    #[test]
    fn bypass_does_not_widen_to_parent_or_sibling_domains() {
        // The security fix: a failure at one host must never disable
        // inspection for sibling subdomains or the parent suffix.
        let backoff = TlsInterceptBackoff::new(Duration::from_secs(30));
        let host = concat!("ab.chatg", "pt.com");
        assert!(!backoff.register_tls_failure(None, None, host, CERT_FAILURE));
        assert!(backoff.register_tls_failure(None, None, host, CERT_FAILURE));
        // Exact host is bypassed…
        assert!(backoff.should_bypass_for_host(host));
        // …but the parent and siblings are NOT.
        assert!(!backoff.should_bypass_for_host(concat!("chatg", "pt.com")));
        assert!(!backoff.should_bypass_for_host(concat!("ws.chatg", "pt.com")));
        assert!(!backoff.should_bypass_for_host("api.example.com"));
    }

    #[test]
    fn failure_window_resets_between_isolated_failures() {
        // Two genuine failures far apart (window expired between them) should
        // not accumulate into an activation. Simulated with a 1ns TTL so the
        // window elapses immediately.
        let backoff = TlsInterceptBackoff::new(Duration::from_nanos(1));
        let host = concat!("chatg", "pt.com");
        assert!(!backoff.register_tls_failure(None, None, host, CERT_FAILURE));
        std::thread::sleep(Duration::from_millis(2));
        // Second failure starts a fresh window (count resets to 1), so it
        // still doesn't cross the threshold on its own.
        assert!(!backoff.register_tls_failure(None, None, host, CERT_FAILURE));
    }
}
