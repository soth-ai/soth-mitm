use dashmap::DashMap;
use std::time::{Duration, Instant};

const DEFAULT_BYPASS_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Debug)]
pub(crate) struct TlsInterceptBackoff {
    bypass_ttl: Duration,
    bypass_until_by_pid: DashMap<u32, Instant>,
    bypass_until_by_host: DashMap<String, Instant>,
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
        let now = Instant::now();
        for host_key in host_lookup_keys(host) {
            if let Some(until) = self.bypass_until_by_host.get(&host_key) {
                if *until > now {
                    return true;
                }
            }
            let _ = self.bypass_until_by_host.remove(&host_key);
        }
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
        if !is_downstream_tls_compat_failure(detail) {
            return false;
        }

        let now = Instant::now();
        let until = now + self.bypass_ttl;
        let mut activated = false;

        if let Some(pid) = pid {
            activated |= register_backoff_deadline(&self.bypass_until_by_pid, pid, now, until);
        }

        for host_key in host_registration_keys(host) {
            activated |=
                register_backoff_deadline(&self.bypass_until_by_host, host_key, now, until);
        }

        activated
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

fn normalize_host(host: &str) -> String {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized == "<unknown>" || normalized == "unknown" {
        String::new()
    } else {
        normalized
    }
}

fn host_lookup_keys(host: &str) -> Vec<String> {
    let host_key = normalize_host(host);
    if host_key.is_empty() {
        return Vec::new();
    }
    let mut keys = Vec::with_capacity(2);
    keys.push(host_key.clone());
    if let Some(parent) = immediate_parent_host(&host_key) {
        keys.push(parent);
    }
    keys
}

fn host_registration_keys(host: &str) -> Vec<String> {
    host_lookup_keys(host)
}

fn immediate_parent_host(host: &str) -> Option<String> {
    let dot_index = host.find('.')?;
    let parent = &host[dot_index + 1..];
    // Avoid reducing to a single-label TLD-like key.
    if parent.contains('.') {
        Some(parent.to_string())
    } else {
        None
    }
}

fn is_downstream_tls_compat_failure(detail: &str) -> bool {
    let normalized = detail.to_ascii_lowercase();
    if !normalized.contains("downstream handshake failed") {
        return false;
    }

    normalized.contains("unknown ca")
        || normalized.contains("unknown issuer")
        || normalized.contains("self signed")
        || normalized.contains("certificate verify failed")
        || normalized.contains("bad certificate")
        || normalized.contains("tls handshake eof")
        || normalized.contains("unexpected eof")
        || normalized.contains("connection reset")
}

#[cfg(test)]
mod tests {
    use super::TlsInterceptBackoff;
    use std::time::Duration;

    #[test]
    fn downstream_eof_failure_enables_bypass_for_pid() {
        let backoff = TlsInterceptBackoff::new(Duration::from_secs(30));
        assert!(!backoff.should_bypass_for_pid(42));
        assert!(backoff.register_tls_failure(
            Some(42),
            Some("codex"),
            concat!("chatg", "pt.com"),
            "downstream handshake failed: downstream rustls handshake failed: tls handshake eof"
        ));
        assert!(backoff.should_bypass_for_pid(42));
        assert!(backoff.should_bypass_for_host(concat!("chatg", "pt.com")));
    }

    #[test]
    fn upstream_failure_does_not_enable_bypass() {
        let backoff = TlsInterceptBackoff::new(Duration::from_secs(30));
        assert!(!backoff.register_tls_failure(
            Some(42),
            Some("codex"),
            concat!("chatg", "pt.com"),
            "upstream handshake failed: certificate verify failed: unknown ca"
        ));
        assert!(!backoff.should_bypass_for_pid(42));
        assert!(!backoff.should_bypass_for_host(concat!("chatg", "pt.com")));
    }

    #[test]
    fn downstream_failure_enables_host_bypass_without_process_info() {
        let backoff = TlsInterceptBackoff::new(Duration::from_secs(30));
        assert!(!backoff.should_bypass_for_host(concat!("chatg", "pt.com")));
        assert!(backoff.register_tls_failure(
            None,
            None,
            concat!("chatg", "pt.com"),
            "downstream handshake failed: downstream rustls handshake failed: tls handshake eof"
        ));
        assert!(backoff.should_bypass_for_host(concat!("chatg", "pt.com")));
    }

    #[test]
    fn parent_domain_bypass_applies_to_subdomains() {
        let backoff = TlsInterceptBackoff::new(Duration::from_secs(30));
        assert!(backoff.register_tls_failure(
            None,
            None,
            concat!("chatg", "pt.com"),
            "downstream handshake failed: downstream rustls handshake failed: tls handshake eof"
        ));
        assert!(backoff.should_bypass_for_host(concat!("ab.chatg", "pt.com")));
        assert!(backoff.should_bypass_for_host(concat!("ws.chatg", "pt.com")));
        assert!(!backoff.should_bypass_for_host("api.example.com"));
    }

    #[test]
    fn subdomain_failure_bypasses_parent_domain_host() {
        let backoff = TlsInterceptBackoff::new(Duration::from_secs(30));
        assert!(backoff.register_tls_failure(
            None,
            None,
            concat!("ab.chatg", "pt.com"),
            "downstream handshake failed: downstream rustls handshake failed: tls handshake eof"
        ));
        assert!(backoff.should_bypass_for_host(concat!("chatg", "pt.com")));
    }
}
