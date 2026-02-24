use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::tls_intercept_contract::IssuedLeafContract;

pub(crate) const DEFAULT_LEAF_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LeafCacheDecision {
    Reuse(IssuedLeafContract),
    Reissue,
}

#[derive(Debug, Clone)]
struct CachedLeaf {
    issued_at: SystemTime,
    leaf: IssuedLeafContract,
}

#[derive(Debug, Default)]
pub(crate) struct LeafCache {
    entries: HashMap<String, CachedLeaf>,
}

impl LeafCache {
    pub(crate) fn insert(&mut self, host: &str, issued_at: SystemTime, leaf: IssuedLeafContract) {
        self.entries
            .insert(host.to_ascii_lowercase(), CachedLeaf { issued_at, leaf });
    }

    pub(crate) fn decision_for_host(
        &self,
        host: &str,
        now: SystemTime,
        ttl: Duration,
    ) -> LeafCacheDecision {
        let Some(entry) = self.entries.get(&host.to_ascii_lowercase()) else {
            return LeafCacheDecision::Reissue;
        };

        let age = now
            .duration_since(entry.issued_at)
            .unwrap_or_else(|_| Duration::from_secs(0));
        if age <= ttl {
            LeafCacheDecision::Reuse(entry.leaf.clone())
        } else {
            LeafCacheDecision::Reissue
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::{LeafCache, LeafCacheDecision, DEFAULT_LEAF_CACHE_TTL};
    use crate::tls_intercept_contract::IssuedLeafContract;

    #[test]
    fn leaf_cache_reuse_within_24h() {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut cache = LeafCache::default();
        cache.insert("api.example.com", issued_at, sample_leaf("api.example.com"));

        let now = issued_at + Duration::from_secs(23 * 60 * 60);
        let decision = cache.decision_for_host("API.EXAMPLE.COM", now, DEFAULT_LEAF_CACHE_TTL);

        match decision {
            LeafCacheDecision::Reuse(leaf) => assert_eq!(leaf.san_host, "api.example.com"),
            LeafCacheDecision::Reissue => panic!("expected cache reuse"),
        }
    }

    #[test]
    fn leaf_cache_reissue_after_ttl() {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut cache = LeafCache::default();
        cache.insert("api.example.com", issued_at, sample_leaf("api.example.com"));

        let now = issued_at + Duration::from_secs(24 * 60 * 60 + 1);
        let decision = cache.decision_for_host("api.example.com", now, DEFAULT_LEAF_CACHE_TTL);

        assert_eq!(decision, LeafCacheDecision::Reissue);
    }

    fn sample_leaf(host: &str) -> IssuedLeafContract {
        IssuedLeafContract {
            cert_pem: b"cert".to_vec(),
            key_pem: b"key".to_vec(),
            san_host: host.to_string(),
        }
    }
}
