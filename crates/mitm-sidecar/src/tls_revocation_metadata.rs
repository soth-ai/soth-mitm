use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TlsRevocationMetadata {
    upstream_ocsp_staple_present: &'static str,
    upstream_ocsp_staple_status: &'static str,
    revocation_policy_mode: &'static str,
    revocation_decision: &'static str,
}

pub(crate) fn insert_tls_revocation_metadata(
    attributes: &mut BTreeMap<String, String>,
    detail: &str,
    peer: &str,
) {
    let metadata = classify_tls_revocation_metadata(detail, peer);
    attributes.insert(
        "upstream_ocsp_staple_present".to_string(),
        metadata.upstream_ocsp_staple_present.to_string(),
    );
    attributes.insert(
        "upstream_ocsp_staple_status".to_string(),
        metadata.upstream_ocsp_staple_status.to_string(),
    );
    attributes.insert(
        "revocation_policy_mode".to_string(),
        metadata.revocation_policy_mode.to_string(),
    );
    attributes.insert(
        "revocation_decision".to_string(),
        metadata.revocation_decision.to_string(),
    );
}

fn classify_tls_revocation_metadata(detail: &str, peer: &str) -> TlsRevocationMetadata {
    if peer != "upstream" {
        return TlsRevocationMetadata {
            upstream_ocsp_staple_present: "not_applicable",
            upstream_ocsp_staple_status: "not_applicable",
            revocation_policy_mode: "passive_observe",
            revocation_decision: "not_applicable",
        };
    }

    let lower = detail.to_ascii_lowercase();

    if contains_any(
        &lower,
        &[
            "certificate revoked",
            "cert revoked",
            "revoked by ocsp",
            "revocation status: revoked",
        ],
    ) {
        return TlsRevocationMetadata {
            upstream_ocsp_staple_present: "unknown",
            upstream_ocsp_staple_status: "revoked",
            revocation_policy_mode: "passive_observe",
            revocation_decision: "signal_revoked",
        };
    }

    if contains_any(
        &lower,
        &[
            "ocsp response required but not provided",
            "ocsp response required but missing",
            "missing ocsp",
            "no ocsp response",
            "must-staple",
            "staple required but not provided",
        ],
    ) {
        return TlsRevocationMetadata {
            upstream_ocsp_staple_present: "false",
            upstream_ocsp_staple_status: "missing",
            revocation_policy_mode: "passive_observe",
            revocation_decision: "signal_missing_staple",
        };
    }

    if lower.contains("ocsp")
        && contains_any(
            &lower,
            &["invalid", "malformed", "parse", "expired", "bad response"],
        )
    {
        return TlsRevocationMetadata {
            upstream_ocsp_staple_present: "true",
            upstream_ocsp_staple_status: "invalid",
            revocation_policy_mode: "passive_observe",
            revocation_decision: "signal_invalid_staple",
        };
    }

    if contains_any(&lower, &["ocsp", "staple", "stapling"]) {
        return TlsRevocationMetadata {
            upstream_ocsp_staple_present: "true",
            upstream_ocsp_staple_status: "present",
            revocation_policy_mode: "passive_observe",
            revocation_decision: "signal_present",
        };
    }

    TlsRevocationMetadata {
        upstream_ocsp_staple_present: "unknown",
        upstream_ocsp_staple_status: "not_checked",
        revocation_policy_mode: "passive_observe",
        revocation_decision: "no_signal",
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::insert_tls_revocation_metadata;

    #[test]
    fn upstream_missing_staple_is_classified_deterministically() {
        let mut attrs = BTreeMap::new();
        insert_tls_revocation_metadata(
            &mut attrs,
            "upstream rejected handshake: OCSP response required but missing",
            "upstream",
        );

        assert_eq!(
            attrs.get("upstream_ocsp_staple_present").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            attrs.get("upstream_ocsp_staple_status").map(String::as_str),
            Some("missing")
        );
        assert_eq!(
            attrs.get("revocation_policy_mode").map(String::as_str),
            Some("passive_observe")
        );
        assert_eq!(
            attrs.get("revocation_decision").map(String::as_str),
            Some("signal_missing_staple")
        );
    }

    #[test]
    fn upstream_invalid_staple_is_classified_deterministically() {
        let mut attrs = BTreeMap::new();
        insert_tls_revocation_metadata(
            &mut attrs,
            "upstream rejected malformed OCSP stapling parse error",
            "upstream",
        );

        assert_eq!(
            attrs.get("upstream_ocsp_staple_present").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            attrs.get("upstream_ocsp_staple_status").map(String::as_str),
            Some("invalid")
        );
        assert_eq!(
            attrs.get("revocation_decision").map(String::as_str),
            Some("signal_invalid_staple")
        );
    }

    #[test]
    fn downstream_failure_marks_revocation_not_applicable() {
        let mut attrs = BTreeMap::new();
        insert_tls_revocation_metadata(
            &mut attrs,
            "certificate verify failed: unknown ca",
            "downstream",
        );

        assert_eq!(
            attrs.get("upstream_ocsp_staple_present").map(String::as_str),
            Some("not_applicable")
        );
        assert_eq!(
            attrs.get("upstream_ocsp_staple_status").map(String::as_str),
            Some("not_applicable")
        );
        assert_eq!(
            attrs.get("revocation_decision").map(String::as_str),
            Some("not_applicable")
        );
    }
}
