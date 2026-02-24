use mitm_tls::{classify_tls_error, TlsFailureReason};
use proptest::prelude::*;

fn text_strategy() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[A-Za-z0-9 _:/.-]{0,128}").expect("text regex")
}

proptest! {
    #[test]
    fn classifier_is_deterministic_for_same_input(detail in text_strategy()) {
        let first = classify_tls_error(&detail);
        let second = classify_tls_error(&detail);
        prop_assert_eq!(first, second);
        prop_assert!(!first.code().is_empty());
    }

    #[test]
    fn unknown_ca_keywords_map_to_unknown_ca(
        prefix in text_strategy(),
        suffix in text_strategy(),
        keyword in prop::sample::select(vec![
            "unknown ca",
            "unknown issuer",
            "self signed",
            "unable to get local issuer certificate",
        ]),
    ) {
        let detail = format!("{prefix} {keyword} {suffix}");
        let classified = classify_tls_error(&detail);
        prop_assert_eq!(classified, TlsFailureReason::UnknownCa);
    }

    #[test]
    fn timeout_keywords_map_to_timeout(
        prefix in text_strategy(),
        suffix in text_strategy(),
        keyword in prop::sample::select(vec![
            "timed out",
            "timeout",
            "operation timed out",
            "deadline has elapsed",
        ]),
    ) {
        let detail = format!("{prefix} {keyword} {suffix}");
        let classified = classify_tls_error(&detail);
        prop_assert_eq!(classified, TlsFailureReason::Timeout);
    }
}
