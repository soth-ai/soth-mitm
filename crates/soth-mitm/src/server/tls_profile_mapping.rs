fn map_upstream_tls_profile(profile: CoreTlsProfile) -> TlsUpstreamTlsProfile {
    match profile {
        CoreTlsProfile::Strict => TlsUpstreamTlsProfile::Strict,
        CoreTlsProfile::Default => TlsUpstreamTlsProfile::Default,
        CoreTlsProfile::Compat => TlsUpstreamTlsProfile::Compat,
    }
}

fn resolve_effective_upstream_tls_profile(
    profile: CoreTlsProfile,
    fingerprint_mode: CoreTlsFingerprintMode,
    fingerprint_class: CoreTlsFingerprintClass,
) -> TlsUpstreamTlsProfile {
    match (fingerprint_mode, fingerprint_class) {
        (CoreTlsFingerprintMode::Native, _) => map_upstream_tls_profile(profile),
        (CoreTlsFingerprintMode::CompatClass, CoreTlsFingerprintClass::ChromeLike) => {
            match profile {
                CoreTlsProfile::Strict => TlsUpstreamTlsProfile::Strict,
                CoreTlsProfile::Default | CoreTlsProfile::Compat => TlsUpstreamTlsProfile::Default,
            }
        }
        (CoreTlsFingerprintMode::CompatClass, CoreTlsFingerprintClass::FirefoxLike) => {
            match profile {
                CoreTlsProfile::Strict => TlsUpstreamTlsProfile::Strict,
                CoreTlsProfile::Default | CoreTlsProfile::Compat => TlsUpstreamTlsProfile::Compat,
            }
        }
        (CoreTlsFingerprintMode::CompatClass, CoreTlsFingerprintClass::Native) => {
            map_upstream_tls_profile(profile)
        }
    }
}

fn map_upstream_sni_mode(mode: CoreUpstreamSniMode) -> TlsUpstreamTlsSniMode {
    match mode {
        CoreUpstreamSniMode::Required => TlsUpstreamTlsSniMode::Required,
        CoreUpstreamSniMode::Auto => TlsUpstreamTlsSniMode::Auto,
        CoreUpstreamSniMode::Disabled => TlsUpstreamTlsSniMode::Disabled,
    }
}

fn map_upstream_client_auth_mode(mode: CoreUpstreamClientAuthMode) -> TlsUpstreamClientAuthMode {
    match mode {
        CoreUpstreamClientAuthMode::Never => TlsUpstreamClientAuthMode::Never,
        CoreUpstreamClientAuthMode::IfRequested => TlsUpstreamClientAuthMode::IfRequested,
        CoreUpstreamClientAuthMode::Required => TlsUpstreamClientAuthMode::Required,
    }
}

fn map_downstream_cert_profile(profile: CoreDownstreamCertProfile) -> TlsDownstreamCertProfile {
    match profile {
        CoreDownstreamCertProfile::Modern => TlsDownstreamCertProfile::Modern,
        CoreDownstreamCertProfile::Compat => TlsDownstreamCertProfile::Compat,
    }
}

fn insert_tls_fingerprint_provenance(
    attributes: &mut std::collections::BTreeMap<String, String>,
    fingerprint_mode: CoreTlsFingerprintMode,
    fingerprint_class: CoreTlsFingerprintClass,
) {
    attributes.insert(
        "tls_fingerprint_mode".to_string(),
        fingerprint_mode.as_str().to_string(),
    );
    attributes.insert(
        "tls_fingerprint_class".to_string(),
        fingerprint_class.as_str().to_string(),
    );
}

#[cfg(test)]
mod tls_fingerprint_profile_tests {
    use super::resolve_effective_upstream_tls_profile;
    use super::{
        CoreTlsFingerprintClass, CoreTlsFingerprintMode, CoreTlsProfile, TlsUpstreamTlsProfile,
    };

    #[test]
    fn compat_class_preserves_strict_profile() {
        assert_eq!(
            resolve_effective_upstream_tls_profile(
                CoreTlsProfile::Strict,
                CoreTlsFingerprintMode::CompatClass,
                CoreTlsFingerprintClass::ChromeLike,
            ),
            TlsUpstreamTlsProfile::Strict
        );
        assert_eq!(
            resolve_effective_upstream_tls_profile(
                CoreTlsProfile::Strict,
                CoreTlsFingerprintMode::CompatClass,
                CoreTlsFingerprintClass::FirefoxLike,
            ),
            TlsUpstreamTlsProfile::Strict
        );
    }

    #[test]
    fn chrome_like_prefers_default_profile_for_non_strict() {
        assert_eq!(
            resolve_effective_upstream_tls_profile(
                CoreTlsProfile::Default,
                CoreTlsFingerprintMode::CompatClass,
                CoreTlsFingerprintClass::ChromeLike,
            ),
            TlsUpstreamTlsProfile::Default
        );
        assert_eq!(
            resolve_effective_upstream_tls_profile(
                CoreTlsProfile::Compat,
                CoreTlsFingerprintMode::CompatClass,
                CoreTlsFingerprintClass::ChromeLike,
            ),
            TlsUpstreamTlsProfile::Default
        );
    }

    #[test]
    fn firefox_like_prefers_compat_profile_for_non_strict() {
        assert_eq!(
            resolve_effective_upstream_tls_profile(
                CoreTlsProfile::Default,
                CoreTlsFingerprintMode::CompatClass,
                CoreTlsFingerprintClass::FirefoxLike,
            ),
            TlsUpstreamTlsProfile::Compat
        );
        assert_eq!(
            resolve_effective_upstream_tls_profile(
                CoreTlsProfile::Compat,
                CoreTlsFingerprintMode::CompatClass,
                CoreTlsFingerprintClass::FirefoxLike,
            ),
            TlsUpstreamTlsProfile::Compat
        );
    }
}
