fn map_upstream_tls_profile(profile: CoreTlsProfile) -> TlsUpstreamTlsProfile {
    match profile {
        CoreTlsProfile::Strict => TlsUpstreamTlsProfile::Strict,
        CoreTlsProfile::Default => TlsUpstreamTlsProfile::Default,
        CoreTlsProfile::Compat => TlsUpstreamTlsProfile::Compat,
    }
}

fn map_upstream_sni_mode(mode: CoreUpstreamSniMode) -> TlsUpstreamTlsSniMode {
    match mode {
        CoreUpstreamSniMode::Required => TlsUpstreamTlsSniMode::Required,
        CoreUpstreamSniMode::Auto => TlsUpstreamTlsSniMode::Auto,
        CoreUpstreamSniMode::Disabled => TlsUpstreamTlsSniMode::Disabled,
    }
}

fn map_downstream_cert_profile(profile: CoreDownstreamCertProfile) -> TlsDownstreamCertProfile {
    match profile {
        CoreDownstreamCertProfile::Modern => TlsDownstreamCertProfile::Modern,
        CoreDownstreamCertProfile::Compat => TlsDownstreamCertProfile::Compat,
    }
}
