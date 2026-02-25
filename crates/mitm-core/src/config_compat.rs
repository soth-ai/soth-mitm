#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct CompatibilityOverrideConfig {
    pub rule_id: String,
    pub host_pattern: String,
    pub force_tunnel: bool,
    pub disable_h2: bool,
    pub strict_header_mode: bool,
    pub skip_upstream_verify: bool,
}

impl CompatibilityOverrideConfig {
    fn is_noop(&self) -> bool {
        !(self.force_tunnel
            || self.disable_h2
            || self.strict_header_mode
            || self.skip_upstream_verify)
    }
}

fn validate_compatibility_overrides(
    overrides: &[CompatibilityOverrideConfig],
) -> Result<(), MitmConfigError> {
    for (index, override_rule) in overrides.iter().enumerate() {
        if override_rule.rule_id.trim().is_empty() {
            return Err(MitmConfigError::EmptyCompatibilityOverrideRuleId { index });
        }
        let host_pattern = override_rule.host_pattern.trim();
        if host_pattern.is_empty() {
            return Err(MitmConfigError::EmptyCompatibilityOverrideHostPattern { index });
        }
        let wildcard_ok = host_pattern.strip_prefix("*.");
        let host_pattern_valid = if let Some(suffix) = wildcard_ok {
            !suffix.is_empty() && !suffix.contains('*') && !suffix.contains(' ')
        } else {
            !host_pattern.contains('*') && !host_pattern.contains(' ')
        };
        if !host_pattern_valid {
            return Err(MitmConfigError::InvalidCompatibilityOverrideHostPattern { index });
        }
        if override_rule.is_noop() {
            return Err(MitmConfigError::NoopCompatibilityOverride { index });
        }
    }
    Ok(())
}

fn host_matches_pattern(server_host: &str, host_pattern: &str) -> bool {
    let host = server_host.trim().to_ascii_lowercase();
    let pattern = host_pattern.trim().to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == pattern
}
