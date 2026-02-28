use crate::errors::MitmError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DestinationRule {
    Exact { key: String },
    Wildcard(WildcardDestinationRule),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WildcardDestinationRule {
    host_pattern: String,
    port: u16,
}

impl WildcardDestinationRule {
    pub(crate) fn matches_host_port(&self, host: &str, port: u16) -> bool {
        if self.port != port {
            return false;
        }
        wildcard_host_matches(&self.host_pattern, &host.to_ascii_lowercase())
    }
}

pub(crate) fn parse_destination_rule(destination: &str) -> Result<DestinationRule, MitmError> {
    let trimmed = destination.trim();
    if trimmed.is_empty() {
        return Err(MitmError::InvalidConfig(
            "interception destination must not be empty".to_string(),
        ));
    }

    let (host, port) = parse_host_port(trimmed)?;
    let host = host.to_ascii_lowercase();

    if host.contains('*') {
        if host.contains(':') {
            return Err(MitmError::InvalidConfig(format!(
                "wildcard interception destinations do not support IPv6 literals: '{destination}'"
            )));
        }
        return Ok(DestinationRule::Wildcard(WildcardDestinationRule {
            host_pattern: host,
            port,
        }));
    }

    Ok(DestinationRule::Exact {
        key: canonical_destination_key(&host, port),
    })
}

pub(crate) fn canonical_destination_key(host: &str, port: u16) -> String {
    format!("{}:{}", host.to_ascii_lowercase(), port)
}

fn parse_host_port(destination: &str) -> Result<(String, u16), MitmError> {
    if let Some(rest) = destination.strip_prefix('[') {
        let Some(closing_bracket) = rest.find(']') else {
            return Err(MitmError::InvalidConfig(format!(
                "invalid IPv6 destination format: '{destination}'"
            )));
        };

        let host = &rest[..closing_bracket];
        let suffix = &rest[closing_bracket + 1..];
        if host.is_empty() {
            return Err(MitmError::InvalidConfig(format!(
                "destination host must not be empty: '{destination}'"
            )));
        }
        let Some(port_raw) = suffix.strip_prefix(':') else {
            return Err(MitmError::InvalidConfig(format!(
                "destination must include ':port': '{destination}'"
            )));
        };
        let port = parse_port(port_raw, destination)?;
        return Ok((host.to_string(), port));
    }

    let Some((host, port_raw)) = destination.rsplit_once(':') else {
        return Err(MitmError::InvalidConfig(format!(
            "interception destination must be host:port, got '{destination}'"
        )));
    };
    if host.is_empty() {
        return Err(MitmError::InvalidConfig(format!(
            "destination host must not be empty: '{destination}'"
        )));
    }
    if host.contains(':') {
        return Err(MitmError::InvalidConfig(format!(
            "IPv6 destinations must use bracket form [::1]:443, got '{destination}'"
        )));
    }
    let port = parse_port(port_raw, destination)?;
    Ok((host.to_string(), port))
}

fn parse_port(raw: &str, destination: &str) -> Result<u16, MitmError> {
    let port = raw.parse::<u16>().map_err(|error| {
        MitmError::InvalidConfig(format!(
            "invalid interception destination port in '{destination}': {error}"
        ))
    })?;
    if port == 0 {
        return Err(MitmError::InvalidConfig(format!(
            "destination port must be greater than zero: '{destination}'"
        )));
    }
    Ok(port)
}

fn wildcard_host_matches(pattern: &str, host: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == host;
    }

    let pattern = pattern.as_bytes();
    let host = host.as_bytes();
    let mut pattern_index = 0usize;
    let mut host_index = 0usize;
    let mut star_index: Option<usize> = None;
    let mut backtrack_host_index = 0usize;

    while host_index < host.len() {
        if pattern_index < pattern.len() && pattern[pattern_index] == host[host_index] {
            pattern_index += 1;
            host_index += 1;
            continue;
        }

        if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            backtrack_host_index = host_index;
            continue;
        }

        if let Some(star) = star_index {
            pattern_index = star + 1;
            backtrack_host_index += 1;
            host_index = backtrack_host_index;
            continue;
        }

        return false;
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::{canonical_destination_key, parse_destination_rule, DestinationRule};

    fn exact_key(destination: &str) -> String {
        let rule = parse_destination_rule(destination).expect("destination must parse");
        let DestinationRule::Exact { key } = rule else {
            panic!("expected exact destination rule");
        };
        key
    }

    #[test]
    fn normalizes_host_and_port_with_case_fold() {
        let key = exact_key("  API.Example.com:443 ");
        assert_eq!(key, canonical_destination_key("api.example.com", 443));
    }

    #[test]
    fn normalizes_bracketed_ipv6_destination() {
        let key = exact_key("[2001:db8::1]:8443");
        assert_eq!(key, "2001:db8::1:8443");
    }

    #[test]
    fn rejects_unbracketed_ipv6_destination() {
        let error = parse_destination_rule("2001:db8::1:8443")
            .expect_err("unbracketed IPv6 should be rejected");
        assert!(
            error
                .to_string()
                .contains("IPv6 destinations must use bracket form"),
            "{error}"
        );
    }

    #[test]
    fn rejects_zero_port() {
        let error =
            parse_destination_rule("api.example.com:0").expect_err("zero port should be rejected");
        assert!(
            error.to_string().contains("port must be greater than zero"),
            "{error}"
        );
    }

    #[test]
    fn parses_wildcard_destination_rule() {
        let rule = parse_destination_rule("runtime-gateway*.example.net:443")
            .expect("wildcard rule must parse");
        assert_eq!(
            rule,
            DestinationRule::Wildcard(super::WildcardDestinationRule {
                host_pattern: "runtime-gateway*.example.net".to_string(),
                port: 443,
            })
        );
    }

    #[test]
    fn wildcard_rule_matches_host_and_port() {
        let rule =
            parse_destination_rule("gateway*.example.net:443").expect("wildcard rule must parse");
        let DestinationRule::Wildcard(rule) = rule else {
            panic!("expected wildcard rule");
        };
        assert!(rule.matches_host_port("gateway.us-east-1.example.net", 443));
        assert!(!rule.matches_host_port("gateway.us-east-1.example.net", 8443));
        assert!(!rule.matches_host_port("api.example.com", 443));
    }

    #[test]
    fn wildcard_rule_is_case_insensitive() {
        let rule = parse_destination_rule("AB.CLIENT*.com:443").expect("wildcard rule must parse");
        let DestinationRule::Wildcard(rule) = rule else {
            panic!("expected wildcard rule");
        };
        assert!(rule.matches_host_port("ab.client.com", 443));
    }
}
