use crate::errors::MitmError;

pub(crate) fn normalize_destination_key(destination: &str) -> Result<String, MitmError> {
    let trimmed = destination.trim();
    if trimmed.is_empty() {
        return Err(MitmError::InvalidConfig(
            "interception destination must not be empty".to_string(),
        ));
    }

    let (host, port) = parse_host_port(trimmed)?;
    Ok(canonical_destination_key(&host, port))
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

#[cfg(test)]
mod tests {
    use super::{canonical_destination_key, normalize_destination_key};

    #[test]
    fn normalizes_host_and_port_with_case_fold() {
        let key =
            normalize_destination_key("  API.Example.com:443 ").expect("destination must parse");
        assert_eq!(key, canonical_destination_key("api.example.com", 443));
    }

    #[test]
    fn normalizes_bracketed_ipv6_destination() {
        let key = normalize_destination_key("[2001:db8::1]:8443").expect("destination must parse");
        assert_eq!(key, "2001:db8::1:8443");
    }

    #[test]
    fn rejects_unbracketed_ipv6_destination() {
        let error = normalize_destination_key("2001:db8::1:8443")
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
        let error = normalize_destination_key("api.example.com:0")
            .expect_err("zero port should be rejected");
        assert!(
            error.to_string().contains("port must be greater than zero"),
            "{error}"
        );
    }
}
