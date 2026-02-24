#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    Direct,
    Reverse,
    UpstreamHttp,
    UpstreamSocks5,
}

impl RouteMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Reverse => "reverse",
            Self::UpstreamHttp => "upstream_http",
            Self::UpstreamSocks5 => "upstream_socks5",
        }
    }
}

impl Default for RouteMode {
    fn default() -> Self {
        Self::Direct
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteEndpointConfig {
    pub host: String,
    pub port: u16,
}

impl Default for RouteEndpointConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 0,
        }
    }
}

fn validate_route_endpoint(
    endpoint: Option<&RouteEndpointConfig>,
    field: &'static str,
) -> Result<(), MitmConfigError> {
    let Some(endpoint) = endpoint else {
        return Ok(());
    };
    if endpoint.host.trim().is_empty() {
        return Err(MitmConfigError::EmptyRouteEndpointHost { field });
    }
    if endpoint.port == 0 {
        return Err(MitmConfigError::ZeroRouteEndpointPort { field });
    }
    Ok(())
}

fn validate_route_mode_bindings(config: &MitmConfig) -> Result<(), MitmConfigError> {
    let mode = config.route_mode.as_str();
    match config.route_mode {
        RouteMode::Direct => {
            require_absent(config.reverse_upstream.as_ref(), mode, "reverse_upstream")?;
            require_absent(config.upstream_http_proxy.as_ref(), mode, "upstream_http_proxy")?;
            require_absent(
                config.upstream_socks5_proxy.as_ref(),
                mode,
                "upstream_socks5_proxy",
            )?;
        }
        RouteMode::Reverse => {
            require_present(config.reverse_upstream.as_ref(), mode, "reverse_upstream")?;
            require_absent(config.upstream_http_proxy.as_ref(), mode, "upstream_http_proxy")?;
            require_absent(
                config.upstream_socks5_proxy.as_ref(),
                mode,
                "upstream_socks5_proxy",
            )?;
        }
        RouteMode::UpstreamHttp => {
            require_absent(config.reverse_upstream.as_ref(), mode, "reverse_upstream")?;
            require_present(
                config.upstream_http_proxy.as_ref(),
                mode,
                "upstream_http_proxy",
            )?;
            require_absent(
                config.upstream_socks5_proxy.as_ref(),
                mode,
                "upstream_socks5_proxy",
            )?;
        }
        RouteMode::UpstreamSocks5 => {
            require_absent(config.reverse_upstream.as_ref(), mode, "reverse_upstream")?;
            require_absent(config.upstream_http_proxy.as_ref(), mode, "upstream_http_proxy")?;
            require_present(
                config.upstream_socks5_proxy.as_ref(),
                mode,
                "upstream_socks5_proxy",
            )?;
        }
    }
    Ok(())
}

fn require_present<T>(
    value: Option<&T>,
    route_mode: &'static str,
    field: &'static str,
) -> Result<(), MitmConfigError> {
    if value.is_some() {
        return Ok(());
    }
    Err(MitmConfigError::MissingRouteEndpoint { route_mode, field })
}

fn require_absent<T>(
    value: Option<&T>,
    route_mode: &'static str,
    field: &'static str,
) -> Result<(), MitmConfigError> {
    if value.is_none() {
        return Ok(());
    }
    Err(MitmConfigError::UnexpectedRouteEndpoint { route_mode, field })
}
