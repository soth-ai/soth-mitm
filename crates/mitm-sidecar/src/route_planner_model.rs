const MAX_PROXY_HEAD_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamRequestTargetMode {
    OriginForm,
    AbsoluteForm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteTarget {
    host: String,
    port: u16,
    policy_path: Option<String>,
}

impl RouteTarget {
    fn new(host: String, port: u16, policy_path: Option<String>) -> Self {
        Self {
            host,
            port,
            policy_path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteBinding {
    mode: mitm_core::RouteMode,
    target_host: String,
    target_port: u16,
    policy_path: Option<String>,
    next_hop_host: String,
    next_hop_port: u16,
    request_target_mode: UpstreamRequestTargetMode,
}

impl RouteBinding {
    fn route_mode_label(&self) -> &'static str {
        match self.mode {
            mitm_core::RouteMode::Direct => "direct",
            mitm_core::RouteMode::Reverse => "reverse",
            mitm_core::RouteMode::UpstreamHttp => "upstream_http",
            mitm_core::RouteMode::UpstreamSocks5 => "upstream_socks5",
        }
    }

    fn same_target_as(&self, target: &RouteTarget) -> bool {
        self.target_host == target.host
            && self.target_port == target.port
            && self.policy_path == target.policy_path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteConnectIntent {
    TargetTunnel,
    ForwardHttpRequest,
}

#[derive(Debug, Default)]
struct FlowRoutePlanner {
    binding: Option<RouteBinding>,
}

impl FlowRoutePlanner {
    fn bind_once(
        &mut self,
        config: &mitm_core::MitmConfig,
        target: RouteTarget,
    ) -> io::Result<RouteBinding> {
        if let Some(existing) = self.binding.as_ref() {
            if existing.same_target_as(&target) {
                return Ok(existing.clone());
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "flow route binding is immutable: existing={} target={}:{} attempted={}:{}",
                    existing.route_mode_label(),
                    existing.target_host,
                    existing.target_port,
                    target.host,
                    target.port
                ),
            ));
        }

        let binding = plan_route(config, target)?;
        self.binding = Some(binding.clone());
        Ok(binding)
    }
}

fn plan_route(config: &mitm_core::MitmConfig, target: RouteTarget) -> io::Result<RouteBinding> {
    match config.route_mode {
        mitm_core::RouteMode::Direct => Ok(RouteBinding {
            mode: config.route_mode,
            target_host: target.host.clone(),
            target_port: target.port,
            policy_path: target.policy_path,
            next_hop_host: target.host,
            next_hop_port: target.port,
            request_target_mode: UpstreamRequestTargetMode::OriginForm,
        }),
        mitm_core::RouteMode::Reverse => {
            let reverse = config.reverse_upstream.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "route_mode=reverse missing reverse_upstream",
                )
            })?;
            Ok(RouteBinding {
                mode: config.route_mode,
                target_host: target.host,
                target_port: target.port,
                policy_path: target.policy_path,
                next_hop_host: reverse.host.clone(),
                next_hop_port: reverse.port,
                request_target_mode: UpstreamRequestTargetMode::OriginForm,
            })
        }
        mitm_core::RouteMode::UpstreamHttp => {
            let proxy = config.upstream_http_proxy.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "route_mode=upstream_http missing upstream_http_proxy",
                )
            })?;
            Ok(RouteBinding {
                mode: config.route_mode,
                target_host: target.host,
                target_port: target.port,
                policy_path: target.policy_path,
                next_hop_host: proxy.host.clone(),
                next_hop_port: proxy.port,
                request_target_mode: UpstreamRequestTargetMode::AbsoluteForm,
            })
        }
        mitm_core::RouteMode::UpstreamSocks5 => {
            let proxy = config.upstream_socks5_proxy.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "route_mode=upstream_socks5 missing upstream_socks5_proxy",
                )
            })?;
            Ok(RouteBinding {
                mode: config.route_mode,
                target_host: target.host,
                target_port: target.port,
                policy_path: target.policy_path,
                next_hop_host: proxy.host.clone(),
                next_hop_port: proxy.port,
                request_target_mode: UpstreamRequestTargetMode::OriginForm,
            })
        }
    }
}

#[cfg(test)]
mod route_planner_tests {
    use super::{plan_route, FlowRoutePlanner, RouteTarget, UpstreamRequestTargetMode};

    #[test]
    fn route_planner_direct_mode_binds_target_as_next_hop() {
        let config = mitm_core::MitmConfig::default();
        let route = plan_route(
            &config,
            RouteTarget::new("api.example.com".to_string(), 443, None),
        )
        .expect("plan route");
        assert_eq!(route.next_hop_host, "api.example.com");
        assert_eq!(route.next_hop_port, 443);
        assert_eq!(route.request_target_mode, UpstreamRequestTargetMode::OriginForm);
    }

    #[test]
    fn route_planner_reverse_mode_uses_reverse_endpoint() {
        let config = mitm_core::MitmConfig {
            route_mode: mitm_core::RouteMode::Reverse,
            reverse_upstream: Some(mitm_core::RouteEndpointConfig {
                host: "reverse.local".to_string(),
                port: 9443,
            }),
            ..mitm_core::MitmConfig::default()
        };
        let route = plan_route(
            &config,
            RouteTarget::new("api.example.com".to_string(), 443, None),
        )
        .expect("plan route");
        assert_eq!(route.next_hop_host, "reverse.local");
        assert_eq!(route.next_hop_port, 9443);
        assert_eq!(route.request_target_mode, UpstreamRequestTargetMode::OriginForm);
    }

    #[test]
    fn route_planner_upstream_http_mode_keeps_absolute_form() {
        let config = mitm_core::MitmConfig {
            route_mode: mitm_core::RouteMode::UpstreamHttp,
            upstream_http_proxy: Some(mitm_core::RouteEndpointConfig {
                host: "proxy.local".to_string(),
                port: 3128,
            }),
            ..mitm_core::MitmConfig::default()
        };
        let route = plan_route(
            &config,
            RouteTarget::new("api.example.com".to_string(), 80, Some("/v1".to_string())),
        )
        .expect("plan route");
        assert_eq!(route.next_hop_host, "proxy.local");
        assert_eq!(route.next_hop_port, 3128);
        assert_eq!(
            route.request_target_mode,
            UpstreamRequestTargetMode::AbsoluteForm
        );
    }

    #[test]
    fn route_planner_upstream_socks5_mode_uses_proxy_endpoint() {
        let config = mitm_core::MitmConfig {
            route_mode: mitm_core::RouteMode::UpstreamSocks5,
            upstream_socks5_proxy: Some(mitm_core::RouteEndpointConfig {
                host: "socks.local".to_string(),
                port: 1080,
            }),
            ..mitm_core::MitmConfig::default()
        };
        let route = plan_route(
            &config,
            RouteTarget::new("api.example.com".to_string(), 443, None),
        )
        .expect("plan route");
        assert_eq!(route.next_hop_host, "socks.local");
        assert_eq!(route.next_hop_port, 1080);
        assert_eq!(route.request_target_mode, UpstreamRequestTargetMode::OriginForm);
    }

    #[test]
    fn flow_route_binding_is_immutable_after_first_target() {
        let config = mitm_core::MitmConfig::default();
        let mut planner = FlowRoutePlanner::default();
        let first = planner
            .bind_once(
                &config,
                RouteTarget::new("first.example.com".to_string(), 443, None),
            )
            .expect("first route bind");
        assert_eq!(first.next_hop_host, "first.example.com");

        let err = planner
            .bind_once(
                &config,
                RouteTarget::new("second.example.com".to_string(), 443, None),
            )
            .expect_err("rebinding with different target should fail");
        assert!(
            err.to_string().contains("flow route binding is immutable"),
            "unexpected error: {err}"
        );
    }
}
