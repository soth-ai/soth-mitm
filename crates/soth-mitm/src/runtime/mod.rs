use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use mitm_core::{MitmConfig as CoreMitmConfig, MitmEngine};
use mitm_policy::{FlowAction, PolicyDecision, PolicyEngine, PolicyInput, PolicyOverrideState};
use mitm_sidecar::{FlowHooks, SidecarConfig, SidecarServer};
use parking_lot::RwLock;

use crate::config::{InterceptionScope, MitmConfig};
use crate::destination::{canonical_destination_key, normalize_destination_key};
use crate::errors::MitmError;
use crate::handler::InterceptHandler;
use crate::metrics::{MetricsEventConsumer, ProxyMetricsStore};

mod connection_id;
mod connection_meta;
mod flow_dispatch;
mod flow_hooks;
mod flow_lifecycle;
mod handler_guard;

pub(crate) type RuntimeServer = SidecarServer<DestinationPolicyEngine, MetricsEventConsumer>;
pub(crate) struct RuntimeServerBundle {
    pub(crate) server: RuntimeServer,
    pub(crate) config_handle: RuntimeConfigHandle,
}

pub(crate) fn build_runtime_server<H: InterceptHandler>(
    config: &MitmConfig,
    handler: Arc<H>,
    metrics_store: Arc<ProxyMetricsStore>,
) -> Result<RuntimeServerBundle, MitmError> {
    config.validate()?;
    let config_handle = RuntimeConfigHandle::from_config(config)?;
    let policy = config_handle.policy_engine();
    let sink = MetricsEventConsumer::new(Arc::clone(&metrics_store));
    let core_config = map_core_config(config);
    let sidecar_config = SidecarConfig {
        listen_addr: core_config.listen_addr.clone(),
        listen_port: core_config.listen_port,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: core_config.max_http_head_bytes,
        idle_watchdog_timeout: Duration::from_millis(config.connection_pool.idle_timeout_ms.max(1)),
        upstream_connect_timeout: Duration::from_millis(config.upstream.connect_timeout_ms.max(1)),
        stream_stage_timeout: Duration::from_millis(config.upstream.timeout_ms.max(1)),
        unix_socket_path: config
            .unix_socket_path
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
    };

    let engine = MitmEngine::new_checked(core_config, policy, sink)
        .map_err(|error| MitmError::InvalidConfig(error.to_string()))?;
    let flow_hooks: Arc<dyn FlowHooks> =
        flow_hooks::build_handler_flow_hooks(config, handler, Arc::clone(&metrics_store));
    let server = SidecarServer::new_with_flow_hooks(sidecar_config, engine, flow_hooks)
        .map_err(MitmError::from)?;
    Ok(RuntimeServerBundle {
        server,
        config_handle,
    })
}

fn map_core_config(config: &MitmConfig) -> CoreMitmConfig {
    let mut core = CoreMitmConfig::default();
    core.listen_addr = config.bind.ip().to_string();
    core.listen_port = config.bind.port();
    core.ca_cert_pem_path = Some(config.tls.ca_cert_path.to_string_lossy().to_string());
    core.ca_key_pem_path = Some(config.tls.ca_key_path.to_string_lossy().to_string());
    core.http2_enabled = true;
    core.max_flow_body_buffer_bytes = config.body.max_size_bytes.max(1);
    core.max_flow_decoder_buffer_bytes = core
        .max_flow_decoder_buffer_bytes
        .min(core.max_flow_body_buffer_bytes);
    core.upstream_tls_insecure_skip_verify = !config.upstream.verify_upstream_tls;
    core
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeConfigHandle {
    snapshot: Arc<RwLock<RuntimeConfigSnapshot>>,
}

impl RuntimeConfigHandle {
    pub(crate) fn from_config(config: &MitmConfig) -> Result<Self, MitmError> {
        config.validate()?;
        let policy_state = DestinationPolicyState::from_scope(&config.interception)?;
        Ok(Self {
            snapshot: Arc::new(RwLock::new(RuntimeConfigSnapshot {
                policy_state,
                active_config: config.clone(),
            })),
        })
    }

    pub(crate) fn policy_engine(&self) -> DestinationPolicyEngine {
        DestinationPolicyEngine {
            snapshot: Arc::clone(&self.snapshot),
        }
    }

    pub(crate) fn apply_reload(&self, next_config: &MitmConfig) -> Result<(), MitmError> {
        next_config.validate()?;
        let next_policy_state = DestinationPolicyState::from_scope(&next_config.interception)?;
        let mut snapshot = self.snapshot.write();
        validate_reload_contract(&snapshot.active_config, next_config)?;
        snapshot.policy_state = next_policy_state;
        snapshot.active_config = next_config.clone();
        Ok(())
    }

    pub(crate) fn current_config(&self) -> MitmConfig {
        self.snapshot.read().active_config.clone()
    }
}

#[derive(Debug, Clone)]
struct RuntimeConfigSnapshot {
    policy_state: DestinationPolicyState,
    active_config: MitmConfig,
}

#[derive(Debug, Clone)]
struct DestinationPolicyState {
    destination_keys: HashSet<String>,
    passthrough_unlisted: bool,
}

impl DestinationPolicyState {
    fn from_scope(scope: &InterceptionScope) -> Result<Self, MitmError> {
        let mut destination_keys = HashSet::new();
        for destination in &scope.destinations {
            let key = normalize_destination_key(destination)?;
            destination_keys.insert(key);
        }
        Ok(Self {
            destination_keys,
            passthrough_unlisted: scope.passthrough_unlisted,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DestinationPolicyEngine {
    snapshot: Arc<RwLock<RuntimeConfigSnapshot>>,
}

impl DestinationPolicyEngine {
    #[cfg(test)]
    pub(crate) fn new(scope: &InterceptionScope) -> Result<Self, MitmError> {
        let policy_state = DestinationPolicyState::from_scope(scope)?;
        Ok(Self {
            snapshot: Arc::new(RwLock::new(RuntimeConfigSnapshot {
                policy_state,
                active_config: MitmConfig::default(),
            })),
        })
    }
}

impl PolicyEngine for DestinationPolicyEngine {
    fn decide(&self, input: &PolicyInput) -> PolicyDecision {
        let snapshot = self.snapshot.read();
        let state = &snapshot.policy_state;

        let key = canonical_destination_key(&input.server_host, input.server_port);
        if state.destination_keys.contains(&key) {
            return PolicyDecision {
                action: FlowAction::Intercept,
                reason: "interception_scope_match".to_string(),
                override_state: PolicyOverrideState::default(),
            };
        }

        if state.passthrough_unlisted {
            PolicyDecision {
                action: FlowAction::Tunnel,
                reason: "passthrough_unlisted".to_string(),
                override_state: PolicyOverrideState::default(),
            }
        } else {
            PolicyDecision {
                action: FlowAction::Block,
                reason: "destination_not_allowed".to_string(),
                override_state: PolicyOverrideState::default(),
            }
        }
    }
}

fn validate_reload_contract(current: &MitmConfig, next: &MitmConfig) -> Result<(), MitmError> {
    let mut allowed = current.clone();
    allowed.interception = next.interception.clone();
    if allowed == *next {
        return Ok(());
    }

    let mut changed_fields = Vec::new();
    if current.bind != next.bind {
        changed_fields.push("bind");
    }
    if current.unix_socket_path != next.unix_socket_path {
        changed_fields.push("unix_socket_path");
    }
    if current.process_attribution != next.process_attribution {
        changed_fields.push("process_attribution");
    }
    if current.tls != next.tls {
        changed_fields.push("tls");
    }
    if current.upstream != next.upstream {
        changed_fields.push("upstream");
    }
    if current.connection_pool != next.connection_pool {
        changed_fields.push("connection_pool");
    }
    if current.body != next.body {
        changed_fields.push("body");
    }
    if current.handler != next.handler {
        changed_fields.push("handler");
    }

    let detail = if changed_fields.is_empty() {
        "unknown non-interception delta".to_string()
    } else {
        changed_fields.join(", ")
    };
    Err(MitmError::InvalidConfig(format!(
        "reload only supports interception scope updates; changed fields: {detail}"
    )))
}

#[cfg(test)]
mod tests {
    use mitm_policy::{FlowAction, PolicyEngine, PolicyInput};

    use super::{map_core_config, DestinationPolicyEngine, RuntimeConfigHandle};
    use crate::config::{InterceptionScope, MitmConfig};

    fn policy(scope: InterceptionScope) -> DestinationPolicyEngine {
        DestinationPolicyEngine::new(&scope).expect("scope must build policy")
    }

    #[test]
    fn destination_scope_intercept_vs_passthrough() {
        let engine = policy(InterceptionScope {
            destinations: vec!["API.Example.COM:443".to_string()],
            passthrough_unlisted: true,
        });
        let intercept = engine.decide(&PolicyInput {
            server_host: "api.example.com".to_string(),
            server_port: 443,
            path: None,
            process_info: None,
        });
        assert_eq!(intercept.action, FlowAction::Intercept);
        assert_eq!(intercept.reason, "interception_scope_match");

        let passthrough = engine.decide(&PolicyInput {
            server_host: "other.example.com".to_string(),
            server_port: 443,
            path: None,
            process_info: None,
        });
        assert_eq!(passthrough.action, FlowAction::Tunnel);
        assert_eq!(passthrough.reason, "passthrough_unlisted");
    }

    #[test]
    fn passthrough_unlisted_false_rst() {
        let engine = policy(InterceptionScope {
            destinations: vec!["api.example.com:443".to_string()],
            passthrough_unlisted: false,
        });
        let decision = engine.decide(&PolicyInput {
            server_host: "other.example.com".to_string(),
            server_port: 443,
            path: None,
            process_info: None,
        });
        assert_eq!(decision.action, FlowAction::Block);
        assert_eq!(decision.reason, "destination_not_allowed");
    }

    #[test]
    fn config_reload_inflight_requests_contract() {
        let mut config = MitmConfig::default();
        config
            .interception
            .destinations
            .push("api.example.com:443".to_string());

        let runtime_config =
            RuntimeConfigHandle::from_config(&config).expect("initial config must be valid");
        let engine = runtime_config.policy_engine();

        let in_flight = engine.decide(&PolicyInput {
            server_host: "api.example.com".to_string(),
            server_port: 443,
            path: None,
            process_info: None,
        });
        assert_eq!(in_flight.action, FlowAction::Intercept);

        let mut reloaded = config.clone();
        reloaded.interception.destinations = vec!["other.example.com:443".to_string()];
        runtime_config
            .apply_reload(&reloaded)
            .expect("reload should apply");

        let applied_config = runtime_config.current_config();
        assert_eq!(
            applied_config.interception.destinations,
            vec!["other.example.com:443".to_string()]
        );

        assert_eq!(
            in_flight.action,
            FlowAction::Intercept,
            "in-flight decisions must keep the pre-reload policy result"
        );

        let old_destination_after_reload = engine.decide(&PolicyInput {
            server_host: "api.example.com".to_string(),
            server_port: 443,
            path: None,
            process_info: None,
        });
        assert_eq!(old_destination_after_reload.action, FlowAction::Tunnel);

        let new_destination_after_reload = engine.decide(&PolicyInput {
            server_host: "other.example.com".to_string(),
            server_port: 443,
            path: None,
            process_info: None,
        });
        assert_eq!(new_destination_after_reload.action, FlowAction::Intercept);
    }

    #[test]
    fn body_size_limit_maps_to_core_runtime_budget() {
        let mut config = MitmConfig::default();
        config.body.max_size_bytes = 32 * 1024;
        let core = map_core_config(&config);
        assert_eq!(core.max_flow_body_buffer_bytes, 32 * 1024);
    }

    #[test]
    fn decoder_budget_is_clamped_by_body_size_limit() {
        let mut config = MitmConfig::default();
        config.body.max_size_bytes = 256;
        let core = map_core_config(&config);
        assert_eq!(core.max_flow_body_buffer_bytes, 256);
        assert!(
            core.max_flow_decoder_buffer_bytes <= 256,
            "decoder budget must be bounded by body size limit"
        );
    }

    #[test]
    fn reload_rejects_non_hot_reloadable_field_changes() {
        let mut config = MitmConfig::default();
        config
            .interception
            .destinations
            .push("api.example.com:443".to_string());
        let runtime_config =
            RuntimeConfigHandle::from_config(&config).expect("initial config must be valid");

        let mut next = config.clone();
        next.upstream.timeout_ms += 1;
        let error = runtime_config
            .apply_reload(&next)
            .expect_err("non hot-reloadable field changes must fail reload");
        match error {
            crate::MitmError::InvalidConfig(message) => {
                assert!(message.contains("changed fields: upstream"));
            }
            other => panic!("expected invalid config error, got {other}"),
        }
    }

    #[test]
    fn runtime_config_handle_rejects_invalid_initial_config() {
        let config = MitmConfig::default();
        let error = RuntimeConfigHandle::from_config(&config)
            .expect_err("invalid config should be rejected at runtime handle creation");
        match error {
            crate::MitmError::InvalidConfig(message) => {
                assert!(message.contains("interception.destinations"));
            }
            other => panic!("expected invalid config error, got {other}"),
        }
    }
}
