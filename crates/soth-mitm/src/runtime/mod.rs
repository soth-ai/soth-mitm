use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use mitm_core::{InterceptMode as CoreInterceptMode, MitmConfig as CoreMitmConfig, MitmEngine};
use mitm_policy::{FlowAction, PolicyDecision, PolicyEngine, PolicyInput, PolicyOverrideState};
use mitm_sidecar::{
    FlowHooks, H2ResponseOverflowMode as SidecarH2ResponseOverflowMode, SidecarConfig,
    SidecarServer,
};
use parking_lot::RwLock;

use crate::config::{InterceptionScope, MitmConfig};
use crate::destination::{
    canonical_destination_key, parse_destination_rule, DestinationRule, WildcardDestinationRule,
};
use crate::errors::MitmError;
use crate::handler::InterceptHandler;
use crate::metrics::{MetricsEventConsumer, ProxyMetricsStore};

mod connection_id;
mod connection_meta;
mod flow_dispatch;
mod flow_hooks;
mod flow_lifecycle;
mod handler_guard;
mod tls_intercept_backoff;

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
    const MIN_IDLE_WATCHDOG_TIMEOUT_MS: u64 = 10 * 60 * 1000;
    config.validate()?;
    let config_handle = RuntimeConfigHandle::from_config(config)?;
    let policy = config_handle.policy_engine();
    let sink = MetricsEventConsumer::new(Arc::clone(&metrics_store));
    let core_config = map_core_config(config);
    // Keep tunnel/relay sessions resilient by clamping legacy low idle values.
    let idle_watchdog_timeout = Duration::from_millis(
        config
            .connection_pool
            .idle_timeout_ms
            .max(MIN_IDLE_WATCHDOG_TIMEOUT_MS),
    );
    let sidecar_config = SidecarConfig {
        listen_addr: core_config.listen_addr.clone(),
        listen_port: core_config.listen_port,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: core_config.max_http_head_bytes,
        accept_retry_backoff_ms: config.accept_retry_backoff_ms.max(1),
        idle_watchdog_timeout,
        websocket_idle_watchdog_timeout: idle_watchdog_timeout.max(Duration::from_secs(600)),
        upstream_connect_timeout: Duration::from_millis(config.upstream.connect_timeout_ms.max(1)),
        stream_stage_timeout: Duration::from_millis(
            config.upstream.h2_header_stage_timeout_ms.max(1),
        ),
        h2_body_idle_timeout: Duration::from_millis(config.upstream.h2_body_idle_timeout_ms.max(1)),
        h2_response_overflow_mode: match config.upstream.h2_response_overflow_mode {
            crate::config::H2ResponseOverflowMode::TruncateContinue => {
                SidecarH2ResponseOverflowMode::TruncateContinue
            }
            crate::config::H2ResponseOverflowMode::StrictFail => {
                SidecarH2ResponseOverflowMode::StrictFail
            }
        },
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
    core.max_http_head_bytes = config.max_http_head_bytes.max(1);
    core.http2_enabled = config.http2_enabled;
    core.http2_max_header_list_size = config.http2_max_header_list_size.max(1);
    core.http3_passthrough = config.http3_passthrough;
    core.max_flow_body_buffer_bytes = config.body.max_size_bytes.max(1);
    core.max_flow_decoder_buffer_bytes = (core.max_flow_body_buffer_bytes / 2).max(1);
    core.max_flow_event_backlog = config.max_flow_event_backlog.max(1);
    core.max_in_flight_bytes = config.max_in_flight_bytes.max(1);
    core.max_concurrent_flows = config.max_concurrent_flows.max(1);
    core.upstream_tls_insecure_skip_verify = !config.upstream.verify_upstream_tls;
    core.intercept_mode = match config.intercept_mode {
        crate::config::InterceptMode::Monitor => CoreInterceptMode::Monitor,
        crate::config::InterceptMode::Enforce => CoreInterceptMode::Enforce,
    };
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
    wildcard_rules: Vec<WildcardDestinationRule>,
    passthrough_unlisted: bool,
}

impl DestinationPolicyState {
    fn from_scope(scope: &InterceptionScope) -> Result<Self, MitmError> {
        let mut destination_keys = HashSet::new();
        let mut wildcard_rules = Vec::new();
        for destination in &scope.destinations {
            match parse_destination_rule(destination)? {
                DestinationRule::Exact { key } => {
                    destination_keys.insert(key);
                }
                DestinationRule::Wildcard(rule) => {
                    wildcard_rules.push(rule);
                }
            }
        }
        Ok(Self {
            destination_keys,
            wildcard_rules,
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
        if state
            .wildcard_rules
            .iter()
            .any(|rule| rule.matches_host_port(&input.server_host, input.server_port))
        {
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
    if current.http2_enabled != next.http2_enabled {
        changed_fields.push("http2_enabled");
    }
    if current.http2_max_header_list_size != next.http2_max_header_list_size {
        changed_fields.push("http2_max_header_list_size");
    }
    if current.http3_passthrough != next.http3_passthrough {
        changed_fields.push("http3_passthrough");
    }
    if current.max_http_head_bytes != next.max_http_head_bytes {
        changed_fields.push("max_http_head_bytes");
    }
    if current.accept_retry_backoff_ms != next.accept_retry_backoff_ms {
        changed_fields.push("accept_retry_backoff_ms");
    }
    if current.max_flow_event_backlog != next.max_flow_event_backlog {
        changed_fields.push("max_flow_event_backlog");
    }
    if current.max_in_flight_bytes != next.max_in_flight_bytes {
        changed_fields.push("max_in_flight_bytes");
    }
    if current.max_concurrent_flows != next.max_concurrent_flows {
        changed_fields.push("max_concurrent_flows");
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
    if current.flow_runtime != next.flow_runtime {
        changed_fields.push("flow_runtime");
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
mod tests;
