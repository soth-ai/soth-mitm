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
fn destination_scope_wildcard_intercept_for_runtime_like_hosts() {
    let engine = policy(InterceptionScope {
        destinations: vec!["runtime-gateway*.example.net:443".to_string()],
        passthrough_unlisted: true,
    });
    let intercept = engine.decide(&PolicyInput {
        server_host: "runtime-gateway.us-east-1.example.net".to_string(),
        server_port: 443,
        path: None,
        process_info: None,
    });
    assert_eq!(intercept.action, FlowAction::Intercept);
    assert_eq!(intercept.reason, "interception_scope_match");
}

#[test]
fn destination_scope_wildcard_match_requires_same_port() {
    let engine = policy(InterceptionScope {
        destinations: vec!["gateway*.example.net:443".to_string()],
        passthrough_unlisted: false,
    });
    let blocked = engine.decide(&PolicyInput {
        server_host: "gateway.us-east-1.example.net".to_string(),
        server_port: 8443,
        path: None,
        process_info: None,
    });
    assert_eq!(blocked.action, FlowAction::Block);
    assert_eq!(blocked.reason, "destination_not_allowed");
}

#[test]
fn destination_scope_exact_and_wildcard_both_intercept() {
    let engine = policy(InterceptionScope {
        destinations: vec![
            "gateway*.example.net:443".to_string(),
            "gateway.us-east-1.example.net:443".to_string(),
        ],
        passthrough_unlisted: false,
    });
    let decision = engine.decide(&PolicyInput {
        server_host: "gateway.us-east-1.example.net".to_string(),
        server_port: 443,
        path: None,
        process_info: None,
    });
    assert_eq!(decision.action, FlowAction::Intercept);
    assert_eq!(decision.reason, "interception_scope_match");
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
    assert_eq!(
        core.max_flow_decoder_buffer_bytes,
        16 * 1024,
        "decoder budget should default to half of body budget"
    );
}

#[test]
fn decoder_budget_is_clamped_by_body_size_limit() {
    let mut config = MitmConfig::default();
    config.body.max_size_bytes = 256;
    let core = map_core_config(&config);
    assert_eq!(core.max_flow_body_buffer_bytes, 256);
    assert_eq!(core.max_flow_decoder_buffer_bytes, 128);
}

#[test]
fn core_runtime_tuning_maps_from_config() {
    let mut config = MitmConfig::default();
    config.http2_enabled = false;
    config.http2_max_header_list_size = 32 * 1024;
    config.http3_passthrough = false;
    config.max_http_head_bytes = 96 * 1024;
    config.max_flow_event_backlog = 16 * 1024;
    config.max_in_flight_bytes = 128 * 1024 * 1024;
    config.max_concurrent_flows = 4_096;
    let core = map_core_config(&config);
    assert!(!core.http2_enabled);
    assert_eq!(core.http2_max_header_list_size, 32 * 1024);
    assert!(!core.http3_passthrough);
    assert_eq!(core.max_http_head_bytes, 96 * 1024);
    assert_eq!(core.max_flow_event_backlog, 16 * 1024);
    assert_eq!(core.max_in_flight_bytes, 128 * 1024 * 1024);
    assert_eq!(core.max_concurrent_flows, 4_096);
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
