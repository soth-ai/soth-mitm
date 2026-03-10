/// Policy actions returned by the proxy decision engine.
///
/// Use `Tunnel` for metadata-only observation use cases:
/// lifecycle events are still emitted, but traffic is not decrypted/intercepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowAction {
    /// Intercept and decode protocol traffic when allowed by policy.
    Intercept,
    /// Pass traffic through CONNECT tunnel while still emitting lifecycle metadata events.
    Tunnel,
    /// Reject the flow and close early.
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub bundle_id: Option<String>,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyInput {
    pub server_host: String,
    pub server_port: u16,
    pub path: Option<String>,
    pub process_info: Option<ProcessInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub action: FlowAction,
    pub reason: String,
    pub override_state: PolicyOverrideState,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyOverrideState {
    pub applied: bool,
    pub rule_id: Option<String>,
    pub matched_host: Option<String>,
    pub force_tunnel: bool,
    pub disable_h2: bool,
    pub strict_header_mode: bool,
    pub skip_upstream_verify: bool,
}

pub trait PolicyEngine: Send + Sync {
    fn decide(&self, input: &PolicyInput) -> PolicyDecision;
}

#[derive(Debug, Clone, Default)]
pub struct DefaultPolicyEngine {
    ignored_hosts: Vec<String>,
    blocked_hosts: Vec<String>,
}

impl DefaultPolicyEngine {
    pub fn new(ignored_hosts: Vec<String>, blocked_hosts: Vec<String>) -> Self {
        Self {
            ignored_hosts,
            blocked_hosts,
        }
    }
}

impl PolicyEngine for DefaultPolicyEngine {
    fn decide(&self, input: &PolicyInput) -> PolicyDecision {
        if self
            .blocked_hosts
            .iter()
            .any(|host| host.eq_ignore_ascii_case(&input.server_host))
        {
            return PolicyDecision {
                action: FlowAction::Block,
                reason: "blocked_host".to_string(),
                override_state: PolicyOverrideState::default(),
            };
        }

        if self
            .ignored_hosts
            .iter()
            .any(|host| host.eq_ignore_ascii_case(&input.server_host))
        {
            return PolicyDecision {
                action: FlowAction::Tunnel,
                reason: "ignored_host".to_string(),
                override_state: PolicyOverrideState::default(),
            };
        }

        PolicyDecision {
            action: FlowAction::Intercept,
            reason: "default_intercept".to_string(),
            override_state: PolicyOverrideState::default(),
        }
    }
}
