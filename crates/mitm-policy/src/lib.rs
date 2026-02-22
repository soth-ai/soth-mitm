#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowAction {
    Intercept,
    Tunnel,
    Block,
    MetadataOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyInput {
    pub server_host: String,
    pub server_port: u16,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub action: FlowAction,
    pub reason: String,
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
            };
        }

        PolicyDecision {
            action: FlowAction::Intercept,
            reason: "default_intercept".to_string(),
        }
    }
}
