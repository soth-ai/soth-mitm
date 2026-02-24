use bytes::Bytes;
use http::HeaderMap;

use crate::actions::HandlerAction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpstreamTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActionExecutionPlan {
    Forward {
        target: UpstreamTarget,
        body: Bytes,
    },
    Block {
        status: u16,
        headers: HeaderMap,
        body: Bytes,
    },
}

impl ActionExecutionPlan {
    pub(crate) fn allows_upstream_connect(&self) -> bool {
        matches!(self, Self::Forward { .. })
    }
}

pub(crate) fn apply_handler_action(
    action: &HandlerAction,
    original_target: &UpstreamTarget,
    original_body: &Bytes,
) -> ActionExecutionPlan {
    match action {
        HandlerAction::Forward => ActionExecutionPlan::Forward {
            target: original_target.clone(),
            body: original_body.clone(),
        },
        HandlerAction::ForwardModified { body } => ActionExecutionPlan::Forward {
            target: original_target.clone(),
            body: body.clone(),
        },
        HandlerAction::Block {
            status,
            headers,
            body,
        } => ActionExecutionPlan::Block {
            status: *status,
            headers: headers.clone(),
            body: body.clone(),
        },
        HandlerAction::Reroute {
            host,
            port,
            path_override,
        } => ActionExecutionPlan::Forward {
            target: UpstreamTarget {
                host: host.clone(),
                port: *port,
                path: path_override
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| original_target.path.clone()),
            },
            body: original_body.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::HeaderMap;

    use super::{apply_handler_action, ActionExecutionPlan, UpstreamTarget};
    use crate::actions::HandlerAction;

    #[test]
    fn forward_modified_does_not_mutate_original_body() {
        let original_target = UpstreamTarget {
            host: "api.example.com".to_string(),
            port: 443,
            path: "/v1/records".to_string(),
        };
        let original_body = Bytes::from_static(b"{\"kind\":\"baseline\"}");
        let action = HandlerAction::ForwardModified {
            body: Bytes::from_static(b"{\"kind\":\"override\"}"),
        };

        let plan = apply_handler_action(&action, &original_target, &original_body);
        let ActionExecutionPlan::Forward { body, .. } = plan else {
            panic!("expected forward plan");
        };
        assert_eq!(body, Bytes::from_static(b"{\"kind\":\"override\"}"));
        assert_eq!(
            original_body,
            Bytes::from_static(b"{\"kind\":\"baseline\"}")
        );
    }

    #[test]
    fn block_prevents_any_upstream_connect() {
        let original_target = UpstreamTarget {
            host: "api.example.com".to_string(),
            port: 443,
            path: "/v1/records".to_string(),
        };
        let original_body = Bytes::from_static(b"{\"kind\":\"baseline\"}");
        let action = HandlerAction::Block {
            status: 451,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"blocked"),
        };

        let plan = apply_handler_action(&action, &original_target, &original_body);
        assert!(!plan.allows_upstream_connect());
        let ActionExecutionPlan::Block { status, .. } = plan else {
            panic!("expected block plan");
        };
        assert_eq!(status, 451);
    }

    #[test]
    fn reroute_target_override_contract() {
        let original_target = UpstreamTarget {
            host: "api.example.com".to_string(),
            port: 443,
            path: "/v1/records".to_string(),
        };
        let original_body = Bytes::from_static(b"{\"kind\":\"baseline\"}");
        let action = HandlerAction::Reroute {
            host: "shadow.example.net".to_string(),
            port: 8443,
            path_override: Some("/debug".to_string()),
        };

        let plan = apply_handler_action(&action, &original_target, &original_body);
        let ActionExecutionPlan::Forward { target, body } = plan else {
            panic!("expected forward plan for reroute");
        };
        assert_eq!(target.host, "shadow.example.net");
        assert_eq!(target.port, 8443);
        assert_eq!(target.path, "/debug");
        assert_eq!(body, original_body);
    }
}
