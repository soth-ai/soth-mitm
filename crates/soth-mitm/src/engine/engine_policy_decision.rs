impl<P, S> MitmEngine<P, S>
where
    P: PolicyEngine,
    S: EventConsumer,
{
    fn emit_connect_decision_event(&self, context: &FlowContext, decision: &PolicyDecision) {
        let mut event = Event::new(EventType::ConnectDecision, context.clone());
        let action = match decision.action {
            FlowAction::Intercept => "intercept",
            FlowAction::Tunnel => "tunnel",
            FlowAction::Block => "block",
        };
        event.attributes.insert("reason".to_string(), decision.reason.clone());
        event.attributes.insert("action".to_string(), action.to_string());
        if decision.override_state.applied {
            event.attributes.insert(
                "override_rule_id".to_string(),
                decision.override_state.rule_id.clone().unwrap_or_default(),
            );
            event.attributes.insert(
                "override_host_pattern".to_string(),
                decision
                    .override_state
                    .matched_host
                    .clone()
                    .unwrap_or_default(),
            );
            event.attributes.insert(
                "override_force_tunnel".to_string(),
                decision.override_state.force_tunnel.to_string(),
            );
            event.attributes.insert(
                "override_disable_h2".to_string(),
                decision.override_state.disable_h2.to_string(),
            );
            event.attributes.insert(
                "override_strict_header_mode".to_string(),
                decision.override_state.strict_header_mode.to_string(),
            );
            event.attributes.insert(
                "override_skip_upstream_verify".to_string(),
                decision.override_state.skip_upstream_verify.to_string(),
            );
        }
        self.emit_event(event);
    }
}
