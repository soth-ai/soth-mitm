use dashmap::DashMap;

#[derive(Debug, Clone)]
struct FlowPolicySnapshot {
    flow_id: u64,
    action: FlowAction,
    reason: String,
    override_state: mitm_policy::PolicyOverrideState,
}

static FLOW_POLICY_SNAPSHOTS: std::sync::OnceLock<DashMap<u64, FlowPolicySnapshot>> =
    std::sync::OnceLock::new();

fn flow_policy_snapshots() -> &'static DashMap<u64, FlowPolicySnapshot> {
    FLOW_POLICY_SNAPSHOTS.get_or_init(DashMap::new)
}

fn resolve_flow_policy_snapshot<P, S>(
    engine: &MitmEngine<P, S>,
    flow_id: u64,
    client_addr: String,
    server_host: String,
    server_port: u16,
    path: Option<String>,
    process_info: Option<mitm_policy::ProcessInfo>,
) -> FlowPolicySnapshot
where
    P: PolicyEngine + Send + Sync + 'static,
    S: EventConsumer + Send + Sync + 'static,
{
    if let Some(snapshot) = flow_policy_snapshots().get(&flow_id) {
        return snapshot.clone();
    }
    let outcome = engine.decide_connect(
        flow_id,
        client_addr,
        server_host,
        server_port,
        path,
        process_info,
    );
    let snapshot = FlowPolicySnapshot {
        flow_id: outcome.flow_id,
        action: outcome.action,
        reason: outcome.reason,
        override_state: outcome.override_state,
    };
    flow_policy_snapshots().insert(flow_id, snapshot.clone());
    snapshot
}

fn clear_flow_policy_snapshot(flow_id: u64) {
    let _ = flow_policy_snapshots().remove(&flow_id);
}
