use dashmap::DashMap;

#[derive(Debug, Clone)]
struct FlowPolicySnapshot {
    flow_id: u64,
    action: FlowAction,
    reason: String,
    override_state: mitm_policy::PolicyOverrideState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowPolicySnapshotKey {
    engine_instance_id: u64,
    flow_id: u64,
}

static FLOW_POLICY_SNAPSHOTS: std::sync::OnceLock<DashMap<FlowPolicySnapshotKey, FlowPolicySnapshot>> =
    std::sync::OnceLock::new();

fn flow_policy_snapshots() -> &'static DashMap<FlowPolicySnapshotKey, FlowPolicySnapshot> {
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
    let snapshot_key = FlowPolicySnapshotKey {
        engine_instance_id: engine.instance_id(),
        flow_id,
    };
    if let Some(snapshot) = flow_policy_snapshots().get(&snapshot_key) {
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
    flow_policy_snapshots().insert(snapshot_key, snapshot.clone());
    snapshot
}

fn clear_flow_policy_snapshot(engine_instance_id: u64, flow_id: u64) {
    let snapshot_key = FlowPolicySnapshotKey {
        engine_instance_id,
        flow_id,
    };
    let _ = flow_policy_snapshots().remove(&snapshot_key);
}
