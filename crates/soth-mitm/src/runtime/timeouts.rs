use mitm_sidecar::RuntimeObservabilitySnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimeoutBudget {
    pub max_budget_denial_count: u64,
    pub max_idle_timeout_count: u64,
    pub max_stream_stage_timeout_count: u64,
    pub max_stuck_flow_count: u64,
}

impl Default for TimeoutBudget {
    fn default() -> Self {
        Self {
            max_budget_denial_count: 0,
            max_idle_timeout_count: 0,
            max_stream_stage_timeout_count: 0,
            max_stuck_flow_count: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TimeoutBudgetReport {
    pub passed: bool,
    pub violations: Vec<String>,
}

pub(crate) fn evaluate_timeout_budget(
    snapshot: &RuntimeObservabilitySnapshot,
    budget: TimeoutBudget,
) -> TimeoutBudgetReport {
    let mut violations = Vec::new();
    if snapshot.budget_denial_count > budget.max_budget_denial_count {
        violations.push(format!(
            "budget_denial_count={} exceeded max={}",
            snapshot.budget_denial_count, budget.max_budget_denial_count
        ));
    }
    if snapshot.idle_timeout_count > budget.max_idle_timeout_count {
        violations.push(format!(
            "idle_timeout_count={} exceeded max={}",
            snapshot.idle_timeout_count, budget.max_idle_timeout_count
        ));
    }
    if snapshot.stream_stage_timeout_count > budget.max_stream_stage_timeout_count {
        violations.push(format!(
            "stream_stage_timeout_count={} exceeded max={}",
            snapshot.stream_stage_timeout_count, budget.max_stream_stage_timeout_count
        ));
    }
    if snapshot.stuck_flow_count > budget.max_stuck_flow_count {
        violations.push(format!(
            "stuck_flow_count={} exceeded max={}",
            snapshot.stuck_flow_count, budget.max_stuck_flow_count
        ));
    }

    TimeoutBudgetReport {
        passed: violations.is_empty(),
        violations,
    }
}

#[cfg(test)]
mod tests {
    use mitm_sidecar::RuntimeObservabilitySnapshot;

    use super::{evaluate_timeout_budget, TimeoutBudget};

    #[test]
    fn runtime_timeout_budget_passes_for_expected_snapshot() {
        let snapshot = RuntimeObservabilitySnapshot {
            budget_denial_count: 0,
            idle_timeout_count: 0,
            stream_stage_timeout_count: 1,
            stuck_flow_count: 1,
            ..RuntimeObservabilitySnapshot::default()
        };
        let budget = TimeoutBudget {
            max_budget_denial_count: 0,
            max_idle_timeout_count: 0,
            max_stream_stage_timeout_count: 2,
            max_stuck_flow_count: 2,
        };
        let report = evaluate_timeout_budget(&snapshot, budget);
        assert!(report.passed, "{report:?}");
    }

    #[test]
    fn runtime_timeout_budget_reports_violations() {
        let snapshot = RuntimeObservabilitySnapshot {
            budget_denial_count: 2,
            idle_timeout_count: 1,
            stream_stage_timeout_count: 3,
            stuck_flow_count: 4,
            ..RuntimeObservabilitySnapshot::default()
        };
        let report = evaluate_timeout_budget(&snapshot, TimeoutBudget::default());
        assert!(!report.passed);
        assert_eq!(report.violations.len(), 4);
    }
}
