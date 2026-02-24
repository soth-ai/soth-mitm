use crate::actions::HandlerAction;
use crate::handler_checkpoint::CheckpointDecision;
use crate::metrics::ProxyMetricsStore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeHandlerDecision {
    Forward,
    Apply(HandlerAction),
    FatalPanicked,
}

pub(crate) fn map_checkpoint_decision(
    decision: CheckpointDecision,
    metrics: &ProxyMetricsStore,
) -> RuntimeHandlerDecision {
    match decision {
        CheckpointDecision::UseHandlerAction(action) => RuntimeHandlerDecision::Apply(action),
        CheckpointDecision::ForwardPending => RuntimeHandlerDecision::Forward,
        CheckpointDecision::ForwardTimedOut => {
            metrics.record_handler_timeout();
            RuntimeHandlerDecision::Forward
        }
        CheckpointDecision::ForwardPanickedRecovered => {
            metrics.record_handler_panic();
            RuntimeHandlerDecision::Forward
        }
        CheckpointDecision::ForwardFailed => RuntimeHandlerDecision::Forward,
        CheckpointDecision::FatalPanicked => {
            metrics.record_handler_panic();
            RuntimeHandlerDecision::FatalPanicked
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{map_checkpoint_decision, RuntimeHandlerDecision};
    use crate::actions::HandlerAction;
    use crate::handler_checkpoint::CheckpointDecision;
    use crate::metrics::ProxyMetricsStore;

    #[test]
    fn handler_timeout_defaults_to_forward_and_counts() {
        let metrics = ProxyMetricsStore::default();

        let decision = map_checkpoint_decision(CheckpointDecision::ForwardTimedOut, &metrics);

        assert_eq!(decision, RuntimeHandlerDecision::Forward);
        assert_eq!(metrics.snapshot().handler_timeout_count, 1);
    }

    #[test]
    fn handler_panic_recover_true_defaults_to_forward() {
        let metrics = ProxyMetricsStore::default();

        let decision =
            map_checkpoint_decision(CheckpointDecision::ForwardPanickedRecovered, &metrics);

        assert_eq!(decision, RuntimeHandlerDecision::Forward);
        assert_eq!(metrics.snapshot().handler_panic_count, 1);
    }

    #[test]
    fn handler_panic_recover_false_propagates() {
        let metrics = ProxyMetricsStore::default();

        let decision = map_checkpoint_decision(CheckpointDecision::FatalPanicked, &metrics);

        assert_eq!(decision, RuntimeHandlerDecision::FatalPanicked);
        assert_eq!(metrics.snapshot().handler_panic_count, 1);
    }

    #[test]
    fn use_handler_action_passes_through() {
        let metrics = ProxyMetricsStore::default();
        let decision = map_checkpoint_decision(
            CheckpointDecision::UseHandlerAction(HandlerAction::Forward),
            &metrics,
        );
        assert_eq!(
            decision,
            RuntimeHandlerDecision::Apply(HandlerAction::Forward)
        );
        assert_eq!(metrics.snapshot().handler_panic_count, 0);
        assert_eq!(metrics.snapshot().handler_timeout_count, 0);
    }
}
