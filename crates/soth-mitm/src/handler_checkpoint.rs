use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;

use crate::config::HandlerConfig;
use crate::handler::InterceptHandler;
use crate::{ConnectionInfo, HandlerAction, InterceptedRequest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HandlerResult {
    Action(HandlerAction),
    TimedOut,
    Panicked,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CheckpointDecision {
    UseHandlerAction(HandlerAction),
    ForwardPending,
    ForwardTimedOut,
    ForwardPanickedRecovered,
    ForwardFailed,
    FatalPanicked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LateResult {
    ActionDiscarded,
    TimedOut,
    Panicked,
    Failed,
}

pub(crate) struct HandlerCheckpointTask {
    receiver: oneshot::Receiver<HandlerResult>,
    recover_from_panics: bool,
    forwarded_pending_at_checkpoint: bool,
}

pub(crate) fn spawn_handler_task<H: InterceptHandler>(
    handler: Arc<H>,
    request: InterceptedRequest,
    connection: ConnectionInfo,
    config: HandlerConfig,
) -> HandlerCheckpointTask {
    let (sender, receiver) = oneshot::channel();
    tokio::spawn(async move {
        let task = tokio::spawn(async move { handler.on_request(&request, &connection).await });
        let result =
            match tokio::time::timeout(Duration::from_millis(config.timeout_ms), task).await {
                Ok(Ok(action)) => HandlerResult::Action(action),
                Ok(Err(join_error)) => {
                    if join_error.is_panic() {
                        HandlerResult::Panicked
                    } else {
                        HandlerResult::Failed
                    }
                }
                Err(_) => HandlerResult::TimedOut,
            };
        let _ = sender.send(result);
    });

    HandlerCheckpointTask {
        receiver,
        recover_from_panics: config.recover_from_panics,
        forwarded_pending_at_checkpoint: false,
    }
}

impl HandlerCheckpointTask {
    pub(crate) fn decision_at_checkpoint(&mut self) -> CheckpointDecision {
        match self.receiver.try_recv() {
            Ok(result) => map_handler_result(result, self.recover_from_panics),
            Err(TryRecvError::Empty) => {
                self.forwarded_pending_at_checkpoint = true;
                CheckpointDecision::ForwardPending
            }
            Err(TryRecvError::Closed) => CheckpointDecision::ForwardFailed,
        }
    }

    pub(crate) async fn observe_late_result(self, wait_for: Duration) -> Option<LateResult> {
        if !self.forwarded_pending_at_checkpoint {
            return None;
        }

        match tokio::time::timeout(wait_for, self.receiver).await {
            Ok(Ok(result)) => Some(map_late_result(result)),
            Ok(Err(_)) => Some(LateResult::Failed),
            Err(_) => None,
        }
    }
}

fn map_handler_result(result: HandlerResult, recover_from_panics: bool) -> CheckpointDecision {
    match result {
        HandlerResult::Action(action) => CheckpointDecision::UseHandlerAction(action),
        HandlerResult::TimedOut => CheckpointDecision::ForwardTimedOut,
        HandlerResult::Panicked => {
            if recover_from_panics {
                CheckpointDecision::ForwardPanickedRecovered
            } else {
                CheckpointDecision::FatalPanicked
            }
        }
        HandlerResult::Failed => CheckpointDecision::ForwardFailed,
    }
}

fn map_late_result(result: HandlerResult) -> LateResult {
    match result {
        HandlerResult::Action(_) => LateResult::ActionDiscarded,
        HandlerResult::TimedOut => LateResult::TimedOut,
        HandlerResult::Panicked => LateResult::Panicked,
        HandlerResult::Failed => LateResult::Failed,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use bytes::Bytes;
    use http::HeaderMap;
    use uuid::Uuid;

    use super::{spawn_handler_task, CheckpointDecision, HandlerCheckpointTask, LateResult};
    use crate::actions::HandlerAction;
    use crate::config::HandlerConfig;
    use crate::handler::InterceptHandler;
    use crate::types::{ConnectionInfo, HttpVersion, InterceptedRequest};

    struct FastBlockHandler;
    impl InterceptHandler for FastBlockHandler {
        async fn on_request(
            &self,
            _request: &InterceptedRequest,
            _connection: &ConnectionInfo,
        ) -> HandlerAction {
            HandlerAction::Block {
                status: 403,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"blocked"),
            }
        }
    }

    struct SlowHandler;
    impl InterceptHandler for SlowHandler {
        async fn on_request(
            &self,
            _request: &InterceptedRequest,
            _connection: &ConnectionInfo,
        ) -> HandlerAction {
            tokio::time::sleep(Duration::from_millis(75)).await;
            HandlerAction::Forward
        }
    }

    struct PanicHandler;
    impl InterceptHandler for PanicHandler {
        async fn on_request(
            &self,
            _request: &InterceptedRequest,
            _connection: &ConnectionInfo,
        ) -> HandlerAction {
            panic!("intentional panic for checkpoint test");
        }
    }

    #[tokio::test]
    async fn uses_handler_action_when_available_at_checkpoint() {
        let mut task = spawn(FastBlockHandler, 1_000, true);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let decision = task.decision_at_checkpoint();
        match decision {
            CheckpointDecision::UseHandlerAction(HandlerAction::Block { status, .. }) => {
                assert_eq!(status, 403);
            }
            other => panic!("unexpected decision: {other:?}"),
        }
        assert!(task
            .observe_late_result(Duration::from_millis(50))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn handler_runs_concurrent_with_upstream_connect() {
        let mut task = spawn(SlowHandler, 1_000, true);
        let start = tokio::time::Instant::now();
        let decision = task.decision_at_checkpoint();
        let elapsed = start.elapsed();
        assert_eq!(decision, CheckpointDecision::ForwardPending);
        assert!(
            elapsed < Duration::from_millis(20),
            "checkpoint should not block on handler completion"
        );
    }

    #[tokio::test]
    async fn late_handler_result_discarded_after_checkpoint() {
        let mut task = spawn(SlowHandler, 1_000, true);
        let decision = task.decision_at_checkpoint();
        assert_eq!(decision, CheckpointDecision::ForwardPending);
        let late = task
            .observe_late_result(Duration::from_millis(200))
            .await
            .expect("late action should arrive");
        assert_eq!(late, LateResult::ActionDiscarded);
    }

    #[tokio::test]
    async fn returns_timeout_when_handler_exceeds_timeout_before_checkpoint() {
        let mut task = spawn(SlowHandler, 10, true);
        tokio::time::sleep(Duration::from_millis(25)).await;
        let decision = task.decision_at_checkpoint();
        assert_eq!(decision, CheckpointDecision::ForwardTimedOut);
    }

    #[tokio::test]
    async fn panic_is_recovered_or_fatal_based_on_config() {
        let mut recover_task = spawn(PanicHandler, 1_000, true);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            recover_task.decision_at_checkpoint(),
            CheckpointDecision::ForwardPanickedRecovered
        );

        let mut fatal_task = spawn(PanicHandler, 1_000, false);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            fatal_task.decision_at_checkpoint(),
            CheckpointDecision::FatalPanicked
        );
    }

    fn spawn<H: InterceptHandler>(
        handler: H,
        timeout_ms: u64,
        recover_from_panics: bool,
    ) -> HandlerCheckpointTask {
        spawn_handler_task(
            Arc::new(handler),
            sample_request(),
            sample_connection(),
            HandlerConfig {
                timeout_ms,
                recover_from_panics,
            },
        )
    }

    fn sample_request() -> InterceptedRequest {
        InterceptedRequest {
            method: "POST".to_string(),
            path: "/v1/records".to_string(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"{\"kind\":\"batch\"}"),
            body_truncated: false,
            body_original_size: None,
        }
    }

    fn sample_connection() -> ConnectionInfo {
        ConnectionInfo {
            connection_id: Uuid::new_v4(),
            source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            source_port: 4242,
            destination_host: "api.example.com".to_string(),
            destination_port: 443,
            tls_fingerprint: None,
            alpn_protocol: Some("h2".to_string()),
            is_http2: true,
            process_info: None,
            connected_at: SystemTime::now(),
            request_count: 1,
        }
    }
}
