use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamFailureKind {
    ConnectFailure,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetryPolicy {
    pub enabled: bool,
    pub max_attempts: u32,
    pub delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            max_attempts: 1,
            delay: Duration::from_millis(0),
        }
    }
}

pub(crate) fn classify_upstream_failure(error: &io::Error) -> UpstreamFailureKind {
    match error.kind() {
        io::ErrorKind::TimedOut => UpstreamFailureKind::Timeout,
        _ => UpstreamFailureKind::ConnectFailure,
    }
}

pub(crate) fn upstream_http_status_for_error(error: &io::Error) -> u16 {
    match classify_upstream_failure(error) {
        UpstreamFailureKind::Timeout => 504,
        UpstreamFailureKind::ConnectFailure => 502,
    }
}

pub(crate) fn should_retry_upstream(
    policy: RetryPolicy,
    attempt_number: u32,
    error: &io::Error,
) -> bool {
    if !policy.enabled || policy.max_attempts == 0 {
        return false;
    }
    if attempt_number >= policy.max_attempts {
        return false;
    }
    matches!(
        classify_upstream_failure(error),
        UpstreamFailureKind::ConnectFailure | UpstreamFailureKind::Timeout
    )
}

pub(crate) async fn abort_upstream_after_downstream_disconnect(
    upstream_task: JoinHandle<()>,
    resource_released: Arc<AtomicBool>,
) -> bool {
    upstream_task.abort();
    let aborted = matches!(upstream_task.await, Err(error) if error.is_cancelled());
    resource_released.store(true, Ordering::Relaxed);
    aborted
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::task::JoinHandle;

    use super::{
        abort_upstream_after_downstream_disconnect, should_retry_upstream,
        upstream_http_status_for_error, RetryPolicy,
    };

    #[test]
    fn upstream_connect_failure_returns_502() {
        let error = io::Error::new(io::ErrorKind::ConnectionRefused, "connect refused");
        assert_eq!(upstream_http_status_for_error(&error), 502);
    }

    #[test]
    fn upstream_timeout_returns_504() {
        let error = io::Error::new(io::ErrorKind::TimedOut, "connect timed out");
        assert_eq!(upstream_http_status_for_error(&error), 504);
    }

    #[tokio::test]
    async fn downstream_disconnect_aborts_upstream_and_releases_resources() {
        let upstream_task: JoinHandle<()> = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let released = Arc::new(AtomicBool::new(false));

        let aborted =
            abort_upstream_after_downstream_disconnect(upstream_task, Arc::clone(&released)).await;

        assert!(aborted, "expected upstream task to be aborted");
        assert!(
            released.load(Ordering::Relaxed),
            "expected resource release marker to be set"
        );
    }

    #[test]
    fn retry_policy_respects_attempt_budget() {
        let policy = RetryPolicy {
            enabled: true,
            max_attempts: 2,
            delay: Duration::from_millis(100),
        };
        let error = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        assert!(should_retry_upstream(policy, 1, &error));
        assert!(!should_retry_upstream(policy, 2, &error));
    }
}
