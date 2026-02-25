use std::future::Future;
use std::panic::resume_unwind;
use std::sync::Arc;
use std::time::Duration;

use crate::metrics::ProxyMetricsStore;

#[derive(Debug)]
pub(crate) struct HandlerCallbackGuard {
    request_timeout: Duration,
    response_timeout: Duration,
    recover_from_panics: bool,
    metrics_store: Arc<ProxyMetricsStore>,
}

impl HandlerCallbackGuard {
    pub(crate) fn new(
        request_timeout: Duration,
        response_timeout: Duration,
        recover_from_panics: bool,
        metrics_store: Arc<ProxyMetricsStore>,
    ) -> Self {
        Self {
            request_timeout,
            response_timeout,
            recover_from_panics,
            metrics_store,
        }
    }

    pub(crate) async fn run_sync<R, F>(&self, default_value: R, callback: F) -> R
    where
        R: Send + 'static,
        F: FnOnce() -> R + Send + 'static,
    {
        match tokio::task::spawn_blocking(callback).await {
            Ok(value) => value,
            Err(join_error) if join_error.is_panic() => {
                self.metrics_store.record_handler_panic();
                if self.recover_from_panics {
                    default_value
                } else {
                    resume_unwind(join_error.into_panic());
                }
            }
            Err(_join_error) => default_value,
        }
    }

    pub(crate) async fn run_request<R, Fut>(&self, default_value: R, future: Fut) -> R
    where
        R: Send + 'static,
        Fut: Future<Output = R> + Send + 'static,
    {
        self.run_async_with_timeout(self.request_timeout, default_value, future)
            .await
    }

    pub(crate) async fn run_response<R, Fut>(&self, default_value: R, future: Fut) -> R
    where
        R: Send + 'static,
        Fut: Future<Output = R> + Send + 'static,
    {
        self.run_async_with_timeout(self.response_timeout, default_value, future)
            .await
    }

    async fn run_async_with_timeout<R, Fut>(
        &self,
        timeout: Duration,
        default_value: R,
        future: Fut,
    ) -> R
    where
        R: Send + 'static,
        Fut: Future<Output = R> + Send + 'static,
    {
        let mut task = tokio::spawn(future);
        match tokio::time::timeout(timeout, &mut task).await {
            Ok(Ok(value)) => value,
            Ok(Err(join_error)) if join_error.is_panic() => {
                self.metrics_store.record_handler_panic();
                if self.recover_from_panics {
                    default_value
                } else {
                    resume_unwind(join_error.into_panic());
                }
            }
            Ok(Err(_join_error)) => default_value,
            Err(_) => {
                task.abort();
                let _ = task.await;
                self.metrics_store.record_handler_timeout();
                default_value
            }
        }
    }
}
