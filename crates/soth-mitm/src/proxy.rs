use std::fs;
#[cfg(unix)]
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mitm_sidecar::RuntimeGovernor;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::ca::CertificateAuthority;
use crate::config::MitmConfig;
use crate::errors::MitmError;
use crate::handler::InterceptHandler;
use crate::metrics::{ProxyMetrics, ProxyMetricsStore};
use crate::runtime::{build_runtime_server, RuntimeConfigHandle};

pub struct MitmProxy<H: InterceptHandler> {
    config: MitmConfig,
    handler: Arc<H>,
    ca: Option<CertificateAuthority>,
    metrics_store: Arc<ProxyMetricsStore>,
}

impl<H: InterceptHandler> MitmProxy<H> {
    pub(crate) fn new(
        config: MitmConfig,
        handler: Arc<H>,
        ca: Option<CertificateAuthority>,
        metrics_store: Arc<ProxyMetricsStore>,
    ) -> Self {
        Self {
            config,
            handler,
            ca,
            metrics_store,
        }
    }

    pub async fn run(self) -> Result<(), MitmError> {
        self.prepare_ca_material()?;
        let runtime_bundle = build_runtime_server(
            &self.config,
            Arc::clone(&self.handler),
            Arc::clone(&self.metrics_store),
        )?;
        runtime_bundle.server.run().await.map_err(MitmError::from)
    }

    pub async fn start(self) -> Result<MitmProxyHandle, MitmError> {
        self.prepare_ca_material()?;
        let runtime_bundle = build_runtime_server(
            &self.config,
            Arc::clone(&self.handler),
            Arc::clone(&self.metrics_store),
        )?;
        let runtime_config = runtime_bundle.config_handle.clone();
        let runtime_governor = runtime_bundle.server.runtime_observability_handle();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let join_handle = tokio::spawn(async move {
            runtime_bundle
                .server
                .run_until_shutdown(shutdown_rx)
                .await
                .map_err(MitmError::from)
        });
        Ok(MitmProxyHandle {
            join_handle: Arc::new(Mutex::new(Some(join_handle))),
            metrics_store: Arc::clone(&self.metrics_store),
            runtime_config,
            runtime_governor,
            shutdown_tx,
        })
    }

    fn prepare_ca_material(&self) -> Result<(), MitmError> {
        let Some(ca) = &self.ca else {
            return Ok(());
        };

        if let Some(parent) = self.config.tls.ca_cert_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        if let Some(parent) = self.config.tls.ca_key_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        fs::write(&self.config.tls.ca_cert_path, &ca.cert_pem)?;
        write_private_key_file(&self.config.tls.ca_key_path, &ca.key_pem)?;
        Ok(())
    }
}

pub struct MitmProxyHandle {
    join_handle: Arc<Mutex<Option<JoinHandle<Result<(), MitmError>>>>>,
    metrics_store: Arc<ProxyMetricsStore>,
    runtime_config: RuntimeConfigHandle,
    runtime_governor: Arc<RuntimeGovernor>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl MitmProxyHandle {
    pub async fn reload(&self, next_config: MitmConfig) -> Result<(), MitmError> {
        self.runtime_config.apply_reload(&next_config)?;
        Ok(())
    }

    pub async fn current_config(&self) -> MitmConfig {
        self.runtime_config.current_config()
    }

    pub async fn shutdown(self, timeout: Duration) -> Result<(), MitmError> {
        let mut guard = self.join_handle.lock().await;
        let Some(handle) = guard.take() else {
            return Ok(());
        };
        drop(guard);
        let mut handle = handle;

        let _ = self.shutdown_tx.send(true);
        let deadline = tokio::time::Instant::now() + timeout;
        let drained =
            wait_for_active_flows_to_drain(Arc::clone(&self.runtime_governor), deadline).await;
        if !drained {
            handle.abort();
            let _ = tokio::time::timeout(Duration::from_millis(100), &mut handle).await;
            return Err(shutdown_timeout_error());
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, &mut handle).await {
            Ok(join_result) => match join_result {
                Ok(result) => result,
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(MitmError::Join(error)),
            },
            Err(_) => {
                handle.abort();
                let _ = tokio::time::timeout(Duration::from_millis(100), &mut handle).await;
                Err(shutdown_timeout_error())
            }
        }
    }

    pub fn metrics(&self) -> ProxyMetrics {
        self.metrics_store.snapshot()
    }
}

fn shutdown_timeout_error() -> MitmError {
    MitmError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "timed out waiting for proxy shutdown",
    ))
}

async fn wait_for_active_flows_to_drain(
    runtime_governor: Arc<RuntimeGovernor>,
    deadline: tokio::time::Instant,
) -> bool {
    loop {
        if runtime_governor.snapshot().active_flows == 0 {
            return true;
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return false;
        }

        let sleep_for = (deadline - now).min(Duration::from_millis(25));
        tokio::time::sleep(sleep_for).await;
    }
}

fn write_private_key_file(path: &Path, key_pem: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(key_pem)?;
        file.flush()?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        fs::write(path, key_pem)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::Duration;

    use mitm_sidecar::{RuntimeBudgetConfig, RuntimeGovernor};
    use tokio::sync::Mutex;

    use super::{write_private_key_file, MitmProxyHandle};
    use crate::config::MitmConfig;
    use crate::errors::MitmError;
    use crate::metrics::ProxyMetricsStore;
    use crate::runtime::RuntimeConfigHandle;

    fn build_handle(
        runtime_governor: Arc<RuntimeGovernor>,
        shutdown_tx: tokio::sync::watch::Sender<bool>,
        join_handle: Option<tokio::task::JoinHandle<Result<(), MitmError>>>,
    ) -> MitmProxyHandle {
        let mut config = MitmConfig::default();
        config
            .interception
            .destinations
            .push("api.example.com:443".to_string());
        MitmProxyHandle {
            join_handle: Arc::new(Mutex::new(join_handle)),
            metrics_store: Arc::new(ProxyMetricsStore::default()),
            runtime_config: RuntimeConfigHandle::from_config(&config)
                .expect("runtime config handle must build"),
            runtime_governor,
            shutdown_tx,
        }
    }

    #[tokio::test]
    async fn shutdown_noop_when_handle_already_consumed() {
        let runtime_governor = Arc::new(RuntimeGovernor::new(RuntimeBudgetConfig::default()));
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let handle = build_handle(runtime_governor, shutdown_tx, None);
        handle
            .shutdown(Duration::from_millis(10))
            .await
            .expect("shutdown should be a no-op when handle is empty");
    }

    #[tokio::test]
    async fn shutdown_drains_active_flows_before_joining_runtime() {
        let runtime_governor = Arc::new(RuntimeGovernor::new(RuntimeBudgetConfig::default()));
        let permit = runtime_governor
            .clone()
            .try_acquire_flow_permit()
            .expect("flow permit");
        let flow_guard = runtime_governor.begin_flow(permit);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let join_handle = tokio::spawn(async move {
            let _ = shutdown_rx.changed().await;
            Ok(())
        });
        let guard_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            drop(flow_guard);
        });

        let handle = build_handle(
            Arc::clone(&runtime_governor),
            shutdown_tx,
            Some(join_handle),
        );
        let started = std::time::Instant::now();
        handle
            .shutdown(Duration::from_millis(250))
            .await
            .expect("shutdown should wait for active flow to drain");
        assert!(
            started.elapsed() >= Duration::from_millis(55),
            "shutdown must wait for in-flight flow drain window"
        );
        guard_task.await.expect("guard task should complete");
    }

    #[tokio::test]
    async fn shutdown_returns_timeout_when_active_flows_do_not_drain() {
        let runtime_governor = Arc::new(RuntimeGovernor::new(RuntimeBudgetConfig::default()));
        let permit = runtime_governor
            .clone()
            .try_acquire_flow_permit()
            .expect("flow permit");
        let _flow_guard = runtime_governor.begin_flow(permit);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let join_handle = tokio::spawn(async move {
            let _ = shutdown_rx.changed().await;
            Ok(())
        });
        let handle = build_handle(runtime_governor, shutdown_tx, Some(join_handle));
        let error = handle
            .shutdown(Duration::from_millis(5))
            .await
            .expect_err("active flow not draining must force timeout");
        match error {
            MitmError::Io(io_error) => {
                assert_eq!(io_error.kind(), std::io::ErrorKind::TimedOut);
                assert!(io_error
                    .to_string()
                    .contains("timed out waiting for proxy shutdown"));
            }
            other => panic!("expected timeout IO error, got {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_key_permissions_are_owner_only_on_unix() {
        let temp_dir =
            std::env::temp_dir().join(format!("soth-mitm-key-perm-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).expect("temp dir");
        let key_path = temp_dir.join("ca-key.pem");

        write_private_key_file(&key_path, b"key-material").expect("write private key");
        let mode = fs::metadata(&key_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "private key file must be owner-readable only");

        let _ = fs::remove_file(&key_path);
        let _ = fs::remove_dir(&temp_dir);
    }
}
