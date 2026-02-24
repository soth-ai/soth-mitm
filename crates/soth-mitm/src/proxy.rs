use std::fs;
use std::sync::Arc;
use std::time::Duration;

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
        let active_config = Arc::new(tokio::sync::RwLock::new(self.config.clone()));
        let runtime_config = runtime_bundle.config_handle.clone();

        let join_handle =
            tokio::spawn(async move { runtime_bundle.server.run().await.map_err(MitmError::from) });
        Ok(MitmProxyHandle {
            join_handle: Arc::new(Mutex::new(Some(join_handle))),
            metrics_store: Arc::clone(&self.metrics_store),
            runtime_config,
            active_config,
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
        fs::write(&self.config.tls.ca_key_path, &ca.key_pem)?;
        Ok(())
    }
}

pub struct MitmProxyHandle {
    join_handle: Arc<Mutex<Option<JoinHandle<Result<(), MitmError>>>>>,
    metrics_store: Arc<ProxyMetricsStore>,
    runtime_config: RuntimeConfigHandle,
    active_config: Arc<tokio::sync::RwLock<MitmConfig>>,
}

impl MitmProxyHandle {
    pub async fn reload(&self, next_config: MitmConfig) -> Result<(), MitmError> {
        next_config.validate()?;
        self.runtime_config.apply_reload(&next_config)?;
        let mut guard = self.active_config.write().await;
        *guard = next_config;
        Ok(())
    }

    pub async fn current_config(&self) -> MitmConfig {
        self.active_config.read().await.clone()
    }

    pub async fn shutdown(self, timeout: Duration) -> Result<(), MitmError> {
        let mut guard = self.join_handle.lock().await;
        let Some(handle) = guard.take() else {
            return Ok(());
        };

        handle.abort();

        match tokio::time::timeout(timeout, handle).await {
            Ok(join_result) => match join_result {
                Ok(result) => result,
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(MitmError::Join(error)),
            },
            Err(_) => Err(MitmError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out waiting for proxy shutdown",
            ))),
        }
    }

    pub fn metrics(&self) -> ProxyMetrics {
        self.metrics_store.snapshot()
    }
}
