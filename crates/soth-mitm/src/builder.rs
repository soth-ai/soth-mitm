use std::sync::Arc;

use crate::ca::CertificateAuthority;
use crate::config::MitmConfig;
use crate::errors::MitmError;
use crate::handler::InterceptHandler;
use crate::metrics::ProxyMetricsStore;
use crate::proxy::MitmProxy;

pub struct MitmProxyBuilder<H: InterceptHandler> {
    config: MitmConfig,
    handler: H,
    ca: Option<CertificateAuthority>,
}

impl<H: InterceptHandler> MitmProxyBuilder<H> {
    pub fn new(config: MitmConfig, handler: H) -> Self {
        Self {
            config,
            handler,
            ca: None,
        }
    }

    pub fn with_ca(mut self, ca: CertificateAuthority) -> Self {
        self.ca = Some(ca);
        self
    }

    pub fn build(self) -> Result<MitmProxy<H>, MitmError> {
        self.config.validate()?;
        Ok(MitmProxy::new(
            self.config,
            Arc::new(self.handler),
            self.ca,
            Arc::new(ProxyMetricsStore::default()),
        ))
    }
}
