use std::sync::Arc;

use crate::ca::CertificateAuthority;
use crate::config::MitmConfig;
use crate::errors::MitmError;
use crate::handler::InterceptHandler;
use crate::metrics::ProxyMetricsStore;
use crate::proxy::MitmProxy;

/// Builder for constructing a [`MitmProxy`] instance.
///
/// Supply a validated [`MitmConfig`] and an [`InterceptHandler`] implementation,
/// optionally attach a pre-generated [`CertificateAuthority`], then call
/// [`build`](Self::build) to produce a ready-to-run proxy.
pub struct MitmProxyBuilder<H: InterceptHandler> {
    config: MitmConfig,
    handler: H,
    ca: Option<CertificateAuthority>,
}

impl<H: InterceptHandler> MitmProxyBuilder<H> {
    /// Creates a new builder with the given configuration and handler.
    pub fn new(config: MitmConfig, handler: H) -> Self {
        Self {
            config,
            handler,
            ca: None,
        }
    }

    /// Attaches a pre-generated CA for TLS interception.
    ///
    /// If omitted, the proxy will load or generate a CA from the paths
    /// specified in [`TlsConfig`](crate::TlsConfig).
    pub fn with_ca(mut self, ca: CertificateAuthority) -> Self {
        self.ca = Some(ca);
        self
    }

    /// Validates the config and builds the [`MitmProxy`].
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
