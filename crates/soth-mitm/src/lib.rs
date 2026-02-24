#[allow(dead_code)]
mod action_apply;
mod actions;
#[allow(dead_code)]
mod buffering;
mod builder;
mod ca;
mod ca_trust;
mod config;
#[allow(dead_code)]
mod connection_identity;
#[allow(dead_code)]
mod connection_lifecycle;
mod destination;
mod errors;
#[allow(dead_code)]
mod fingerprint_capture;
mod handler;
#[allow(dead_code)]
mod handler_checkpoint;
#[allow(dead_code)]
mod handler_outcome;
#[allow(dead_code)]
mod header_rewrite;
#[allow(dead_code)]
mod leaf_cache;
mod metrics;
#[allow(dead_code)]
mod process;
mod proxy;
mod runtime;
#[allow(dead_code)]
mod sse_dispatch;
#[allow(dead_code)]
mod tls_intercept_contract;
mod types;
#[allow(dead_code)]
mod upstream_failures;

pub use actions::{HandlerAction, ResponseAction};
pub use builder::MitmProxyBuilder;
pub use ca::{
    generate_ca, install_ca_system_trust, is_ca_trusted, load_ca, load_ca_from_files,
    uninstall_ca_system_trust, CertificateAuthority,
};
pub use config::{
    BodyConfig, ConnectionPoolConfig, HandlerConfig, InterceptionScope, MitmConfig, TlsConfig,
    UpstreamConfig,
};
pub use errors::{CaError, MitmError};
pub use handler::InterceptHandler;
pub use metrics::ProxyMetrics;
pub use proxy::{MitmProxy, MitmProxyHandle};
pub use types::{
    ConnectionInfo, ConnectionStats, HttpVersion, InterceptedRequest, InterceptedResponse,
    ProcessInfo, TlsClientFingerprint, TlsVersion,
};
