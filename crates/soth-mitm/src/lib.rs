// Consolidated sub-crate modules
pub(crate) mod engine;
pub(crate) mod observe;
pub(crate) mod policy;
pub(crate) mod protocol;
pub(crate) mod server;
pub(crate) mod tls;

// Facade modules
mod actions;
mod builder;
mod ca;
mod ca_trust;
mod config;
mod destination;
mod errors;
#[cfg(test)]
mod fingerprint_capture;
mod handler;
mod metrics;
mod process;
mod proxy;
mod runtime;
mod types;

pub use actions::HandlerDecision;
pub use builder::MitmProxyBuilder;
pub use ca::{
    generate_ca, install_ca_system_trust, is_ca_trusted, load_ca, load_ca_from_files,
    uninstall_ca_system_trust, CertificateAuthority,
};
pub use config::{
    BodyConfig, ConnectionPoolConfig, FlowRuntimeConfig, H2ResponseOverflowMode, HandlerConfig,
    InterceptMode, InterceptionScope, MitmConfig, ProcessAttributionConfig, TlsConfig,
    UpstreamConfig,
};
pub use errors::{CaError, MitmError};
pub use handler::InterceptHandler;
pub use metrics::ProxyMetrics;
pub use proxy::{MitmProxy, MitmProxyHandle};
pub use types::{
    ConnectionMeta, FlowId, FrameKind, ProcessInfo, RawRequest, RawResponse, SocketFamily,
    StreamChunk, TlsInfo, TlsVersion,
};

// TLS helpers re-exported for benchmarks
#[doc(hidden)]
pub mod bench_tls {
    pub use crate::tls::{build_http1_client_config, build_http1_server_config_for_host};
}

// Re-exports for integration tests.  These expose the consolidated sub-crate
// modules so that `tests/*.rs` (which are external to the crate) can reach
// internal types that were previously accessible as separate crate deps.
#[doc(hidden)]
pub mod test_engine {
    pub use crate::engine::{
        server, CompatibilityOverrideConfig, ConnectParseError, ConnectParseMode,
        DownstreamCertProfile, InterceptMode, MitmConfig, MitmConfigError, MitmEngine,
        RouteEndpointConfig, RouteMode, TlsFingerprintClass, TlsFingerprintMode, TlsProfile,
        UpstreamClientAuthMode, UpstreamSniMode,
        parse_connect_request_head_with_mode, parse_connect_request_line_with_mode,
    };
}

#[doc(hidden)]
pub mod test_policy {
    pub use crate::policy::{DefaultPolicyEngine, FlowAction, PolicyEngine};
}

#[doc(hidden)]
pub mod test_protocol {
    pub use crate::protocol::{
        ApplicationProtocol, SseParser,
        // decoder chain
        DecoderFrame, DecoderStage, DecoderStageProcessor, DecoderStageStatus,
        DecoderFailureCode, DecoderPipelineResult, DecoderPipelineRegistry,
        LayeredDecoderPipeline, StageProcessOutcome, validate_stage_order,
        // anti-hijack
        AntiHijackSanitizationStage, SANITIZED_ATTRIBUTE, SANITIZED_PREFIX_ATTRIBUTE,
        SANITIZED_PROVENANCE_ATTRIBUTE,
        // grpc envelope
        GrpcEnvelopeMalformedCode, GrpcEnvelopeParser, GrpcEnvelopeRecord,
    };
}

#[doc(hidden)]
pub mod test_observe {
    pub use crate::observe::{
        Event, EventConsumer, EventEnvelope, EventType, FlowContext, NoopEventConsumer,
        VecEventConsumer, EVENT_SCHEMA_VERSION,
    };
    pub use crate::observe::event_log_v2::{
        deterministic_event_record_v2, DeterministicEventRecordV2,
        EventLogV2Config, EventLogV2Consumer,
    };
}

#[doc(hidden)]
pub mod test_server {
    pub use crate::server::{
        FlowHooks, FrameKind, H2ResponseOverflowMode, MitmproxyTlsCallback, MitmproxyTlsHook,
        NoopFlowHooks, RawRequest, RawResponse, RuntimeGovernor,
        SidecarConfig, SidecarServer, StreamChunk,
        TlsDiagnostics, TlsDiagnosticsSnapshot,
        TlsLearningDecision, TlsLearningGuardrails, TlsLearningOutcome,
        TlsLearningSignal, TlsLearningSnapshot,
        parse_http1_request_head_bytes, parse_http1_response_head_bytes,
        MitmproxyTlsAdapterEvent, adapt_mitmproxy_tls_callback,
    };
}

#[doc(hidden)]
pub mod test_tls {
    pub use crate::tls::{
        build_http1_client_config, build_http1_server_config_for_host,
        build_http_client_config, build_http_server_config_for_host,
        classify_tls_error, CertificateAuthorityConfig, MitmCertificateStore,
        TlsFailureReason,
    };
}
