// Internal items are only reachable when __internal is enabled; suppress dead-code
// warnings for the public build where those modules are gated out.
#![cfg_attr(not(feature = "__internal"), allow(dead_code))]

//! # soth-mitm
//!
//! Rust intercepting proxy crate with deterministic handler/event contracts.
//!
//! `soth-mitm` provides a MITM (man-in-the-middle) proxy that intercepts HTTP/1.1,
//! HTTP/2, WebSocket, gRPC, and SSE traffic over TLS. It exposes a trait-based
//! handler API that lets you inspect, allow, or block requests in real time.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use bytes::Bytes;
//! use soth_mitm::{
//!     HandlerDecision, InterceptHandler, MitmConfig, MitmProxyBuilder, RawRequest,
//! };
//!
//! struct MyHandler;
//!
//! impl InterceptHandler for MyHandler {
//!     async fn on_request(&self, request: &RawRequest) -> HandlerDecision {
//!         if request.path.contains("/blocked") {
//!             return HandlerDecision::Block {
//!                 status: 403,
//!                 body: Bytes::from_static(b"blocked"),
//!             };
//!         }
//!         HandlerDecision::Allow
//!     }
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut config = MitmConfig::default();
//!     config
//!         .interception
//!         .destinations
//!         .push("api.example.com:443".to_string());
//!
//!     let _proxy = MitmProxyBuilder::new(config, MyHandler).build()?;
//!     Ok(())
//! }
//! ```
//!
//! ## Feature Flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `openssl-backend` | off | Enables OpenSSL-based CA material validation on cert load |
//! | `__internal` | off | Exposes internal modules for integration tests — **not stable API** |
//!
//! ## Minimum Supported Rust Version
//!
//! This crate requires **Rust 1.88** or later.
//!
//! ## License
//!
//! Licensed under the [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/).

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
    ConnectionMeta, FlowId, FrameDirection, FrameKind, ProcessInfo, RawRequest, RawResponse,
    SocketFamily, StreamChunk, TlsInfo, TlsVersion,
};

// Re-export key transitive types that appear in the public API surface.
// Users should not need to add separate `bytes`, `http`, or `uuid` deps.
pub use bytes::Bytes;
pub use http::HeaderMap;
pub use uuid::Uuid;

/// Re-initializes the global DNS resolver with new nameserver configuration.
///
/// Safe to call at any time, including while the proxy is handling traffic.
/// In-flight DNS queries on the previous resolver complete via Arc refcounting;
/// new queries immediately use the replacement resolver.
///
/// Pass `None` to auto-detect system nameservers, or supply explicit entries
/// such as `"8.8.8.8"`, `"1.1.1.1:53"`, or `"[2606:4700::1111]:53"`.
pub fn reload_dns_resolver(nameservers: Option<&[String]>) {
    server::dns_resolver::reinstall_dns_resolver(nameservers);
}

// --- Internal modules gated behind the `__internal` feature ---
// These expose consolidated sub-crate internals for integration tests and
// benchmarks. They are NOT part of the stable public API and may change
// without notice between any versions.

#[cfg(feature = "__internal")]
#[doc(hidden)]
pub mod bench_tls {
    pub use crate::tls::{build_http1_client_config, build_http1_server_config_for_host};
}

#[cfg(feature = "__internal")]
#[doc(hidden)]
pub mod test_engine {
    pub use crate::engine::{
        parse_connect_request_head_with_mode, parse_connect_request_line_with_mode, server,
        CompatibilityOverrideConfig, ConnectParseError, ConnectParseMode, DownstreamCertProfile,
        InterceptMode, MitmConfig, MitmConfigError, MitmEngine, RouteEndpointConfig, RouteMode,
        TlsFingerprintClass, TlsFingerprintMode, TlsProfile, UpstreamClientAuthMode,
        UpstreamSniMode,
    };
}

#[cfg(feature = "__internal")]
#[doc(hidden)]
pub mod test_policy {
    pub use crate::policy::{DefaultPolicyEngine, FlowAction, PolicyEngine};
}

#[cfg(feature = "__internal")]
#[doc(hidden)]
pub mod test_protocol {
    pub use crate::protocol::{
        validate_stage_order,
        // anti-hijack
        AntiHijackSanitizationStage,
        ApplicationProtocol,
        DecoderFailureCode,
        // decoder chain
        DecoderFrame,
        DecoderPipelineRegistry,
        DecoderPipelineResult,
        DecoderStage,
        DecoderStageProcessor,
        DecoderStageStatus,
        // grpc envelope
        GrpcEnvelopeMalformedCode,
        GrpcEnvelopeParser,
        GrpcEnvelopeParserLimits,
        GrpcEnvelopeRecord,
        LayeredDecoderPipeline,
        SseParser,
        StageProcessOutcome,
        // websocket
        WebSocketTurn,
        WebSocketTurnAggregator,
        WsDirection,
        WsFrameKind,
        SANITIZED_ATTRIBUTE,
        SANITIZED_PREFIX_ATTRIBUTE,
        SANITIZED_PROVENANCE_ATTRIBUTE,
    };
}

#[cfg(feature = "__internal")]
#[doc(hidden)]
pub mod test_observe {
    pub use crate::observe::event_log_v2::{
        deterministic_event_record_v2, DeterministicEventRecordV2, EventLogV2Config,
        EventLogV2Consumer,
    };
    pub use crate::observe::{
        Event, EventConsumer, EventEnvelope, EventType, FlowContext, NoopEventConsumer,
        VecEventConsumer, EVENT_SCHEMA_VERSION,
    };
}

#[cfg(feature = "__internal")]
#[doc(hidden)]
pub mod test_server {
    pub use crate::server::{
        adapt_mitmproxy_tls_callback, parse_http1_request_head_bytes,
        parse_http1_response_head_bytes, FlowHooks, FrameKind, H2ResponseOverflowMode,
        MitmproxyTlsAdapterEvent, MitmproxyTlsCallback, MitmproxyTlsHook, NoopFlowHooks,
        RawRequest, RawResponse, RuntimeGovernor, SidecarConfig, SidecarServer, StreamChunk,
        TlsDiagnostics, TlsDiagnosticsSnapshot, TlsLearningDecision, TlsLearningGuardrails,
        TlsLearningOutcome, TlsLearningSignal, TlsLearningSnapshot,
    };
}

#[cfg(feature = "__internal")]
#[doc(hidden)]
pub mod test_tls {
    pub use crate::tls::{
        build_http1_client_config, build_http1_server_config_for_host, build_http_client_config,
        build_http_server_config_for_host, classify_tls_error, CertificateAuthorityConfig,
        MitmCertificateStore, TlsFailureReason,
    };
}
