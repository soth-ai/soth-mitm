use std::collections::BTreeMap;

use mitm_http::ApplicationProtocol;
use mitm_observe::{EventType, FlowContext};
use mitm_tls::classify_tls_error;

const MITMPROXY_PROVIDER: &str = "mitmproxy";
const MISSING_DETAIL: &str = "mitmproxy callback reported TLS failure without detail";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmproxyTlsHook {
    TlsHandshakeStartedClient,
    TlsHandshakeStartedServer,
    TlsHandshakeSucceededClient,
    TlsHandshakeSucceededServer,
    TlsFailedClient,
    TlsFailedServer,
}

impl MitmproxyTlsHook {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TlsHandshakeStartedClient => "tls_handshake_started_client",
            Self::TlsHandshakeStartedServer => "tls_handshake_started_server",
            Self::TlsHandshakeSucceededClient => "tls_handshake_succeeded_client",
            Self::TlsHandshakeSucceededServer => "tls_handshake_succeeded_server",
            Self::TlsFailedClient => "tls_failed_client",
            Self::TlsFailedServer => "tls_failed_server",
        }
    }

    pub fn peer(self) -> &'static str {
        match self {
            Self::TlsHandshakeStartedClient
            | Self::TlsHandshakeSucceededClient
            | Self::TlsFailedClient => "downstream",
            Self::TlsHandshakeStartedServer
            | Self::TlsHandshakeSucceededServer
            | Self::TlsFailedServer => "upstream",
        }
    }

    pub fn event_type(self) -> EventType {
        match self {
            Self::TlsHandshakeStartedClient | Self::TlsHandshakeStartedServer => {
                EventType::TlsHandshakeStarted
            }
            Self::TlsHandshakeSucceededClient | Self::TlsHandshakeSucceededServer => {
                EventType::TlsHandshakeSucceeded
            }
            Self::TlsFailedClient | Self::TlsFailedServer => EventType::TlsHandshakeFailed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmproxyTlsCallback {
    pub flow_id: u64,
    pub client_addr: String,
    pub server_host: String,
    pub server_port: u16,
    pub protocol: ApplicationProtocol,
    pub hook: MitmproxyTlsHook,
    pub error: Option<String>,
    pub provider_error_class: Option<String>,
    pub provider_error_code: Option<String>,
    pub provider_error_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmproxyTlsFailure {
    pub source: String,
    pub reason: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmproxyTlsAdapterEvent {
    pub kind: EventType,
    pub context: FlowContext,
    pub attributes: BTreeMap<String, String>,
    pub failure: Option<MitmproxyTlsFailure>,
}

pub fn adapt_mitmproxy_tls_callback(callback: &MitmproxyTlsCallback) -> MitmproxyTlsAdapterEvent {
    let context = FlowContext {
        flow_id: callback.flow_id,
        client_addr: callback.client_addr.clone(),
        server_host: callback.server_host.clone(),
        server_port: callback.server_port,
        protocol: callback.protocol,
    };
    let kind = callback.hook.event_type();

    let mut attributes = BTreeMap::new();
    attributes.insert("peer".to_string(), callback.hook.peer().to_string());
    attributes.insert(
        "tls_ops_provider".to_string(),
        MITMPROXY_PROVIDER.to_string(),
    );
    attributes.insert(
        "tls_ops_provider_hook".to_string(),
        callback.hook.as_str().to_string(),
    );
    if let Some(value) = &callback.provider_error_class {
        attributes.insert("tls_ops_provider_error_class".to_string(), value.clone());
    }
    if let Some(value) = &callback.provider_error_code {
        attributes.insert("tls_ops_provider_error_code".to_string(), value.clone());
    }
    if let Some(value) = &callback.provider_error_detail {
        attributes.insert("tls_ops_provider_error_detail".to_string(), value.clone());
    }

    let failure = if kind == EventType::TlsHandshakeFailed {
        let detail = callback
            .provider_error_detail
            .as_ref()
            .or(callback.error.as_ref())
            .cloned()
            .unwrap_or_else(|| MISSING_DETAIL.to_string());
        let reason = classify_tls_error(&detail).code().to_string();
        let source = callback.hook.peer().to_string();
        attributes.insert("detail".to_string(), detail.clone());
        attributes.insert("tls_failure_reason".to_string(), reason.clone());
        attributes.insert("tls_failure_source".to_string(), source.clone());
        Some(MitmproxyTlsFailure {
            source,
            reason,
            detail,
        })
    } else {
        None
    };

    MitmproxyTlsAdapterEvent {
        kind,
        context,
        attributes,
        failure,
    }
}

#[cfg(test)]
mod tests {
    use super::{adapt_mitmproxy_tls_callback, MitmproxyTlsCallback, MitmproxyTlsHook};
    use mitm_http::ApplicationProtocol;
    use mitm_observe::EventType;

    #[test]
    fn adapter_maps_failed_client_callback_to_tls_failed_with_taxonomy() {
        let callback = MitmproxyTlsCallback {
            flow_id: 42,
            client_addr: "127.0.0.1:50000".to_string(),
            server_host: "api.example.com".to_string(),
            server_port: 443,
            protocol: ApplicationProtocol::Http1,
            hook: MitmproxyTlsHook::TlsFailedClient,
            error: Some("certificate verify failed: unknown ca".to_string()),
            provider_error_class: Some("TlsException".to_string()),
            provider_error_code: Some("X509_UNKNOWN_CA".to_string()),
            provider_error_detail: None,
        };

        let adapted = adapt_mitmproxy_tls_callback(&callback);
        assert_eq!(adapted.kind, EventType::TlsHandshakeFailed);
        assert_eq!(
            adapted.attributes.get("peer").map(String::as_str),
            Some("downstream")
        );
        assert_eq!(
            adapted
                .attributes
                .get("tls_failure_reason")
                .map(String::as_str),
            Some("unknown_ca")
        );
        assert_eq!(
            adapted
                .attributes
                .get("tls_ops_provider")
                .map(String::as_str),
            Some("mitmproxy")
        );
        assert_eq!(
            adapted
                .attributes
                .get("tls_ops_provider_hook")
                .map(String::as_str),
            Some("tls_failed_client")
        );
    }

    #[test]
    fn adapter_maps_started_server_callback_to_tls_started() {
        let callback = MitmproxyTlsCallback {
            flow_id: 7,
            client_addr: "127.0.0.1:50001".to_string(),
            server_host: "example.org".to_string(),
            server_port: 443,
            protocol: ApplicationProtocol::Http1,
            hook: MitmproxyTlsHook::TlsHandshakeStartedServer,
            error: None,
            provider_error_class: None,
            provider_error_code: None,
            provider_error_detail: None,
        };

        let adapted = adapt_mitmproxy_tls_callback(&callback);
        assert_eq!(adapted.kind, EventType::TlsHandshakeStarted);
        assert!(adapted.failure.is_none());
        assert_eq!(
            adapted.attributes.get("peer").map(String::as_str),
            Some("upstream")
        );
    }
}
