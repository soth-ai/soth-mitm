use soth_mitm::{
    generate_ca, HandlerAction, InterceptHandler, InterceptedRequest, MitmConfig, MitmProxyBuilder,
};

struct ForwardHandler;

impl InterceptHandler for ForwardHandler {
    async fn on_request(
        &self,
        _request: &InterceptedRequest,
        _connection: &soth_mitm::ConnectionInfo,
    ) -> HandlerAction {
        HandlerAction::Forward
    }
}

#[test]
fn builder_constructs_proxy_shell() {
    let mut config = MitmConfig::default();
    config
        .interception
        .destinations
        .push("api.example.com:443".to_string());
    let builder = MitmProxyBuilder::new(config, ForwardHandler);
    let proxy = builder.build().expect("build proxy shell");
    let _ = proxy;
}

#[test]
fn generate_ca_returns_non_empty_material() {
    let ca = generate_ca().expect("generate local CA");
    assert!(!ca.cert_pem.is_empty());
    assert!(!ca.key_pem.is_empty());
    assert!(!ca.fingerprint.is_empty());
}
