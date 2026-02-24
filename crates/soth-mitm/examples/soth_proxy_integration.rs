use soth_mitm::{
    ConnectionInfo, HandlerAction, InterceptHandler, InterceptedRequest, MitmConfig,
    MitmProxyBuilder,
};

struct ForwardOnly;

impl InterceptHandler for ForwardOnly {
    async fn on_request(
        &self,
        _request: &InterceptedRequest,
        _connection: &ConnectionInfo,
    ) -> HandlerAction {
        HandlerAction::Forward
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = MitmConfig::default();
    config
        .interception
        .destinations
        .push("api.example.com:443".to_string());

    let _proxy = MitmProxyBuilder::new(config, ForwardOnly).build()?;
    Ok(())
}
