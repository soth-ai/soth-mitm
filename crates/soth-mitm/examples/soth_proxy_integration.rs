use soth_mitm::{HandlerDecision, InterceptHandler, MitmConfig, MitmProxyBuilder, RawRequest};

struct ForwardOnly;

impl InterceptHandler for ForwardOnly {
    async fn on_request(&self, _request: &RawRequest) -> HandlerDecision {
        HandlerDecision::Allow
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
