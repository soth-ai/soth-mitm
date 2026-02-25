use std::env;
use std::path::PathBuf;

use soth_mitm::{
    generate_ca, load_ca_from_files, HandlerDecision, InterceptHandler, MitmConfig,
    MitmProxyBuilder, RawRequest,
};

struct ForwardOnly;

impl InterceptHandler for ForwardOnly {
    async fn on_request(&self, _request: &RawRequest) -> HandlerDecision {
        HandlerDecision::Allow
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("SOTH_MITM_BENCH_BIND").unwrap_or_else(|_| "127.0.0.1:28080".to_string());
    let destination =
        env::var("SOTH_MITM_BENCH_DEST").unwrap_or_else(|_| "127.0.0.1:29080".to_string());
    let passthrough_unlisted = env_bool("SOTH_MITM_BENCH_PASSTHROUGH_UNLISTED", true);
    let verify_upstream_tls = env_bool("SOTH_MITM_BENCH_VERIFY_UPSTREAM_TLS", false);
    let use_ca = env_bool("SOTH_MITM_BENCH_USE_CA", true);
    let ca_cert_path = env_path("SOTH_MITM_BENCH_CA_CERT_PATH");
    let ca_key_path = env_path("SOTH_MITM_BENCH_CA_KEY_PATH");

    let mut config = MitmConfig::default();
    config.bind = bind.parse()?;
    config.interception.destinations = vec![destination];
    config.interception.passthrough_unlisted = passthrough_unlisted;
    config.upstream.verify_upstream_tls = verify_upstream_tls;
    config.process_attribution.enabled = false;
    config.body.buffer_request_bodies = false;
    config.handler.request_timeout_ms = 10_000;
    config.handler.response_timeout_ms = 10_000;
    if let Some(path) = ca_cert_path.as_ref() {
        config.tls.ca_cert_path = path.clone();
    }
    if let Some(path) = ca_key_path.as_ref() {
        config.tls.ca_key_path = path.clone();
    }

    let mut builder = MitmProxyBuilder::new(config, ForwardOnly);
    if use_ca {
        let ca = match (ca_cert_path.as_ref(), ca_key_path.as_ref()) {
            (Some(cert), Some(key)) => load_ca_from_files(cert, key)?,
            _ => generate_ca()?,
        };
        builder = builder.with_ca(ca);
    }

    builder.build()?.run().await?;
    Ok(())
}

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

fn env_path(key: &str) -> Option<PathBuf> {
    env::var(key)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from)
}
