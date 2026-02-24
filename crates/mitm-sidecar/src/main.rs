use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::NoopEventConsumer;
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mitm_config = MitmConfig::default();
    let policy = DefaultPolicyEngine::new(
        mitm_config.ignore_hosts.clone(),
        mitm_config.blocked_hosts.clone(),
    );
    let sink = NoopEventConsumer;
    let engine = MitmEngine::new(mitm_config.clone(), policy, sink);

    let sidecar_config = SidecarConfig {
        listen_addr: mitm_config.listen_addr,
        listen_port: mitm_config.listen_port,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: mitm_config.max_http_head_bytes,
    };

    eprintln!(
        "starting soth-mitm sidecar on {}:{}",
        sidecar_config.listen_addr, sidecar_config.listen_port
    );

    SidecarServer::new(sidecar_config, engine)?.run().await
}
