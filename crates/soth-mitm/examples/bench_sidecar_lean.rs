use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use mitm_core::{MitmConfig as CoreMitmConfig, MitmEngine};
use mitm_observe::NoopEventConsumer;
use mitm_policy::{FlowAction, PolicyDecision, PolicyEngine, PolicyInput, PolicyOverrideState};
use mitm_sidecar::{SidecarConfig, SidecarServer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BenchMode {
    Passthrough,
    Mitm,
}

#[derive(Debug, Clone, Copy)]
struct BenchPolicy {
    mode: BenchMode,
}

impl PolicyEngine for BenchPolicy {
    fn decide(&self, _input: &PolicyInput) -> PolicyDecision {
        let action = match self.mode {
            BenchMode::Passthrough => FlowAction::Tunnel,
            BenchMode::Mitm => FlowAction::Intercept,
        };
        PolicyDecision {
            action,
            reason: "bench_policy".to_string(),
            override_state: PolicyOverrideState::default(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("SOTH_LEAN_BENCH_BIND").unwrap_or_else(|_| "127.0.0.1:28483".to_string());
    let mode =
        parse_mode(&env::var("SOTH_LEAN_BENCH_MODE").unwrap_or_else(|_| "mitm".to_string()))?;
    let ca_cert_path = env_path("SOTH_LEAN_BENCH_CA_CERT_PATH")
        .ok_or("SOTH_LEAN_BENCH_CA_CERT_PATH is required")?;
    let ca_key_path =
        env_path("SOTH_LEAN_BENCH_CA_KEY_PATH").ok_or("SOTH_LEAN_BENCH_CA_KEY_PATH is required")?;

    let bind_addr: SocketAddr = bind.parse()?;

    let mut core = CoreMitmConfig::default();
    core.listen_addr = bind_addr.ip().to_string();
    core.listen_port = bind_addr.port();
    core.ca_cert_pem_path = Some(ca_cert_path.to_string_lossy().to_string());
    core.ca_key_pem_path = Some(ca_key_path.to_string_lossy().to_string());
    core.upstream_tls_insecure_skip_verify = true;

    let mut sidecar = SidecarConfig::default();
    sidecar.listen_addr = bind_addr.ip().to_string();
    sidecar.listen_port = bind_addr.port();

    let engine = MitmEngine::new_checked(core, BenchPolicy { mode }, NoopEventConsumer)
        .map_err(|error| format!("invalid core config: {error}"))?;
    let server = SidecarServer::new(sidecar, engine)?;
    server.run().await?;
    Ok(())
}

fn parse_mode(raw: &str) -> Result<BenchMode, Box<dyn std::error::Error>> {
    if raw.eq_ignore_ascii_case("passthrough") {
        return Ok(BenchMode::Passthrough);
    }
    if raw.eq_ignore_ascii_case("mitm") {
        return Ok(BenchMode::Mitm);
    }
    Err(format!("unsupported SOTH_LEAN_BENCH_MODE: {raw}").into())
}

fn env_path(key: &str) -> Option<PathBuf> {
    env::var(key)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from)
}
