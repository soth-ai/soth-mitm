use std::env;
use std::fs;
use std::future::Future;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::hyper::Request;
use hudsucker::rcgen::{Issuer, KeyPair};
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::rustls::pki_types::CertificateDer;
use hudsucker::rustls::{ClientConfig, RootCertStore};
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};
use hyper_rustls::HttpsConnectorBuilder;

#[derive(Clone)]
struct BenchHttpHandler {
    intercept: bool,
}

impl HttpHandler for BenchHttpHandler {
    fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> impl Future<Output = RequestOrResponse> + Send {
        async move { req.into() }
    }

    fn should_intercept(
        &mut self,
        _ctx: &HttpContext,
        _req: &Request<Body>,
    ) -> impl Future<Output = bool> + Send {
        let intercept = self.intercept;
        async move { intercept }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("HUDSUCKER_BENCH_BIND").unwrap_or_else(|_| "127.0.0.1:28482".to_string());
    let mode = env::var("HUDSUCKER_BENCH_MODE").unwrap_or_else(|_| "mitm".to_string());
    let ca_cert_path = env_path("HUDSUCKER_BENCH_CA_CERT_PATH");
    let ca_key_path = env_path("HUDSUCKER_BENCH_CA_KEY_PATH");
    let upstream_ca_path =
        env_path("HUDSUCKER_BENCH_UPSTREAM_CA_CERT_PATH").or_else(|| ca_cert_path.clone());

    let bind_addr: SocketAddr = bind.parse()?;
    let ca_cert_path = ca_cert_path.ok_or("HUDSUCKER_BENCH_CA_CERT_PATH is required")?;
    let ca_key_path = ca_key_path.ok_or("HUDSUCKER_BENCH_CA_KEY_PATH is required")?;
    let upstream_ca_path =
        upstream_ca_path.ok_or("HUDSUCKER_BENCH_UPSTREAM_CA_CERT_PATH is required")?;
    let intercept = !mode.eq_ignore_ascii_case("passthrough");

    let issuer = load_issuer(&ca_cert_path, &ca_key_path)?;
    let ca = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());
    let connector = build_https_connector(&upstream_ca_path)?;

    let proxy = Proxy::builder()
        .with_addr(bind_addr)
        .with_ca(ca)
        .with_http_connector(connector)
        .with_http_handler(BenchHttpHandler { intercept })
        .build()?;

    proxy.start().await?;
    Ok(())
}

fn load_issuer(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Issuer<'static, KeyPair>, Box<dyn std::error::Error>> {
    let cert_pem = fs::read_to_string(cert_path)?;
    let key_pem = fs::read_to_string(key_path)?;
    let key = KeyPair::from_pem(&key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)?;
    Ok(issuer)
}

fn build_https_connector(
    upstream_ca_path: &Path,
) -> Result<
    impl hudsucker::hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
    Box<dyn std::error::Error>,
> {
    let mut roots = RootCertStore::empty();
    for cert in load_certificates(upstream_ca_path)? {
        roots.add(cert)?;
    }

    let client = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(client)
        .https_or_http()
        .enable_http1()
        .build();
    Ok(connector)
}

fn load_certificates(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn env_path(key: &str) -> Option<PathBuf> {
    env::var(key)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from)
}
