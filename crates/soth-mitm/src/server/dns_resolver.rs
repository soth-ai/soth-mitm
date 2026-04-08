use std::net::SocketAddr;
use std::sync::OnceLock;

use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::TokioResolver;

/// Global DNS resolver instance, initialized once at server start.
/// Uses hickory-resolver to send DNS queries directly over UDP/TCP to
/// nameservers, completely bypassing libc `getaddrinfo`. This prevents the
/// circular dependency where the proxy's own DNS resolution would route back
/// through itself when acting as the system proxy.
static DNS_RESOLVER: OnceLock<TokioResolver> = OnceLock::new();

/// Install the global DNS resolver with optional explicit nameservers.
///
/// When `nameservers` is `None` or empty, hickory-resolver auto-detects
/// system nameservers from `/etc/resolv.conf` (Linux) or `scutil --dns`
/// (macOS) and queries them directly over UDP/TCP — not via `getaddrinfo`.
///
/// When `nameservers` contains entries, those are used instead. Each entry
/// should be an IP address or `IP:port` (e.g., `"8.8.8.8"`, `"1.1.1.1:53"`,
/// `"[2606:4700::1111]:53"`).
pub(crate) fn install_dns_resolver(nameservers: Option<&[String]>) {
    let resolver = build_resolver(nameservers);
    let _ = DNS_RESOLVER.set(resolver);
}

/// Resolve A/AAAA records for `host` and return socket addresses with `port`.
/// Bypasses `getaddrinfo` entirely. IP literals are returned directly without
/// a DNS query.
pub(crate) async fn resolve_host(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    // Fast path: IP literals don't need DNS.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let resolver = DNS_RESOLVER.get_or_init(|| build_resolver(None));

    let response = resolver.lookup_ip(host).await.map_err(|error| {
        std::io::Error::new(
            resolve_error_kind(&error),
            format!("dns resolution failed for {host}: {error}"),
        )
    })?;

    let addrs: Vec<SocketAddr> = response.iter().map(|ip| SocketAddr::new(ip, port)).collect();
    Ok(addrs)
}

fn resolve_error_kind(error: &hickory_resolver::ResolveError) -> std::io::ErrorKind {
    use hickory_resolver::ResolveErrorKind;
    match error.kind() {
        ResolveErrorKind::Proto(proto) => {
            use hickory_resolver::proto::ProtoErrorKind;
            match proto.kind() {
                ProtoErrorKind::NoRecordsFound { .. } => std::io::ErrorKind::NotFound,
                ProtoErrorKind::Timeout => std::io::ErrorKind::TimedOut,
                _ => std::io::ErrorKind::Other,
            }
        }
        _ => std::io::ErrorKind::Other,
    }
}

fn build_resolver(nameservers: Option<&[String]>) -> TokioResolver {
    let has_custom = nameservers.is_some_and(|ns| !ns.is_empty());

    let config = if has_custom {
        build_custom_config(nameservers.unwrap())
    } else {
        system_config()
    };

    let opts = resolver_opts();
    let mut builder =
        TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
    *builder.options_mut() = opts;
    builder.build()
}

fn build_custom_config(nameservers: &[String]) -> ResolverConfig {
    let mut config = ResolverConfig::new();
    for ns in nameservers {
        let socket_addr = if let Ok(addr) = ns.parse::<SocketAddr>() {
            addr
        } else if let Ok(ip) = ns.parse::<std::net::IpAddr>() {
            SocketAddr::new(ip, 53)
        } else {
            tracing::warn!(nameserver = %ns, "skipping unparseable dns nameserver entry");
            continue;
        };
        // UDP primary, TCP fallback for truncated responses.
        config.add_name_server(NameServerConfig::new(socket_addr, Protocol::Udp));
        config.add_name_server(NameServerConfig::new(socket_addr, Protocol::Tcp));
    }
    config
}

fn system_config() -> ResolverConfig {
    let (config, _system_opts) = hickory_resolver::system_conf::read_system_conf().unwrap_or_else(
        |error| {
            tracing::warn!(
                error = %error,
                "failed to read system dns config; falling back to Cloudflare public DNS"
            );
            (ResolverConfig::cloudflare(), ResolverOpts::default())
        },
    );
    config
}

fn resolver_opts() -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.cache_size = 512;
    // Bypass /etc/hosts to prevent loops when the proxy is the system proxy.
    opts.use_hosts_file = ResolveHosts::Never;
    opts.positive_min_ttl = Some(std::time::Duration::from_secs(30));
    opts.positive_max_ttl = Some(std::time::Duration::from_secs(300));
    opts
}

#[cfg(test)]
mod dns_resolver_tests {
    use super::*;

    #[test]
    fn resolve_host_returns_ip_directly_for_ipv4_literal() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let addrs = resolve_host("127.0.0.1", 443).await.unwrap();
            assert_eq!(addrs.len(), 1);
            assert_eq!(addrs[0], "127.0.0.1:443".parse().unwrap());
        });
    }

    #[test]
    fn resolve_host_returns_ip_directly_for_ipv6_literal() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let addrs = resolve_host("::1", 80).await.unwrap();
            assert_eq!(addrs.len(), 1);
            assert_eq!(
                addrs[0],
                SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 80)
            );
        });
    }

    #[test]
    fn build_resolver_with_custom_nameservers_does_not_panic() {
        let nameservers = vec![
            "8.8.8.8".to_string(),
            "1.1.1.1:53".to_string(),
            "[2606:4700::1111]:53".to_string(),
        ];
        let _resolver = build_resolver(Some(&nameservers));
    }

    #[test]
    fn build_resolver_with_empty_nameservers_falls_back_to_system() {
        let _resolver = build_resolver(Some(&[]));
    }

    #[test]
    fn build_resolver_with_none_falls_back_to_system() {
        let _resolver = build_resolver(None);
    }

    #[test]
    fn build_resolver_skips_invalid_nameserver_entries() {
        let nameservers = vec!["not-an-ip".to_string(), "8.8.8.8".to_string()];
        let _resolver = build_resolver(Some(&nameservers));
    }
}
