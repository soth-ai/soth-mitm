use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use arc_swap::ArcSwap;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolveHosts, ResolverConfig, ResolverOpts,
    CLOUDFLARE,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;

/// Global DNS resolver instance, hot-swappable at runtime.
///
/// Uses hickory-resolver to send DNS queries directly over UDP/TCP to
/// nameservers, completely bypassing libc `getaddrinfo`. This prevents the
/// circular dependency where the proxy's own DNS resolution would route back
/// through itself when acting as the system proxy.
///
/// Wrapped in [`ArcSwap`] so the resolver can be replaced without restarting
/// the proxy. In-flight queries on the previous resolver complete safely via
/// Arc refcounting.
static DNS_RESOLVER: LazyLock<ArcSwap<TokioResolver>> =
    LazyLock::new(|| ArcSwap::from_pointee(build_resolver(None)));

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
    DNS_RESOLVER.store(Arc::new(resolver));
}

/// Re-initializes the global DNS resolver with new nameserver configuration.
///
/// Unlike [`install_dns_resolver`], this can be called at any time — including
/// while the proxy is actively handling traffic. In-flight DNS queries on the
/// previous resolver complete safely via Arc refcounting; new queries
/// immediately use the replacement resolver.
pub(crate) fn reinstall_dns_resolver(nameservers: Option<&[String]>) {
    let resolver = build_resolver(nameservers);
    DNS_RESOLVER.store(Arc::new(resolver));
    tracing::info!("dns resolver reloaded");
}

/// Resolve A/AAAA records for `host` and return socket addresses with `port`.
///
/// Primary path is hickory, querying nameservers directly (bypassing
/// `getaddrinfo`) to avoid the proxy resolving its own DNS through itself.
/// But direct-to-nameserver querying cannot answer several classes of name
/// that the OS stub resolver can, and on those networks a hard failure here
/// means the proxy drops connectivity the user would otherwise have:
///
///   - outbound :53 firewalled (hotels, hardened corp) — only the local
///     stub resolver is permitted
///   - IPv6-only / DNS64-NAT64 — the OS synthesizes AAAA the direct query
///     can't
///   - split-horizon / internal corp names / Tailscale MagicDNS / `.local`
///     mDNS / `/etc/hosts` overrides
///
/// So on any hickory failure (or an empty answer) we **fail open** to the OS
/// resolver via `getaddrinfo`. The loop concern that motivated bypassing
/// `getaddrinfo` in the first place does not apply on this path: it is only
/// reached when the direct query already couldn't answer, and selective-MITM
/// means a DoH/DoT resolver the OS might use is tunnelled, not intercepted.
/// IP literals are returned directly without any query.
pub(crate) async fn resolve_host(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    // Fast path: IP literals don't need DNS.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let resolver = DNS_RESOLVER.load();

    let start = std::time::Instant::now();
    match resolver.lookup_ip(host).await {
        Ok(response) => {
            let addrs: Vec<SocketAddr> = response
                .iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect();
            if addrs.is_empty() {
                // A successful lookup with no usable records — treat like a
                // failure and let the OS resolver try (it may know the name
                // via /etc/hosts, mDNS, or DNS64 synthesis).
                return resolve_via_os_fallback(host, port, "hickory returned no addresses").await;
            }
            let elapsed = start.elapsed();
            tracing::debug!(
                host,
                port,
                elapsed_ms = elapsed.as_millis() as u64,
                addr_count = addrs.len(),
                "dns resolution succeeded"
            );
            Ok(addrs)
        }
        Err(error) => {
            let elapsed = start.elapsed();
            let kind = net_error_kind(&error);
            tracing::warn!(
                host,
                elapsed_ms = elapsed.as_millis() as u64,
                error = %error,
                "hickory dns resolution failed; falling back to OS resolver"
            );
            resolve_via_os_fallback(host, port, "hickory query failed")
                .await
                .map_err(|os_error| {
                    // Both resolvers failed. Surface hickory's error kind
                    // (the caller distinguishes TimedOut / NotFound) but
                    // include both causes for diagnosis.
                    std::io::Error::new(
                        kind,
                        format!(
                            "dns resolution failed for {host}: hickory={error}; os_fallback={os_error}"
                        ),
                    )
                })
        }
    }
}

/// Caps concurrent `getaddrinfo` fallbacks. `tokio::net::lookup_host`
/// dispatches libc `getaddrinfo` onto the blocking pool, and the caller's
/// `tokio::time::timeout` only *drops the future* — it cannot cancel the
/// in-flight syscall, which keeps running on its thread until the OS stub
/// returns. On a firewalled-`:53` network (where hickory fails and every
/// connection then falls back) a burst could otherwise pin the whole blocking
/// pool. This bounds it: past the cap we skip the fallback and surface the
/// hickory error rather than pinning more threads.
static OS_FALLBACK_SLOTS: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(128));

/// Fail-open resolution via the OS stub (`getaddrinfo`) for the cases the
/// direct hickory query can't answer (firewalled `:53`, IPv6-only DNS64,
/// split-horizon, `/etc/hosts`, mDNS/MagicDNS).
///
/// NOTE on bounding: the caller wraps this in the connect deadline, which
/// bounds *latency* but NOT the underlying `getaddrinfo` syscall — that runs
/// on a blocking-pool thread that is not reclaimed when the deadline fires.
/// Concurrency is therefore capped via [`OS_FALLBACK_SLOTS`] so a storm on a
/// resolver-down network can't exhaust the pool.
async fn resolve_via_os_fallback(
    host: &str,
    port: u16,
    reason: &str,
) -> std::io::Result<Vec<SocketAddr>> {
    let _slot = OS_FALLBACK_SLOTS.try_acquire().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "os resolver fallback concurrency cap reached",
        )
    })?;
    let start = std::time::Instant::now();
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("os resolver returned no addresses for {host}"),
        ));
    }
    tracing::info!(
        host,
        port,
        addr_count = addrs.len(),
        elapsed_ms = start.elapsed().as_millis() as u64,
        reason,
        "resolved via OS getaddrinfo fallback"
    );
    Ok(addrs)
}

fn net_error_kind(error: &hickory_resolver::net::NetError) -> std::io::ErrorKind {
    use hickory_resolver::net::{DnsError, NetError};
    match error {
        NetError::Timeout => std::io::ErrorKind::TimedOut,
        NetError::Dns(DnsError::NoRecordsFound(_)) => std::io::ErrorKind::NotFound,
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

    let nameserver_addrs: Vec<String> = config
        .name_servers()
        .iter()
        .flat_map(|ns| {
            ns.connections
                .iter()
                .map(move |c| format!("{}:{}/{:?}", ns.ip, c.port, c.protocol))
        })
        .collect();
    tracing::info!(
        nameservers = ?nameserver_addrs,
        custom = has_custom,
        "initializing dns resolver"
    );

    let opts = resolver_opts();
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    *builder.options_mut() = opts;
    builder
        .build()
        .expect("hickory resolver build should succeed with validated config")
}

fn build_custom_config(nameservers: &[String]) -> ResolverConfig {
    let mut name_servers: Vec<NameServerConfig> = Vec::new();
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
        let mut udp = ConnectionConfig::new(ProtocolConfig::Udp);
        udp.port = socket_addr.port();
        let mut tcp = ConnectionConfig::new(ProtocolConfig::Tcp);
        tcp.port = socket_addr.port();
        name_servers.push(NameServerConfig::new(
            socket_addr.ip(),
            true,
            vec![udp, tcp],
        ));
    }
    ResolverConfig::from_parts(None, vec![], name_servers)
}

fn system_config() -> ResolverConfig {
    let (system, _system_opts) =
        hickory_resolver::system_conf::read_system_conf().unwrap_or_else(|error| {
            tracing::warn!(
                error = %error,
                "failed to read system dns config; falling back to Cloudflare public DNS"
            );
            (
                ResolverConfig::udp_and_tcp(&CLOUDFLARE),
                ResolverOpts::default(),
            )
        });
    // Rebuild config with only nameservers, dropping search domains (e.g. `.local`)
    // inherited from the OS. Without this, hickory-resolver appends search suffixes
    // to bare hostnames, causing lookups like `polymarket.com.local.` which fail.
    let name_servers: Vec<NameServerConfig> = system.name_servers().to_vec();
    ResolverConfig::from_parts(None, vec![], name_servers)
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

    #[test]
    fn os_fallback_resolves_loopback_hostname() {
        // "localhost" is not resolvable via direct-to-nameserver querying
        // (it lives in /etc/hosts, which hickory is configured to ignore),
        // but the OS resolver always knows it. This exercises the fail-open
        // path end to end without network access.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let addrs = resolve_via_os_fallback("localhost", 443, "test")
                .await
                .expect("OS resolver must know localhost");
            assert!(!addrs.is_empty());
            assert!(addrs.iter().all(|addr| addr.ip().is_loopback()));
            assert!(addrs.iter().all(|addr| addr.port() == 443));
        });
    }

    #[test]
    fn os_fallback_errors_on_unresolvable_name() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let result =
                resolve_via_os_fallback("soth.invalid.nonexistent.test.", 80, "test").await;
            assert!(result.is_err(), "a bogus name must not resolve");
        });
    }

    #[test]
    fn resolve_host_falls_back_to_os_for_hosts_file_name() {
        // With the default resolver (use_hosts_file=Never) a hickory lookup of
        // "localhost" fails; resolve_host must fail open to the OS resolver
        // and still return the loopback address.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let addrs = resolve_host("localhost", 8080)
                .await
                .expect("resolve_host must fail open to the OS resolver for localhost");
            assert!(addrs.iter().all(|addr| addr.ip().is_loopback()));
        });
    }
}
