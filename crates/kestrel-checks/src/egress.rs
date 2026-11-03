//! Egress guard for server-side outbound HTTP to tenant-supplied URLs.
//!
//! Private (RFC 1918 and ULA) addresses stay reachable because monitoring
//! internal hosts is the product. Loopback, link-local (including cloud
//! metadata), unspecified, multicast and broadcast addresses are refused, as
//! are operator-listed endpoints such as the shared metric store. The check
//! runs on the addresses the client actually connects to, through a custom
//! resolver, so a name that re-resolves to a refused address is still refused.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

/// Server-side outbound policy. Cheap to clone behind an `Arc`.
#[derive(Debug, Clone, Default)]
pub struct EgressGuard {
    allow_loopback: bool,
    denied: Vec<(String, u16)>,
}

impl EgressGuard {
    /// A guard that refuses loopback unless `allow_loopback` is set.
    pub fn new(allow_loopback: bool) -> Self {
        Self {
            allow_loopback,
            denied: Vec::new(),
        }
    }

    /// Refuse `host:port` by name and by every address the name resolves to.
    pub fn deny_endpoint(mut self, host: &str, port: u16) -> Self {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        self.denied.push((host.to_ascii_lowercase(), port));
        self
    }

    /// True when `ip` is in a refused address class.
    pub fn blocked_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => blocked_v4(v4, self.allow_loopback),
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return !self.allow_loopback;
                }
                if let Some(v4) = embedded_v4(v6) {
                    return blocked_v4(v4, self.allow_loopback);
                }
                v6.is_unspecified()
                    || v6.is_multicast()
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
                    // AWS IPv6 instance metadata sits in ULA space.
                    || v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
            }
        }
    }

    /// Check a set of resolved addresses for `host:port`.
    pub async fn check_addrs(
        &self,
        host: &str,
        port: u16,
        addrs: &[SocketAddr],
    ) -> Result<(), String> {
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        if addrs.iter().any(|addr| self.blocked_ip(addr.ip())) {
            return Err("target address is not permitted".into());
        }
        for (denied_host, denied_port) in &self.denied {
            if *denied_port != port {
                continue;
            }
            if *denied_host == host {
                return Err("target address is not permitted".into());
            }
            let denied: Vec<IpAddr> =
                match tokio::net::lookup_host((denied_host.as_str(), *denied_port)).await {
                    Ok(found) => found.map(|addr| addr.ip()).collect(),
                    Err(_) => continue,
                };
            if addrs.iter().any(|addr| {
                denied
                    .iter()
                    .any(|ip| canonical(*ip) == canonical(addr.ip()))
            }) {
                return Err("target address is not permitted".into());
            }
        }
        Ok(())
    }

    /// Validate `url` and return a builder whose connections are guarded.
    ///
    /// Literal IP hosts are checked here because reqwest does not resolve them.
    /// Named hosts are checked by the resolver at connect time. Proxies are
    /// disabled so the checked address is the connected address, and callers
    /// must keep redirects disabled.
    pub async fn apply(
        self: &Arc<Self>,
        builder: reqwest::ClientBuilder,
        url: &str,
    ) -> Result<reqwest::ClientBuilder, String> {
        let parsed = reqwest::Url::parse(url).map_err(|_| "invalid URL".to_string())?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err("URL must use HTTP(S)".into());
        }
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| "URL has no port".to_string())?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "URL has no host".to_string())?
            .to_string();
        if let Ok(ip) = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            self.check_addrs(&host, port, &[SocketAddr::new(ip, port)])
                .await?;
        }
        Ok(builder.no_proxy().dns_resolver(Arc::new(GuardedResolve {
            guard: Arc::clone(self),
            port,
        })))
    }
}

fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    // NAT64 well-known prefix 64:ff9b::/96 carries an IPv4 address.
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [.., a, b, c, d] = v6.octets();
        return Some(Ipv4Addr::new(a, b, c, d));
    }
    // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d).
    v6.to_ipv4()
}

/// Fold IPv6 forms that carry an IPv4 address (mapped, compatible, NAT64)
/// onto that address, so denied endpoints match however they are written.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => embedded_v4(v6).map(IpAddr::V4).unwrap_or(ip),
        ip => ip,
    }
}

fn blocked_v4(ip: Ipv4Addr, allow_loopback: bool) -> bool {
    (ip.is_loopback() && !allow_loopback)
        || ip.is_unspecified()
        || ip.octets()[0] == 0
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
}

struct GuardedResolve {
    guard: Arc<EgressGuard>,
    port: u16,
}

impl reqwest::dns::Resolve for GuardedResolve {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let guard = Arc::clone(&self.guard);
        let port = self.port;
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                .await?
                .collect();
            guard
                .check_addrs(&host, port, &addrs)
                .await
                .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> { err.into() })?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_blocks_metadata_loopback_and_keeps_private_ranges() {
        let guard = EgressGuard::new(false);
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "fd00:ec2::254",
        ] {
            assert!(
                guard.blocked_ip(ip.parse().unwrap()),
                "{ip} must be refused"
            );
        }
        for ip in [
            "10.0.0.5",
            "172.16.1.1",
            "192.168.1.10",
            "fd12:3456::1",
            "8.8.8.8",
            "::ffff:10.0.0.5",
        ] {
            assert!(
                !guard.blocked_ip(ip.parse().unwrap()),
                "{ip} must be allowed"
            );
        }
        assert!(!EgressGuard::new(true).blocked_ip("127.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn egress_refuses_denied_endpoints_and_literal_addresses() {
        let guard = Arc::new(EgressGuard::new(true).deny_endpoint("127.0.0.1", 8428));
        let builder = || reqwest::Client::builder();
        assert!(guard
            .apply(builder(), "http://127.0.0.1:8428/federate")
            .await
            .is_err());
        assert!(guard
            .apply(builder(), "http://[::ffff:127.0.0.1]:8428/")
            .await
            .is_err());
        assert!(guard
            .apply(builder(), "http://[64:ff9b::7f00:1]:8428/")
            .await
            .is_err());
        assert!(guard
            .apply(builder(), "http://127.0.0.1:9100/")
            .await
            .is_ok());
        let strict = Arc::new(EgressGuard::new(false));
        assert!(strict
            .apply(builder(), "http://169.254.169.254/latest/meta-data/")
            .await
            .is_err());
        assert!(strict.apply(builder(), "file:///etc/passwd").await.is_err());
    }

    #[tokio::test]
    async fn egress_resolver_refuses_names_that_resolve_to_loopback() {
        let guard = Arc::new(EgressGuard::new(false));
        let client = guard
            .apply(reqwest::Client::builder(), "http://localhost:9/")
            .await
            .unwrap()
            .build()
            .unwrap();
        let err = client.get("http://localhost:9/").send().await.unwrap_err();
        assert!(format!("{err:?}").contains("not permitted"), "{err:?}");
    }
}
