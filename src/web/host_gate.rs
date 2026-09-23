//! `Host` gate of the web interface: the names an origin-form request may
//! address the daemon by.
//!
//! The web-interface ACL checks who is asking, not which name they asked
//! for, and that is not enough against DNS rebinding: a page an admin visits
//! re-points its own DNS name at the daemon's address and then reads `/`,
//! `/logs` and `/healthcheck` same-origin from the admin's browser, whose
//! address passes the ACL. The browser still sends the attacker's name in
//! `Host`, so the web interface answers only to names that cannot be
//! rebound: an IP literal, `localhost`, the system hostname and the
//! operator's `webif_hostnames`. Everything else is a 421 Misdirected
//! Request (`RejectReason::MisdirectedWebUi`).
//!
//! The set is built once at startup ([`WebifHosts::from_system`]); matching
//! ([`WebifHosts::permits`]) is pure so the rules are unit-testable.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::config::DomainName;

/// The DNS names, besides IP literals and `localhost`, the web interface
/// answers to.
#[derive(Debug)]
pub(crate) struct WebifHosts {
    /// Lowercase, without a trailing dot.
    names: Vec<Box<str>>,
}

impl WebifHosts {
    /// A set admitting only IP literals and `localhost`.
    #[cfg(test)]
    pub(crate) const NONE: Self = Self { names: Vec::new() };

    /// The system hostname (and, when it is a dotted name, its first label)
    /// plus the configured `webif_hostnames`.
    ///
    /// The fully qualified name is taken only from the kernel hostname: the
    /// resolver is not asked, because `hostname -f` style lookups can block
    /// startup on a broken DNS setup. A name the kernel does not report goes
    /// into `webif_hostnames`.
    #[must_use]
    pub(crate) fn from_system(configured: &[DomainName]) -> Self {
        let system = nix::unistd::gethostname()
            .ok()
            .and_then(|name| name.into_string().ok());
        Self::new(system.as_deref(), configured)
    }

    #[must_use]
    fn new(system_hostname: Option<&str>, configured: &[DomainName]) -> Self {
        let mut names: Vec<Box<str>> = Vec::new();
        let mut add = |name: &str| {
            let name = normalize(name);
            if !name.is_empty() && !names.iter().any(|n| **n == *name) {
                names.push(name.into_boxed_str());
            }
        };
        if let Some(hostname) = system_hostname {
            add(hostname);
            if let Some((short, _domain)) = hostname.split_once('.') {
                add(short);
            }
        }
        for name in configured {
            add(name.as_str());
        }
        Self { names }
    }

    /// The configured and derived names, for the startup log.
    pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(|n| &**n)
    }

    /// Whether a `Host` header value (`host[:port]`, IPv6 bracketed) names
    /// this daemon. A malformed value is refused.
    #[must_use]
    pub(crate) fn permits(&self, host_header: &[u8]) -> bool {
        let Ok(value) = std::str::from_utf8(host_header) else {
            return false;
        };

        if let Some(rest) = value.strip_prefix('[') {
            return rest.split_once(']').is_some_and(|(addr, suffix)| {
                valid_port_suffix(suffix) && addr.parse::<Ipv6Addr>().is_ok()
            });
        }
        let host = match value.split_once(':') {
            Some((host, port)) if valid_port(port) => host,
            Some(_) => return false,
            None => value,
        };

        if host.parse::<Ipv4Addr>().is_ok() {
            return true;
        }
        let host = host.strip_suffix('.').unwrap_or(host);
        host.eq_ignore_ascii_case("localhost")
            || self.names.iter().any(|n| n.eq_ignore_ascii_case(host))
    }
}

/// Lowercase, one trailing dot dropped (`localhost.` is `localhost`).
fn normalize(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// What may follow `]` in a bracketed IPv6 host: nothing or `:<port>`.
fn valid_port_suffix(suffix: &str) -> bool {
    suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port)
}

/// A port: RFC 3986 allows it to be empty, otherwise ASCII digits only.
fn valid_port(port: &str) -> bool {
    port.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured(names: &[&str]) -> Vec<DomainName> {
        names
            .iter()
            .map(|n| DomainName::new((*n).to_owned()).unwrap())
            .collect()
    }

    #[test]
    fn ip_literals_and_localhost_are_always_permitted() {
        let hosts = WebifHosts::NONE;
        for host in [
            "127.0.0.1",
            "127.0.0.1:3142",
            "10.1.2.3:80",
            "[::1]",
            "[::1]:3142",
            "[fe80::1]:",
            "localhost",
            "localhost:3142",
            "LOCALHOST",
            "LocalHost:3142",
            "localhost.",
            "localhost.:3142",
            "localhost:",
        ] {
            assert!(hosts.permits(host.as_bytes()), "{host}");
        }
    }

    #[test]
    fn rebindable_names_are_refused() {
        let hosts = WebifHosts::new(Some("cache"), &configured(&["apt.corp.example"]));
        for host in [
            "",
            "attacker.example",
            "attacker.example:3142",
            "localhost.attacker.example",
            "127.0.0.1.attacker.example",
            "cache.attacker.example",
            "corp.example",
            "xapt.corp.example",
            "sub.localhost",
            "localhost..",
            // Malformed values.
            "::1",
            "[::1",
            "[::1]x",
            "[::1]:x",
            "[localhost]",
            "localhost:3142:1",
            "localhost:port",
            "127.0.0.1:-1",
            "local host",
        ] {
            assert!(!hosts.permits(host.as_bytes()), "{host}");
        }
        assert!(!hosts.permits(b"localhost\xff"));
    }

    #[test]
    fn system_hostname_and_configured_names_are_permitted() {
        let hosts = WebifHosts::new(
            Some("Cache.Corp.Example"),
            &configured(&["apt.corp.example", "Mirror.Example"]),
        );
        for host in [
            "cache",
            "CACHE:3142",
            "cache.corp.example",
            "cache.corp.example.:3142",
            "apt.corp.example",
            "APT.Corp.Example:80",
            "mirror.example",
        ] {
            assert!(hosts.permits(host.as_bytes()), "{host}");
        }
        assert_eq!(
            hosts.names().collect::<Vec<_>>(),
            [
                "cache.corp.example",
                "cache",
                "apt.corp.example",
                "mirror.example"
            ]
        );
    }

    #[test]
    fn missing_system_hostname_leaves_the_builtin_names() {
        let hosts = WebifHosts::new(None, &[]);
        assert_eq!(hosts.names().count(), 0);
        assert!(hosts.permits(b"localhost"));
        assert!(!hosts.permits(b"cache"));
    }
}
