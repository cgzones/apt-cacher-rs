//! Port validation shared by request targets, CONNECT and redirects.

use std::num::NonZero;

use http::uri::Authority;

/// The default port of the `http` scheme, which names the same resource as
/// no port (RFC 3986 §6.2.3).
pub(crate) const HTTP_DEFAULT_PORT: u16 = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("port must be a decimal number between 1 and 65535")]
pub(crate) struct InvalidPort;

/// Read an optional port without conflating an invalid explicit port with
/// an absent one, as `Authority::port_u16` does. RFC 3986 permits an empty
/// port, which uses the scheme's default just like an absent port. CONNECT
/// callers must additionally require `Some`.
pub(crate) fn port(authority: &Authority) -> Result<Option<NonZero<u16>>, InvalidPort> {
    let host_port = authority
        .as_str()
        .rsplit_once('@')
        .map_or(authority.as_str(), |(_, host_port)| host_port);
    // `host()` includes IPv6 brackets and excludes userinfo. Looking only
    // after that host avoids interpreting an address segment or password
    // as a port.
    let suffix = host_port
        .strip_prefix(authority.host())
        .ok_or(InvalidPort)?;
    if suffix.is_empty() || suffix == ":" {
        return Ok(None);
    }
    let port = suffix.strip_prefix(':').ok_or(InvalidPort)?;
    if !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(InvalidPort);
    }
    port.parse().map(Some).map_err(|_invalid_port| InvalidPort)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_are_validated_after_the_whole_host() {
        for host in [
            "mirror.example",
            "192.0.2.1",
            "[2001:db8::80]",
            "[::ffff:192.0.2.1]",
        ] {
            for (suffix, expected) in [
                ("", Ok(None)),
                (":", Ok(None)),
                (":1", Ok(NonZero::new(1))),
                (":00080", Ok(NonZero::new(80))),
                (":65535", Ok(NonZero::new(u16::MAX))),
                (":0", Err(InvalidPort)),
                (":000", Err(InvalidPort)),
                (":65536", Err(InvalidPort)),
                (":99999999999999999999", Err(InvalidPort)),
                (":nonsense", Err(InvalidPort)),
                (":+80", Err(InvalidPort)),
                (":-1", Err(InvalidPort)),
            ] {
                for userinfo in ["", "user:password@"] {
                    let text = format!("{userinfo}{host}{suffix}");
                    let authority: Authority = text.parse().expect("authority syntax");
                    assert_eq!(port(&authority), expected, "{text}");
                }
            }
        }
    }
}
