//! Shared CONNECT-tunnel target validation used by every HTTP backend.
//!
//! Both the hyper and sendfile/splice backends call
//! [`validate_connect_target`] so their tunnel policy (enable flag, authority
//! bound, port ACL, mirror ACL) — and the metrics/log side effects — stay
//! identical. The per-request proxy-client ACL is *not* handled here; both
//! backends enforce `allowed_proxy_clients` for `CONNECT` in
//! `request_dispatch::preflight_method` before reaching this validator.

use core::num::NonZero;

use http::{StatusCode, uri::Uri};
use tracing::info;

use crate::{client_info::ClientInfo, config::Config, limits, metrics, warn_once_or_info};

/// A rejected CONNECT target: the status/body the backend should return to the
/// client. All logging and metric bumping already happened inside
/// [`validate_connect_target`].
pub(crate) struct ConnectReject {
    pub status: StatusCode,
    pub msg: &'static str,
}

/// Validate a CONNECT request's authority against tunnel policy.
///
/// On success returns the parsed `(host, port)`. On rejection returns a
/// [`ConnectReject`] and has already emitted the matching log line and bumped
/// the relevant metric, so both backends behave identically.
pub(crate) fn validate_connect_target(
    config: &Config,
    client: &ClientInfo,
    uri: &Uri,
) -> Result<(String, NonZero<u16>), ConnectReject> {
    if !config.https_tunnel_enabled {
        info!(
            "Rejecting https tunnel request for client {client} to {uri}: https tunneling is disabled (`https_tunnel_enabled`)"
        );
        metrics::TUNNEL_REJECTED_POLICY.increment();
        return Err(ConnectReject {
            status: StatusCode::FORBIDDEN,
            msg: "HTTPS tunneling disabled",
        });
    }

    // Bound the authority length before any further work. hyper already
    // bounds the request line, but defending here keeps the CONNECT path
    // self-contained against any future relaxation of those limits.
    if let Some(auth) = uri.authority()
        && auth.as_str().len() > limits::MAX_AUTHORITY_LEN
    {
        warn_once_or_info!(
            "Oversized CONNECT authority from client {client} ({} bytes); rejecting the tunnel request with 400",
            auth.as_str().len()
        );
        return Err(ConnectReject {
            status: StatusCode::BAD_REQUEST,
            msg: "Invalid CONNECT address",
        });
    }

    let Some((host, port)) = uri.authority().and_then(|a| {
        a.port_u16()
            .and_then(NonZero::new)
            .map(|p| (a.host().to_string(), p))
    }) else {
        warn_once_or_info!(
            "Invalid CONNECT address `{uri}` from client {client}; rejecting the tunnel request with 400"
        );
        return Err(ConnectReject {
            status: StatusCode::BAD_REQUEST,
            msg: "Invalid CONNECT address",
        });
    };

    if !config.https_tunnel_allowed_ports.is_empty()
        && config
            .https_tunnel_allowed_ports
            .binary_search(&port)
            .is_err()
    {
        info!("Rejecting https tunnel request for client {client} to disallowed port {port}");
        metrics::TUNNEL_REJECTED_POLICY.increment();
        return Err(ConnectReject {
            status: StatusCode::FORBIDDEN,
            msg: "HTTPS tunnel port not permitted",
        });
    }

    if !config.https_tunnel_allowed_mirrors.is_empty()
        && config
            .https_tunnel_allowed_mirrors
            .binary_search_by(|d| str::cmp(d, host.as_str()))
            .is_err()
    {
        info!("Rejecting https tunnel request for client {client} due to disallowed host {host}");
        metrics::AUTHZ_REJECTED_TUNNEL_MIRROR.increment();
        return Err(ConnectReject {
            status: StatusCode::FORBIDDEN,
            msg: "HTTPS tunnel target not permitted",
        });
    }

    Ok((host, port))
}
