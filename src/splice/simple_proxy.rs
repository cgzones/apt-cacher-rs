//! Cache-less pass-through relay: [`splice_simple_proxy`] connects upstream,
//! forwards the request and relays the complete response (headers rewritten
//! by [`rewrite_simple_proxy_headers`], body via `BodyFraming::relay_to_client`)
//! with no caching, active-download tracking or resume handling.

use std::io::ErrorKind;

use http::StatusCode;
use tokio::net::TcpStream;
use tracing::{debug, info, trace};

use crate::database_task::{DatabaseCommand, send_db_command};
use crate::deb_mirror::{Mirror, Origin, OriginSighting};
use crate::error::ErrorReport;
use crate::http_helpers::{
    ConnectionAction, ConnectionVersion, WritePhase, write_all_to_stream, write_invalid_response,
};
use crate::humanfmt::HumanFmt;
use crate::limits::MAX_UPSTREAM_HEADERS;
use crate::precise_instant::PreciseInstant;
use crate::rate_log;
use crate::{
    build_info::APP_VIA, client_counter, client_info::ClientInfo, metrics, warn_once_or_info,
    warn_once_or_info_logged,
};

use super::acquire::{UpstreamExchange, standard_upstream_connect};
use super::http::BodyFraming;
use super::{SpliceProxyError, VOLATILE_BODY_MAX};
use crate::transfer_error::UpstreamError;

/// Hop-by-hop headers per RFC 9110 §7.6.1 — must not be forwarded to the client.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

/// Body-framing headers: replaced by the framing the relay applies, never
/// forwarded (see [`rewrite_simple_proxy_headers`]).
const FRAMING: &[&str] = &["content-length", "transfer-encoding"];

/// Rewrite upstream response headers for the simple-proxy pass-through.
///
/// Strips hop-by-hop headers and emits exactly one `Connection:` header
/// matching the client's keep-alive decision regardless of how many
/// `Connection:` headers the upstream sent (they're hop-by-hop and therefore
/// all dropped during the filter pass).
///
/// The upstream's `Content-Length` / `Transfer-Encoding` lines are never
/// forwarded either: the head announces `framing`, the framing the relay
/// applies (`BodyFraming::header_line`). Forwarding them would let a client
/// frame the body by a line the relay ignored (a second `Transfer-Encoding`,
/// a conflicting `Content-Length`) or lose it to a `Connection:` nomination,
/// and read the body's tail as a forged next response. `conn_action` must
/// already be `framing`'s verdict (`BodyFraming::client_action`).
///
/// Extracted from `splice_simple_proxy` so the filtering invariants can be
/// unit-tested without requiring a live upstream socket.
pub(super) fn rewrite_simple_proxy_headers(
    raw_headers: &[u8],
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    status_code: StatusCode,
    framing: BodyFraming,
) -> std::io::Result<String> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_UPSTREAM_HEADERS];
    let mut parsed = httparse::Response::new(&mut headers);
    if parsed.parse(raw_headers).is_err() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "failed to re-parse upstream headers for rewrite",
        ));
    }

    // RFC 9110 §7.6.1: the Connection header nominates further connection-specific
    // field names that an intermediary must remove before forwarding.
    // Borrowed from `raw_headers`, and compared case-insensitively below, so
    // no owned lowercase copy of each token is needed.
    let mut connection_nominated: Vec<&str> = Vec::new();
    for h in parsed.headers.iter() {
        if h.name.eq_ignore_ascii_case("connection")
            && let Ok(v) = std::str::from_utf8(h.value)
        {
            connection_nominated.extend(v.split(',').map(str::trim).filter(|tok| !tok.is_empty()));
        }
    }

    let mut buf = format!("{conn_version} {status_code}\r\nConnection: {conn_action}\r\n");
    if let Some(line) = framing.header_line(status_code) {
        buf.push_str(&line);
    }
    for h in parsed.headers.iter() {
        if HOP_BY_HOP
            .iter()
            .chain(FRAMING)
            .any(|n| h.name.eq_ignore_ascii_case(n))
        {
            continue;
        }
        if connection_nominated
            .iter()
            .any(|n| h.name.eq_ignore_ascii_case(n))
        {
            continue;
        }
        // Reject non-ASCII header values: HTTP headers are ASCII per RFC
        // 9110 §5.5, and non-ASCII bytes smuggled via `from_utf8_lossy`
        // would silently introduce U+FFFD replacement chars into the
        // rewritten headers.
        let Ok(value) = std::str::from_utf8(h.value) else {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("non-UTF8 value for header `{}`", h.name),
            ));
        };
        if value
            .bytes()
            .any(|b| !b.is_ascii() || b == b'\r' || b == b'\n')
        {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid bytes in header `{}` value", h.name),
            ));
        }
        buf.push_str(h.name);
        buf.push_str(": ");
        buf.push_str(value);
        buf.push_str("\r\n");
    }
    buf.push_str("Via: ");
    buf.push_str(APP_VIA);
    buf.push_str("\r\n");
    buf.push_str("\r\n");
    Ok(buf)
}

/// Connects to upstream, sends a GET request, and forwards the complete response
/// (headers + body) to the client.  No caching, no active-download tracking,
/// no resume handling — just a transparent relay.
///
/// Returns what becomes of the client connection: `conn_action`, unless the
/// relayed body was close-delimited and the connection has to close.
pub(crate) async fn splice_simple_proxy(
    client_stream: &TcpStream,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    mirror: &Mirror,
    upstream_path: &str,
    client: ClientInfo,
    request_received_at: PreciseInstant,
) -> Result<ConnectionAction, SpliceProxyError> {
    let host_authority = mirror.format_authority();
    // Strip the query so cache identity (registry keys, Origin rows) stays
    // path-only; the query still rides on the upstream GET line via
    // `upstream_path`. Matches the hyper backend.
    let original_uri_path = upstream_path
        .split_once('?')
        .map_or(upstream_path, |(path, _)| path);

    // Account this passthrough under `ACTIVE_CLIENT_DOWNLOADS` for the
    // duration of the function (RAII drop on every return path). The hyper
    // passthrough is counted via `ClientCountedBody`; the splice passthrough
    // serves bytes synchronously inside this frame and would otherwise be
    // invisible to the counter.
    let _client_count = client_counter::ClientDownload::new();

    let UpstreamExchange {
        conn: upstream,
        response: resp,
        header_buf: hdr_buf,
        header_end: hdr_end,
        reused: _,
    } = standard_upstream_connect(mirror, host_authority, upstream_path, 0, None, None, None)
        .await
        .map_err(|err| {
            // The report names the attempted target itself.
            SpliceProxyError::Upstream(err.conclude(|err| {
                warn_once_or_info_logged!(
                    "simple proxy: failed to fetch the pass-through for client {client}; returning 502:  {}",
                    ErrorReport(err)
                )
            }))
        })?;

    debug!(
        "simple proxy: upstream returned {} for {upstream_path} from {host_authority}",
        resp.status_code
    );

    // Fail closed before any byte of the head goes out: an interim head or a
    // body prefix beyond the declared length would hand the client bytes the
    // upstream appended (a forged second response). The socket still holds
    // the unread remainder, so the connection must not be pooled.
    let body_prefix = &hdr_buf[hdr_end..];
    if let Err(reason) = resp.check_relayable(body_prefix.len() as u64) {
        reason.record_metrics();
        warn_once_or_info!(
            "simple proxy: unrelayable upstream response {} for {upstream_path} from {host_authority} ({}); returning 502",
            resp.status_code,
            reason.body()
        );
        return write_invalid_response(
            client_stream,
            conn_version,
            conn_action,
            StatusCode::BAD_GATEWAY,
            reason.body(),
            None,
        )
        .await
        .map(|()| conn_action)
        .map_err(SpliceProxyError::client("simple-proxy reject 502"));
    }

    // Rewrite response headers: adjust HTTP version and Connection header
    // to match the client's protocol version and keep-alive strategy, which
    // a close-delimited body overrides.
    let conn_action = resp.framing.client_action(conn_action);
    let rewritten_headers = match rewrite_simple_proxy_headers(
        &hdr_buf[..hdr_end],
        conn_version,
        conn_action,
        resp.status_code,
        resp.framing,
    ) {
        Ok(s) => s,
        Err(err) => {
            let reported = UpstreamError::io("passthrough headers", err).conclude(|err| {
                warn_once_or_info_logged!(
                    "simple proxy: failed to rewrite headers for {upstream_path} from {host_authority}; returning 502:  {}",
                    ErrorReport(err)
                )
            });
            return Err(SpliceProxyError::Upstream(reported));
        }
    };

    trace!("Outgoing rewritten headers:\n{rewritten_headers}");

    metrics::record_client_status(resp.status_code);
    metrics::REQUESTS_PASSTHROUGH.increment();

    // Mirror the hyper simple-proxy passthrough: record an Origin row on a
    // 2xx response (only that proves the index exists), for a path the
    // cache itself would accept, so the cleanup machinery can find the
    // owning mirror.
    if resp.status_code.is_success()
        && let Some(origin) = Origin::from_path(
            original_uri_path,
            mirror.host().clone(),
            mirror.port(),
            &client,
        )
    {
        let cmd = DatabaseCommand::Origin(origin, OriginSighting::Upstream);
        send_db_command(cmd).await;
    }

    let t_client_first = PreciseInstant::now();
    write_all_to_stream(
        client_stream,
        rewritten_headers.as_bytes(),
        WritePhase::Header,
    )
    .await
    .map_err(SpliceProxyError::client("simple-proxy headers"))?;

    // Forward the body that arrived with the headers plus the rest, framed
    // per the upstream's framing. The parser resolved it (or refused an
    // ambiguous head), and `rewrite_simple_proxy_headers` above announced
    // exactly that framing, so the headers and the body framing agree.
    let forwarded: u64 = resp
        .framing
        .relay_to_client(upstream, client_stream, body_prefix, VOLATILE_BODY_MAX)
        .await
        .map_err(|failure| SpliceProxyError::AfterHeader {
            phase: "simple-proxy body",
            failure,
        })?;

    let t_done = PreciseInstant::now();
    let in_time = request_received_at.elapsed();
    info!(
        "simple proxy: passed through {upstream_path} from host {host_authority} for client {client} in {} ({}, {})",
        HumanFmt::Time(in_time),
        rate_log::upstream_segment(forwarded, t_done.duration_since(resp.request_sent_at)),
        rate_log::client_segment(forwarded, t_done.duration_since(t_client_first)),
    );

    metrics::SERVED_PASSTHROUGH.increment();
    metrics::SERVED_TOTAL.increment();

    Ok(conn_action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrite_simple_proxy_headers_single_connection() {
        // Upstream sends two Connection headers; the rewrite must emit
        // exactly one (ours), regardless of how many the upstream sent.
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Connection: keep-alive\r\n\
                    Connection: close\r\n\
                    Content-Type: text/plain\r\n\
                    Content-Length: 5\r\n\
                    \r\n";
        let out = rewrite_simple_proxy_headers(
            raw,
            ConnectionVersion::Http11,
            ConnectionAction::KeepAlive,
            StatusCode::OK,
            BodyFraming::ContentLength(5),
        )
        .expect("rewrite should succeed");

        let connection_lines = out
            .split("\r\n")
            .filter(|line| line.to_ascii_lowercase().starts_with("connection:"))
            .count();
        assert_eq!(
            connection_lines, 1,
            "expected exactly one Connection header in rewritten output, got:\n{out}"
        );
        assert!(out.contains("Connection: keep-alive\r\n"));
        // Upstream's Connection values must not be forwarded.
        assert!(!out.contains("Connection: close"));
        // The relay's own Content-Length announces the framing.
        assert!(out.contains("Content-Length: 5\r\n"));
        assert!(out.contains("Via: "));
    }

    /// The upstream's framing lines never reach the client, however many
    /// there are or whichever `Connection:` nominates: the head announces the
    /// framing the relay applies, once, and nothing for a bodyless status.
    #[test]
    fn rewrite_simple_proxy_headers_announces_only_the_relay_framing() {
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Connection: Content-Length, Transfer-Encoding\r\n\
                    Transfer-Encoding: gzip\r\n\
                    Transfer-Encoding: chunked\r\n\
                    Content-Length: 5\r\n\
                    Content-Length: 7\r\n\
                    \r\n";
        let framing_lines = |out: &str| -> Vec<String> {
            out.split("\r\n")
                .filter(|line| {
                    let line = line.to_ascii_lowercase();
                    line.starts_with("content-length:") || line.starts_with("transfer-encoding:")
                })
                .map(str::to_owned)
                .collect()
        };
        for (status, framing, expected) in [
            (
                StatusCode::OK,
                BodyFraming::ContentLength(5),
                vec!["Content-Length: 5"],
            ),
            (
                StatusCode::OK,
                BodyFraming::Chunked,
                vec!["Transfer-Encoding: chunked"],
            ),
            (
                StatusCode::OK,
                BodyFraming::ContentLength(0),
                vec!["Content-Length: 0"],
            ),
            (StatusCode::OK, BodyFraming::CloseDelimited, vec![]),
            (
                StatusCode::NOT_MODIFIED,
                BodyFraming::ContentLength(0),
                vec![],
            ),
            (
                StatusCode::NO_CONTENT,
                BodyFraming::ContentLength(0),
                vec![],
            ),
        ] {
            let out = rewrite_simple_proxy_headers(
                raw,
                ConnectionVersion::Http11,
                framing.client_action(ConnectionAction::KeepAlive),
                status,
                framing,
            )
            .expect("rewrite should succeed");
            assert_eq!(
                framing_lines(&out),
                expected,
                "{framing:?}/{status}:\n{out}"
            );
        }
    }

    #[test]
    fn close_delimited_framing_closes_the_client_connection() {
        for (framing, expected) in [
            (BodyFraming::ContentLength(5), "keep-alive"),
            (BodyFraming::Chunked, "keep-alive"),
            (BodyFraming::CloseDelimited, "close"),
        ] {
            assert_eq!(
                framing
                    .client_action(ConnectionAction::KeepAlive)
                    .to_string(),
                expected,
                "{framing:?}"
            );
            assert_eq!(
                framing.client_action(ConnectionAction::Close).to_string(),
                "close",
                "{framing:?}"
            );
        }
    }

    #[test]
    fn test_rewrite_simple_proxy_headers_drops_cl_with_chunked() {
        // RFC 9112 §6.1: Content-Length must be dropped when Transfer-Encoding:
        // chunked is also present (smuggling defense).
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Transfer-Encoding: chunked\r\n\
                    Content-Length: 12345\r\n\
                    \r\n";
        let out = rewrite_simple_proxy_headers(
            raw,
            ConnectionVersion::Http11,
            ConnectionAction::Close,
            StatusCode::OK,
            BodyFraming::Chunked,
        )
        .expect("rewrite should succeed");
        assert!(!out.to_ascii_lowercase().contains("content-length:"));
        assert!(out.contains("Transfer-Encoding: chunked\r\n"));
    }

    #[test]
    fn test_rewrite_simple_proxy_headers_drops_connection_nominated() {
        // RFC 9110 §7.6.1: header fields nominated by the upstream Connection
        // header must be stripped before forwarding to the client.
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Connection: close, X-Custom-Hop\r\n\
                    X-Custom-Hop: secret\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n";
        let out = rewrite_simple_proxy_headers(
            raw,
            ConnectionVersion::Http11,
            ConnectionAction::Close,
            StatusCode::OK,
            BodyFraming::CloseDelimited,
        )
        .expect("rewrite should succeed");

        // The nominated field must not be forwarded.
        assert!(
            !out.to_ascii_lowercase().contains("x-custom-hop"),
            "Connection-nominated header leaked into output:\n{out}"
        );
        // End-to-end headers still pass through.
        assert!(out.contains("Content-Type: text/plain\r\n"));
        // Exactly one Connection header (ours), regardless of the upstream's.
        let connection_lines = out
            .split("\r\n")
            .filter(|line| line.to_ascii_lowercase().starts_with("connection:"))
            .count();
        assert_eq!(
            connection_lines, 1,
            "expected exactly one Connection header in rewritten output, got:\n{out}"
        );
    }
}
