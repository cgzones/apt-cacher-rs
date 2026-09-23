//! Unified request pre-flight and URI dispatch entry point shared by the
//! hyper backend in `hyper_conn.rs` and the sendfile backend in
//! `sendfile_conn.rs`.
//!
//! The pre-flight ([`preflight_method`] + [`preflight_target`]) is the
//! backend-independent part of "is this a request we serve at all": method
//! gate, proxy-client ACL for `CONNECT`, URI scheme and target-form gates,
//! the HTTP/1.1 `Host` requirement, the web-interface ACL and `Host` name
//! gate, and the port sanity check.  Both functions are pure over their
//! parameters (no `global_config()`); the backends feed them the
//! already-parsed request line and map the shared [`RejectReason`] onto their
//! response type.  The host allowlist stays in
//! `permitted_host_cache::authorize_cache_access`, which the backends call on
//! the returned [`RequestTarget::Proxy`] host.
//!
//! Owns the request-classification pipeline that previously appeared inline
//! in both dispatchers:
//!
//!   1. diff-request gate          - reject (410) pdiff URLs when configured,
//!      else fall through silently as `Unrecognized`
//!   2. [`normalize_uri_path`]     - collapse `//` runs / strip `.` segments
//!   3. [`parse_request_path`]     - structural shape-match into `ResourceFile`
//!   4. [`classify_request`]       - per-field URL-decode + allowlist validate
//!   5. unsafe-cache-path gate     - empty/dot segments, control bytes once
//!      decoded, on a classified request
//!   6. flat-blocklist collision   - host-level `flat/` claimed by structured
//!   7. deferred `Origin` DB write - for `Packages` requests w/ a real arch
//!   8. unsafe-proxy-path gate     - traversal/control bytes in passthrough
//!
//! Backends translate the returned [`DispatchOutcome`] into their response
//! type.  All logging, metric bumping, the deferred `Origin` DB write and
//! `record_uncacheable` happen here, so the two parallel paths cannot drift
//! apart.  [`dispatch_request`] runs exactly once per client request: the
//! sendfile backend's `NotApplicable` handoff carries its outcome to hyper
//! (`hyper_conn::HandoffPlan`) instead of letting hyper re-dispatch, so every
//! side-effect in here is exactly-once by construction.
//!
//! [`classify_request`]: crate::cache_layout::classify_request
//! [`normalize_uri_path`]: crate::deb_mirror::normalize_uri_path
//! [`parse_request_path`]: crate::deb_mirror::parse_request_path

use std::{cell::LazyCell, num::NonZero};

use http::{StatusCode, uri::Uri};
use tracing::{debug, trace};

use crate::{
    build_info::APP_VIA_PSEUDONYM,
    cache_layout::{self, ClassifyError, ConnectionDetails, MAX_DEBNAME_LEN},
    client_info::ClientInfo,
    config::{Alias, CacheHost, ClientHost, Config, IpNetOrAddr, resolve_alias},
    deb_mirror::{
        Mirror, is_diff_request_path, is_unsafe_cache_path, is_unsafe_proxy_path,
        normalize_uri_path, parse_request_path,
    },
    error::ErrorReport,
    flat_blocklist, global_config, info_once, metrics,
    precise_instant::PreciseInstant,
    uncacheables::record_uncacheable,
    warn_once_or_debug, warn_once_or_info,
    web::host_gate::WebifHosts,
};

/// Reason the pre-flight or the dispatcher refused a request with a fixed
/// 4xx response.
///
/// Backends call [`Self::response_parts`] to materialise the `(status, body)`
/// pair - the single status/body table for every shared rejection; logging
/// and metric bumping have already been done by the function that returned
/// the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RejectReason {
    /// Request method other than `GET` or `CONNECT`.
    UnsupportedMethod,
    /// A `CONNECT` from a client outside `allowed_proxy_clients`.  (A `GET`
    /// from such a client is refused by `authorize_cache_access` instead.)
    UnauthorizedClient,
    /// Absolute-form `GET` with a scheme other than `http` (HTTPS goes
    /// through `CONNECT`).
    UnsupportedScheme,
    /// HTTP/1.1 origin-form request without a `Host` header (RFC 9112 §3.2).
    MissingHost,
    /// Origin-form (web-interface) request from a client outside
    /// `allowed_webif_clients`.
    UnauthorizedWebUi,
    /// Origin-form (web-interface) request whose `Host` names neither an IP
    /// literal, `localhost`, the system hostname nor a `webif_hostnames`
    /// entry: a DNS-rebinding page addressing the daemon under its own name
    /// (see [`crate::web::host_gate`]).
    MisdirectedWebUi,
    /// Absolute-form `GET` naming port 0.
    InvalidPort,
    /// A `GET` whose request target carries no absolute path: the
    /// authority-form (`host:port`, the shape of a `CONNECT` target) or the
    /// asterisk-form.
    InvalidTarget,
    /// URL-decoding a request field produced invalid UTF-8.
    BadEncoding,
    /// A decoded field failed its allowlist validator
    /// (`valid_mirrorname`, `valid_distribution`, etc.).
    InvalidValue,
    /// The simple-proxy gate found `..`/`.` traversal segments or a
    /// control byte in the percent-decoded path, or the cache-route gate an
    /// empty or dot segment or a control byte in the decoded normalized path.
    UnsafePath,
    /// Configured to refuse pdiff requests, and this is one
    /// (`/Packages.diff/T-...`, `/Sources.diff/T-...`,
    /// `/Translation-XX.diff/T-...`).
    DiffRequest,
    /// The request's `Via` already names this proxy: it was asked to fetch
    /// from itself (a wildcard `allowed_mirrors` entry covering its own
    /// name).  Forwarding would loop and would let the loopback hop evaluate
    /// the web-interface ACL for the outer client.
    LoopDetected,
}

impl RejectReason {
    /// Whether this is an authorization refusal (the proxy-client or
    /// web-interface ACL).  Every backend closes the connection after one,
    /// so a refused client cannot keep its connection slot by asking again.
    #[must_use]
    #[cfg_attr(
        not(feature = "hyper"),
        expect(
            dead_code,
            reason = "the sendfile backend spells the same set out in `reject_result`"
        )
    )]
    pub(crate) const fn is_authorization_refusal(self) -> bool {
        match self {
            Self::UnauthorizedClient | Self::UnauthorizedWebUi | Self::MisdirectedWebUi => true,
            Self::UnsupportedMethod
            | Self::UnsupportedScheme
            | Self::MissingHost
            | Self::InvalidPort
            | Self::InvalidTarget
            | Self::BadEncoding
            | Self::InvalidValue
            | Self::UnsafePath
            | Self::DiffRequest
            | Self::LoopDetected => false,
        }
    }

    /// Fixed `(status, body)` pair associated with this reason.
    #[must_use]
    pub(crate) const fn response_parts(self) -> (StatusCode, &'static str) {
        match self {
            Self::UnsupportedMethod => (StatusCode::METHOD_NOT_ALLOWED, "Method not supported"),
            Self::UnauthorizedClient | Self::UnauthorizedWebUi => {
                (StatusCode::FORBIDDEN, "Unauthorized client")
            }
            Self::UnsupportedScheme => (StatusCode::BAD_REQUEST, "Unsupported URI scheme"),
            Self::MissingHost => (StatusCode::BAD_REQUEST, "Missing Host header"),
            Self::MisdirectedWebUi => (StatusCode::MISDIRECTED_REQUEST, "Misdirected request"),
            Self::InvalidPort => (StatusCode::BAD_REQUEST, "Invalid port"),
            Self::InvalidTarget => (StatusCode::BAD_REQUEST, "Invalid request target"),
            Self::BadEncoding => (StatusCode::BAD_REQUEST, "Unsupported URL encoding"),
            Self::InvalidValue | Self::UnsafePath => {
                (StatusCode::BAD_REQUEST, "Unsupported request")
            }
            Self::DiffRequest => (StatusCode::GONE, "Diff requests are not supported"),
            Self::LoopDetected => (StatusCode::LOOP_DETECTED, "Proxy loop detected"),
        }
    }
}

/// The client allowlists the pre-flight consults, borrowed from [`Config`],
/// and the web interface's `Host` names.
///
/// A view rather than `&Config` so unit tests can build one from slices
/// without parsing a TOML document.  `webif_clients` already has the
/// "inherit `allowed_proxy_clients`" fallback applied.
pub(crate) struct ClientAcls<'a> {
    pub(crate) proxy_clients: &'a [IpNetOrAddr],
    pub(crate) webif_clients: &'a [IpNetOrAddr],
    pub(crate) webif_hosts: &'a WebifHosts,
}

impl<'a> ClientAcls<'a> {
    #[must_use]
    pub(crate) fn new(config: &'a Config, webif_hosts: &'a WebifHosts) -> Self {
        Self {
            proxy_clients: &config.allowed_proxy_clients,
            webif_clients: config
                .allowed_webif_clients
                .as_deref()
                .unwrap_or(&config.allowed_proxy_clients),
            webif_hosts,
        }
    }
}

impl ClientAcls<'_> {
    /// Whether any request from `client` could be served: it passes the
    /// proxy-client or the web-interface list.  The accept loop closes a
    /// connection that passes neither before it takes a connection slot, so
    /// a host outside every list cannot hold slots until
    /// `client_idle_timeout` by sending nothing.
    #[must_use]
    pub(crate) fn admits(&self, client: &ClientInfo) -> bool {
        // The `Host` names only gate the web interface's requests, which
        // an accept-time check has not seen yet.
        let Self {
            proxy_clients,
            webif_clients,
            webif_hosts: _,
        } = self;
        client_permitted(proxy_clients, client) || client_permitted(webif_clients, client)
    }
}

/// Whether `client` passes `acl`.  An empty list permits everyone.
#[must_use]
pub(crate) fn client_permitted(acl: &[IpNetOrAddr], client: &ClientInfo) -> bool {
    if acl.is_empty() {
        return true;
    }
    let client_ip = client.ip();
    acl.iter().any(|ac| ac.contains(&client_ip))
}

/// What an accepted request method asks the proxy to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestKind {
    /// A `GET`; continue with [`preflight_target`].
    Get,
    /// A `CONNECT` from a client permitted by `allowed_proxy_clients`.  The
    /// backend parses the authority-form target and hands it to
    /// `connect_tunnel::validate_connect_target`.
    Connect,
}

/// Method gate shared by both backends: `GET` and `CONNECT` are the only
/// methods served, and `CONNECT` additionally passes the proxy-client ACL
/// here (the `GET` path enforces it inside `authorize_cache_access`).
///
/// Logs and bumps metrics for every rejection; the caller only maps the
/// [`RejectReason`] onto its response type.
pub(crate) fn preflight_method(
    method: &str,
    client: &ClientInfo,
    acls: &ClientAcls<'_>,
) -> Result<RequestKind, RejectReason> {
    match method {
        "GET" => Ok(RequestKind::Get),
        "CONNECT" => {
            if !client_permitted(acls.proxy_clients, client) {
                warn_once_or_info!("Unauthorized proxy client {client}; returning 403");
                metrics::AUTHZ_REJECTED_CLIENT.increment();
                return Err(RejectReason::UnauthorizedClient);
            }
            Ok(RequestKind::Connect)
        }
        m => {
            warn_once_or_info!(
                "Unsupported request method `{}` from client {client}; returning 405",
                m.escape_debug(),
            );
            Err(RejectReason::UnsupportedMethod)
        }
    }
}

/// Loop gate shared by both backends: a `Via` element whose received-by
/// token is this proxy's pseudonym means the request has already passed
/// through here (RFC 9110 §7.6.3).  `via_values` are the raw `Via` header
/// values of the request, comma lists included.
pub(crate) fn preflight_via<'a>(
    via_values: impl IntoIterator<Item = &'a str>,
    client: &ClientInfo,
) -> Result<(), RejectReason> {
    let names_us = via_values
        .into_iter()
        .flat_map(|value| value.split(','))
        .any(|element| element.split_whitespace().nth(1) == Some(APP_VIA_PSEUDONYM));
    if names_us {
        warn_once_or_info!(
            "Request from client {client} already passed through this proxy (Via names `{APP_VIA_PSEUDONYM}`); returning 508"
        );
        metrics::PROXY_LOOP_REJECTED.increment();
        return Err(RejectReason::LoopDetected);
    }
    Ok(())
}

/// Where an accepted `GET` is headed.
#[derive(Debug)]
pub(crate) enum RequestTarget<'a> {
    /// Origin-form request (no authority): the local web interface.  The
    /// web-interface ACL has passed.
    WebUi,
    /// Absolute-form request to a mirror.  `host` is the raw authority host,
    /// still to be validated by `permitted_host_cache::authorize_cache_access`
    /// (which also enforces `allowed_proxy_clients`); `port` is `None` for
    /// the default port.
    Proxy {
        host: &'a str,
        port: Option<NonZero<u16>>,
    },
}

/// Target gate shared by both backends for a `GET`: scheme check, the
/// absolute-path requirement, the HTTP/1.1 `Host` requirement, web-interface
/// ACL and `Host` name gate for origin-form requests, and the port sanity
/// check for absolute-form ones.
///
/// `host_header` yields the raw value of the request's `Host` header, if
/// any.  It is only consulted for origin-form requests, so the sendfile
/// backend's linear header scan is skipped on the proxy path.  Logs and
/// bumps metrics for every rejection.
pub(crate) fn preflight_target<'a, 'h>(
    uri: &'a Uri,
    is_http11: bool,
    host_header: impl FnOnce() -> Option<&'h [u8]>,
    client: &ClientInfo,
    acls: &ClientAcls<'_>,
) -> Result<RequestTarget<'a>, RejectReason> {
    // Proxy GET requests always use http://, HTTPS goes through CONNECT.
    // Reject any other scheme (e.g. ftp://, file://).
    if let Some(scheme) = uri.scheme()
        && *scheme != http::uri::Scheme::HTTP
    {
        warn_once_or_info!("Unsupported URI scheme `{scheme}` from client {client}; returning 400");
        return Err(RejectReason::UnsupportedScheme);
    }

    // Only the origin-form and the absolute-form name a resource path.  An
    // authority-form target (`GET host:port`) parses into a URI with an
    // authority but no path, which neither the dispatcher nor the upstream
    // relay can forward.
    if uri.path_and_query().is_none() || !uri.path().starts_with('/') {
        warn_once_or_info!(
            "Unsupported request target `{uri}` from client {client}; returning 400"
        );
        return Err(RejectReason::InvalidTarget);
    }

    let Some(authority) = uri.authority() else {
        // RFC 9112 §3.2: A server MUST respond with a 400 (Bad Request) status
        // code to any HTTP/1.1 request message that lacks a Host header field.
        // HTTP/1.0 did not require Host, so only enforce for 1.1.
        let host = host_header();
        if is_http11 && host.is_none() {
            debug!("Missing Host header from HTTP/1.1 request from client {client}");
            return Err(RejectReason::MissingHost);
        }

        // No authority means it's a direct request to the local web interface.
        if !client_permitted(acls.webif_clients, client) {
            warn_once_or_info!(
                "Unauthorized web-interface access by client {client}; returning 403"
            );
            metrics::AUTHZ_REJECTED_WEBUI.increment();
            return Err(RejectReason::UnauthorizedWebUi);
        }

        // DNS rebinding: a browser page that re-pointed its own name at us
        // passes the client ACL above but still names itself in `Host`.
        // An HTTP/1.0 request without `Host` has no name to check.
        if let Some(host) = host
            && !acls.webif_hosts.permits(host)
        {
            warn_once_or_info!(
                "Web-interface request from client {client} names the unrecognized host `{}`; returning 421",
                host.escape_ascii()
            );
            metrics::AUTHZ_REJECTED_WEBUI_HOST.increment();
            return Err(RejectReason::MisdirectedWebUi);
        }
        return Ok(RequestTarget::WebUi);
    };

    let port = match authority.port_u16() {
        Some(port) => {
            let Some(port) = NonZero::new(port) else {
                warn_once_or_info!(
                    "Unsupported request port 0 from client {client}; returning 400"
                );
                return Err(RejectReason::InvalidPort);
            };
            Some(port)
        }
        None => None,
    };

    Ok(RequestTarget::Proxy {
        host: authority.host(),
        port,
    })
}

/// Why the cache pipeline declined and the request must be forwarded
/// uncached.  The sendfile backend uses this to name the reason in its
/// `NotApplicable` handoff to hyper; hyper's simple proxy and
/// `splice_simple_proxy` forward regardless of the reason.
#[derive(Clone, Copy, Debug)]
pub(crate) enum PassthroughReason {
    /// The parser did not recognise a known archive shape.
    Unrecognized,
    /// The parser matched a Pool URL but the filename failed the
    /// `.deb`/`.udeb`/`.ddeb` extension check or the strict flat-pool
    /// `<name>_<ver>_<arch>.<ext>` shape check.
    NonDebPool,
    /// A structured mirror has registered `mirror_path == "flat"` (or
    /// `"flat/..."`) on this host, claiming the host-level `flat/`
    /// anchor.  Flat caching is disabled for the host
    /// (see [`crate::flat_blocklist`]).
    FlatBlocked,
    /// An otherwise cacheable request carries a query string.  The query is
    /// forwarded upstream but no part of the cache name, so caching the
    /// answer would serve the query variant to every later plain request.
    QueryString,
    /// A distribution, component or architecture holding a `_`, which the
    /// `dists/` cache names use as their field separator (see
    /// [`ClassifyError::JoinedFieldUnderscore`]).
    JoinedFieldUnderscore,
    /// Every field is valid, but the cache name they join into is longer
    /// than [`MAX_DEBNAME_LEN`], so the cache file could not be created.
    NameTooLong,
}

impl PassthroughReason {
    /// Short human-readable name for log lines.
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Unrecognized => "unrecognized resource path",
            Self::NonDebPool => "unsupported pool filename",
            Self::FlatBlocked => "flat host blocked by structured collision",
            Self::QueryString => "query string on a cacheable path",
            Self::JoinedFieldUnderscore => "`_` in a distribution, component or architecture",
            Self::NameTooLong => "cache name too long",
        }
    }
}

/// Dispatcher verdict.  Backends own response-type construction; this
/// module owns logging, metric bumping, the deferred `Origin` DB write and
/// `record_uncacheable`, so the two backends stay structurally in sync.
#[derive(Debug)]
pub(crate) enum DispatchOutcome {
    /// Route through the cache pipeline; the request's `ConnectionDetails`
    /// are complete (the dispatcher already holds `client`), so the backend
    /// hands them straight to its cache pipeline.
    Cache(ConnectionDetails),
    /// Refuse with a fixed 4xx response.  Logging and metric bumping
    /// already done.
    Reject(RejectReason),
    /// Forward to upstream uncached.  Logging, metric bumping and
    /// `record_uncacheable` already done.  `requested_host` is returned so
    /// backends can build an upstream `Mirror` or emit per-request log lines
    /// without re-deriving it.
    Passthrough {
        // Named in the "Proxying (without caching)" line by both backends
        // and in sendfile's `NotApplicable` handoff.
        reason: PassthroughReason,
        requested_host: ClientHost,
        // Consumed by both backends: `splice_simple_proxy` (`splice/simple_proxy.rs`,
        // via the sendfile dispatch) and `PassthroughBody` (`hyper_conn.rs`).
        request_received_at: PreciseInstant,
    },
}

/// Output of [`decide_request`].
///
/// Mirrors [`DispatchOutcome`] without the async wrapper's side-effects
/// (`record_uncacheable`), so unit tests exercise the routing logic without
/// standing up the DB task channel.
#[derive(Debug)]
enum Decision {
    /// `conn_details.origin_fields` is `Some` when `class.origin_fields`
    /// indicated a real (non-pseudo) architecture; the backend records it
    /// once the request is answered.
    Cache {
        conn_details: ConnectionDetails,
    },
    Reject(RejectReason),
    Passthrough {
        reason: PassthroughReason,
        requested_host: ClientHost,
        request_received_at: PreciseInstant,
    },
}

/// Split a request target's path-and-query at its first `?`, which RFC 3986
/// reserves as the query delimiter (a literal `?` in the path is `%3F`).
fn split_query(path_and_query: &str) -> (&str, Option<&str>) {
    match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    }
}

/// Classify an incoming request URL and decide how to route it.
///
/// `path_and_query` is the **raw** request-line path (not yet normalised)
/// with its query string, if any; the dispatcher normalises the path
/// internally for parsing while keeping the raw form for logs and the
/// uncacheables ring.  `client` is borrowed for log inclusion only; nothing
/// about the classification depends on caller identity.
pub(crate) async fn dispatch_request(
    path_and_query: &str,
    requested_host: ClientHost,
    requested_port: Option<NonZero<u16>>,
    client: &ClientInfo,
) -> DispatchOutcome {
    let request_received_at = PreciseInstant::now();
    let cfg = global_config();
    let decision = decide_request(
        path_and_query,
        requested_host,
        requested_port,
        client,
        &cfg.aliases,
        cfg.reject_pdiff_requests,
        flat_blocklist::is_blocked,
        request_received_at,
    );
    match decision {
        // The `Origin` row rides along in `conn_details.origin_fields` and is
        // recorded by the backend once the request is answered
        // (`ConnectionDetails::record_origin`), not here: a probe the
        // upstream 404s must not mint a row.
        Decision::Cache { conn_details } => DispatchOutcome::Cache(conn_details),
        Decision::Reject(reason) => DispatchOutcome::Reject(reason),
        Decision::Passthrough {
            reason,
            requested_host,
            request_received_at,
        } => {
            // Exactly-once: the dispatcher runs once per request (see the
            // module docs), so the uncacheables ring buffer and its
            // `UNCACHEABLE` counter are fed here rather than at each
            // backend's forwarding step.
            record_uncacheable(&requested_host, split_query(path_and_query).0);
            DispatchOutcome::Passthrough {
                reason,
                requested_host,
                request_received_at,
            }
        }
    }
}

/// Routing decision without `RUNTIMEDETAILS`/DB dependencies or async
/// side-effects (it does bump reject metrics and the `warn_once` state).
///
/// The two real-world side-effects that surround it -
/// `flat_blocklist::is_blocked` and the deferred `Origin` DB write - are
/// expressed as a closure and a return-value field respectively, so unit
/// tests can drive every branch without standing up the DB task channel or
/// the `RUNTIMEDETAILS`/`BLOCKLIST` `OnceLock`s.
#[expect(
    clippy::too_many_arguments,
    reason = "single production call site; grouping the params would not aid clarity"
)]
fn decide_request(
    path_and_query: &str,
    requested_host: ClientHost,
    requested_port: Option<NonZero<u16>>,
    client: &ClientInfo,
    aliases: &[Alias],
    reject_pdiff_requests: bool,
    is_flat_blocked: impl FnOnce(&CacheHost, Option<NonZero<u16>>) -> bool,
    request_received_at: PreciseInstant,
) -> Decision {
    let (uri_path, query) = split_query(path_and_query);
    trace!("Dispatching request from client {client}: host=`{requested_host}` path=`{uri_path}`");

    // pdiff URLs have a known shape (`/Packages.diff/T-...`, `/Sources.diff/T-...`,
    // `/Translation-XX.diff/T-...`) that `parse_request_path` deliberately does
    // not match — they are uncacheable in this proxy.  Detect them here so we
    // either refuse with 410 (the default) or fall through to a silent
    // passthrough, in both cases avoiding a misleading "Unrecognized resource
    // path" warning for a URL shape we actually do recognise.
    let is_diff = LazyCell::new(|| is_diff_request_path(uri_path));

    if reject_pdiff_requests && *is_diff {
        // Several per `apt update`; the count lives in PDIFF_REJECTED.
        info_once!(
            "Rejecting diff request {uri_path} for client {client}; pdiff URLs are uncacheable here and are refused with 410 (further rejections counted in PDIFF_REJECTED)"
        );
        metrics::PDIFF_REJECTED.increment();
        return Decision::Reject(RejectReason::DiffRequest);
    }

    let normalized = normalize_uri_path(uri_path);
    let passthrough_reason: PassthroughReason = match parse_request_path(&normalized) {
        None => {
            if !*is_diff {
                warn_once_or_debug!(
                    "Unrecognized resource path {uri_path} from client {client}; forwarding it upstream uncached"
                );
            }
            PassthroughReason::Unrecognized
        }
        Some(resource) => match cache_layout::classify_request(&resource, client) {
            Ok(class) => {
                // The upstream is asked for the path as sent, while the cache
                // name comes from the validated fields alone: a dot segment
                // the validators missed would cache one resource under
                // another's name.
                if is_unsafe_cache_path(&normalized) {
                    warn_once_or_info!(
                        "Rejecting unsafe cache path {uri_path} for client {client} with 400"
                    );
                    metrics::UNSAFE_PATH_REJECTED.increment();
                    return Decision::Reject(RejectReason::UnsafePath);
                }

                let aliased_host = resolve_alias(aliases, &requested_host);

                let cache_id = aliased_host.unwrap_or_else(|| requested_host.as_cache_host());
                let layout = class.resource_kind.layout();
                if query.is_some() {
                    warn_once_or_info!(
                        "Query string on cacheable path {uri_path} from client {client}; forwarding it upstream uncached"
                    );
                    PassthroughReason::QueryString
                } else if class.debname.len() > MAX_DEBNAME_LEN {
                    warn_once_or_info!(
                        "Uncacheable path {uri_path} from client {client} (its {}-byte cache name exceeds {MAX_DEBNAME_LEN} bytes); forwarding it upstream uncached",
                        class.debname.len()
                    );
                    PassthroughReason::NameTooLong
                } else if layout.is_flat() && is_flat_blocked(cache_id, requested_port) {
                    warn_once_or_info!(
                        "Flat caching disabled for host `{requested_host}` due to colliding structured mirror; passing {uri_path} through uncached for client {client}"
                    );
                    PassthroughReason::FlatBlocked
                } else {
                    // Resolve the alias exactly once: the `Mirror` every
                    // store keys on names the alias' main host, while the
                    // upstream fetch still dials the host the client named.
                    let canonical_host = aliased_host
                        .map_or_else(|| requested_host.clone(), CacheHost::to_client_host);
                    let mirror = Mirror::new(
                        canonical_host,
                        requested_port,
                        class.mirror_path,
                        layout.mirror_kind(),
                    );

                    return Decision::Cache {
                        conn_details: ConnectionDetails {
                            client: *client,
                            request_received_at,
                            mirror,
                            upstream_host: requested_host,
                            debname: class.debname,
                            resource_kind: class.resource_kind,
                            origin_fields: class.origin_fields.map(Box::new),
                        },
                    };
                }
            }
            Err(ClassifyError::BadEncoding { kind, raw, source }) => {
                warn_once_or_info!(
                    "Failed to decode {kind} `{}` from client {client}; rejecting with 400:  {}",
                    raw.escape_debug(),
                    ErrorReport(&source)
                );
                return Decision::Reject(RejectReason::BadEncoding);
            }
            Err(ClassifyError::InvalidValue { kind, decoded }) => {
                warn_once_or_info!(
                    "Unsupported {kind} `{}` from client {client}; rejecting with 400",
                    decoded.escape_debug()
                );
                return Decision::Reject(RejectReason::InvalidValue);
            }
            Err(ClassifyError::JoinedFieldUnderscore { kind, decoded }) => {
                warn_once_or_info!(
                    "Uncacheable {kind} `{}` from client {client} (`_` separates cache-name fields); forwarding it upstream uncached",
                    decoded.escape_debug()
                );
                PassthroughReason::JoinedFieldUnderscore
            }
            Err(ClassifyError::NonDebPool { filename }) => {
                warn_once_or_info!(
                    "Unsupported pool filename `{}` from client {client}; forwarding it upstream uncached",
                    filename.escape_debug()
                );
                PassthroughReason::NonDebPool
            }
        },
    };

    // The cache pipeline declined.  Before forwarding upstream uncached,
    // run the safety gate that applies to all passthrough requests: refuse
    // traversal/control-byte paths.  (The pdiff gate already fired above,
    // before parsing, so we don't repeat it here.)

    if is_unsafe_proxy_path(uri_path) {
        warn_once_or_info!(
            "Rejecting unsafe passthrough path {uri_path} ({}) for client {client} with 400",
            passthrough_reason.label()
        );
        metrics::UNSAFE_PATH_REJECTED.increment();
        return Decision::Reject(RejectReason::UnsafePath);
    }

    // `record_uncacheable` happens in the async wrapper (`dispatch_request`)
    // alongside the other global side-effects, keeping this function pure
    // for the unit tests.
    Decision::Passthrough {
        reason: passthrough_reason,
        requested_host,
        request_received_at,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::cache_layout::CacheLayout;
    use crate::test_support::local_client;

    const OPEN_ACLS: ClientAcls<'static> = ClientAcls {
        proxy_clients: &[],
        webif_clients: &[],
        webif_hosts: &WebifHosts::NONE,
    };

    /// A `Host` header naming the daemon as a browser on the same machine
    /// would.
    const LOCALHOST: Option<&[u8]> = Some(b"localhost:3142");

    /// ACLs that admit only a host the loopback test client is not.
    const OTHER_HOST_ACLS: ClientAcls<'static> = ClientAcls {
        proxy_clients: &[IpNetOrAddr::Addr(IpAddr::V4(Ipv4Addr::new(
            192, 168, 99, 99,
        )))],
        webif_clients: &[IpNetOrAddr::Addr(IpAddr::V4(Ipv4Addr::new(
            192, 168, 99, 99,
        )))],
        webif_hosts: &WebifHosts::NONE,
    };

    #[test]
    fn acls_admit_a_client_passing_either_list() {
        let local = [IpNetOrAddr::Addr(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        let other = OTHER_HOST_ACLS.proxy_clients;
        for (proxy_clients, webif_clients, admitted) in [
            (&[][..], &[][..], true),
            (other, other, false),
            (&local[..], other, true),
            (other, &local[..], true),
            (other, &[][..], true),
        ] {
            let acls = ClientAcls {
                proxy_clients,
                webif_clients,
                webif_hosts: &WebifHosts::NONE,
            };
            assert_eq!(
                acls.admits(&local_client()),
                admitted,
                "proxy {proxy_clients:?}, webif {webif_clients:?}"
            );
        }
    }

    #[test]
    fn preflight_method_accepts_get_and_connect() {
        assert_eq!(
            preflight_method("GET", &local_client(), &OPEN_ACLS),
            Ok(RequestKind::Get)
        );
        assert_eq!(
            preflight_method("CONNECT", &local_client(), &OPEN_ACLS),
            Ok(RequestKind::Connect)
        );
        // The proxy-client ACL only gates CONNECT here; GET is checked later
        // by authorize_cache_access.
        assert_eq!(
            preflight_method("GET", &local_client(), &OTHER_HOST_ACLS),
            Ok(RequestKind::Get)
        );
    }

    #[test]
    fn preflight_method_rejects_other_methods() {
        for m in ["POST", "PUT", "HEAD", "get"] {
            assert_eq!(
                preflight_method(m, &local_client(), &OPEN_ACLS),
                Err(RejectReason::UnsupportedMethod),
                "{m}"
            );
        }
    }

    #[test]
    fn preflight_method_rejects_connect_from_unlisted_client() {
        assert_eq!(
            preflight_method("CONNECT", &local_client(), &OTHER_HOST_ACLS),
            Err(RejectReason::UnauthorizedClient)
        );
    }

    #[test]
    fn preflight_target_rejects_non_http_scheme() {
        let uri: Uri = "ftp://deb.example.com/debian/dists/sid/Release"
            .parse()
            .unwrap();
        assert_eq!(
            preflight_target(&uri, true, || LOCALHOST, &local_client(), &OPEN_ACLS).unwrap_err(),
            RejectReason::UnsupportedScheme
        );
    }

    #[test]
    fn preflight_target_origin_form_requires_host_on_http11_only() {
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(
            preflight_target(&uri, true, || None, &local_client(), &OPEN_ACLS).unwrap_err(),
            RejectReason::MissingHost
        );
        assert!(matches!(
            preflight_target(&uri, true, || LOCALHOST, &local_client(), &OPEN_ACLS),
            Ok(RequestTarget::WebUi)
        ));
        assert!(matches!(
            preflight_target(&uri, false, || None, &local_client(), &OPEN_ACLS),
            Ok(RequestTarget::WebUi)
        ));
    }

    #[test]
    fn preflight_target_origin_form_enforces_webif_acl() {
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(
            preflight_target(&uri, true, || LOCALHOST, &local_client(), &OTHER_HOST_ACLS)
                .unwrap_err(),
            RejectReason::UnauthorizedWebUi
        );
        // The proxy-client ACL is not consulted for the web interface once a
        // dedicated webif list is given.
        let webif_only = ClientAcls {
            proxy_clients: OTHER_HOST_ACLS.proxy_clients,
            webif_clients: &[],
            webif_hosts: &WebifHosts::NONE,
        };
        assert!(matches!(
            preflight_target(&uri, true, || LOCALHOST, &local_client(), &webif_only),
            Ok(RequestTarget::WebUi)
        ));
    }

    /// DNS rebinding: an origin-form request naming a host the daemon does
    /// not answer to is misdirected, whatever the client ACL says; an
    /// HTTP/1.0 request without `Host` has no name to check.
    #[test]
    fn preflight_target_origin_form_refuses_unrecognized_host() {
        let uri: Uri = "/logs".parse().unwrap();
        for is_http11 in [true, false] {
            assert_eq!(
                preflight_target(
                    &uri,
                    is_http11,
                    || Some(b"rebind.attacker.example:3142".as_slice()),
                    &local_client(),
                    &OPEN_ACLS
                )
                .unwrap_err(),
                RejectReason::MisdirectedWebUi
            );
        }
        assert!(matches!(
            preflight_target(
                &uri,
                true,
                || Some(b"127.0.0.1:3142".as_slice()),
                &local_client(),
                &OPEN_ACLS
            ),
            Ok(RequestTarget::WebUi)
        ));
        // The client ACL is still decided first.
        assert_eq!(
            preflight_target(
                &uri,
                true,
                || Some(b"attacker.example".as_slice()),
                &local_client(),
                &OTHER_HOST_ACLS
            )
            .unwrap_err(),
            RejectReason::UnauthorizedWebUi
        );
        // The proxy path does not look at `Host` at all.
        let uri: Uri = "http://deb.example.com/debian/dists/sid/Release"
            .parse()
            .unwrap();
        assert!(matches!(
            preflight_target(
                &uri,
                true,
                || Some(b"attacker.example".as_slice()),
                &local_client(),
                &OPEN_ACLS
            ),
            Ok(RequestTarget::Proxy { .. })
        ));
    }

    #[test]
    fn preflight_target_absolute_form_yields_host_and_port() {
        let client = local_client();
        let uri: Uri = "http://deb.example.com/debian/dists/sid/Release"
            .parse()
            .unwrap();
        let Ok(RequestTarget::Proxy { host, port }) =
            preflight_target(&uri, true, || None, &client, &OPEN_ACLS)
        else {
            unreachable!("expected Proxy target")
        };
        assert_eq!(host, "deb.example.com");
        assert_eq!(port, None);

        let uri: Uri = "http://deb.example.com:8080/debian/dists/sid/Release"
            .parse()
            .unwrap();
        let Ok(RequestTarget::Proxy { host, port }) =
            preflight_target(&uri, true, || None, &client, &OPEN_ACLS)
        else {
            unreachable!("expected Proxy target")
        };
        assert_eq!(host, "deb.example.com");
        assert_eq!(port, NonZero::new(8080));

        // Absolute-form requests need no Host header even on HTTP/1.1, and
        // the ACLs are left to authorize_cache_access.
        assert!(matches!(
            preflight_target(&uri, true, || None, &client, &OTHER_HOST_ACLS),
            Ok(RequestTarget::Proxy { .. })
        ));
    }

    #[test]
    fn preflight_target_rejects_a_target_without_an_absolute_path() {
        // Authority-form (the shape of a `CONNECT` target) and asterisk-form
        // name no resource path; a `GET` carrying one must not reach the
        // dispatcher or the upstream relay.
        for target in [
            "deb.example.com:80",
            "deb.example.com:8080",
            "127.0.0.1:3142",
            "*",
        ] {
            let uri: Uri = target.parse().unwrap();
            assert_eq!(
                preflight_target(&uri, true, || LOCALHOST, &local_client(), &OPEN_ACLS)
                    .unwrap_err(),
                RejectReason::InvalidTarget,
                "{target}"
            );
        }
        // An absolute-form target without a path still names the root.
        let uri: Uri = "http://deb.example.com".parse().unwrap();
        assert!(matches!(
            preflight_target(&uri, true, || None, &local_client(), &OPEN_ACLS),
            Ok(RequestTarget::Proxy { .. })
        ));
    }

    #[test]
    fn preflight_target_rejects_port_zero() {
        let uri: Uri = "http://deb.example.com:0/debian/dists/sid/Release"
            .parse()
            .unwrap();
        assert_eq!(
            preflight_target(&uri, true, || None, &local_client(), &OPEN_ACLS).unwrap_err(),
            RejectReason::InvalidPort
        );
    }

    #[test]
    fn preflight_reject_reasons_map_to_fixed_responses() {
        assert_eq!(
            RejectReason::UnsupportedMethod.response_parts(),
            (StatusCode::METHOD_NOT_ALLOWED, "Method not supported")
        );
        assert_eq!(
            RejectReason::UnauthorizedClient.response_parts(),
            (StatusCode::FORBIDDEN, "Unauthorized client")
        );
        assert_eq!(
            RejectReason::UnauthorizedWebUi.response_parts(),
            (StatusCode::FORBIDDEN, "Unauthorized client")
        );
        assert_eq!(
            RejectReason::UnsupportedScheme.response_parts(),
            (StatusCode::BAD_REQUEST, "Unsupported URI scheme")
        );
        assert_eq!(
            RejectReason::MissingHost.response_parts(),
            (StatusCode::BAD_REQUEST, "Missing Host header")
        );
        assert_eq!(
            RejectReason::MisdirectedWebUi.response_parts(),
            (StatusCode::MISDIRECTED_REQUEST, "Misdirected request")
        );
        assert_eq!(
            RejectReason::InvalidPort.response_parts(),
            (StatusCode::BAD_REQUEST, "Invalid port")
        );
        assert_eq!(
            RejectReason::InvalidTarget.response_parts(),
            (StatusCode::BAD_REQUEST, "Invalid request target")
        );
        assert_eq!(
            RejectReason::BadEncoding.response_parts(),
            (StatusCode::BAD_REQUEST, "Unsupported URL encoding")
        );
        assert_eq!(
            RejectReason::InvalidValue.response_parts(),
            (StatusCode::BAD_REQUEST, "Unsupported request")
        );
        assert_eq!(
            RejectReason::UnsafePath.response_parts(),
            (StatusCode::BAD_REQUEST, "Unsupported request")
        );
        assert_eq!(
            RejectReason::DiffRequest.response_parts(),
            (StatusCode::GONE, "Diff requests are not supported")
        );
        assert_eq!(
            RejectReason::LoopDetected.response_parts(),
            (StatusCode::LOOP_DETECTED, "Proxy loop detected")
        );
    }

    fn fake_host() -> ClientHost {
        ClientHost::new("deb.example.com".to_string()).unwrap()
    }

    fn never_flat_blocked(_: &CacheHost, _: Option<NonZero<u16>>) -> bool {
        false
    }

    #[test]
    fn cache_outcome_for_pool_deb() {
        let decision = decide_request(
            "/debian/pool/main/f/firefox/firefox_1.0_amd64.deb",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        let Decision::Cache { conn_details } = decision else {
            unreachable!("expected Cache outcome")
        };
        assert_eq!(conn_details.layout(), CacheLayout::StructuredPool);
        assert_eq!(conn_details.debname, "firefox_1.0_amd64.deb");
        assert!(conn_details.origin_fields.is_none());
    }

    #[test]
    fn cache_outcome_packages_with_real_arch_records_origin() {
        let decision = decide_request(
            "/debian/dists/sid/main/binary-amd64/Packages.gz",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        let Decision::Cache { conn_details } = decision else {
            unreachable!("expected Cache outcome")
        };
        assert_eq!(conn_details.layout(), CacheLayout::Dists);
        let origin = conn_details
            .origin_fields
            .as_ref()
            .expect("binary-amd64 must record an origin");
        assert_eq!(origin.distribution, "sid");
        assert_eq!(origin.component, "main");
        assert_eq!(origin.architecture, "binary-amd64");
    }

    #[test]
    fn cache_outcome_resolves_alias_once_and_keeps_the_upstream_host() {
        use crate::config::Alias;
        let main = ClientHost::new("deb.debian.org".to_owned()).expect("valid host");
        let alias = ClientHost::new("ftp.ca.debian.org".to_owned()).expect("valid host");
        let aliases = [Alias {
            main: main.clone().into_cache_host(),
            aliases: vec![alias.clone()],
        }];
        let decision = decide_request(
            "/debian/pool/main/f/firefox/firefox_1.0_amd64.deb",
            alias.clone(),
            None,
            &local_client(),
            &aliases,
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        let Decision::Cache { conn_details } = decision else {
            unreachable!("expected Cache outcome")
        };
        // The identity every store keys on is the alias' main host ...
        assert_eq!(conn_details.mirror.host(), &main);
        assert_eq!(conn_details.site().host, main.as_cache_host());
        // ... while the dial still goes to the mirror the client named.
        assert_eq!(conn_details.upstream_host, alias);
        assert_eq!(conn_details.upstream_authority(), "ftp.ca.debian.org");
    }

    #[test]
    fn passthrough_unrecognized_when_parser_declines() {
        let decision = decide_request(
            "/foo/bar.txt",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        assert!(
            matches!(
                decision,
                Decision::Passthrough {
                    reason: PassthroughReason::Unrecognized,
                    ..
                }
            ),
            "expected Unrecognized passthrough, got {decision:?}"
        );
    }

    /// The query is no part of the cache name, so a cacheable path carrying
    /// one is relayed uncached rather than cached under the plain name.
    #[test]
    fn passthrough_query_string_on_a_cacheable_path() {
        for target in [
            "/debian/pool/main/f/firefox/firefox_1.0_amd64.deb?x=1",
            "/debian/dists/sid/main/binary-amd64/Packages.gz?",
            "/apt/Packages.gz?a=b&c=d",
        ] {
            let decision = decide_request(
                target,
                fake_host(),
                None,
                &local_client(),
                &[],
                true,
                never_flat_blocked,
                PreciseInstant::now(),
            );
            assert!(
                matches!(
                    decision,
                    Decision::Passthrough {
                        reason: PassthroughReason::QueryString,
                        ..
                    }
                ),
                "{target}: expected QueryString passthrough, got {decision:?}"
            );
        }

        // The query does not change the verdict for anything uncacheable.
        let decision = decide_request(
            "/foo/bar.txt?x=1",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        assert!(
            matches!(
                decision,
                Decision::Passthrough {
                    reason: PassthroughReason::Unrecognized,
                    ..
                }
            ),
            "expected Unrecognized passthrough, got {decision:?}"
        );
    }

    #[test]
    fn passthrough_underscore_in_a_joined_field() {
        let decision = decide_request(
            "/debian/dists/sid_main_binary-amd64/Release",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        assert!(
            matches!(
                decision,
                Decision::Passthrough {
                    reason: PassthroughReason::JoinedFieldUnderscore,
                    ..
                }
            ),
            "expected JoinedFieldUnderscore passthrough, got {decision:?}"
        );
    }

    /// A cache name longer than [`MAX_DEBNAME_LEN`] could not be created (its
    /// `.partial` would pass `NAME_MAX`), so the request is relayed uncached;
    /// one at the limit still caches.
    #[test]
    fn passthrough_cache_name_too_long() {
        let decide = |path: &str| {
            decide_request(
                path,
                fake_host(),
                None,
                &local_client(),
                &[],
                true,
                never_flat_blocked,
                PreciseInstant::now(),
            )
        };
        // Each field within its own cap, the joined name far past NAME_MAX.
        let joined = format!(
            "/debian/dists/{}/{}/binary-{}/Release",
            "a".repeat(128),
            "b".repeat(128),
            "c".repeat(120)
        );
        let pool_at = |len: usize| {
            let stem = "f".repeat(len - "_1_all.deb".len());
            format!("/debian/pool/main/f/foo/{stem}_1_all.deb")
        };
        for path in [joined, pool_at(MAX_DEBNAME_LEN + 1), pool_at(255)] {
            let decision = decide(&path);
            assert!(
                matches!(
                    decision,
                    Decision::Passthrough {
                        reason: PassthroughReason::NameTooLong,
                        ..
                    }
                ),
                "{path}: expected NameTooLong passthrough, got {decision:?}"
            );
        }
        let decision = decide(&pool_at(MAX_DEBNAME_LEN));
        assert!(
            matches!(decision, Decision::Cache { .. }),
            "expected Cache at the limit, got {decision:?}"
        );
    }

    #[test]
    fn passthrough_non_deb_pool_for_pool_with_text_filename() {
        let decision = decide_request(
            "/debian/pool/main/f/foo/README.txt",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        assert!(
            matches!(
                decision,
                Decision::Passthrough {
                    reason: PassthroughReason::NonDebPool,
                    ..
                }
            ),
            "expected NonDebPool passthrough, got {decision:?}"
        );
    }

    #[test]
    fn passthrough_flat_blocked_when_blocklist_hits() {
        let decision = decide_request(
            "/apt/Packages.gz",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            |_, _| true,
            PreciseInstant::now(),
        );
        assert!(
            matches!(
                decision,
                Decision::Passthrough {
                    reason: PassthroughReason::FlatBlocked,
                    ..
                }
            ),
            "expected FlatBlocked passthrough, got {decision:?}"
        );
    }

    #[test]
    fn flat_request_caches_when_blocklist_does_not_hit() {
        let decision = decide_request(
            "/apt/Packages.gz",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        assert!(
            matches!(decision, Decision::Cache { .. }),
            "expected Cache, got {decision:?}"
        );
    }

    #[test]
    fn reject_pdiff_request_when_configured() {
        let decision = decide_request(
            "/debian/dists/sid/main/binary-amd64/Packages.diff/T-12345",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        assert!(
            matches!(decision, Decision::Reject(RejectReason::DiffRequest)),
            "expected DiffRequest reject, got {decision:?}"
        );
    }

    #[test]
    fn pdiff_request_passes_through_when_not_configured() {
        let decision = decide_request(
            "/debian/dists/sid/main/binary-amd64/Packages.diff/T-12345",
            fake_host(),
            None,
            &local_client(),
            &[],
            false,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        // Path is not a recognised structured shape (parser rejects), and the
        // pdiff gate is disabled, so this falls through to a plain Unrecognized
        // passthrough.
        assert!(
            matches!(
                decision,
                Decision::Passthrough {
                    reason: PassthroughReason::Unrecognized,
                    ..
                }
            ),
            "expected Unrecognized passthrough, got {decision:?}"
        );
    }

    #[test]
    fn reject_unsafe_traversal_path() {
        let decision = decide_request(
            "/foo/../etc/passwd",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        assert!(
            matches!(decision, Decision::Reject(RejectReason::UnsafePath)),
            "expected UnsafePath reject, got {decision:?}"
        );
    }

    /// Regression (cache poisoning): the traversal used to reach the cache
    /// as `debian/victim_1.0_amd64.deb` while the upstream was asked for
    /// `/victim_1.0_amd64.deb`.
    #[test]
    fn reject_dot_segments_on_a_cached_route() {
        for path in [
            "/debian/pool/updates/../../../victim_1.0_amd64.deb",
            "/debian/pool/main/%2e%2e/%2e%2e/victim_1.0_amd64.deb",
            "/debian/dists/../../evil/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
        ] {
            let decision = decide_request(
                path,
                fake_host(),
                None,
                &local_client(),
                &[],
                true,
                never_flat_blocked,
                PreciseInstant::now(),
            );
            assert!(
                matches!(decision, Decision::Reject(RejectReason::InvalidValue)),
                "{path}: expected InvalidValue reject, got {decision:?}"
            );
        }
    }

    #[test]
    fn reject_bad_encoding_in_pool_filename() {
        // `%ff%fe` survives `parse_request_path` (percent-escapes are kept
        // raw there) and fails UTF-8 validation in `classify_request`.
        let decision = decide_request(
            "/debian/pool/main/f/foo/foo%ff%fe_1.0_amd64.deb",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        assert!(
            matches!(decision, Decision::Reject(RejectReason::BadEncoding)),
            "expected BadEncoding reject, got {decision:?}"
        );
    }

    #[test]
    fn reject_invalid_value_in_pool_filename() {
        // `%2F` decodes to `/`, which `valid_filename` refuses; the decode
        // happens per field, so the structural parse above it still succeeds.
        let decision = decide_request(
            "/debian/pool/main/f/foo/foo%2Fbar_1.0_amd64.deb",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        assert!(
            matches!(decision, Decision::Reject(RejectReason::InvalidValue)),
            "expected InvalidValue reject, got {decision:?}"
        );
    }

    #[test]
    fn pdiff_rejection_wins_over_unsafe_path_check() {
        // The pdiff gate fires before parsing (and therefore before the
        // unsafe-path gate), so a path that triggers both is rejected as a
        // DiffRequest.  This locks in precedence: future refactors that move
        // the pdiff gate after the unsafe-path gate will fail this test.
        let decision = decide_request(
            "/debian/dists/sid/main/binary-amd64/Packages.diff/T-../escape",
            fake_host(),
            None,
            &local_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        assert!(
            matches!(decision, Decision::Reject(RejectReason::DiffRequest)),
            "expected DiffRequest reject, got {decision:?}"
        );
    }
}
