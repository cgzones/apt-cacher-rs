//! Unified URI dispatch entry point shared by the hyper backend in
//! `main.rs` and the sendfile backend in `sendfile_conn.rs`.
//!
//! Owns the request-classification pipeline that previously appeared inline
//! in both dispatchers:
//!
//!   1. diff-request gate          - reject (410) pdiff URLs when configured,
//!      else fall through silently as `Unrecognized`
//!   2. [`normalize_uri_path`]     - collapse `//` runs / strip `.` segments
//!   3. [`parse_request_path`]     - structural shape-match into `ResourceFile`
//!   4. [`classify_request`]       - per-field URL-decode + allowlist validate
//!   5. flat-blocklist collision   - host-level `flat/` claimed by structured
//!   6. deferred `Origin` DB write - for `Packages` requests w/ a real arch
//!   7. unsafe-proxy-path gate     - traversal/control bytes in passthrough
//!
//! Backends translate the returned [`DispatchOutcome`] into their response
//! type.  All logging, metric bumping, and deferred `Origin` DB writes happen
//! here, so the two parallel paths cannot drift apart.  `record_uncacheable`
//! is *not* called here - it is intentionally deferred to each backend's
//! terminal passthrough step (hyper's simple-proxy block; the sendfile splice
//! path).  Sendfile's `NotApplicable` handoff causes hyper to re-enter this
//! dispatcher for the same request, so recording inside the dispatcher would
//! double-count; recording at the terminal step yields exactly-once
//! semantics.
//!
//! [`classify_request`]: crate::cache_layout::classify_request
//! [`normalize_uri_path`]: crate::deb_mirror::normalize_uri_path
//! [`parse_request_path`]: crate::deb_mirror::parse_request_path

use std::{cell::LazyCell, num::NonZero};

use http::StatusCode;
use log::{info, trace};

use crate::{
    ClientInfo,
    cache_layout::{self, CacheLayout, CachedFlavor, ClassifyError},
    config::{Alias, CacheHost, ClientHost, resolve_alias},
    database_task::{DatabaseCommand, DbCmdOrigin, send_db_command},
    deb_mirror::{
        Mirror, Origin, is_diff_request_path, is_unsafe_proxy_path, normalize_uri_path,
        parse_request_path,
    },
    flat_blocklist, global_config, metrics,
    precise_instant::PreciseInstant,
    warn_once_or_debug, warn_once_or_info,
};

/// Post-classification payload routed through the cache pipeline.
///
/// Mirrors the fields of [`crate::cache_layout::ConnectionDetails`] minus
/// `client`, which the caller adds when assembling `ConnectionDetails`.
#[derive(Debug)]
pub(crate) struct CachePlan {
    pub(crate) mirror: Mirror,
    pub(crate) aliased_host: Option<&'static CacheHost>,
    pub(crate) debname: String,
    pub(crate) cached_flavor: CachedFlavor,
    pub(crate) layout: CacheLayout,
    pub(crate) request_received_at: PreciseInstant,
    _private: (),
}

/// Reason the dispatcher refused a request with a fixed 4xx/5xx response.
///
/// Backends call [`Self::response_parts`] to materialise the `(status, body)`
/// pair; logging and metric bumping have already been done by the dispatcher.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RejectReason {
    /// URL-decoding a request field produced invalid UTF-8.
    BadEncoding,
    /// A decoded field failed its allowlist validator
    /// (`valid_mirrorname`, `valid_distribution`, etc.).
    InvalidValue,
    /// The simple-proxy gate found `..`/`.` traversal segments or a
    /// control byte in the percent-decoded path.
    UnsafePath,
    /// Configured to refuse pdiff requests, and this is one
    /// (`/Packages.diff/T-...`, `/Sources.diff/T-...`,
    /// `/Translation-XX.diff/T-...`).
    DiffRequest,
}

impl RejectReason {
    /// Fixed `(status, body)` pair associated with this reason.
    #[must_use]
    pub(crate) const fn response_parts(self) -> (StatusCode, &'static str) {
        match self {
            Self::BadEncoding => (StatusCode::BAD_REQUEST, "Unsupported URL encoding"),
            Self::InvalidValue | Self::UnsafePath => {
                (StatusCode::BAD_REQUEST, "Unsupported request")
            }
            Self::DiffRequest => (StatusCode::GONE, "Diff requests are not supported"),
        }
    }
}

/// Why the cache pipeline declined and the request must be forwarded
/// uncached.  Backends use this to pick between hyper's simple proxy,
/// `splice_simple_proxy`, and the `NotApplicable` handoff back to hyper.
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
}

/// Dispatcher verdict.  Backends own response-type construction; this
/// module owns logging, metric bumping, and deferred `Origin` DB writes, so
/// the two backends stay structurally in sync.  `record_uncacheable` is
/// *not* called here - see the module docs for why it is deferred to each
/// backend's terminal forwarding step.
#[derive(Debug)]
pub(crate) enum DispatchOutcome {
    /// Route through the cache pipeline using `plan` as the
    /// `ConnectionDetails` seed.
    Cache(CachePlan),
    /// Refuse with a fixed 4xx/5xx response.  Logging and metric bumping
    /// already done.
    Reject(RejectReason),
    /// Forward to upstream uncached.  Logging and metric bumping already
    /// done; the caller is responsible for `record_uncacheable` at its
    /// terminal forwarding step.  `requested_host` is returned so backends
    /// can build an upstream `Mirror` or emit per-request log lines without
    /// re-deriving it.
    Passthrough {
        // The hyper backend only needs `requested_host` to continue its
        // uncached forwarding flow (it ignores `reason` via `reason: _`); the
        // sendfile backend (`sendfile_conn.rs`) inspects `reason` to choose
        // between `splice_simple_proxy` and a `NotApplicable` handoff back to
        // hyper.  Under feature configurations that exclude sendfile
        // (e.g. `--no-default-features --features tls_hyper`), the field is
        // genuinely unread - silence the dead-code lint there.
        #[cfg_attr(
            not(feature = "sendfile"),
            expect(dead_code, reason = "consumed only by sendfile_conn dispatch")
        )]
        reason: PassthroughReason,
        requested_host: ClientHost,
        // Consumed by both backends: `splice_simple_proxy` (`splice_conn.rs`,
        // via the sendfile dispatch) and `PassthroughBody` (`main.rs`).
        request_received_at: PreciseInstant,
    },
}

/// Output of [`decide_request`].
///
/// Mirrors [`DispatchOutcome`] but attaches the deferred `pending_origin` to
/// the `Cache` arm only - the one outcome it can legally accompany - so a
/// non-`Cache` decision cannot carry a stray origin.  The async wrapper drives
/// that side-effect, then maps to the backend-facing `DispatchOutcome`.  The
/// split lets unit tests exercise the routing logic without standing up the DB
/// task channel.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "transient value: built in decide_request and destructured immediately in \
              dispatch_request, never stored or collected, so the variant-size gap is \
              irrelevant; boxing the plan would add a per-request heap alloc on the cache path"
)]
enum Decision {
    /// `pending_origin` is `Some` when `class.origin_fields` indicated a real
    /// (non-pseudo) architecture; the wrapper forwards it to `send_db_command`
    /// before returning the `Cache` outcome.
    Cache {
        plan: CachePlan,
        pending_origin: Option<Origin>,
    },
    Reject(RejectReason),
    Passthrough {
        reason: PassthroughReason,
        requested_host: ClientHost,
        request_received_at: PreciseInstant,
    },
}

/// Classify an incoming request URL and decide how to route it.
///
/// `uri_path` is the **raw** request-line path (not yet normalised); the
/// dispatcher normalises internally for parsing while keeping the raw form
/// for logs and the simple-proxy passthrough.  `client` is borrowed for log
/// inclusion only; nothing about the classification depends on caller
/// identity.
pub(crate) async fn dispatch_request(
    uri_path: &str,
    requested_host: ClientHost,
    requested_port: Option<NonZero<u16>>,
    client: &ClientInfo,
) -> DispatchOutcome {
    let request_received_at = PreciseInstant::now();
    let cfg = global_config();
    let decision = decide_request(
        uri_path,
        requested_host,
        requested_port,
        client,
        &cfg.aliases,
        cfg.reject_pdiff_requests,
        flat_blocklist::is_blocked,
        request_received_at,
    );
    match decision {
        Decision::Cache {
            plan,
            pending_origin,
        } => {
            if let Some(origin) = pending_origin {
                send_db_command(DatabaseCommand::Origin(DbCmdOrigin { origin })).await;
            }
            DispatchOutcome::Cache(plan)
        }
        Decision::Reject(reason) => DispatchOutcome::Reject(reason),
        Decision::Passthrough {
            reason,
            requested_host,
            request_received_at,
        } => DispatchOutcome::Passthrough {
            reason,
            requested_host,
            request_received_at,
        },
    }
}

/// Pure routing decision: no global reads, no async side-effects.
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
    uri_path: &str,
    requested_host: ClientHost,
    requested_port: Option<NonZero<u16>>,
    client: &ClientInfo,
    aliases: &'static [Alias],
    reject_pdiff_requests: bool,
    is_flat_blocked: impl FnOnce(&CacheHost, Option<NonZero<u16>>) -> bool,
    request_received_at: PreciseInstant,
) -> Decision {
    trace!("Dispatching request from client {client}: host=`{requested_host}` path=`{uri_path}`");

    // pdiff URLs have a known shape (`/Packages.diff/T-...`, `/Sources.diff/T-...`,
    // `/Translation-XX.diff/T-...`) that `parse_request_path` deliberately does
    // not match — they are uncacheable in this proxy.  Detect them here so we
    // either refuse with 410 (the default) or fall through to a silent
    // passthrough, in both cases avoiding a misleading "Unrecognized resource
    // path" warning for a URL shape we actually do recognise.
    let is_diff = LazyCell::new(|| is_diff_request_path(uri_path));

    if reject_pdiff_requests && *is_diff {
        info!("Rejecting diff request {uri_path} for client {client}");
        metrics::PDIFF_REJECTED.increment();
        return Decision::Reject(RejectReason::DiffRequest);
    }

    let normalized = normalize_uri_path(uri_path);
    let passthrough_reason: PassthroughReason = match parse_request_path(&normalized) {
        None => {
            if !*is_diff {
                warn_once_or_debug!("Unrecognized resource path from client {client}: {uri_path}");
            }
            PassthroughReason::Unrecognized
        }
        Some(resource) => match cache_layout::classify_request(&resource, client) {
            Ok(class) => {
                let aliased_host = resolve_alias(aliases, &requested_host);

                let cache_id: &CacheHost = match aliased_host {
                    Some(cache) => cache,
                    None => requested_host.as_cache_host(),
                };
                if class.layout.is_flat() && is_flat_blocked(cache_id, requested_port) {
                    warn_once_or_info!(
                        "Flat caching disabled for host `{requested_host}` due to colliding structured mirror; passing `{uri_path}` through uncached for client {client}"
                    );
                    PassthroughReason::FlatBlocked
                } else {
                    let mirror = Mirror::new(
                        requested_host,
                        requested_port,
                        class.mirror_path,
                        class.layout.mirror_kind(),
                    );

                    let pending_origin = class.origin_fields.map(|fields| Origin {
                        mirror: mirror.clone(),
                        distribution: fields.distribution,
                        component: fields.component,
                        architecture: fields.architecture,
                    });

                    return Decision::Cache {
                        plan: CachePlan {
                            mirror,
                            aliased_host,
                            debname: class.debname,
                            cached_flavor: class.cached_flavor,
                            layout: class.layout,
                            request_received_at,
                            _private: (),
                        },
                        pending_origin,
                    };
                }
            }
            Err(ClassifyError::BadEncoding { kind, raw, source }) => {
                warn_once_or_info!(
                    "Failed to decode {kind} `{}` from client {client}:  {source}",
                    raw.escape_debug()
                );
                return Decision::Reject(RejectReason::BadEncoding);
            }
            Err(ClassifyError::InvalidValue { kind, decoded }) => {
                warn_once_or_info!(
                    "Unsupported {kind} `{}` from client {client}",
                    decoded.escape_debug()
                );
                return Decision::Reject(RejectReason::InvalidValue);
            }
            Err(ClassifyError::NonDebPool { filename }) => {
                warn_once_or_info!(
                    "Unsupported pool filename `{}` from client {client}",
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
        let passthrough_label = match passthrough_reason {
            PassthroughReason::Unrecognized => "unrecognized",
            PassthroughReason::NonDebPool => "non-deb pool",
            PassthroughReason::FlatBlocked => "flat-blocked",
        };
        warn_once_or_info!(
            "Rejecting unsafe passthrough path {uri_path} ({passthrough_label}) for client {client}"
        );
        metrics::UNSAFE_PATH_REJECTED.increment();
        return Decision::Reject(RejectReason::UnsafePath);
    }

    // `record_uncacheable` is intentionally NOT called here.  The sendfile
    // backend hands `NonDebPool` / `FlatBlocked` / non-splice `Unrecognized`
    // back to hyper via `ZeroCopyResult::NotApplicable`, which causes hyper
    // to re-enter this dispatcher for the same request.  Recording at the
    // backend's terminal forwarding step (hyper's simple-proxy block; the
    // sendfile splice path) instead of inside the dispatcher gives an
    // exactly-once guarantee.
    Decision::Passthrough {
        reason: passthrough_reason,
        requested_host,
        request_received_at,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use super::*;
    use crate::ClientInfo;

    fn fake_client() -> ClientInfo {
        ClientInfo::new(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
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
            &fake_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        let Decision::Cache {
            plan,
            pending_origin,
        } = decision
        else {
            unreachable!("expected Cache outcome")
        };
        assert_eq!(plan.layout, CacheLayout::StructuredPool);
        assert_eq!(plan.debname, "firefox_1.0_amd64.deb");
        assert!(pending_origin.is_none());
    }

    #[test]
    fn cache_outcome_packages_with_real_arch_records_origin() {
        let decision = decide_request(
            "/debian/dists/sid/main/binary-amd64/Packages.gz",
            fake_host(),
            None,
            &fake_client(),
            &[],
            true,
            never_flat_blocked,
            PreciseInstant::now(),
        );
        let Decision::Cache {
            plan,
            pending_origin,
        } = decision
        else {
            unreachable!("expected Cache outcome")
        };
        assert_eq!(plan.layout, CacheLayout::Dists);
        let origin = pending_origin.expect("binary-amd64 must record an origin");
        assert_eq!(origin.distribution, "sid");
        assert_eq!(origin.component, "main");
        assert_eq!(origin.architecture, "binary-amd64");
    }

    #[test]
    fn passthrough_unrecognized_when_parser_declines() {
        let decision = decide_request(
            "/foo/bar.txt",
            fake_host(),
            None,
            &fake_client(),
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
    fn passthrough_non_deb_pool_for_pool_with_text_filename() {
        let decision = decide_request(
            "/debian/pool/main/f/foo/README.txt",
            fake_host(),
            None,
            &fake_client(),
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
            &fake_client(),
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
            &fake_client(),
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
            &fake_client(),
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
            &fake_client(),
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
            &fake_client(),
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
            &fake_client(),
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
