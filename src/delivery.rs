//! Completion bookkeeping for bodies served from the cache to a client.
//!
//! Every path that ships a cached (or in-progress) file - hyper stream, mmap,
//! channel, sendfile - ends the same way: bump `SERVED_<mechanism>` +
//! `SERVED_TOTAL` iff the body was fully delivered, log one completion or
//! abort line whose wording only differs in the mechanism token and the
//! cached/late-joiner phrasing, and record a `deliveries` row on success.
//! [`finish_cached_serve`] is the single implementation; the hyper bodies
//! call it from `Drop` (see `accounted_body.rs`), sendfile after its
//! syscall loop. (The splice path logs a combined upstream+client line and
//! stays separate.)

use std::fmt::Display;
use std::time::Duration;

use tracing::{info, warn};

use crate::{
    cache_layout::{CachedFlavor, ConnectionDetails},
    database_task::{DbCmdTransfer, TransferKind},
    humanfmt::HumanFmt,
    metrics::{self, Counter},
    rate_log,
};

/// How the bytes reached the client. Selects the per-mechanism metrics and
/// the `via <token>` in the completion line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Mechanism {
    /// hyper, buffered file read (`REQUESTS_COPY`).
    #[cfg(feature = "hyper")]
    Stream,
    /// hyper, memory-mapped file.
    #[cfg(all(feature = "mmap", feature = "hyper"))]
    Mmap,
    /// hyper, late joiner fed through an in-process channel.
    #[cfg(feature = "hyper")]
    Channel,
    /// sendfile(2) from the cache file.
    #[cfg(feature = "sendfile")]
    Sendfile,
}

impl Mechanism {
    /// The `via` token of the completion line.
    #[must_use]
    pub(crate) fn via(self) -> &'static str {
        match self {
            #[cfg(feature = "hyper")]
            Self::Stream => "stream",
            #[cfg(all(feature = "mmap", feature = "hyper"))]
            Self::Mmap => "mmap",
            #[cfg(feature = "hyper")]
            Self::Channel => "channel",
            #[cfg(feature = "sendfile")]
            Self::Sendfile => "sendfile",
        }
    }

    /// The per-request counter bumped when a body of this kind is created.
    #[cfg(feature = "hyper")]
    #[must_use]
    pub(crate) fn requests(self) -> &'static Counter {
        match self {
            Self::Stream => &metrics::REQUESTS_COPY,
            #[cfg(feature = "mmap")]
            Self::Mmap => &metrics::REQUESTS_MMAP,
            Self::Channel => &metrics::REQUESTS_CHANNEL,
            #[cfg(feature = "sendfile")]
            Self::Sendfile => &metrics::REQUESTS_SENDFILE,
        }
    }

    /// The byte accumulator for bytes shipped by this mechanism.
    #[cfg(feature = "hyper")]
    #[must_use]
    pub(crate) fn bytes_served(self) -> &'static metrics::Accumulator {
        match self {
            Self::Stream => &metrics::BYTES_SERVED_COPY,
            #[cfg(feature = "mmap")]
            Self::Mmap => &metrics::BYTES_SERVED_MMAP,
            Self::Channel => &metrics::BYTES_SERVED_CHANNEL,
            #[cfg(feature = "sendfile")]
            Self::Sendfile => &metrics::BYTES_SERVED_SENDFILE,
        }
    }

    /// The "body fully delivered" counter; parent is `SERVED_TOTAL`.
    fn served(self) -> &'static Counter {
        match self {
            #[cfg(feature = "hyper")]
            Self::Stream => &metrics::SERVED_COPY,
            #[cfg(all(feature = "mmap", feature = "hyper"))]
            Self::Mmap => &metrics::SERVED_MMAP,
            #[cfg(feature = "hyper")]
            Self::Channel => &metrics::SERVED_CHANNEL,
            #[cfg(feature = "sendfile")]
            Self::Sendfile => &metrics::SERVED_SENDFILE,
        }
    }
}

/// Whether the client was served a finished cache entry or joined an
/// in-flight download; only changes the wording of the completion line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    /// "Served cached file ... for client ..."
    Cached,
    /// "Served downloading file ... for joining client ..." - keep the
    /// "joining client" wording, it is a documented log marker.
    LateJoiner,
}

impl Role {
    fn words(self) -> (&'static str, &'static str) {
        match self {
            Self::Cached => ("cached", "client"),
            Self::LateJoiner => ("downloading", "joining client"),
        }
    }
}

/// Why a delivery stopped short, when the transport reported a reason.
pub(crate) struct AbortCause<'a> {
    pub(crate) reason: &'a dyn Display,
    /// Classified by the caller (`utils::is_peer_disconnect` or the body's
    /// equivalent): demotes the abort line to INFO and bumps
    /// `CLIENT_DISCONNECTED_MID_BODY`.
    pub(crate) peer_disconnect: bool,
}

/// What happened to one served body.
pub(crate) struct ServeOutcome<'a> {
    /// Bytes the response promised (after Range trimming).
    pub(crate) size: u64,
    /// Bytes actually shipped.
    pub(crate) transferred: u64,
    /// The body reached its end: `SERVED_*` credit and a DB row.
    pub(crate) complete: bool,
    /// A 206 delivery (recorded on the `deliveries` row).
    pub(crate) partial: bool,
    /// Client-side transfer window (from the first body byte).
    pub(crate) elapsed: Duration,
    /// Set when the transport surfaced an error; `None` for a silent
    /// client hang-up, which is logged at INFO without a reason.
    pub(crate) abort: Option<AbortCause<'a>>,
}

/// Finish one cached-file delivery: metrics, the completion/abort log line,
/// and - on a complete delivery - the `deliveries` row to enqueue. The
/// caller sends the row (`send_db_command` from async code,
/// `send_db_command_nonblocking` from `Drop`).
#[must_use]
pub(crate) fn finish_cached_serve(
    cd: &ConnectionDetails,
    mechanism: Mechanism,
    role: Role,
    outcome: ServeOutcome<'_>,
) -> Option<DbCmdTransfer> {
    let ServeOutcome {
        size,
        transferred,
        complete,
        partial,
        elapsed,
        abort,
    } = outcome;
    let (what, who) = role.words();
    let via = mechanism.via();
    let aliased = cd
        .aliased_host
        .map_or_else(String::new, |alias| format!(" aliased to host {alias}"));
    let in_time = cd.request_received_at.elapsed();
    let volatile = if cd.cached_flavor == CachedFlavor::Volatile {
        "volatile "
    } else {
        ""
    };

    if complete {
        mechanism.served().increment();
        metrics::SERVED_TOTAL.increment();
        info!(
            "Served {what} {volatile}file {} from mirror {}{aliased} for {who} {} in {} via {via} ({})",
            cd.debname,
            cd.mirror,
            cd.client,
            HumanFmt::Time(in_time),
            rate_log::client_segment(transferred, elapsed),
        );
        return Some(DbCmdTransfer {
            mirror: cd.mirror.clone(),
            debname: cd.debname.clone(),
            size,
            elapsed,
            client_ip: cd.client.ip(),
            kind: TransferKind::Delivery { partial },
        });
    }

    let segment = rate_log::client_disconnect_segment(transferred, elapsed);
    match abort {
        Some(AbortCause {
            reason,
            peer_disconnect: true,
        }) => {
            metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
            info!(
                "Aborted serving {what} {volatile}file {} from mirror {}{aliased} for {who} {} in {} via {via} ({segment}):  {reason}",
                cd.debname,
                cd.mirror,
                cd.client,
                HumanFmt::Time(in_time),
            );
        }
        Some(AbortCause {
            reason,
            peer_disconnect: false,
        }) => {
            warn!(
                "Aborted serving {what} {volatile}file {} from mirror {}{aliased} for {who} {} in {} via {via} ({segment}):  {reason}",
                cd.debname,
                cd.mirror,
                cd.client,
                HumanFmt::Time(in_time),
            );
        }
        None => {
            info!(
                "Aborted serving {what} {volatile}file {} from mirror {}{aliased} for {who} {} in {} via {via} ({segment})",
                cd.debname,
                cd.mirror,
                cd.client,
                HumanFmt::Time(in_time),
            );
        }
    }
    None
}
