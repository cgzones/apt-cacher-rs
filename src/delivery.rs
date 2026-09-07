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

use std::time::Duration;

use tracing::info;

use crate::{
    cache_layout::{CachedFlavor, ConnectionDetails},
    database_task::{DbCmdTransfer, TransferKind},
    humanfmt::HumanFmt,
    metrics::{self, Counter},
    rate_log,
    transfer_error::{DeliveryEnd, EndsDelivery as _},
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

/// What happened to one served body.
pub(crate) struct ServeOutcome {
    /// Bytes the response promised (after Range trimming).
    pub(crate) size: u64,
    /// Bytes actually shipped.
    pub(crate) transferred: u64,
    /// A 206 delivery (recorded on the `deliveries` row).
    pub(crate) partial: bool,
    /// Client-side transfer window (from the first body byte).
    pub(crate) elapsed: Duration,
    /// How the delivery ended.
    pub(crate) end: DeliveryEnd,
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
    outcome: ServeOutcome,
) -> Option<DbCmdTransfer> {
    let ServeOutcome {
        size,
        transferred,
        partial,
        elapsed,
        end,
    } = outcome;
    let (what, who) = role.words();
    let via = mechanism.via();
    let aliased = cd.alias_suffix();
    let in_time = cd.request_received_at.elapsed();
    let volatile = if cd.cached_flavor() == CachedFlavor::Volatile {
        "volatile "
    } else {
        ""
    };

    let DeliveryEnd::Aborted(abort) = end else {
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
    };

    let segment = if abort.is_peer_disconnect() {
        rate_log::client_disconnect_segment(transferred, elapsed)
    } else {
        rate_log::client_abort_segment(transferred, elapsed)
    };
    let _reported = abort.conclude(format_args!(
        "Aborted serving {what} {volatile}file {} from mirror {}{aliased} for {who} {} in {} via {via} ({segment})",
        cd.debname,
        cd.mirror,
        cd.client,
        HumanFmt::Time(in_time),
    ));
    None
}

#[cfg(test)]
mod tests {
    use super::{Mechanism, Role};

    /// A build with neither client-facing backend has no [`Mechanism`] variant
    /// to serve through, so the abort sink is unreachable there.
    #[cfg(any(feature = "sendfile", feature = "hyper"))]
    mod abort {
        use tracing::Level;

        use super::super::{
            DeliveryEnd, Duration, Mechanism, Role, ServeOutcome, finish_cached_serve, metrics,
        };
        use crate::{
            test_support::{connection_details, levels_during},
            transfer_error::{ClientError, DeliveryFailure},
        };

        /// The mechanism token never enters the abort bookkeeping; the tests
        /// below take whichever variant the build under test compiles.
        #[cfg(feature = "sendfile")]
        const ABORT_VIA: Mechanism = Mechanism::Sendfile;
        #[cfg(all(feature = "hyper", not(feature = "sendfile")))]
        const ABORT_VIA: Mechanism = Mechanism::Channel;

        fn aborted(failure: DeliveryFailure) -> ServeOutcome {
            ServeOutcome {
                size: 10,
                transferred: 4,
                partial: false,
                elapsed: Duration::from_millis(5),
                end: DeliveryEnd::Aborted(failure),
            }
        }

        /// The sink owns no counter table: the failure counts itself exactly
        /// once through `record_terminal`, and reports itself at its own
        /// `severity`.
        #[test]
        fn cached_abort_counts_once_and_uses_the_policy_level() {
            let before = metrics::CLIENT_DISCONNECTED_MID_BODY.get();
            let cd = connection_details("abort.deb");
            let outcome = aborted(
                ClientError::io("write client", std::io::ErrorKind::BrokenPipe.into()).into(),
            );
            let levels = levels_during(|| {
                assert!(finish_cached_serve(&cd, ABORT_VIA, Role::Cached, outcome).is_none());
            });
            assert_eq!(metrics::CLIENT_DISCONNECTED_MID_BODY.get(), before + 1);
            assert_eq!(levels, vec![Level::INFO], "{levels:?}");
        }

        /// A client that stops reading is expected client behaviour, so the
        /// severity table reports it at INFO even though it is not a
        /// disconnect; the pre-policy sink logged this one at WARN.
        #[test]
        fn a_client_timeout_abort_is_reported_at_info() {
            let cd = connection_details("slow.deb");
            let outcome = aborted(
                ClientError::io("write client", std::io::ErrorKind::TimedOut.into()).into(),
            );
            let levels = levels_during(|| {
                assert!(finish_cached_serve(&cd, ABORT_VIA, Role::Cached, outcome).is_none());
            });
            assert_eq!(levels, vec![Level::INFO], "{levels:?}");
        }
    }

    /// `docs/logging.md` fixes the completion-line wording: a late-joiner
    /// serve says "joining client", never "client", and the mechanism token
    /// is the `via <token>` an operator greps for.
    #[test]
    fn completion_line_wording_stays_the_documented_one() {
        assert_eq!(Role::Cached.words(), ("cached", "client"));
        assert_eq!(Role::LateJoiner.words(), ("downloading", "joining client"));

        #[cfg(feature = "hyper")]
        {
            assert_eq!(Mechanism::Stream.via(), "stream");
            assert_eq!(Mechanism::Channel.via(), "channel");
        }
        #[cfg(all(feature = "mmap", feature = "hyper"))]
        assert_eq!(Mechanism::Mmap.via(), "mmap");
        #[cfg(feature = "sendfile")]
        assert_eq!(Mechanism::Sendfile.via(), "sendfile");
    }
}
