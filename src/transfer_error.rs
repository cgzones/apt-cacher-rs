//! Source-preserving failures shared by transfer backends.
//!
//! Conversion from an untyped library error belongs at the operation adapter.
//! In particular, client failures cannot convert into a shared download failure.
//!
//! A failure that ends a delivery or a download is *concluded* exactly once, by
//! the owner that ends it: [`EndsDelivery::conclude`] (for a
//! [`DeliveryFailure`] or a `HeaderWriteFailure`),
//! [`DownloadFailure::conclude`] and `UpstreamError::conclude` bump the cause's terminal counters, log it
//! and return the [`Reported`] proof. Terminal counting is private to this
//! module, so no sink can count without logging, or count twice by forgetting
//! that another sink already did; constructing a failure has no side effects.

#[cfg(feature = "sendfile")]
use std::time::Duration;
use std::{
    convert::Infallible,
    error::Error,
    fmt, io,
    path::Path,
    sync::{Arc, atomic::AtomicBool},
};

use http::StatusCode;

#[cfg(feature = "sendfile")]
use crate::humanfmt::HumanFmt;
use crate::{
    error::{ErrorReport, is_peer_disconnect},
    log_once::{Logged, Reported},
    metrics::{self, Counter},
    rate_checker::InsufficientRate,
    upstream_retry::RetryStop,
};

/// Log level a terminal failure is reported at. [`DeliveryFailure::severity`]
/// is the sole implementation of the delivery-severity table, so a sink picks
/// its level by asking the failure rather than by re-deriving the table.
///
/// This implements the table in `docs/logging.md`: a client timeout and a
/// client rate breach are INFO alongside a peer disconnect, because both are
/// expected client behaviour that is already counter-backed -- an operator
/// sees them in `RATE_LIMIT_CLIENT` and the socket-timeout counters, so a
/// WARN per occurrence only floods the log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Severity {
    Info,
    Warn,
    Error,
}

/// Where in the upstream exchange a failure happened. Connect and Head failures
/// are once-gated by [`DownloadFailure::conclude`] (a down mirror must not
/// flood WARN); Body failures are ungated (each stalling mirror is operator
/// signal).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Connect,
    Head,
    Body,
}

/// What went wrong in one operation. Shared by every failure family; what is
/// family-specific (an upstream phase, retry attempts, a terminal counter)
/// lives on the family, so no family carries a state it can never be in.
#[derive(Debug)]
enum Cause {
    Io(io::Error),
    Transport(Box<dyn Error + Send + Sync>),
    #[cfg(feature = "sendfile")]
    Timeout(Duration),
    Rate(InsufficientRate),
    Invalid(String),
}

#[derive(Debug)]
struct OperationFailure {
    operation: &'static str,
    cause: Cause,
}

impl fmt::Display for OperationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { operation, cause } = self;
        match cause {
            Cause::Io(_) | Cause::Transport(_) => f.write_str(operation),
            #[cfg(feature = "sendfile")]
            Cause::Timeout(duration) => {
                write!(f, "{operation} after {}", HumanFmt::Time(*duration))
            }
            Cause::Rate(rate) => rate.fmt_with_context(f, format_args!(" for {operation}")),
            Cause::Invalid(reason) => write!(f, "{operation}: {reason}"),
        }
    }
}

impl Error for OperationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.cause {
            Cause::Io(error) => Some(error),
            Cause::Transport(error) => Some(error.as_ref()),
            #[cfg(feature = "sendfile")]
            Cause::Timeout(_) => None,
            Cause::Rate(_) | Cause::Invalid(_) => None,
        }
    }
}

macro_rules! local_error {
    ($name:ident) => {
        #[derive(Clone, Debug, thiserror::Error)]
        #[error(transparent)]
        pub(crate) struct $name(Arc<OperationFailure>);

        impl $name {
            fn new(operation: &'static str, cause: Cause) -> Self {
                Self(Arc::new(OperationFailure { operation, cause }))
            }
        }
    };
}
local_error!(ClientError);
local_error!(CacheError);
local_error!(InternalError);

/// The upstream exchange step a failure belongs to. A connect failure is the
/// terminal end of the retry loop, so its attempt count and the reason the
/// loop stopped belong to it and to no other phase.
#[derive(Debug)]
enum UpstreamPhase {
    Connect { attempts: u32, stop: RetryStop },
    Head,
    Body,
}

#[derive(Debug)]
struct UpstreamFailure {
    failure: OperationFailure,
    phase: UpstreamPhase,
    /// Bumped by [`UpstreamError::record_terminal`], never at construction:
    /// an error built and then handled as non-terminal must not count.
    counter: Option<&'static Counter>,
}

/// Request failures retain the target after redirects, aliases and scheme
/// selection. Attaching it does not change the phase or terminal counter.
#[derive(Clone, Debug)]
pub(crate) struct UpstreamError {
    failure: Arc<UpstreamFailure>,
    target: Option<Arc<str>>,
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { failure, target } = self;
        let UpstreamFailure {
            failure,
            phase,
            counter: _,
        } = failure.as_ref();
        match phase {
            UpstreamPhase::Connect { attempts, stop } => write!(
                f,
                "{} after {attempts} connection attempts ({stop})",
                failure.operation
            )?,
            UpstreamPhase::Head | UpstreamPhase::Body => failure.fmt(f)?,
        }
        if let Some(target) = target {
            write!(f, " for `{target}`")?;
        }
        Ok(())
    }
}

impl Error for UpstreamError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        let Self { failure, target: _ } = self;
        // Like the transparent source wrappers: Display renders the operation,
        // and source exposes the underlying error without repeating that layer.
        failure.failure.source()
    }
}

impl UpstreamError {
    fn new(
        operation: &'static str,
        phase: UpstreamPhase,
        cause: Cause,
        counter: Option<&'static Counter>,
    ) -> Self {
        Self {
            failure: Arc::new(UpstreamFailure {
                failure: OperationFailure { operation, cause },
                phase,
                counter,
            }),
            target: None,
        }
    }

    pub(crate) fn with_target(mut self, target: impl Into<Arc<str>>) -> Self {
        self.target = Some(target.into());
        self
    }

    #[cfg(feature = "splice")]
    pub(crate) fn io(operation: &'static str, error: io::Error) -> Self {
        Self::new(operation, UpstreamPhase::Body, Cause::Io(error), None)
    }

    #[cfg(any(feature = "hyper", test))]
    pub(crate) fn transport(
        operation: &'static str,
        error: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self::new(
            operation,
            UpstreamPhase::Body,
            Cause::Transport(Box::new(error)),
            None,
        )
    }

    #[cfg(feature = "splice")]
    pub(crate) fn timeout(operation: &'static str, duration: Duration) -> Self {
        Self::new(
            operation,
            UpstreamPhase::Body,
            Cause::Timeout(duration),
            None,
        )
    }

    /// Counts `UPSTREAM_PROTOCOL_VIOLATION` once concluded.
    pub(crate) fn protocol(reason: impl Into<String>) -> Self {
        Self::new(
            "upstream protocol failure",
            UpstreamPhase::Body,
            Cause::Invalid(reason.into()),
            Some(&metrics::UPSTREAM_PROTOCOL_VIOLATION),
        )
    }

    /// A valid response can exceed this proxy's local body limit. Counts
    /// `UPSTREAM_BODY_LIMIT` once concluded.
    pub(crate) fn body_limit(reason: impl Into<String>) -> Self {
        Self::new(
            "upstream body limit",
            UpstreamPhase::Body,
            Cause::Invalid(reason.into()),
            Some(&metrics::UPSTREAM_BODY_LIMIT),
        )
    }

    /// Counts `RATE_LIMIT_UPSTREAM` once concluded.
    pub(crate) fn rate(rate: InsufficientRate) -> Self {
        Self::new(
            "upstream",
            UpstreamPhase::Body,
            Cause::Rate(rate),
            Some(&metrics::RATE_LIMIT_UPSTREAM),
        )
    }

    pub(crate) fn is_rate(&self) -> bool {
        matches!(self.failure.failure.cause, Cause::Rate(_))
    }

    /// The terminal end of the connect-retry loop: `attempts` and the reason
    /// that stopped it are part of the failure, not of the call site, so every
    /// backend renders them identically.
    pub(crate) fn connect(
        operation: &'static str,
        error: io::Error,
        attempts: u32,
        stop: RetryStop,
    ) -> Self {
        Self::new(
            operation,
            UpstreamPhase::Connect { attempts, stop },
            Cause::Io(error),
            None,
        )
    }

    /// Only a backend reading its response head off a raw socket produces an
    /// `io::Error` for the head phase; hyper's head failures are
    /// `Self::head_transport`.
    #[cfg_attr(
        not(any(feature = "splice", test)),
        expect(
            dead_code,
            reason = "the splice backend is the only head-phase io caller"
        )
    )]
    pub(crate) fn head_io(operation: &'static str, error: io::Error) -> Self {
        Self::new(operation, UpstreamPhase::Head, Cause::Io(error), None)
    }

    #[cfg(feature = "hyper")]
    pub(crate) fn head_transport(
        operation: &'static str,
        error: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self::new(
            operation,
            UpstreamPhase::Head,
            Cause::Transport(Box::new(error)),
            None,
        )
    }

    /// A head the transport delivered intact but HTTP could not accept: the
    /// reason is the whole failure, so there is no source error under it.
    #[cfg_attr(
        not(any(feature = "splice", test)),
        expect(
            dead_code,
            reason = "the splice backend is the only head-phase protocol caller"
        )
    )]
    pub(crate) fn head_protocol(reason: impl Into<String>) -> Self {
        Self::new(
            "upstream response head",
            UpstreamPhase::Head,
            Cause::Invalid(reason.into()),
            None,
        )
    }

    pub(crate) fn phase(&self) -> Phase {
        match self.failure.phase {
            UpstreamPhase::Connect {
                attempts: _,
                stop: _,
            } => Phase::Connect,
            UpstreamPhase::Head => Phase::Head,
            UpstreamPhase::Body => Phase::Body,
        }
    }

    /// The one counter bump for an upstream failure that ends a transfer.
    fn record_terminal(&self) {
        if let Some(counter) = self.failure.counter {
            counter.increment();
        }
    }

    /// End the transfer this failure stops outside any download runner or
    /// delivery sink (a pass-through relay's connect, a cleanup fetch, a
    /// connection-reuse drain): count it, then log it through `log`, whose
    /// [`Logged`] proves the line was written.
    #[cfg(feature = "splice")]
    pub(crate) fn conclude(self, log: impl FnOnce(&Self) -> Logged) -> Reported<Self> {
        self.record_terminal();
        log(&self).with(self)
    }
}

/// An upstream failure concluded outside any download runner; see
/// [`UpstreamError::conclude`].
#[cfg(feature = "splice")]
pub(crate) type ReportedUpstream = Reported<UpstreamError>;

impl ClientError {
    #[cfg(any(feature = "sendfile", test))]
    pub(crate) fn io(operation: &'static str, error: io::Error) -> Self {
        Self::new(operation, Cause::Io(error))
    }

    #[cfg(feature = "sendfile")]
    pub(crate) fn timeout(operation: &'static str, duration: Duration) -> Self {
        Self::new(operation, Cause::Timeout(duration))
    }

    pub(crate) fn rate(rate: InsufficientRate) -> Self {
        Self::new("client", Cause::Rate(rate))
    }

    pub(crate) fn is_rate(&self) -> bool {
        matches!(self.0.cause, Cause::Rate(_))
    }

    pub(crate) fn is_timeout(&self) -> bool {
        match &self.0.cause {
            #[cfg(feature = "sendfile")]
            Cause::Timeout(_) => true,
            Cause::Rate(_) => true,
            Cause::Io(error) => error.kind() == io::ErrorKind::TimedOut,
            Cause::Transport(_) | Cause::Invalid(_) => false,
        }
    }

    pub(crate) fn is_peer_disconnect(&self) -> bool {
        matches!(&self.0.cause, Cause::Io(error) if is_peer_disconnect(error))
    }
}

impl CacheError {
    /// A cache-directory syscall failed: count it where it happened, then
    /// retain its path and type it. The counter's scope is stat/open/read/write
    /// failures, so a consistency check that finds the bytes wrong builds a
    /// [`Self::invalid`] instead and leaves `CACHE_IO_FAILURE` alone.
    pub(crate) fn counted_io(operation: &'static str, path: &Path, error: io::Error) -> Self {
        #[derive(Debug, thiserror::Error)]
        #[error("`{}`", path.display())]
        struct CacheIoError {
            path: std::path::PathBuf,
            source: io::Error,
        }

        metrics::CACHE_IO_FAILURE.increment();
        Self::io(
            operation,
            io::Error::new(
                error.kind(),
                CacheIoError {
                    path: path.to_owned(),
                    source: error,
                },
            ),
        )
    }

    pub(crate) fn io(operation: &'static str, error: io::Error) -> Self {
        Self::new(operation, Cause::Io(error))
    }

    pub(crate) fn invalid(operation: &'static str, reason: impl Into<String>) -> Self {
        Self::new(operation, Cause::Invalid(reason.into()))
    }
}

impl InternalError {
    #[cfg(feature = "sendfile")]
    pub(crate) fn io(operation: &'static str, error: io::Error) -> Self {
        Self::new(operation, Cause::Io(error))
    }

    pub(crate) fn invalid(operation: &'static str, reason: impl Into<String>) -> Self {
        Self::new(operation, Cause::Invalid(reason.into()))
    }

    #[cfg(feature = "splice")]
    pub(crate) fn transport(
        operation: &'static str,
        error: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self::new(operation, Cause::Transport(Box::new(error)))
    }
}

/// A client write that failed before the response body: the head of a
/// response, or a whole proxy-generated error response. It ends the delivery
/// but loses no body byte and cannot breach a rate, so -- unlike a
/// [`DeliveryFailure::Client`] -- it has no terminal counter to bump:
/// `CLIENT_DISCONNECTED_MID_BODY` keeps its mid-body scope by construction.
#[cfg(feature = "splice")]
#[derive(Clone, Debug)]
pub(crate) struct HeaderWriteFailure(ClientError);

#[cfg(feature = "splice")]
impl HeaderWriteFailure {
    pub(crate) fn io(operation: &'static str, error: io::Error) -> Self {
        Self(ClientError::io(operation, error))
    }
}

/// A failure that can end a delivery. Concluding it is the one sink for that
/// delivery: it bumps whatever terminal counters the failure's type carries,
/// logs `{context}:  {report}` at [`DeliveryFailure::severity`] and proves
/// it. Lets a sink shared by header and body writes take either without
/// re-deciding at runtime which of them counts.
pub(crate) trait EndsDelivery {
    fn conclude(self, context: fmt::Arguments<'_>) -> ReportedDelivery;
}

/// The one sink every owner that ends a delivery calls, once: it bumps the
/// cause's terminal counters and logs `{context}:  {report}` at
/// [`DeliveryFailure::severity`].
impl EndsDelivery for DeliveryFailure {
    fn conclude(self, context: fmt::Arguments<'_>) -> ReportedDelivery {
        self.record_terminal();
        self.report(context)
    }
}

/// Counts nothing: a header write lost no body byte.
#[cfg(feature = "splice")]
impl EndsDelivery for HeaderWriteFailure {
    fn conclude(self, context: fmt::Arguments<'_>) -> ReportedDelivery {
        let Self(error) = self;
        DeliveryFailure::Client(error).report(context)
    }
}

/// One process-wide gate for every connect/head failure of every download: a
/// mirror that is down fails identically for every request in flight, so the
/// gate belongs to the condition, not to a call site.
static UPSTREAM_CONNECT_GATE: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum DownloadFailure {
    #[error("upstream download aborted")]
    Upstream(#[from] UpstreamError),
    #[error("local I/O failure")]
    Cache(#[from] CacheError),
    #[error("internal transfer failure")]
    Internal(#[from] InternalError),
    #[error("download cancelled; cause unknown")]
    Cancelled,
}

impl DownloadFailure {
    /// Base severity, before [`Self::conclude`] applies connect/head flood
    /// control.
    pub(crate) fn severity(&self) -> Severity {
        match self {
            Self::Cancelled => Severity::Info,
            Self::Upstream(_) => Severity::Warn,
            Self::Cache(_) | Self::Internal(_) => Severity::Error,
        }
    }

    pub(crate) fn is_rate(&self) -> bool {
        matches!(self, Self::Upstream(error) if error.is_rate())
    }

    /// The one counter bump for a download that ends here; the cause decides.
    fn record_terminal(&self) {
        match self {
            Self::Upstream(error) => error.record_terminal(),
            Self::Cache(_) | Self::Internal(_) | Self::Cancelled => {}
        }
    }

    /// The response a backend still able to answer sends for this failure.
    /// Every backend and every joiner consumes this; CLAUDE.md's 5xx
    /// convention lists the bodies.
    pub(crate) fn response_parts(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Upstream(_) => (StatusCode::BAD_GATEWAY, "Upstream Error"),
            Self::Cache(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure"),
            Self::Internal(_) | Self::Cancelled => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Download Aborted")
            }
        }
    }

    /// End the download: count the cause, log `{context}:  {report}` and
    /// prove it. A connect or head failure shares one process-wide WARN-once
    /// gate (then INFO); every other cause logs at [`Self::severity`].
    pub(crate) fn conclude(self, context: fmt::Arguments<'_>) -> ReportedDownloadFailure {
        self.record_terminal();
        let line = fmt::from_fn(|f| write!(f, "{context}:  {}", ErrorReport(&self)));
        let logged = if matches!(&self, Self::Upstream(error)
            if matches!(error.phase(), Phase::Connect | Phase::Head))
        {
            Logged::warn_once_or_info(&UPSTREAM_CONNECT_GATE, format_args!("{line}"))
        } else {
            Logged::at(self.severity(), format_args!("{line}"))
        };
        logged.with(Arc::new(self))
    }
}

/// A download the owning runner concluded: readers share the same allocation,
/// and only [`DownloadFailure::conclude`] can mint one.
pub(crate) type ReportedDownloadFailure = Reported<Arc<DownloadFailure>>;

impl ReportedDownloadFailure {
    pub(crate) fn failure(&self) -> &DownloadFailure {
        self.get()
    }

    /// Publish the retained cause to readers without reallocating it.
    pub(crate) fn shared(&self) -> Arc<DownloadFailure> {
        Arc::clone(self.get())
    }
}

#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum DeliveryFailure {
    /// An uncached body reads directly from its upstream, with no shared owner.
    #[error("upstream body failed")]
    Upstream(#[from] UpstreamError),
    #[error("{}", if .0.is_peer_disconnect() { "peer disconnect" } else if .0.is_timeout() { "downstream timeout" } else { "downstream I/O failure" })]
    Client(#[from] ClientError),
    #[error("local I/O failure")]
    Cache(#[from] CacheError),
    #[error("internal transfer failure")]
    Internal(#[from] InternalError),
    #[error("shared download failed")]
    Download(#[source] Arc<DownloadFailure>),
    #[error("delivery cancelled; cause unknown")]
    Cancelled,
}

/// A delivery its owner concluded; see [`DeliveryFailure::conclude`].
pub(crate) type ReportedDelivery = Reported<DeliveryFailure>;

impl DeliveryFailure {
    pub(crate) fn is_peer_disconnect(&self) -> bool {
        matches!(self, Self::Client(error) if error.is_peer_disconnect())
    }

    /// The level this failure is reported at, wherever it lands. A shared
    /// download carries the severity of the failure it wraps, so a joiner and
    /// the writer report the same cause at the same level.
    pub(crate) fn severity(&self) -> Severity {
        match self {
            Self::Client(error) => {
                if error.is_peer_disconnect() || error.is_timeout() {
                    Severity::Info
                } else {
                    Severity::Warn
                }
            }
            Self::Cancelled => Severity::Info,
            Self::Upstream(_) => Severity::Warn,
            Self::Cache(_) | Self::Internal(_) => Severity::Error,
            Self::Download(failure) => failure.severity(),
        }
    }

    /// The one counter bump for a delivery that ends here. Rate probes that
    /// end in demotion never reach a sink, so demotion counts only as demotion.
    /// [`Self::Download`] does not re-count: the writer counted it.
    fn record_terminal(&self) {
        match self {
            Self::Client(error) => {
                if error.is_rate() {
                    metrics::RATE_LIMIT_CLIENT.increment();
                }
                if error.is_peer_disconnect() {
                    metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
                }
            }
            Self::Upstream(error) => error.record_terminal(),
            Self::Download(_) | Self::Cache(_) | Self::Internal(_) | Self::Cancelled => {}
        }
    }

    /// Log `{context}:  {report}` at [`Self::severity`], counting nothing.
    fn report(self, context: fmt::Arguments<'_>) -> ReportedDelivery {
        Logged::at(
            self.severity(),
            format_args!("{context}:  {}", ErrorReport(&self)),
        )
        .with(self)
    }

    /// `sendfile(2)` reads a file and writes a socket, so only the socket
    /// errnos prove the client's side failed; every other descriptor failure
    /// is ours.
    #[cfg(feature = "sendfile")]
    pub(crate) fn sendfile(error: io::Error) -> Self {
        let Some(raw) = error.raw_os_error() else {
            return InternalError::io("sendfile file-to-socket operation", error).into();
        };
        match classify_mixed_descriptor(nix::errno::Errno::from_raw(raw), Descriptors::FileToSocket)
        {
            MixedFailure::Socket(error) => ClientError::io("sendfile client socket", error).into(),
            MixedFailure::Internal(error) => {
                InternalError::io("sendfile file-to-socket operation", error).into()
            }
        }
    }
}

/// The two descriptors a mixed-descriptor syscall moves bytes between, source
/// first. Which errnos can only have come from the socket depends on it.
#[cfg(feature = "sendfile")]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Descriptors {
    /// `sendfile(2)` from a cache file: the file may sit on a network
    /// filesystem, so `ETIMEDOUT` is not the socket's.
    FileToSocket,
    /// `splice(2)` from a pipe into a socket: a pipe neither times out nor
    /// reports `EPIPE` on its read side.
    #[cfg_attr(
        all(not(feature = "splice"), not(test)),
        expect(dead_code, reason = "only the splice backend splices into a socket")
    )]
    PipeToSocket,
    /// `splice(2)` from a socket into a pipe: `EPIPE` names the pipe
    /// destination, not the peer.
    #[cfg_attr(
        all(not(feature = "splice"), not(test)),
        expect(dead_code, reason = "only the splice backend splices into a pipe end")
    )]
    SocketToPipe,
}

/// Verdict of [`classify_mixed_descriptor`]; the caller types the side.
#[cfg(feature = "sendfile")]
#[derive(Debug)]
pub(crate) enum MixedFailure {
    /// An errno only the socket can raise: its end of the transfer failed
    /// (the peer is gone, or the network path to it is).
    Socket(io::Error),
    /// Any other errno: a descriptor or pipe problem on our side.
    Internal(io::Error),
}

/// The one errno table for syscalls that touch a socket and a file or pipe.
/// A socket errno is attributed to the socket's side whatever it means --
/// peer loss or an unreachable network alike -- so a zero-copy transfer
/// attributes it exactly like the userspace write of the same socket would.
#[cfg(feature = "sendfile")]
pub(crate) fn classify_mixed_descriptor(
    errno: nix::errno::Errno,
    descriptors: Descriptors,
) -> MixedFailure {
    use nix::errno::Errno;

    let socket_only = matches!(
        errno,
        Errno::ECONNRESET
            | Errno::ECONNABORTED
            | Errno::ECONNREFUSED
            | Errno::ENOTCONN
            | Errno::ESHUTDOWN
            | Errno::ENETRESET
            | Errno::ENETDOWN
            | Errno::ENETUNREACH
            | Errno::EHOSTDOWN
            | Errno::EHOSTUNREACH
    );
    let socket = socket_only
        || (errno == Errno::EPIPE && !matches!(descriptors, Descriptors::SocketToPipe))
        || (errno == Errno::ETIMEDOUT && !matches!(descriptors, Descriptors::FileToSocket));
    let error = io::Error::from_raw_os_error(errno as i32);
    if socket {
        MixedFailure::Socket(error)
    } else {
        MixedFailure::Internal(error)
    }
}

impl From<Infallible> for DeliveryFailure {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

/// A complete delivery carries no failure; cancellation is an explicit failure.
/// `F` is [`ReportedDelivery`] once the owner that ended the delivery
/// concluded it, so a concluded end cannot be concluded again.
#[derive(Clone, Debug)]
pub(crate) enum DeliveryEnd<F = DeliveryFailure> {
    Complete,
    Aborted(F),
}

/// The result handed across a transfer/task boundary. Bytes remain progress,
/// independent of which operation failed.
#[cfg(feature = "sendfile")]
#[derive(Debug)]
pub(crate) struct TransferOutcome<F = DeliveryFailure> {
    pub(crate) transferred: u64,
    pub(crate) end: DeliveryEnd<F>,
}

#[cfg(feature = "sendfile")]
impl<F> TransferOutcome<F> {
    pub(crate) fn complete(transferred: u64) -> Self {
        Self {
            transferred,
            end: DeliveryEnd::Complete,
        }
    }
}

#[cfg(feature = "sendfile")]
impl TransferOutcome {
    pub(crate) fn aborted(transferred: u64, failure: impl Into<DeliveryFailure>) -> Self {
        Self {
            transferred,
            end: DeliveryEnd::Aborted(failure.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::ErrorReport, nonzero, rate_checker::RateChecker, upstream_retry::RetryLimit,
    };

    #[test]
    fn a_cache_broken_pipe_is_not_a_client_disconnect() {
        let failure: DeliveryFailure =
            CacheError::io("read cache", io::ErrorKind::BrokenPipe.into()).into();
        assert!(!failure.is_peer_disconnect());
        assert!(matches!(failure, DeliveryFailure::Cache(_)));
        let failure: DeliveryFailure =
            ClientError::io("write client", io::ErrorKind::BrokenPipe.into()).into();
        assert!(failure.is_peer_disconnect());
    }

    #[test]
    fn shared_failure_keeps_each_source_layer_once() {
        let source = io::Error::new(io::ErrorKind::TimedOut, "injected upstream timeout");
        let failure = Arc::new(DownloadFailure::Upstream(UpstreamError::transport(
            "read upstream body",
            source,
        )));
        let delivery = DeliveryFailure::Download(Arc::clone(&failure));
        let rendered = ErrorReport(&delivery).to_string();
        for layer in [
            "shared download failed",
            "upstream download aborted",
            "read upstream body",
            "injected upstream timeout",
        ] {
            assert_eq!(rendered.matches(layer).count(), 1, "{rendered}");
        }
        assert!(!delivery.is_peer_disconnect());
        assert_eq!(Arc::strong_count(&failure), 2);
    }

    #[test]
    fn severity_table() {
        let disconnect: DeliveryFailure =
            ClientError::io("write client", io::ErrorKind::BrokenPipe.into()).into();
        assert_eq!(disconnect.severity(), Severity::Info);
        let timeout: DeliveryFailure =
            ClientError::io("write client", io::ErrorKind::TimedOut.into()).into();
        assert_eq!(timeout.severity(), Severity::Info);
        let other: DeliveryFailure =
            ClientError::io("write client", io::ErrorKind::InvalidInput.into()).into();
        assert_eq!(other.severity(), Severity::Warn);
        // A client rate breach is expected, counter-backed behaviour: INFO
        // alongside a disconnect. The same breach on the upstream side is a
        // stalling mirror and stays at WARN.
        let mut rc = RateChecker::with_timeframe(nonzero!(1000), nonzero!(1));
        rc.add(1);
        let rate = rc.check_fail().expect("1 B/s breaches 1000 B/s");
        let client_rate: DeliveryFailure = ClientError::rate(rate).into();
        assert_eq!(client_rate.severity(), Severity::Info);
        let upstream_rate: DeliveryFailure = UpstreamError::rate(rate).into();
        assert_eq!(upstream_rate.severity(), Severity::Warn);
        let upstream: DeliveryFailure = UpstreamError::protocol("bad").into();
        assert_eq!(upstream.severity(), Severity::Warn);
        assert_eq!(DeliveryFailure::Cancelled.severity(), Severity::Info);
        let shared_cancel = DeliveryFailure::Download(Arc::new(DownloadFailure::Cancelled));
        assert_eq!(shared_cancel.severity(), Severity::Info);
        let shared_upstream = DeliveryFailure::Download(Arc::new(DownloadFailure::Upstream(
            UpstreamError::protocol("bad"),
        )));
        assert_eq!(shared_upstream.severity(), Severity::Warn);
        let cache: DeliveryFailure = CacheError::invalid("read", "short").into();
        assert_eq!(cache.severity(), Severity::Error);
        let internal: DeliveryFailure = InternalError::invalid("pipe", "broken").into();
        assert_eq!(internal.severity(), Severity::Error);
    }

    #[test]
    fn shared_delivery_severity_preserves_every_download_cause() {
        for (failure, level) in [
            (DownloadFailure::Cancelled, Severity::Info),
            (UpstreamError::protocol("short body").into(), Severity::Warn),
            (
                CacheError::invalid("read", "short file").into(),
                Severity::Error,
            ),
            (
                InternalError::invalid("pipe", "unexpected EOF").into(),
                Severity::Error,
            ),
        ] {
            assert_eq!(failure.severity(), level);
            assert_eq!(
                DeliveryFailure::Download(Arc::new(failure)).severity(),
                level
            );
        }
    }

    #[test]
    fn response_parts_table() {
        assert_eq!(
            DownloadFailure::Upstream(UpstreamError::protocol("x")).response_parts(),
            (StatusCode::BAD_GATEWAY, "Upstream Error")
        );
        assert_eq!(
            DownloadFailure::Cache(CacheError::invalid("op", "r")).response_parts(),
            (StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure")
        );
        assert_eq!(
            DownloadFailure::Internal(InternalError::invalid("op", "r")).response_parts(),
            (StatusCode::INTERNAL_SERVER_ERROR, "Download Aborted")
        );
        assert_eq!(
            DownloadFailure::Cancelled.response_parts(),
            (StatusCode::INTERNAL_SERVER_ERROR, "Download Aborted")
        );
    }

    #[test]
    fn upstream_phase_is_fixed_by_constructor() {
        let connect = UpstreamError::connect(
            "connect upstream",
            io::Error::new(io::ErrorKind::ConnectionRefused, "injected refusal"),
            3,
            RetryLimit::Attempts.into(),
        )
        .with_target("https://redirect.example:8443/pool/package.deb");
        assert_eq!(connect.phase(), Phase::Connect);
        assert!(
            connect
                .to_string()
                .contains("after 3 connection attempts (attempt cap reached)"),
            "{connect}"
        );
        // The retry loop's own error stays reachable as a source, so the
        // runner's single once-gated line still names why the dial failed.
        assert!(connect.source().is_some());
        let rendered = ErrorReport(&connect).to_string();
        assert_eq!(
            rendered
                .matches("https://redirect.example:8443/pool/package.deb")
                .count(),
            1,
            "{rendered}"
        );
        assert_eq!(
            rendered.matches("connect upstream").count(),
            1,
            "{rendered}"
        );
        assert_eq!(
            rendered.matches("injected refusal").count(),
            1,
            "{rendered}"
        );
        assert_eq!(
            UpstreamError::head_protocol("bad head").phase(),
            Phase::Head
        );
        assert_eq!(
            UpstreamError::head_io("read upstream head", io::ErrorKind::Other.into()).phase(),
            Phase::Head
        );
        #[cfg(feature = "hyper")]
        assert_eq!(
            UpstreamError::head_transport("await upstream head", io::Error::other("injected"))
                .phase(),
            Phase::Head
        );
        assert_eq!(UpstreamError::protocol("bad body").phase(), Phase::Body);
    }

    #[test]
    fn terminal_counters_follow_the_cause() {
        let mut rc = RateChecker::with_timeframe(nonzero!(1000), nonzero!(1));
        rc.add(1);
        let rate = rc.check_fail().expect("1 B/s breaches 1000 B/s");
        let before_client = metrics::RATE_LIMIT_CLIENT.get();
        let before_disc = metrics::CLIENT_DISCONNECTED_MID_BODY.get();
        let before_up = metrics::RATE_LIMIT_UPSTREAM.get();
        DeliveryFailure::from(ClientError::rate(rate)).record_terminal();
        assert_eq!(metrics::RATE_LIMIT_CLIENT.get(), before_client + 1);
        DeliveryFailure::from(ClientError::io("w", io::ErrorKind::BrokenPipe.into()))
            .record_terminal();
        assert_eq!(metrics::CLIENT_DISCONNECTED_MID_BODY.get(), before_disc + 1);
        DownloadFailure::Upstream(UpstreamError::rate(rate)).record_terminal();
        assert_eq!(metrics::RATE_LIMIT_UPSTREAM.get(), before_up + 1);
        // An uncached body reads its upstream directly, so the delivery side
        // owns the same bump for the same cause.
        DeliveryFailure::Upstream(UpstreamError::rate(rate)).record_terminal();
        assert_eq!(metrics::RATE_LIMIT_UPSTREAM.get(), before_up + 2);
        DeliveryFailure::Cancelled.record_terminal();
        assert_eq!(metrics::RATE_LIMIT_CLIENT.get(), before_client + 1);
        assert_eq!(metrics::CLIENT_DISCONNECTED_MID_BODY.get(), before_disc + 1);
    }

    #[test]
    #[cfg(feature = "sendfile")]
    fn mixed_descriptor_classifier_owns_the_socket_errnos() {
        use Descriptors::{FileToSocket, PipeToSocket, SocketToPipe};
        use nix::errno::Errno;

        let socket = |errno, descriptors| {
            matches!(
                classify_mixed_descriptor(errno, descriptors),
                MixedFailure::Socket(_)
            )
        };
        // EPIPE is the socket's only when the socket is the destination.
        assert!(socket(Errno::EPIPE, FileToSocket));
        assert!(socket(Errno::EPIPE, PipeToSocket));
        assert!(!socket(Errno::EPIPE, SocketToPipe));
        // A timeout can come from a network filesystem, never from a pipe.
        assert!(!socket(Errno::ETIMEDOUT, FileToSocket));
        assert!(socket(Errno::ETIMEDOUT, PipeToSocket));
        assert!(socket(Errno::ETIMEDOUT, SocketToPipe));
        // Errnos only a socket raises are the socket's in every direction,
        // peer loss and an unreachable network alike.
        for errno in [
            Errno::ECONNRESET,
            Errno::ECONNABORTED,
            Errno::ENOTCONN,
            Errno::EHOSTUNREACH,
            Errno::ENETUNREACH,
        ] {
            for descriptors in [FileToSocket, PipeToSocket, SocketToPipe] {
                assert!(socket(errno, descriptors), "{errno} {descriptors:?}");
            }
        }
        // Descriptor and file-side errnos stay ours.
        for errno in [Errno::EBADF, Errno::EIO, Errno::EINVAL] {
            for descriptors in [FileToSocket, PipeToSocket, SocketToPipe] {
                assert!(!socket(errno, descriptors), "{errno} {descriptors:?}");
            }
        }

        let peer = DeliveryFailure::sendfile(io::Error::from_raw_os_error(nix::libc::EPIPE));
        assert!(peer.is_peer_disconnect());
        let no_errno = DeliveryFailure::sendfile(io::Error::other("synthetic"));
        assert!(matches!(no_errno, DeliveryFailure::Internal(_)));
        assert!(matches!(
            DeliveryFailure::sendfile(io::Error::from_raw_os_error(nix::libc::EBADF)),
            DeliveryFailure::Internal(_)
        ));
        // An unreachable client is the client's failure, at WARN like the
        // userspace write of the same socket, not an internal ERROR.
        let unreachable =
            DeliveryFailure::sendfile(io::Error::from_raw_os_error(nix::libc::EHOSTUNREACH));
        assert!(matches!(unreachable, DeliveryFailure::Client(_)));
        assert_eq!(unreachable.severity(), Severity::Warn);
    }
}
