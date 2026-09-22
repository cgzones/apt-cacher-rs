//! Log-level policy helpers: the per-call-site once-gates for flood control
//! (the `*_once` macros, the gate they share and the [`Logged`] proof token),
//! plus [`info_or_warn!`](crate::info_or_warn), which carries no gate at all.
//!
//! Each `*_once` macro plants its own `static` gate, so "once" means once per
//! call site, not once per process. `docs/logging.md` is the binding policy
//! for which level each variant carries.

use tracing::error;

use crate::{metrics, transfer_error::Severity};

/// The gate every `*_once` macro and gated helper below is built on: `true`
/// exactly once per `fired`, `false` on every later call.
///
/// The relaxed load before the CAS keeps the steady state read-only — an
/// unconditional `compare_exchange` is an RMW on a shared static cache line
/// even when it fails, and several call sites sit on per-request reject paths
/// an abusive client can hammer.
#[inline]
pub(crate) fn first_fire(fired: &std::sync::atomic::AtomicBool) -> bool {
    use std::sync::atomic::Ordering::Relaxed;

    !fired.load(Relaxed)
        && fired
            .compare_exchange(false, true, Relaxed, Relaxed)
            .is_ok()
}

/// Emit one message at INFO when `$expected` holds and at WARN otherwise.
///
/// For the delivery split `docs/logging.md` mandates: a client that hung up
/// (or, on the writers whose stall paths surface as `TimedOut`, one that
/// stalled) is an expected end to a transfer and logs at INFO, while any
/// other I/O failure is the operator's business. Not gated — these lines are
/// the per-request narrative, which `docs/logging.md`'s flood-control section
/// exempts.
///
/// Exists so the message is written once: the hand-written form repeats the
/// whole format string in both arms, where a rewording can silently reach
/// only one of them.
#[macro_export]
macro_rules! info_or_warn {
    ($expected:expr, $($arg:tt)*) => {{
        if $expected {
            ::tracing::info!($($arg)*);
        } else {
            ::tracing::warn!($($arg)*);
        }
    }};
}

/// Emit one message at a severity chosen at runtime.
///
/// Expands to an explicit `tracing` call per `transfer_error::Severity` arm
/// rather than `event!(level, …)` so each level keeps its own call-site
/// metadata (and its static level filter). An exported macro cannot link that
/// crate-private type, so it is named in plain text. Not gated -- like
/// [`info_or_warn!`](crate::info_or_warn) these are per-request narrative lines.
#[macro_export]
macro_rules! log_at {
    ($severity:expr, $($arg:tt)*) => {{
        match $severity {
            $crate::transfer_error::Severity::Info => ::tracing::info!($($arg)*),
            $crate::transfer_error::Severity::Warn => ::tracing::warn!($($arg)*),
            $crate::transfer_error::Severity::Error => ::tracing::error!($($arg)*),
        }
    }};
}

#[macro_export]
macro_rules! warn_once {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        if $crate::log_once::first_fire(&FIRED) {
            tracing::warn!($($t)*);
        }
    }};
}

#[macro_export]
macro_rules! warn_once_or_info {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        if $crate::log_once::first_fire(&FIRED) {
            tracing::warn!($($t)*);
        } else {
            tracing::info!($($t)*);
        }
    }};
}

#[macro_export]
macro_rules! warn_once_or_debug {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        if $crate::log_once::first_fire(&FIRED) {
            tracing::warn!($($t)*);
        } else {
            tracing::debug!($($t)*);
        }
    }};
}

#[macro_export]
macro_rules! info_once {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        if $crate::log_once::first_fire(&FIRED) {
            tracing::info!($($t)*);
        }
    }};
}

/// [`warn_once_or_info!`] that returns the [`Logged`] proof for
/// an error variant whose policy is "logged at the throw site". Same per-site
/// once-gate; the level split lives in `warn_once_or_info_gated`.
#[macro_export]
macro_rules! warn_once_or_info_logged {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        $crate::log_once::Logged::warn_once_or_info(&FIRED, format_args!($($t)*))
    }};
}

/// [`warn_once_or_info!`] with a caller-owned gate, for generic code: a
/// `static` inside a generic function body is one gate shared by every
/// instantiation, so a per-type site (see `xattr_helpers::XattrValue`) must
/// hand its own in.
pub(crate) fn warn_once_or_info_gated(
    fired: &'static std::sync::atomic::AtomicBool,
    args: std::fmt::Arguments<'_>,
) {
    if first_fire(fired) {
        tracing::warn!("{args}");
    } else {
        tracing::info!("{args}");
    }
}

/// Proof that a failure was logged, carrying the value it was logged for.
///
/// A failure is logged once, at the site that decides the outcome. Some sites
/// must be that site because the context that makes the line actionable --
/// the on-disk path, the upstream authority and attempt count -- exists only
/// there; the error variant they return then carries this token instead of
/// (or next to) the error, and the outer arm receiving it maps silently. The
/// field is private and every constructor logs: the [`Logged`] helpers below
/// write the line, and [`Logged::with`] attaches the value to that proof, so a
/// `Reported<T>` cannot exist without its log line, and a reviewer reading one
/// at a throw site knows which helper wrote it.
///
/// Terminal failures reach it through their `conclude` methods
/// (`transfer_error`), which count the cause before logging it; that is the
/// only way to count one.
///
/// The helpers log from this module, so the `target` recorded for the line
/// (visible only in the web interface's log store, which prints targets) is
/// `log_once`, not the throw site's module. The console/file sinks print no
/// target.
#[derive(Clone, Debug)]
#[must_use = "a reported failure proves its line was written; hand it on"]
pub(crate) struct Reported<T>(T);

/// The bare proof, before a value is attached.
pub(crate) type Logged = Reported<()>;

impl<T> Reported<T> {
    pub(crate) fn get(&self) -> &T {
        &self.0
    }
}

impl Logged {
    /// Attach the value this line reported.
    pub(crate) fn with<T>(self, value: T) -> Reported<T> {
        let Self(()) = self;
        Reported(value)
    }

    /// Log the line at `severity` and prove it.
    pub(crate) fn at(severity: Severity, args: std::fmt::Arguments<'_>) -> Self {
        crate::log_at!(severity, "{args}");
        Self(())
    }

    /// `debug!` the line and prove it: a terminal failure whose outcome the
    /// caller reports itself (cleanup's decision log).
    #[cfg(feature = "splice")]
    pub(crate) fn debug(args: std::fmt::Arguments<'_>) -> Self {
        tracing::debug!("{args}");
        Self(())
    }

    /// `error!` the line and prove it.
    pub(crate) fn error(args: std::fmt::Arguments<'_>) -> Self {
        error!("{args}");
        Self(())
    }

    /// A cached-file syscall failed: bump `CACHE_IO_FAILURE` and `error!`
    /// the line.
    pub(crate) fn cache_io_failure(args: std::fmt::Arguments<'_>) -> Self {
        metrics::CACHE_IO_FAILURE.increment();
        Self::error(args)
    }

    /// WARN on `fired`'s first use, INFO after. The body of
    /// [`crate::warn_once_or_info_logged!`], where `fired` is that call site's
    /// own once-gate, so per-site flood control is unchanged from
    /// [`crate::warn_once_or_info!`]; a caller handing in a shared gate
    /// deliberately collapses every site that uses it into one condition.
    pub(crate) fn warn_once_or_info(
        fired: &'static std::sync::atomic::AtomicBool,
        args: std::fmt::Arguments<'_>,
    ) -> Self {
        warn_once_or_info_gated(fired, args);
        Self(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::*;
    use crate::test_support::levels_during;

    #[test]
    fn first_fire_is_true_exactly_once() {
        let gate = AtomicBool::new(false);
        assert!(first_fire(&gate));
        assert!(!first_fire(&gate));
        assert!(!first_fire(&gate));
    }

    #[test]
    fn gates_are_independent() {
        let a = AtomicBool::new(false);
        let b = AtomicBool::new(false);
        assert!(first_fire(&a));
        assert!(first_fire(&b), "a spent gate does not spend its sibling");
        assert!(!first_fire(&a));
        assert!(!first_fire(&b));
    }

    #[test]
    fn a_pre_fired_gate_never_fires() {
        let gate = AtomicBool::new(true);
        assert!(!first_fire(&gate));
    }

    #[test]
    fn once_macros_gate_per_call_site() {
        // Two expansions plant two gates: the second site still warns after
        // the first has fired, and each site only warns once.
        let levels = levels_during(|| {
            for _ in 0..3 {
                warn_once!("site one");
            }
            for _ in 0..3 {
                warn_once!("site two");
            }
        });
        assert_eq!(levels, [tracing::Level::WARN, tracing::Level::WARN]);
    }

    #[test]
    fn warn_once_or_info_demotes_after_the_first_line() {
        static FIRED: AtomicBool = AtomicBool::new(false);
        let levels = levels_during(|| {
            for _ in 0..3 {
                warn_once_or_info_gated(&FIRED, format_args!("repeat"));
            }
        });
        assert_eq!(
            levels,
            [
                tracing::Level::WARN,
                tracing::Level::INFO,
                tracing::Level::INFO
            ]
        );
    }

    #[test]
    fn logged_error_emits_one_error_line() {
        let levels = levels_during(|| {
            let _proof = Logged::error(format_args!("boom"));
        });
        assert_eq!(levels, [tracing::Level::ERROR]);
    }

    #[test]
    fn logged_cache_io_failure_bumps_the_counter_and_errors() {
        let before = metrics::CACHE_IO_FAILURE.get();
        let levels = levels_during(|| {
            let _proof = Logged::cache_io_failure(format_args!("stat failed"));
        });
        assert_eq!(levels, [tracing::Level::ERROR]);
        assert_eq!(metrics::CACHE_IO_FAILURE.get() - before, 1);
    }

    #[test]
    fn logged_warn_once_or_info_uses_the_handed_in_gate() {
        static FIRED: AtomicBool = AtomicBool::new(false);
        let levels = levels_during(|| {
            let _first = Logged::warn_once_or_info(&FIRED, format_args!("x"));
            let _second = Logged::warn_once_or_info(&FIRED, format_args!("x"));
        });
        assert_eq!(levels, [tracing::Level::WARN, tracing::Level::INFO]);
    }
}
