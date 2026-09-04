//! Per-call-site once-gates for log flood control: the `*_once` macros, the
//! gate they share, and the [`Logged`] proof token.
//!
//! Each macro plants its own `static` gate, so "once" means once per call
//! site, not once per process. `docs/logging.md` is the binding policy for
//! which level each variant carries.

#[cfg(feature = "splice")]
use tracing::info;
use tracing::{error, warn};

use crate::metrics;

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
/// once-gate; the level split lives in `Logged::warn_once_or_info`.
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

/// Proof that a failure was logged at its throw site.
///
/// A failure is logged once, at the site that decides the
/// outcome. Some sites must be that site because the context that makes the
/// line actionable -- the on-disk path, the upstream authority and attempt
/// count -- exists only there; the error variant they return then carries
/// this token instead of (or next to) the error, and the outer arm receiving
/// it maps silently. The field is private and the only constructors are the
/// logging helpers below, so such a variant cannot be thrown without its log
/// line, and a reviewer reading `Logged` at a throw site knows which helper
/// wrote it.
///
/// The helpers log from this module, so the `target` recorded for the line
/// (visible only in the web interface's log store, which prints targets) is
/// `log_once`, not the throw site's module. The console/file sinks print no
/// target.
#[derive(Debug)]
pub(crate) struct Logged(());

impl Logged {
    /// `error!` the line and prove it.
    pub(crate) fn error(args: std::fmt::Arguments<'_>) -> Self {
        error!("{args}");
        Self(())
    }

    /// `warn!` the line and prove it.
    pub(crate) fn warn(args: std::fmt::Arguments<'_>) -> Self {
        warn!("{args}");
        Self(())
    }

    /// A cached-file syscall failed: bump `CACHE_IO_FAILURE` and `error!`
    /// the line.
    pub(crate) fn cache_io_failure(args: std::fmt::Arguments<'_>) -> Self {
        metrics::CACHE_IO_FAILURE.increment();
        Self::error(args)
    }

    /// The body of [`crate::warn_once_or_info_logged!`]: `fired` is that
    /// call site's own once-gate, so per-site flood control is unchanged
    /// from [`crate::warn_once_or_info!`]. Call through the macro, never
    /// directly -- a shared gate would collapse every site into one.
    #[cfg(feature = "splice")]
    pub(crate) fn warn_once_or_info(
        fired: &'static std::sync::atomic::AtomicBool,
        args: std::fmt::Arguments<'_>,
    ) -> Self {
        if first_fire(fired) {
            warn!("{args}");
        } else {
            info!("{args}");
        }
        Self(())
    }
}
