//! Log-level policy helpers: once-gates for flood control.
//!
//! Each `*_once` macro plants its own `static` gate, so "once" means once per
//! call site, not once per process. A [`KeyedGate`] is the exception: one
//! gate per key, for a fact that repeats per key (an unreachable upstream
//! host) rather than per call site. `docs/logging.md` is the binding policy
//! for which level each variant carries.

use tracing::error;

use crate::{metrics, transfer_error::Severity};

/// `true` exactly once per `fired`, `false` on every later call.
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

/// A once-gate per key: [`KeyedGate::first_fire`] is `true` exactly once for
/// each key. Bounded: once `cap` distinct keys have fired, every new key reads
/// as already fired, so a stream of ever-new keys -- host names a client picks
/// under a wildcard `allowed_mirrors` entry -- cannot turn the gate into one
/// WARN per request.
pub(crate) struct KeyedGate {
    fired: parking_lot::Mutex<Vec<Box<str>>>,
    cap: usize,
}

impl KeyedGate {
    pub(crate) const fn new(cap: usize) -> Self {
        Self {
            fired: parking_lot::Mutex::new(Vec::new()),
            cap,
        }
    }

    /// Only failure paths consult it, so a linear scan under the lock is
    /// fine.
    fn first_fire(&self, key: &str) -> bool {
        let mut fired = self.fired.lock();
        if fired.len() >= self.cap || fired.iter().any(|seen| **seen == *key) {
            return false;
        }
        fired.push(key.into());
        true
    }
}

/// Emit one message at INFO when `$expected` holds and at WARN otherwise.
///
/// For the delivery split `docs/logging.md` mandates: a client that hung up
/// or stalled is an expected end to a transfer and logs at INFO, while any
/// other I/O failure is the operator's business. Not gated: these lines are
/// the per-request narrative, which the flood-control policy exempts.
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
/// metadata (and its static level filter). Not gated.
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

        $crate::warn_once_or_debug_gated!(&FIRED, $($t)*)
    }};
}

/// [`warn_once_or_debug!`] with a caller-owned gate, for a site whose one
/// line reports one of several facts: each fact gets a gate, so the first
/// occurrence of one does not demote the first occurrence of another (see
/// `integrity::log_registry_miss`). A macro rather than a function, so the
/// line keeps the caller's module as its `target`.
#[macro_export]
macro_rules! warn_once_or_debug_gated {
    ($fired:expr, $($t:tt)*) => {{
        if $crate::log_once::first_fire($fired) {
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
/// an error variant whose policy is "logged at the throw site".
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
/// A failure is logged once, at the site that decides the outcome. Where the
/// context that makes the line actionable (the on-disk path, the upstream
/// authority and attempt count) exists only at the throw site, the error
/// variant it returns carries this token, and the outer arm receiving it maps
/// silently. The field is private and every constructor logs, so a
/// `Reported<T>` cannot exist without its log line.
///
/// The helpers log from this module, so the `target` recorded for the line
/// (visible only in the web interface's log store) is `log_once`, not the
/// throw site's module.
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

    pub(crate) fn at(severity: Severity, args: std::fmt::Arguments<'_>) -> Self {
        crate::log_at!(severity, "{args}");
        Self(())
    }

    /// For a terminal failure whose outcome the caller reports itself
    /// (cleanup's decision log).
    #[cfg(all(feature = "splice", not(feature = "hyper")))]
    pub(crate) fn debug(args: std::fmt::Arguments<'_>) -> Self {
        tracing::debug!("{args}");
        Self(())
    }

    pub(crate) fn error(args: std::fmt::Arguments<'_>) -> Self {
        error!("{args}");
        Self(())
    }

    /// A cached-file syscall failed.
    pub(crate) fn cache_io_failure(args: std::fmt::Arguments<'_>) -> Self {
        metrics::CACHE_IO_FAILURE.increment();
        Self::error(args)
    }

    /// WARN on `fired`'s first use, INFO after.
    pub(crate) fn warn_once_or_info(
        fired: &'static std::sync::atomic::AtomicBool,
        args: std::fmt::Arguments<'_>,
    ) -> Self {
        warn_once_or_info_gated(fired, args);
        Self(())
    }

    /// WARN on `key`'s first use of `gate`, INFO after.
    pub(crate) fn warn_once_or_info_keyed(
        gate: &KeyedGate,
        key: &str,
        args: std::fmt::Arguments<'_>,
    ) -> Self {
        if gate.first_fire(key) {
            tracing::warn!("{args}");
        } else {
            tracing::info!("{args}");
        }
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
        assert!(!first_fire(&AtomicBool::new(true)), "a pre-fired gate");
    }

    #[test]
    fn keyed_gate_fires_once_per_key() {
        let gate = KeyedGate::new(8);
        assert!(gate.first_fire("a"));
        assert!(
            gate.first_fire("b"),
            "a spent key does not spend its sibling"
        );
        assert!(!gate.first_fire("a"));
        assert!(!gate.first_fire("b"));
    }

    #[test]
    fn keyed_gate_stops_firing_at_its_cap() {
        let gate = KeyedGate::new(2);
        assert!(gate.first_fire("a"));
        assert!(gate.first_fire("b"));
        assert!(
            !gate.first_fire("c"),
            "a full gate treats a new key as fired"
        );
        assert!(!gate.first_fire("a"));
    }

    #[test]
    fn logged_warn_once_or_info_keyed_demotes_per_key() {
        static GATE: KeyedGate = KeyedGate::new(8);
        let levels = levels_during(|| {
            let _a = Logged::warn_once_or_info_keyed(&GATE, "a", format_args!("x"));
            let _a2 = Logged::warn_once_or_info_keyed(&GATE, "a", format_args!("x"));
            let _b = Logged::warn_once_or_info_keyed(&GATE, "b", format_args!("x"));
        });
        assert_eq!(
            levels,
            [
                tracing::Level::WARN,
                tracing::Level::INFO,
                tracing::Level::WARN
            ]
        );
    }

    #[test]
    fn once_macros_gate_per_call_site() {
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
    fn warn_once_or_debug_gated_warns_once_per_handed_in_gate() {
        static A: AtomicBool = AtomicBool::new(false);
        static B: AtomicBool = AtomicBool::new(false);
        let levels = levels_during(|| {
            for gate in [&A, &A, &B, &B] {
                crate::warn_once_or_debug_gated!(gate, "one site");
            }
        });
        assert_eq!(
            levels,
            [
                tracing::Level::WARN,
                tracing::Level::DEBUG,
                tracing::Level::WARN,
                tracing::Level::DEBUG
            ]
        );
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
