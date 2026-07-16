// All four macros share the load-before-CAS shape: the relaxed load keeps
// the steady state read-only — an unconditional compare_exchange is an RMW
// on a shared static cache line even when it fails, and several call sites
// sit on per-request reject paths an abusive client can hammer.

#[macro_export]
macro_rules! warn_once {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        if !FIRED.load(std::sync::atomic::Ordering::Relaxed)
            && FIRED.compare_exchange(false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed).is_ok()
        {
            tracing::warn!($($t)*);
        }
    }};
}

#[macro_export]
macro_rules! warn_once_or_info {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        if !FIRED.load(std::sync::atomic::Ordering::Relaxed)
            && FIRED.compare_exchange(false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed).is_ok()
        {
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

        if !FIRED.load(std::sync::atomic::Ordering::Relaxed)
            && FIRED.compare_exchange(false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed).is_ok()
        {
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

        if !FIRED.load(std::sync::atomic::Ordering::Relaxed)
            && FIRED.compare_exchange(false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed).is_ok()
        {
            tracing::info!($($t)*);
        }
    }};
}
