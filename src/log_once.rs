#[macro_export]
macro_rules! warn_once {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        match FIRED.compare_exchange(false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed) {
            Ok(false) => tracing::warn!($($t)*),
            Ok(true) => unreachable!("value must never change from true to false"),
            Err(_) => {}
        }
    }};
}

#[macro_export]
macro_rules! warn_once_or_info {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        match FIRED.compare_exchange(false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed) {
            Ok(false) => tracing::warn!($($t)*),
            Ok(true) => unreachable!("value must never change from true to false"),
            Err(_) => tracing::info!($($t)*),
        }
    }};
}

#[macro_export]
macro_rules! warn_once_or_debug {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        match FIRED.compare_exchange(false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed) {
            Ok(false) => tracing::warn!($($t)*),
            Ok(true) => unreachable!("value must never change from true to false"),
            Err(_) => tracing::debug!($($t)*),
        }
    }};
}

#[macro_export]
macro_rules! info_once {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        match FIRED.compare_exchange(false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed) {
            Ok(false) => tracing::info!($($t)*),
            Ok(true) => unreachable!("value must never change from true to false"),
            Err(_) => {}
        }
    }};
}
