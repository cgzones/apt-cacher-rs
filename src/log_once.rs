#[macro_export]
macro_rules! warn_once {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        match FIRED.compare_exchange(false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed) {
            Ok(false) => log::warn!($($t)*),
            Ok(true) => unreachable!("value must never change from false to true"),
            Err(_) => {}
        }
    }};
}

#[macro_export]
macro_rules! warn_once_or_info {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        let level = match FIRED.compare_exchange(false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed) {
            Ok(false) => log::Level::Warn,
            Ok(true) => unreachable!("value must never change from false to true"),
            Err(_) => log::Level::Info,
        };
        log::log!(level, $($t)*);
    }};
}

#[macro_export]
macro_rules! info_once {
    ($($t:tt)*) => {{
        static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        match FIRED.compare_exchange(false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed) {
            Ok(false) => log::info!($($t)*),
            Ok(true) => unreachable!("value must never change from false to true"),
            Err(_) => {}
        }
    }};
}
