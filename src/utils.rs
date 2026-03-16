/// Compile-time macro for creating a `NonZero` value, panicking if the value is zero.
#[macro_export]
macro_rules! nonzero {
    ($exp:expr) => {
        const {
            match ::std::num::NonZero::new($exp) {
                Some(v) => v,
                None => panic!("nonzero!() called with zero value"),
            }
        }
    };
}

/// Compile-time assertion macro.
#[macro_export]
macro_rules! static_assert {
    ($cond:expr) => {
        const _: () = assert!($cond);
    };
    ($cond:expr, $msg:expr) => {
        const _: () = assert!($cond, $msg);
    };
}
