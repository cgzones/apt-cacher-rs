//! Infallible formatted appends to a [`String`].

/// Destination of [`swrite!`], implemented for [`String`] only — so the macro
/// cannot be aimed at a genuinely fallible [`std::fmt::Write`] sink, where
/// discarding the `Result` would hide a real I/O error.
pub(crate) trait StringWrite {
    /// Append `args`, panicking on the unreachable formatting failure.
    fn swrite_fmt(&mut self, args: std::fmt::Arguments<'_>);
}

impl StringWrite for String {
    fn swrite_fmt(&mut self, args: std::fmt::Arguments<'_>) {
        std::fmt::Write::write_fmt(self, args).expect("formatting into a String cannot fail");
    }
}

/// `write!` to a [`String`], without a `Result` at the call site.
///
/// `String`'s [`std::fmt::Write`] impl never fails, so the only way the
/// underlying `write_fmt` can error is a `Display` impl returning `Err` — a
/// bug, not a runtime condition. Callers need no `use std::fmt::Write` import.
#[macro_export]
macro_rules! swrite {
    ($dst:expr, $($arg:tt)*) => {{
        use $crate::string_write::StringWrite as _;

        $dst.swrite_fmt(::std::format_args!($($arg)*))
    }};
}

#[cfg(test)]
mod tests {
    #[test]
    fn appends_to_owned_string() {
        let mut s = String::from("a=");
        swrite!(s, "{}{:03}", 'b', 7);
        swrite!(s, "!");
        assert_eq!(s, "a=b007!", "appends without replacing");
    }

    #[test]
    fn accepts_a_mutable_reference() {
        fn append(out: &mut String) {
            swrite!(out, "x{}", 1);
        }

        let mut s = String::new();
        append(&mut s);
        assert_eq!(s, "x1", "reborrows through a &mut String");
    }

    #[test]
    fn appends_to_a_struct_field() {
        struct Holder {
            out: String,
        }

        let mut h = Holder { out: String::new() };
        swrite!(h.out, "{}", 42);
        assert_eq!(h.out, "42", "accepts an arbitrary place expression");
    }
}
