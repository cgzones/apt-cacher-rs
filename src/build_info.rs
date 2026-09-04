//! Compile-time identity of this build: the crate name and version strings
//! the daemon announces (`User-Agent`, `Via`, `Server`, the dashboard) and
//! the feature-flag summary `--version` and the startup banner print.

pub(crate) const APP_NAME: &str = env!("CARGO_PKG_NAME");
pub(crate) const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const APP_USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

pub(crate) const APP_VIA: &str = concat!("1.1 ", env!("CARGO_PKG_NAME"));
/// The received-by token of [`APP_VIA`]: what an incoming `Via` element
/// carries when the request already passed through this proxy.
pub(crate) const APP_VIA_PSEUDONYM: &str = env!("CARGO_PKG_NAME");

#[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
macro_rules! feature_tls {
    () => {
        "hyper"
    };
}

#[cfg(feature = "tls_rustls")]
macro_rules! feature_tls {
    () => {
        "rustls"
    };
}

// Expand to the literal "true" when `feature` is enabled, "false" otherwise.
macro_rules! feature_bool {
    ($name:ident, $feature:literal) => {
        #[cfg(feature = $feature)]
        macro_rules! $name {
            () => {
                "true"
            };
        }
        #[cfg(not(feature = $feature))]
        macro_rules! $name {
            () => {
                "false"
            };
        }
    };
}

feature_bool!(feature_hyper, "hyper");
feature_bool!(feature_mmap, "mmap");
feature_bool!(feature_sendfile, "sendfile");
feature_bool!(feature_splice, "splice");
feature_bool!(feature_ktls, "ktls");

/// The `key=value` feature summary, joined by `$sep`.
macro_rules! feature_summary {
    ($sep:expr) => {
        concat!(
            "TLS=",
            feature_tls!(),
            $sep,
            "hyper=",
            feature_hyper!(),
            $sep,
            "mmap=",
            feature_mmap!(),
            $sep,
            "sendfile=",
            feature_sendfile!(),
            $sep,
            "splice=",
            feature_splice!(),
            $sep,
            "ktls=",
            feature_ktls!(),
        )
    };
}

/// The crate version followed by the newline-separated feature summary; what
/// `--version` prints.
pub(crate) const VERSION_AND_FEATURES: &str =
    concat!(env!("CARGO_PKG_VERSION"), "\n", feature_summary!("\n"));

/// The feature summary on one line, for the startup banner and the
/// dashboard's "Features" row. A separate const rather than a runtime
/// `.replace('\n', " ")` at each of them.
pub(crate) const FEATURES_ONE_LINE: &str = feature_summary!(" ");
