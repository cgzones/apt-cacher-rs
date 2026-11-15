//! Compile-time identity of this build: name, version and feature summary.

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
feature_bool!(feature_sendfile, "sendfile");
feature_bool!(feature_splice, "splice");

macro_rules! feature_summary {
    ($sep:expr) => {
        concat!(
            "TLS=",
            feature_tls!(),
            $sep,
            "hyper=",
            feature_hyper!(),
            $sep,
            "sendfile=",
            feature_sendfile!(),
            $sep,
            "splice=",
            feature_splice!(),
        )
    };
}

/// What `--version` prints.
pub(crate) const VERSION_AND_FEATURES: &str =
    concat!(env!("CARGO_PKG_VERSION"), "\n", feature_summary!("\n"));

/// For the startup banner and the dashboard's "Features" row.
pub(crate) const FEATURES_ONE_LINE: &str = feature_summary!(" ");
