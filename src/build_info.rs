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

#[must_use]
#[inline]
pub(crate) const fn get_features(version: bool) -> &'static str {
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

    if version {
        concat!(
            env!("CARGO_PKG_VERSION"),
            "\n",
            "TLS=",
            feature_tls!(),
            "\n",
            "hyper=",
            feature_hyper!(),
            "\n",
            "mmap=",
            feature_mmap!(),
            "\n",
            "sendfile=",
            feature_sendfile!(),
            "\n",
            "splice=",
            feature_splice!(),
            "\n",
            "ktls=",
            feature_ktls!(),
        )
    } else {
        concat!(
            "TLS=",
            feature_tls!(),
            "\n",
            "hyper=",
            feature_hyper!(),
            "\n",
            "mmap=",
            feature_mmap!(),
            "\n",
            "sendfile=",
            feature_sendfile!(),
            "\n",
            "splice=",
            feature_splice!(),
            "\n",
            "ktls=",
            feature_ktls!(),
        )
    }
}
