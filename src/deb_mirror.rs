use std::{
    borrow::Cow,
    num::NonZero,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use crate::{config::DomainName, database};

#[derive(Debug)]
pub(crate) struct Mirror {
    host: DomainName,
    port: Option<NonZero<u16>>,
    path: String,
    /// Lazily-populated cache of `host.format_authority(port)` when the result
    /// is owned (i.e. requires allocation: an IPv6 host or a non-empty port).
    /// Skipped from `Hash`/`Eq`/`Clone` impls because it is purely derived
    /// from `host` + `port`.
    cached_authority: OnceLock<Box<str>>,
}

impl Mirror {
    #[must_use]
    pub(crate) const fn new(host: DomainName, port: Option<NonZero<u16>>, path: String) -> Self {
        Self {
            host,
            port,
            path,
            cached_authority: OnceLock::new(),
        }
    }

    #[must_use]
    pub(crate) fn format_authority(&self) -> Cow<'_, str> {
        // Fast path: no allocation needed for DNS/IPv4 hosts without a port.
        if self.port.is_none() && !self.host.is_ipv6() {
            return Cow::Borrowed(self.host.as_str());
        }
        Cow::Borrowed(self.cached_authority.get_or_init(|| {
            self.host
                .format_authority(self.port)
                .into_owned()
                .into_boxed_str()
        }))
    }

    #[must_use]
    pub(crate) const fn host(&self) -> &DomainName {
        &self.host
    }

    #[must_use]
    pub(crate) const fn port(&self) -> Option<NonZero<u16>> {
        self.port
    }

    #[must_use]
    pub(crate) const fn path(&self) -> &str {
        self.path.as_str()
    }
}

impl PartialEq for Mirror {
    fn eq(&self, other: &Self) -> bool {
        self.host == other.host && self.port == other.port && self.path == other.path
    }
}

impl Clone for Mirror {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            port: self.port,
            path: self.path.clone(),
            cached_authority: OnceLock::new(),
        }
    }
}

impl Eq for Mirror {}

impl std::hash::Hash for Mirror {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.host.hash(state);
        self.port.hash(state);
        self.path.hash(state);
    }
}

impl std::fmt::Display for Mirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.format_authority(), self.path)
    }
}

pub(crate) fn mirror_cache_path_impl(
    host: &DomainName,
    port: Option<NonZero<u16>>,
    path: &str,
) -> PathBuf {
    let host_dir = host.format_cache_dir(port);
    let cache_path: PathBuf = [Path::new(host_dir.as_ref()), Path::new(path)]
        .iter()
        .collect();

    assert!(
        cache_path.is_relative(),
        "cache path must be relative in order to be joined with the host directory"
    );

    cache_path
}

#[derive(Debug, PartialEq)]
pub(crate) struct Origin {
    pub(crate) mirror: Mirror,
    pub(crate) distribution: String,
    pub(crate) component: String,
    pub(crate) architecture: String,
}

#[derive(Debug, PartialEq)]
pub(crate) struct OriginRef<'a> {
    pub(crate) mirror: &'a Mirror,
    pub(crate) distribution: &'a str,
    pub(crate) component: &'a str,
    pub(crate) architecture: &'a str,
}

impl Origin {
    #[must_use]
    pub(crate) fn from_path(
        path: &str,
        host: DomainName,
        port: Option<NonZero<u16>>,
    ) -> Option<Self> {
        /* /debian/dists/sid/main/binary-amd64/Packages{,.diff,.gz,.xz} */

        let path = path.trim_start_matches('/');

        let (mirror_path, origin_path) = path.rsplit_once("/dists/")?;

        let mut parts = origin_path.split('/');

        let distribution = parts.next()?;

        let component = parts.next()?;

        let architecture = parts.next()?;

        let filename = parts.next()?;
        if !filename.starts_with("Packages") && filename != "by-hash" {
            return None;
        }

        Some(Self {
            mirror: Mirror::new(host, port, mirror_path.to_owned()),
            distribution: distribution.to_owned(),
            component: component.to_owned(),
            architecture: architecture.to_owned(),
        })
    }

    #[must_use]
    #[inline]
    pub(crate) const fn as_ref(&self) -> OriginRef<'_> {
        OriginRef {
            mirror: &self.mirror,
            distribution: self.distribution.as_str(),
            component: self.component.as_str(),
            architecture: self.architecture.as_str(),
        }
    }
}

pub(crate) trait UriFormat {
    #[must_use]
    fn uri(&self) -> String;
}

fn format_origin_uri(
    host: &DomainName,
    port: Option<NonZero<u16>>,
    mirror_path: &str,
    dist: &str,
    comp: &str,
    arch: &str,
) -> String {
    // deb.debian.org/debian/dists/sid/main/binary-amd64/Packages

    let authority = host.format_authority(port);
    format!("http://{authority}/{mirror_path}/dists/{dist}/{comp}/{arch}/Packages")
}

impl UriFormat for Origin {
    #[inline]
    fn uri(&self) -> String {
        format_origin_uri(
            &self.mirror.host,
            self.mirror.port,
            &self.mirror.path,
            &self.distribution,
            &self.component,
            &self.architecture,
        )
    }
}

impl UriFormat for &database::OriginEntry {
    #[inline]
    fn uri(&self) -> String {
        format_origin_uri(
            &self.host,
            self.port(),
            &self.mirror_path,
            &self.distribution,
            &self.component,
            &self.architecture,
        )
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum ResourceFile<'a> {
    /// A pool file
    Pool {
        mirror_path: &'a str,
        filename: &'a str,
    },
    /// A dists file
    Release {
        mirror_path: &'a str,
        distribution: &'a str,
        filename: &'a str,
    },
    /// A packages file
    Packages {
        mirror_path: &'a str,
        distribution: &'a str,
        component: &'a str,
        architecture: &'a str,
        filename: &'a str,
    },
    /// A file named and acquired by its hash value
    ByHash {
        mirror_path: &'a str,
        filename: &'a str,
    },
    /// An icons file
    Icon {
        mirror_path: &'a str,
        distribution: &'a str,
        component: &'a str,
        filename: &'a str,
    },
    /// A sources file
    Sources {
        mirror_path: &'a str,
        distribution: &'a str,
        component: &'a str,
        filename: &'a str,
    },
    /// A translation file
    Translation {
        mirror_path: &'a str,
        distribution: &'a str,
        component: &'a str,
        filename: &'a str,
    },
}

/// Parses a request path into the mirror path and the filename.
///
/// The directory name "pool" is not supported as part of the mirror path.
/// The directory name "dists" should be avoided as part of the mirror path.
#[must_use]
pub(crate) fn parse_request_path(path: &str) -> Option<ResourceFile<'_>> {
    let path = path.trim_start_matches('/');

    /*
     * debian/pool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb
     * debian-security/pool/updates/main/c/chromium/chromium-common_141.0.7390.65-1%7edeb12u1_amd64.deb
     */
    if let Some((mirror_path, pool_path)) = path.split_once("/pool/") {
        let mut parts = pool_path.rsplit('/');

        let filename = parts.next()?;

        let package = parts.next()?;

        let prefix = parts.next()?;
        if !package.starts_with(prefix) {
            return None;
        }

        let _component = parts.next()?;

        if parts
            .next()
            .is_some_and(|s| s != "updates" || parts.next().is_some())
        {
            return None;
        }

        return Some(ResourceFile::Pool {
            mirror_path,
            filename,
        });
    }

    /*
     * debian/dists/sid/InRelease
     * debs/dists/vscodium/main/binary-amd64/Packages.gz
     * debian/dists/sid/main/source/Sources.xz
     * debian/dists/sid/main/dep11/icons-128x128.tar.gz
     * debian/dists/unstable/main/i18n/Translation-en.bz2
     * debian/dists/trixie/main/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba
     */
    if let Some((mirror_path, dists_path)) = path.rsplit_once("/dists/") {
        let mut parts = dists_path.rsplit('/');

        let filename = parts.next()?;
        #[expect(
            clippy::case_sensitive_file_extension_comparisons,
            reason = "filename is case-sensitive in Debian dists"
        )]
        if filename == "Release" || filename == "InRelease" {
            let distribution = parts.next()?;

            if parts.next().is_some() {
                return None;
            }

            return Some(ResourceFile::Release {
                mirror_path,
                distribution,
                filename,
            });
        } else if filename == "Packages.gz" || filename == "Packages.xz" || filename == "Packages" {
            let architecture = parts.next()?;
            let component = parts.next()?;
            let distribution = parts.next()?;

            if parts.next().is_some() {
                return None;
            }

            return Some(ResourceFile::Packages {
                mirror_path,
                distribution,
                component,
                architecture,
                filename,
            });
        } else if filename == "Sources.gz" || filename == "Sources.xz" {
            if parts.next()? != "source" {
                return None;
            }

            let component = parts.next()?;
            let distribution = parts.next()?;

            if parts.next().is_some() {
                return None;
            }

            return Some(ResourceFile::Sources {
                mirror_path,
                distribution,
                component,
                filename,
            });
        } else if filename.starts_with("Translation-") && filename.ends_with(".bz2") {
            if parts.next()? != "i18n" {
                return None;
            }

            let component = parts.next()?;
            let distribution = parts.next()?;

            if parts.next().is_some() {
                return None;
            }

            return Some(ResourceFile::Translation {
                mirror_path,
                distribution,
                component,
                filename,
            });
        } else if filename.starts_with("icons-") {
            if parts.next()? != "dep11" {
                return None;
            }

            let component = parts.next()?;
            let distribution = parts.next()?;

            if parts.next().is_some() {
                return None;
            }

            return Some(ResourceFile::Icon {
                mirror_path,
                distribution,
                component,
                filename,
            });
        } else if filename.len() >= 64 && filename.chars().all(|c| c.is_ascii_hexdigit()) {
            let hash_algorithm = parts.next()?;

            // The filename length >= 64 characters ensures that only SHA >= SHA256 is supported
            if !hash_algorithm.starts_with("SHA") {
                return None;
            }

            if parts.next()? != "by-hash" {
                return None;
            }

            return Some(ResourceFile::ByHash {
                mirror_path,
                filename,
            });
        }

        return None;
    }

    None
}

#[must_use]
pub(crate) fn valid_filename(name: &str) -> bool {
    name.len() >= 4
        && name.len() <= 255
        && name.chars().enumerate().all(|(i, c)| {
            (i > 0 || c.is_ascii_alphanumeric())
                && c.is_ascii()
                && !c.is_ascii_control()
                && c != std::path::MAIN_SEPARATOR
                && c != '/'
        })
}

/// Check whether the given URI path is a diff request path.
///
/// Note: calls should be guarded by the configuration setting `reject_pdiff_requests`.
///
/// Example request paths:
/// - `http://deb.debian.org/debian-debug/dists/sid-debug/main/binary-i386/Packages.diff/T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz`
/// - `http://deb.debian.org/debian/dists/unstable/main/i18n/Translation-en.diff/T-2024-10-03-0804.49-F-2024-10-02-2011.04.gz`
/// - `http://deb.debian.org/debian/dists/unstable/main/i18n/Translation-de.diff/T-2024-10-03-0804.49-F-2024-10-02-2011.04.gz`
/// - `http://deb.debian.org/debian/dists/sid/main/source/Sources.diff/T-2024-10-03-1409.04-F-2024-10-03-1409.04.gz`
///
/// A regex-based implementation was considered but rejected: the linear-scan
/// contains/find approach avoids pulling in the `regex` crate solely for this
/// check and stays linear in the path length with no allocation.
#[must_use]
pub(crate) fn is_diff_request_path(uri_path: &str) -> bool {
    const FIXED_MARKERS: &[&str] = &["/Packages.diff/T-", "/Sources.diff/T-"];
    FIXED_MARKERS.iter().any(|m| uri_path.contains(m)) || contains_translation_diff(uri_path)
}

/// Check whether the path contains a `Translation-XX.diff/T-` segment for any language.
#[must_use]
fn contains_translation_diff(uri_path: &str) -> bool {
    const PREFIX: &str = "/Translation-";
    const SUFFIX: &str = ".diff/T-";

    let mut haystack = uri_path;
    while let Some(idx) = haystack.find(PREFIX) {
        let rest = haystack.split_at(idx + PREFIX.len()).1;
        if let Some(diff_idx) = rest.find(SUFFIX) {
            let lang = rest.split_at(diff_idx).0;
            // Language tags in Debian translations are of the form `en`, `de`,
            // `zh_CN`, `pt_BR` — alphanumeric with optional underscore.  Reject
            // arbitrary separator runs (e.g. `---`) that the previous matcher
            // accepted.
            if !lang.is_empty() && lang.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return true;
            }
        }
        haystack = rest;
    }
    false
}

/// Check whether a percent-decoded URI path is safe to forward upstream.
///
/// Rejects traversal segments (`..`, `.`) and control characters (including null bytes).
///
/// Returns `true` if the path is unsafe and should be rejected.
#[must_use]
pub(crate) fn is_unsafe_proxy_path(raw_path: &str) -> bool {
    let decoded = match urlencoding::decode(raw_path) {
        Ok(d) => d,
        // Failed to decode — reject as unsafe
        Err(_err @ std::string::FromUtf8Error { .. }) => return true,
    };

    decoded
        .split('/')
        .any(|seg| seg == "." || seg == ".." || seg.contains(|c: char| c.is_ascii_control()))
}

/// Valid Debian package extensions (`.deb`, `.udeb`, `.ddeb`).
pub(crate) const VALID_DEB_EXTENSIONS: &[&str] = &["deb", "udeb", "ddeb"];

/// Whether the filename represents a Debian binary package (`.deb`, `.udeb`, `.ddeb`).
#[must_use]
pub(crate) fn is_deb_package(filename: &str) -> bool {
    let extension = filename.rsplit_once('.').map(|(_, ext)| ext);

    matches!(extension, Some(ext) if VALID_DEB_EXTENSIONS.contains(&ext))
}

#[must_use]
pub(crate) fn valid_mirrorname(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && name.split('/').all(valid_path_segment)
}

#[must_use]
fn valid_path_segment(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.chars().enumerate().all(|(i, c)| {
            c.is_ascii_alphanumeric() || (i > 0 && (c == '-' || c == '.' || c == '_'))
        })
}

#[must_use]
pub(crate) fn valid_distribution(name: &str) -> bool {
    valid_path_segment(name)
}

#[must_use]
pub(crate) fn valid_component(name: &str) -> bool {
    valid_path_segment(name)
}

#[must_use]
pub(crate) fn valid_architecture(name: &str) -> bool {
    valid_path_segment(name)
}

#[cfg(test)]
mod tests {
    use crate::{config::DomainName, nonzero};

    use super::*;

    #[test]
    fn test_parse_1() {
        let result = Origin::from_path(
            "/debian/dists/sid/main/binary-amd64/Packages/",
            DomainName::new("deb.debian.org".to_string()).unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(
            result,
            Origin {
                mirror: Mirror::new(
                    DomainName::new("deb.debian.org".to_string()).unwrap(),
                    None,
                    "debian".to_string(),
                ),
                distribution: "sid".to_string(),
                component: "main".to_string(),
                architecture: "binary-amd64".to_string()
            }
        );
        assert_eq!(
            result.uri(),
            "http://deb.debian.org/debian/dists/sid/main/binary-amd64/Packages"
        );
    }

    #[test]
    fn test_parse_2() {
        let result = Origin::from_path(
            "/private/debian/dists/sid/main/binary-amd64/by-hash/SHA256/\
        84b902c50d12a499fb2156ca2190ddaa9bb9dd8c7354aaccfc56590318bc0b83",
            DomainName::new("site.example.com".to_string()).unwrap(),
            Some(nonzero!(80)),
        )
        .unwrap();
        assert_eq!(
            result,
            Origin {
                mirror: Mirror::new(
                    DomainName::new("site.example.com".to_string()).unwrap(),
                    Some(nonzero!(80)),
                    "private/debian".to_string(),
                ),
                distribution: "sid".to_string(),
                component: "main".to_string(),
                architecture: "binary-amd64".to_string()
            }
        );
        assert_eq!(
            result.uri(),
            "http://site.example.com:80/private/debian/dists/sid/main/binary-amd64/Packages"
        );
    }

    #[test]
    fn test_parse_3() {
        let result = Origin::from_path(
            "/unstable/dists/llvm-toolchain-19/main/binary-amd64/Packages.gz",
            DomainName::new("apt.llvm.org".to_string()).unwrap(),
            Some(nonzero!(443)),
        )
        .unwrap();
        assert_eq!(
            result,
            Origin {
                mirror: Mirror::new(
                    DomainName::new("apt.llvm.org".to_string()).unwrap(),
                    Some(nonzero!(443)),
                    "unstable".to_string(),
                ),
                distribution: "llvm-toolchain-19".to_string(),
                component: "main".to_string(),
                architecture: "binary-amd64".to_string()
            }
        );
        assert_eq!(
            result.uri(),
            "http://apt.llvm.org:443/unstable/dists/llvm-toolchain-19/main/binary-amd64/Packages"
        );
    }

    #[test]
    fn test_parse_ipv6() {
        let result = Origin::from_path(
            "/debian/dists/sid/main/binary-amd64/Packages/",
            DomainName::new("2001:db8::1".to_string()).unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(
            result,
            Origin {
                mirror: Mirror::new(
                    DomainName::new("2001:db8::1".to_string()).unwrap(),
                    None,
                    "debian".to_string(),
                ),
                distribution: "sid".to_string(),
                component: "main".to_string(),
                architecture: "binary-amd64".to_string()
            }
        );
        assert_eq!(
            result.uri(),
            "http://[2001:db8::1]/debian/dists/sid/main/binary-amd64/Packages"
        );

        // IPv6 with port
        let result = Origin::from_path(
            "/debian/dists/sid/main/binary-amd64/Packages/",
            DomainName::new("::1".to_string()).unwrap(),
            Some(nonzero!(8080)),
        )
        .unwrap();
        assert_eq!(
            result.uri(),
            "http://[::1]:8080/debian/dists/sid/main/binary-amd64/Packages"
        );
    }

    #[test]
    fn test_parse_request_path() {
        /*
         * success
         */

        assert_eq!(
            parse_request_path("debian/pool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"),
            Some(ResourceFile::Pool {
                mirror_path: "debian",
                filename: "firefox-esr_115.9.1esr-1_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path(
                "private/ubuntu/pool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"
            ),
            Some(ResourceFile::Pool {
                mirror_path: "private/ubuntu",
                filename: "firefox-esr_115.9.1esr-1_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path("debian/pool/main/libs/libssh/libssh-doc_0.10.6-2_all.deb"),
            Some(ResourceFile::Pool {
                mirror_path: "debian",
                filename: "libssh-doc_0.10.6-2_all.deb"
            })
        );

        assert_eq!(
            parse_request_path(
                "debian/pool/main/libt/libtirpc/libtirpc3t64_1.3.4%2bds-1.2_amd64.deb"
            ),
            Some(ResourceFile::Pool {
                mirror_path: "debian",
                filename: "libtirpc3t64_1.3.4%2bds-1.2_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path("debian/pool/main/m/mesa/libgl1-mesa-dri_24.0.5-1_amd64.deb"),
            Some(ResourceFile::Pool {
                mirror_path: "debian",
                filename: "libgl1-mesa-dri_24.0.5-1_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path("public/debian/dists/sid/InRelease"),
            Some(ResourceFile::Release {
                mirror_path: "public/debian",
                distribution: "sid",
                filename: "InRelease"
            })
        );

        assert_eq!(
            parse_request_path("very///private/debian/dists/trixie/Release"),
            Some(ResourceFile::Release {
                mirror_path: "very///private/debian",
                distribution: "trixie",
                filename: "Release"
            })
        );

        assert_eq!(
            parse_request_path("debs/dists/vscodium/main/binary-amd64/Packages.gz"),
            Some(ResourceFile::Packages {
                mirror_path: "debs",
                distribution: "vscodium",
                component: "main",
                architecture: "binary-amd64",
                filename: "Packages.gz"
            })
        );

        assert_eq!(
            parse_request_path(
                "debian-security/dists/bookworm-security/main/binary-amd64/Packages.xz"
            ),
            Some(ResourceFile::Packages {
                mirror_path: "debian-security",
                distribution: "bookworm-security",
                component: "main",
                architecture: "binary-amd64",
                filename: "Packages.xz"
            })
        );

        assert_eq!(
            parse_request_path(
                "/pool/dists/unstable/dists/llvm-toolchain/main/binary-amd64/Packages.gz"
            ),
            Some(ResourceFile::Packages {
                mirror_path: "pool/dists/unstable",
                distribution: "llvm-toolchain",
                component: "main",
                architecture: "binary-amd64",
                filename: "Packages.gz"
            })
        );

        assert_eq!(
            parse_request_path(
                "/pool/dists/debian-security/pool/updates/main/c/chromium/chromium-common_141.0.7390.65-1%7edeb12u1_amd64.deb"
            ),
            Some(ResourceFile::Pool {
                mirror_path: "pool/dists/debian-security",
                filename: "chromium-common_141.0.7390.65-1%7edeb12u1_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path(
                "debian/dists/sid/main/binary-amd64/Packages.diff/by-hash/SHA256/491ddac17f4b86d771a457e6b084c499dfeb9ee29004b92d5d05fe79f1f0dede"
            ),
            Some(ResourceFile::ByHash {
                mirror_path: "debian",
                filename: "491ddac17f4b86d771a457e6b084c499dfeb9ee29004b92d5d05fe79f1f0dede"
            })
        );

        assert_eq!(
            parse_request_path(
                "debian/dists/sid/main/dep11/by-hash/SHA256/cf31e359ca5863e438c1b2d3ddaa1d473519ad26bd71e3dac7803dade82e4482"
            ),
            Some(ResourceFile::ByHash {
                mirror_path: "debian",
                filename: "cf31e359ca5863e438c1b2d3ddaa1d473519ad26bd71e3dac7803dade82e4482"
            })
        );

        assert_eq!(
            parse_request_path(
                "debian/dists/trixie/main/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ),
            Some(ResourceFile::ByHash {
                mirror_path: "debian",
                filename: "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            })
        );

        assert_eq!(
            parse_request_path("debian/dists/sid/main/dep11/icons-128x128.tar.gz"),
            Some(ResourceFile::Icon {
                mirror_path: "debian",
                distribution: "sid",
                component: "main",
                filename: "icons-128x128.tar.gz"
            })
        );

        assert_eq!(
            parse_request_path("debian/dists/sid/main/source/Sources.gz"),
            Some(ResourceFile::Sources {
                mirror_path: "debian",
                distribution: "sid",
                component: "main",
                filename: "Sources.gz"
            })
        );

        assert_eq!(
            parse_request_path("debian/dists/unstable/main/i18n/Translation-en.bz2"),
            Some(ResourceFile::Translation {
                mirror_path: "debian",
                distribution: "unstable",
                component: "main",
                filename: "Translation-en.bz2"
            })
        );

        /*
         * TODO: support those?
         */

        assert_eq!(
            parse_request_path(
                "debian/dists/sid/main/binary-amd64/Packages.diff/T-2024-04-16-1405.22-F-2024-04-15-2018.42.gz"
            ),
            None
        );

        /*
         * failures
         */

        assert_eq!(
            parse_request_path("debian/pool/main/g/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"),
            None
        );

        assert_eq!(
            parse_request_path("debian/loop/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"),
            None
        );

        assert_eq!(
            parse_request_path("pool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"),
            None
        );

        assert_eq!(
            parse_request_path(
                "debian%2Fpool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"
            ),
            None
        );

        assert_eq!(parse_request_path("debian/dists/sid/Foo"), None);

        assert_eq!(parse_request_path("debian/bar/sid/InRelease"), None);

        assert_eq!(parse_request_path("debian/dists/a/b/InRelease"), None);

        assert_eq!(
            parse_request_path("debian/dists/trixie/main/by-hash/SHA256/Packages"),
            None
        );

        assert_eq!(
            parse_request_path("debian/dists/trixie/main/by-hash/SHA256/cf31e359ca5"),
            None
        );
    }

    #[test]
    fn test_invalid_filename() {
        /* valid */
        assert!(valid_filename("firefox-esr_115.9.1esr-1_amd64.deb"));

        /* invalid */
        assert!(!valid_filename(""));
        assert!(!valid_filename("."));
        assert!(!valid_filename(".."));
        assert!(!valid_filename("-foo"));
        assert!(!valid_filename(".foo"));
        assert!(!valid_filename("_foo"));
        assert!(!valid_filename("foo\nbar"));
        assert!(!valid_filename("foo/bar"));
        assert!(!valid_filename("foo/./bar"));
        assert!(!valid_filename("foo/../bar"));
        assert!(!valid_filename("foo//bar"));
        assert!(!valid_filename("/"));
        assert!(!valid_filename("/debian"));
        assert!(!valid_filename("~/foo"));
        assert!(!valid_filename("~foo"));
    }

    #[test]
    fn test_invalid_mirrorname() {
        /* valid */
        assert!(valid_mirrorname("debian"));
        assert!(valid_mirrorname("public/ubuntu"));
        assert!(valid_mirrorname("public/private/kali"));
        assert!(valid_mirrorname("foo/bar"));

        /* invalid */
        assert!(!valid_mirrorname(""));
        assert!(!valid_mirrorname("."));
        assert!(!valid_mirrorname(".."));
        assert!(!valid_mirrorname("-foo"));
        assert!(!valid_mirrorname(".foo"));
        assert!(!valid_mirrorname("_foo"));
        assert!(!valid_mirrorname("foo\nbar"));
        assert!(!valid_mirrorname("foo/./bar"));
        assert!(!valid_mirrorname("foo/../bar"));
        assert!(!valid_mirrorname("foo//bar"));
        assert!(!valid_mirrorname("/"));
        assert!(!valid_mirrorname("/debian"));
        assert!(!valid_mirrorname("~/foo"));
        assert!(!valid_mirrorname("~foo"));
        assert!(!valid_mirrorname("public%2Fubuntu"));
    }

    #[test]
    fn test_invalid_distribution() {
        /* valid */
        assert!(valid_distribution("sid"));
        assert!(valid_distribution("lunar-updates"));

        /* invalid */
        assert!(!valid_distribution(""));
        assert!(!valid_distribution("."));
        assert!(!valid_distribution(".."));
        assert!(!valid_distribution("-foo"));
        assert!(!valid_distribution(".foo"));
        assert!(!valid_distribution("_foo"));
        assert!(!valid_distribution("foo\nbar"));
        assert!(!valid_distribution("foo/bar"));
        assert!(!valid_distribution("foo/./bar"));
        assert!(!valid_distribution("foo/../bar"));
        assert!(!valid_distribution("foo//bar"));
        assert!(!valid_distribution("/"));
        assert!(!valid_distribution("/debian"));
        assert!(!valid_distribution("~/foo"));
        assert!(!valid_distribution("~foo"));
    }

    #[test]
    fn test_invalid_component() {
        /* valid */
        assert!(valid_component("main"));
        assert!(valid_component("non-free"));
        assert!(valid_component("mysql-8.0"));
        assert!(valid_component("foo_bar"));

        /* invalid */
        assert!(!valid_component(""));
        assert!(!valid_component("."));
        assert!(!valid_component(".."));
        assert!(!valid_component("-foo"));
        assert!(!valid_component(".foo"));
        assert!(!valid_component("_foo"));
        assert!(!valid_component("foo\nbar"));
        assert!(!valid_component("foo/bar"));
        assert!(!valid_component("foo/./bar"));
        assert!(!valid_component("foo/../bar"));
        assert!(!valid_component("foo//bar"));
        assert!(!valid_component("/"));
        assert!(!valid_component("/debian"));
        assert!(!valid_component("~/foo"));
        assert!(!valid_component("~foo"));
    }

    #[test]
    fn test_invalid_architecture() {
        /* valid */
        assert!(valid_architecture("binary-amd64"));

        /* invalid */
        assert!(!valid_architecture(""));
        assert!(!valid_architecture("."));
        assert!(!valid_architecture(".."));
        assert!(!valid_architecture("-foo"));
        assert!(!valid_architecture(".foo"));
        assert!(!valid_architecture("_foo"));
        assert!(!valid_architecture("foo\nbar"));
        assert!(!valid_architecture("foo/bar"));
        assert!(!valid_architecture("foo/./bar"));
        assert!(!valid_architecture("foo/../bar"));
        assert!(!valid_architecture("foo//bar"));
        assert!(!valid_architecture("/"));
        assert!(!valid_architecture("/debian"));
        assert!(!valid_architecture("~/foo"));
        assert!(!valid_architecture("~foo"));
    }

    #[test]
    fn test_is_unsafe_proxy_path() {
        // safe paths
        assert!(!is_unsafe_proxy_path(
            "/debian/pool/main/a/apt/apt_2.9.8_amd64.deb"
        ));
        assert!(!is_unsafe_proxy_path("/debian/dists/sid/InRelease"));
        assert!(!is_unsafe_proxy_path("/"));
        assert!(!is_unsafe_proxy_path(""));
        // legitimate percent-encoded characters
        assert!(!is_unsafe_proxy_path(
            "/debian/pool/main/c/chromium/chromium-common_141.0.7390.65-1%7edeb12u1_amd64.deb"
        ));
        assert!(!is_unsafe_proxy_path(
            "/debian/pool/main/libt/libtirpc/libtirpc3t64_1.3.4%2bds-1.2_amd64.deb"
        ));
        // literal '%' in path (encoded as %25) is legitimate and must not be rejected
        assert!(!is_unsafe_proxy_path(
            "/debian/pool/main/foo%25bar/file.deb"
        ));
        // double-encoded sequences must be allowed (decoded once)
        assert!(!is_unsafe_proxy_path("/debian/foo%2520bar/file.deb"));

        // traversal
        assert!(is_unsafe_proxy_path("/debian/../etc/passwd"));
        assert!(is_unsafe_proxy_path("/debian/./pool/file.deb"));
        assert!(is_unsafe_proxy_path("/.."));
        assert!(is_unsafe_proxy_path("/."));
        // percent-encoded traversal
        assert!(is_unsafe_proxy_path("/debian/%2e%2e/etc/passwd"));
        assert!(is_unsafe_proxy_path("/debian/%2E%2E/etc/passwd"));

        // control characters / NUL
        assert!(is_unsafe_proxy_path("/debian/foo\nbar"));
        assert!(is_unsafe_proxy_path("/debian/foo%00bar"));
        assert!(is_unsafe_proxy_path("/debian/foo%0abar"));

        // invalid UTF-8 in percent-encoding
        assert!(is_unsafe_proxy_path("/debian/%ff%fe"));
    }

    #[test]
    fn test_is_diff_request_path() {
        // valid
        assert!(is_diff_request_path(
            "/debian/dists/unstable/main/i18n/Translation-en.diff/T-2024-10-03-0804.49-F-2024-10-02-2011.04.gz"
        ));
        assert!(is_diff_request_path(
            "/debian/dists/unstable/main/i18n/Translation-de.diff/T-2024-10-03-0804.49-F-2024-10-02-2011.04.gz"
        ));
        assert!(is_diff_request_path(
            "/debian/dists/sid/main/source/Sources.diff/T-2024-10-03-1409.04-F-2024-10-03-1409.04.gz"
        ));
        assert!(is_diff_request_path(
            "/debian/dists/sid/main/binary-i386/Packages.diff/T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz"
        ));

        // invalid — not diff paths
        assert!(!is_diff_request_path(
            "/debian/dists/sid/main/binary-amd64/Packages.gz"
        ));
        assert!(!is_diff_request_path(
            "/debian/dists/sid/main/binary-amd64/Packages.xz"
        ));
        assert!(!is_diff_request_path(
            "/debian/dists/sid/main/source/Sources.gz"
        ));
        assert!(!is_diff_request_path(
            "/debian/dists/sid/main/i18n/Translation-en.gz"
        ));
        assert!(!is_diff_request_path("/debian/dists/sid/InRelease"));
        assert!(!is_diff_request_path(
            "/debian/pool/main/a/apt/apt_2.9.8_amd64.deb"
        ));
        assert!(!is_diff_request_path(""));
        assert!(!is_diff_request_path("/"));
        // Contains "diff" but not in the expected pattern
        assert!(!is_diff_request_path(
            "/debian/dists/sid/main/binary-amd64/Packages.diff/"
        ));
        assert!(!is_diff_request_path(
            "/debian/dists/sid/main/source/Sources.diff/Index"
        ));
    }
}
