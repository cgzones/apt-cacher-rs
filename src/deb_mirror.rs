use crate::config::DomainName;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Mirror {
    pub(crate) host: DomainName,
    pub(crate) path: String,
}

impl std::fmt::Display for Mirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.host, self.path)
    }
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
    pub(crate) fn from_path(path: &str, host: DomainName) -> Option<Self> {
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
            mirror: Mirror {
                host,
                path: mirror_path.to_owned(),
            },
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

impl UriFormat for Origin {
    #[inline]
    fn uri(&self) -> String {
        /* deb.debian.org/debian/dists/sid/main/binary-amd64/Packages */
        format!(
            "https://{}/{}/dists/{}/{}/{}/Packages",
            self.mirror.host,
            self.mirror.path,
            self.distribution,
            self.component,
            self.architecture
        )
    }
}

impl UriFormat for &crate::database::OriginEntry {
    #[inline]
    fn uri(&self) -> String {
        /* deb.debian.org/debian/dists/sid/main/binary-amd64/Packages */
        format!(
            "https://{}/{}/dists/{}/{}/{}/Packages",
            self.host, self.mirror_path, self.distribution, self.component, self.architecture
        )
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum ResourceFile<'a> {
    /// A pool file consisting of the mirror path and the filename
    Pool(&'a str, &'a str),
    /// A dists file consisting of the mirror path, the distribution, and the filename
    Dists(&'a str, &'a str, &'a str),
    /// A package file consisting of the mirror path, the distribution, the component, the architecture, and the filename
    Package(&'a str, &'a str, &'a str, &'a str, &'a str),
    /// A file named and acquired by its hash value consisting of the mirror path and the filename
    ByHash(&'a str, &'a str),
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

        return Some(ResourceFile::Pool(mirror_path, filename));
    }

    /*
     * debian/dists/sid/InRelease
     * debs/dists/vscodium/main/binary-amd64/Packages.gz
     * debian/dists/trixie/main/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba
     */
    if let Some((mirror_path, dists_path)) = path.rsplit_once("/dists/") {
        let mut parts = dists_path.rsplit('/');

        let filename = parts.next()?;
        if filename == "Release" || filename == "InRelease" {
            let distribution = parts.next()?;

            if parts.next().is_some() {
                return None;
            }

            return Some(ResourceFile::Dists(mirror_path, distribution, filename));
        } else if filename == "Packages.gz" || filename == "Packages.xz" {
            let architecture = parts.next()?;
            let component = parts.next()?;
            let distribution = parts.next()?;

            if parts.next().is_some() {
                return None;
            }

            return Some(ResourceFile::Package(
                mirror_path,
                distribution,
                component,
                architecture,
                filename,
            ));
        } else if filename.len() >= 64 && filename.chars().all(|c| c.is_ascii_hexdigit()) {
            let hash_algorithm = parts.next()?;

            // The filename length >= 64 characters ensures that only SHA >= SHA256 is supported
            if !hash_algorithm.starts_with("SHA") {
                return None;
            }

            if parts.next()? != "by-hash" {
                return None;
            }

            return Some(ResourceFile::ByHash(mirror_path, filename));
        }

        return None;
    }

    None
}

#[must_use]
pub(crate) fn valid_filename(name: &str) -> bool {
    name.len() >= 4
        && name.chars().enumerate().all(|(i, c)| {
            (i > 0 || c.is_ascii_alphanumeric())
                && c.is_ascii()
                && !c.is_ascii_control()
                && c != std::path::MAIN_SEPARATOR
                && c != '/'
        })
}

#[must_use]
pub(crate) fn valid_mirrorname(name: &str) -> bool {
    !name.is_empty()
        && name.split('/').all(|part| {
            !part.is_empty()
                && part.chars().all(|c| {
                    c.is_ascii()
                        && !c.is_ascii_control()
                        && c != std::path::MAIN_SEPARATOR
                        && c != '/'
                        && c != '.'
                })
        })
}

#[must_use]
pub(crate) fn valid_distribution(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .enumerate()
            .all(|(i, c)| c.is_ascii_alphanumeric() || (i > 0 && c == '-'))
}

#[must_use]
pub(crate) fn valid_component(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .enumerate()
            .all(|(i, c)| c.is_ascii_alphanumeric() || (i > 0 && c == '-'))
}

#[must_use]
pub(crate) fn valid_architecture(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .enumerate()
            .all(|(i, c)| c.is_ascii_alphanumeric() || (i > 0 && c == '-'))
}

#[cfg(test)]
mod tests {
    use crate::config::DomainName;

    use super::*;

    #[test]
    fn test_parse_1() {
        let result = Origin::from_path(
            "/debian/dists/sid/main/binary-amd64/Packages/",
            DomainName::new("deb.debian.org".to_string()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            result,
            Origin {
                mirror: Mirror {
                    host: DomainName::new("deb.debian.org".to_string()).unwrap(),
                    path: "debian".to_string(),
                },
                distribution: "sid".to_string(),
                component: "main".to_string(),
                architecture: "binary-amd64".to_string()
            }
        );
        assert_eq!(
            result.uri(),
            "https://deb.debian.org/debian/dists/sid/main/binary-amd64/Packages"
        );
    }

    #[test]
    fn test_parse_2() {
        let result = Origin::from_path(
            "/private/debian/dists/sid/main/binary-amd64/by-hash/SHA256/\
        84b902c50d12a499fb2156ca2190ddaa9bb9dd8c7354aaccfc56590318bc0b83",
            DomainName::new("site.example.com".to_string()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            result,
            Origin {
                mirror: Mirror {
                    host: DomainName::new("site.example.com".to_string()).unwrap(),
                    path: "private/debian".to_string(),
                },
                distribution: "sid".to_string(),
                component: "main".to_string(),
                architecture: "binary-amd64".to_string()
            }
        );
        assert_eq!(
            result.uri(),
            "https://site.example.com/private/debian/dists/sid/main/binary-amd64/Packages"
        );
    }

    #[test]
    fn test_parse_3() {
        let result = Origin::from_path(
            "/unstable/dists/llvm-toolchain-19/main/binary-amd64/Packages.gz",
            DomainName::new("apt.llvm.org".to_string()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            result,
            Origin {
                mirror: Mirror {
                    host: DomainName::new("apt.llvm.org".to_string()).unwrap(),
                    path: "unstable".to_string(),
                },
                distribution: "llvm-toolchain-19".to_string(),
                component: "main".to_string(),
                architecture: "binary-amd64".to_string()
            }
        );
        assert_eq!(
            result.uri(),
            "https://apt.llvm.org/unstable/dists/llvm-toolchain-19/main/binary-amd64/Packages"
        );
    }

    #[test]
    fn test_parse_request_path() {
        /*
         * success
         */

        assert_eq!(
            parse_request_path("debian/pool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"),
            Some(ResourceFile::Pool(
                "debian",
                "firefox-esr_115.9.1esr-1_amd64.deb"
            ))
        );

        assert_eq!(
            parse_request_path(
                "private/ubuntu/pool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"
            ),
            Some(ResourceFile::Pool(
                "private/ubuntu",
                "firefox-esr_115.9.1esr-1_amd64.deb"
            ))
        );

        assert_eq!(
            parse_request_path("debian/pool/main/libs/libssh/libssh-doc_0.10.6-2_all.deb"),
            Some(ResourceFile::Pool("debian", "libssh-doc_0.10.6-2_all.deb"))
        );

        assert_eq!(
            parse_request_path(
                "debian/pool/main/libt/libtirpc/libtirpc3t64_1.3.4%2bds-1.2_amd64.deb"
            ),
            Some(ResourceFile::Pool(
                "debian",
                "libtirpc3t64_1.3.4%2bds-1.2_amd64.deb"
            ))
        );

        assert_eq!(
            parse_request_path("debian/pool/main/m/mesa/libgl1-mesa-dri_24.0.5-1_amd64.deb"),
            Some(ResourceFile::Pool(
                "debian",
                "libgl1-mesa-dri_24.0.5-1_amd64.deb"
            ))
        );

        assert_eq!(
            parse_request_path("public/debian/dists/sid/InRelease"),
            Some(ResourceFile::Dists("public/debian", "sid", "InRelease"))
        );

        assert_eq!(
            parse_request_path("very///private/debian/dists/trixie/Release"),
            Some(ResourceFile::Dists(
                "very///private/debian",
                "trixie",
                "Release"
            ))
        );

        assert_eq!(
            parse_request_path("debs/dists/vscodium/main/binary-amd64/Packages.gz"),
            Some(ResourceFile::Package(
                "debs",
                "vscodium",
                "main",
                "binary-amd64",
                "Packages.gz"
            ))
        );

        assert_eq!(
            parse_request_path(
                "debian-security/dists/bookworm-security/main/binary-amd64/Packages.xz"
            ),
            Some(ResourceFile::Package(
                "debian-security",
                "bookworm-security",
                "main",
                "binary-amd64",
                "Packages.xz"
            ))
        );

        assert_eq!(
            parse_request_path(
                "/pool/dists/unstable/dists/llvm-toolchain/main/binary-amd64/Packages.gz"
            ),
            Some(ResourceFile::Package(
                "pool/dists/unstable",
                "llvm-toolchain",
                "main",
                "binary-amd64",
                "Packages.gz"
            ))
        );

        assert_eq!(
            parse_request_path(
                "/pool/dists/debian-security/pool/updates/main/c/chromium/chromium-common_141.0.7390.65-1%7edeb12u1_amd64.deb"
            ),
            Some(ResourceFile::Pool(
                "pool/dists/debian-security",
                "chromium-common_141.0.7390.65-1%7edeb12u1_amd64.deb"
            ))
        );

        assert_eq!(
            parse_request_path(
                "debian/dists/sid/main/binary-amd64/Packages.diff/by-hash/SHA256/491ddac17f4b86d771a457e6b084c499dfeb9ee29004b92d5d05fe79f1f0dede"
            ),
            Some(ResourceFile::ByHash(
                "debian",
                "491ddac17f4b86d771a457e6b084c499dfeb9ee29004b92d5d05fe79f1f0dede"
            ))
        );

        assert_eq!(
            parse_request_path(
                "debian/dists/sid/main/dep11/by-hash/SHA256/cf31e359ca5863e438c1b2d3ddaa1d473519ad26bd71e3dac7803dade82e4482"
            ),
            Some(ResourceFile::ByHash(
                "debian",
                "cf31e359ca5863e438c1b2d3ddaa1d473519ad26bd71e3dac7803dade82e4482"
            ))
        );

        assert_eq!(
            parse_request_path(
                "debian/dists/trixie/main/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ),
            Some(ResourceFile::ByHash(
                "debian",
                "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ))
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
        assert!(!valid_filename("foo/bar"));
        assert!(!valid_filename("foo\nbar"));
    }

    #[test]
    fn test_invalid_mirrorname() {
        /* valid */
        assert!(valid_mirrorname("debian"));
        assert!(valid_mirrorname("public/ubuntu"));
        assert!(valid_mirrorname("public/private/kali"));
        assert!(valid_mirrorname("public%2Fubuntu"));

        /* invalid */
        assert!(!valid_mirrorname(""));
        assert!(!valid_mirrorname("."));
        assert!(!valid_mirrorname(".."));
        assert!(!valid_mirrorname("foo\nbar"));
        assert!(!valid_mirrorname("foo/./bar"));
        assert!(!valid_mirrorname("foo/../bar"));
        assert!(!valid_mirrorname("foo//bar"));
        assert!(!valid_mirrorname("/"));
        assert!(!valid_mirrorname("/debian"));
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
        assert!(!valid_distribution("foo\nbar"));
        assert!(!valid_distribution("foo/bar"));
        assert!(!valid_distribution("foo/./bar"));
        assert!(!valid_distribution("foo/../bar"));
        assert!(!valid_distribution("foo//bar"));
        assert!(!valid_distribution("/"));
        assert!(!valid_distribution("/debian"));
    }

    #[test]
    fn test_invalid_component() {
        /* valid */
        assert!(valid_component("main"));
        assert!(valid_component("non-free"));

        /* invalid */
        assert!(!valid_component(""));
        assert!(!valid_component("."));
        assert!(!valid_component(".."));
        assert!(!valid_component("-foo"));
        assert!(!valid_component("foo\nbar"));
        assert!(!valid_component("foo/bar"));
        assert!(!valid_component("foo/./bar"));
        assert!(!valid_component("foo/../bar"));
        assert!(!valid_component("foo//bar"));
        assert!(!valid_component("/"));
        assert!(!valid_component("/debian"));
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
        assert!(!valid_architecture("foo\nbar"));
        assert!(!valid_architecture("foo/bar"));
        assert!(!valid_architecture("foo/./bar"));
        assert!(!valid_architecture("foo/../bar"));
        assert!(!valid_architecture("foo//bar"));
        assert!(!valid_architecture("/"));
        assert!(!valid_architecture("/debian"));
    }
}
