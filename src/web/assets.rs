//! The web interface's static assets, embedded at build time from
//! `src/web/assets/` and served under content-hashed URLs: the stylesheet
//! and the optional script bundle (`/app.js`, the files under `js/` joined
//! in order; `js/core.js` says what they may and may not do).
//!
//! A page links an asset as `{path}?v={version}`, the version being the
//! first 16 hex digits of the asset's SHA-256. A new build whose asset
//! changed links a new URL, so a browser may keep each URL for good
//! (`immutable`) and still never pairs a new page with an old stylesheet.
//! A request without `v`, or with another build's `v` (a page loaded before
//! an upgrade), is answered `no-cache`: those bytes are this build's and
//! must not be remembered under a URL that names other ones.

use std::{
    fmt::{self, Display, Formatter},
    sync::OnceLock,
};

use sha2::{Digest as _, Sha256};

use super::response::{Caching, WebResponse};

/// One embedded asset.
pub(super) struct Asset {
    /// The path it is served at, without the version query.
    pub(super) path: &'static str,
    pub(super) content_type: &'static str,
    pub(super) body: &'static str,
    /// Hex digits of the body's SHA-256 prefix, computed on first use.
    version: OnceLock<Box<str>>,
}

impl Asset {
    const fn new(path: &'static str, content_type: &'static str, body: &'static str) -> Self {
        Self {
            path,
            content_type,
            body,
            version: OnceLock::new(),
        }
    }

    /// The content hash the page's link carries as `v=`.
    pub(super) fn version(&self) -> &str {
        self.version.get_or_init(|| version_of(self.body))
    }

    /// The versioned URL a page links, e.g. `/style.css?v=0123456789abcdef`.
    pub(super) fn url(&self) -> AssetUrl<'_> {
        AssetUrl(self)
    }

    /// The response to a GET of this asset with `query` as its query string:
    /// cacheable for good when it names this build's version.
    pub(super) fn response(&self, query: Option<&str>) -> WebResponse {
        let caching = if requested_version(query) == Some(self.version()) {
            Caching::Immutable
        } else {
            Caching::Revalidate
        };
        WebResponse::static_resource(self.content_type, self.body, caching)
    }
}

/// See [`Asset::url`].
pub(super) struct AssetUrl<'a>(&'a Asset);

impl Display for AssetUrl<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self(asset) = self;
        write!(f, "{}?v={}", asset.path, asset.version())
    }
}

/// 64 bits of SHA-256, as 16 lowercase hex digits: a version, not a
/// security boundary, so the prefix only has to make an accidental clash
/// between two builds' assets implausible.
fn version_of(body: &str) -> Box<str> {
    let digest = Sha256::digest(body.as_bytes());
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    Box::from(const_hex::const_encode::<8, false>(&prefix).as_str())
}

/// The `v` parameter of an asset request's query string.
fn requested_version(query: Option<&str>) -> Option<&str> {
    query?.split('&').find_map(|pair| pair.strip_prefix("v="))
}

pub(super) static STYLESHEET: Asset = Asset::new(
    "/style.css",
    "text/css; charset=utf-8",
    include_str!("assets/style.css"),
);

/// The optional scripts, one bundle. `core.js` comes first: it defines the
/// `ACR` namespace the others register with. `text/javascript` per RFC 9239.
pub(super) static SCRIPT: Asset = Asset::new(
    "/app.js",
    "text/javascript; charset=utf-8",
    concat!(
        include_str!("assets/js/core.js"),
        include_str!("assets/js/refresh.js"),
        include_str!("assets/js/sort.js"),
        include_str!("assets/js/filter.js"),
        include_str!("assets/js/series.js"),
        include_str!("assets/js/logs.js"),
    ),
);

/// Every asset, for the route handler.
static ALL: [&Asset; 2] = [&STYLESHEET, &SCRIPT];

/// The asset served at `path`, if any.
pub(super) fn find(path: &str) -> Option<&'static Asset> {
    ALL.iter().copied().find(|asset| asset.path == path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_control(response: &WebResponse) -> &'static str {
        response
            .extra_headers()
            .iter()
            .find(|(name, _)| *name == "Cache-Control")
            .map(|(_, value)| *value)
            .expect("assets carry Cache-Control")
    }

    #[test]
    fn the_version_is_a_stable_hex_prefix_of_the_content_hash() {
        let version = STYLESHEET.version();
        assert_eq!(version.len(), 16);
        assert!(
            version
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{version}"
        );
        assert_eq!(version, &*version_of(STYLESHEET.body));
        assert_ne!(&*version_of("a"), &*version_of("b"));
        assert_eq!(
            STYLESHEET.url().to_string(),
            format!("/style.css?v={version}")
        );
    }

    #[test]
    fn only_the_current_version_is_cached_for_good() {
        let current = format!("v={}", STYLESHEET.version());
        assert_eq!(
            cache_control(&STYLESHEET.response(Some(&current))),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            cache_control(&STYLESHEET.response(Some(&format!("x=1&{current}")))),
            "public, max-age=31536000, immutable"
        );
        for query in [None, Some(""), Some("v=0000000000000000"), Some("v=")] {
            assert_eq!(
                cache_control(&STYLESHEET.response(query)),
                "no-cache",
                "{query:?}"
            );
        }
    }

    #[test]
    fn assets_are_found_by_their_path() {
        assert!(find("/style.css").is_some_and(|asset| asset.path == STYLESHEET.path));
        assert!(find("/app.js").is_some_and(|asset| asset.path == SCRIPT.path));
        assert!(find("/style.css?v=1").is_none());
        assert!(find("/nope.css").is_none());
        assert_ne!(STYLESHEET.version(), SCRIPT.version());
    }

    /// The one absolute URL the scripts may name: the SVG namespace, which
    /// is an identifier, never fetched.
    const SVG_NS: &str = "http://www.w3.org/2000/svg";

    /// What the scripts must never contain. HTML-parsing sinks and
    /// string-to-code (Trusted Types and `script-src 'self'` would refuse
    /// them, leaving a feature broken instead of a hole), CSSOM writes (which
    /// `style-src 'self'` does NOT cover, so the policy cannot catch them),
    /// dynamic imports and script URLs.
    const BANNED: &[&str] = &[
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "DOMParser",
        "createContextualFragment",
        "parseHTMLUnsafe",
        "setHTMLUnsafe",
        ".srcdoc",
        "eval(",
        "Function(",
        "setTimeout(\"",
        "setTimeout('",
        "setInterval(\"",
        "setInterval('",
        ".style",
        "setAttribute(\"style\"",
        "setAttribute('style'",
        "attributeStyleMap",
        "cssText",
        "insertRule",
        "CSSStyleSheet",
        "adoptedStyleSheets",
        "javascript:",
        "import(",
        "importScripts",
        "document.cookie",
        "createPolicy",
    ];

    /// The first `.onfoo =` assignment in `js`: handlers are attached with
    /// addEventListener throughout, which keeps them greppable and makes a
    /// stray handler *attribute* stand out in review.
    fn handler_assignment(js: &str) -> Option<&str> {
        js.match_indices(".on").find_map(|(at, _)| {
            let rest = js.get(at + 3..)?;
            let name = rest.bytes().take_while(u8::is_ascii_lowercase).count();
            let after = rest.get(name..)?.trim_start_matches(' ');
            (name > 0 && after.starts_with('=') && !after.starts_with("=="))
                .then(|| js.get(at..at + 3 + name))
                .flatten()
        })
    }

    #[test]
    fn the_script_bundle_stays_inside_the_policy() {
        let js = SCRIPT.body;
        assert!(js.is_ascii(), "the scripts are ASCII only");
        assert!(
            js.starts_with(include_str!("assets/js/core.js")),
            "core.js leads the bundle: it defines ACR"
        );
        for banned in BANNED {
            assert!(!js.contains(banned), "the scripts use `{banned}`");
        }
        let without_namespace = js.replace(SVG_NS, "");
        for scheme in ["http:", "https:", "data:", "blob:", "ws:", "wss:"] {
            assert!(
                !without_namespace.contains(scheme),
                "the scripts name a `{scheme}` URL"
            );
        }
        assert_eq!(handler_assignment(js), None);
        assert_eq!(handler_assignment("x.onload = f"), Some(".onload"));
        assert_eq!(handler_assignment("x.onState(f); a.on == b"), None);
    }

    #[test]
    fn the_stylesheet_loads_nothing_else() {
        let css = STYLESHEET.body;
        assert!(css.is_ascii(), "the stylesheet is ASCII only");
        for banned in ["@import", "url(", "expression("] {
            assert!(!css.contains(banned), "the stylesheet uses `{banned}`");
        }
    }
}
