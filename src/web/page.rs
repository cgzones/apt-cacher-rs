//! Page chrome shared by the dashboard and the logs page: the query-string
//! options (`theme`, `refresh`), the `<html>` skeleton, the `<nav>` bar and
//! the favicon.

use std::{
    fmt::{self, Display, Formatter},
    sync::LazyLock,
};

use crate::swrite;

use super::{
    assets::{SCRIPT, STYLESHEET},
    fmt::HtmlEscape,
};

/// The system hostname, read once at first use.
///
/// Without it two daemons are indistinguishable in a browser tab and in a
/// screenshot pasted into a ticket; it is the only instance identity the
/// server can put in the page, since the URL the client typed never reaches
/// us in a form worth trusting.
static HOSTNAME: LazyLock<Box<str>> = LazyLock::new(|| {
    nix::unistd::gethostname()
        .ok()
        .and_then(|name| name.into_string().ok())
        .unwrap_or_else(|| String::from("unknown host"))
        .into_boxed_str()
});

/// Renders `<page> on <hostname>`. The page part is `&'static str` so no
/// user-controlled value can reach the `<title>`; the hostname is escaped
/// because it is only as well-formed as the machine's configuration.
#[derive(Clone, Copy)]
pub(super) struct PageTitle(pub(super) &'static str);

impl Display for PageTitle {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} on {}", self.0, HtmlEscape(&HOSTNAME))
    }
}

/// First-run guidance. With nothing fetched yet the dashboard is a wall of
/// zeroes, and the one thing its reader needs is the line that points apt at
/// this daemon.
pub(super) struct SetupHint(pub(super) std::num::NonZero<u16>);

impl Display for SetupHint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<div class=\"section setup\" data-section=\"setup\"><h2>Getting Started</h2>\
             <p>No mirror has been contacted yet. Point apt at this proxy by writing \
             <code>Acquire::http::Proxy \"http://{}:{}\";</code> into \
             <code>/etc/apt/apt.conf.d/01proxy</code> on a client.</p></div>",
            HtmlEscape(&HOSTNAME),
            self.0,
        )
    }
}

/// The page heading, carrying the same identity as the `<title>`.
pub(super) struct Heading;

impl Display for Heading {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<h1>apt-cacher-rs <span class=\"host\">on {}</span></h1>",
            HtmlEscape(&HOSTNAME)
        )
    }
}

// ---------------------------------------------------------------------------
// Page chrome
// ---------------------------------------------------------------------------

/// User-selected colour theme. `Auto` defers to `prefers-color-scheme`.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub(super) enum Theme {
    #[default]
    Auto,
    Light,
    Dark,
}

impl Theme {
    const fn html_attr(self) -> &'static str {
        match self {
            Self::Auto => "",
            Self::Light => " data-theme=\"light\"",
            Self::Dark => " data-theme=\"dark\"",
        }
    }

    const fn query_param(self) -> Option<&'static str> {
        match self {
            Self::Auto => None,
            Self::Light => Some("theme=light"),
            Self::Dark => Some("theme=dark"),
        }
    }
}

/// The dashboard's collapsible sections, by the stem of their heading id
/// (`{key}-head`): the names `open=` accepts.
const SECTIONS: [&str; 8] = [
    "mirrors",
    "origins",
    "clients",
    "packages",
    "uncacheables",
    "maintenance",
    "configuration",
    "metrics",
];

/// The sections `open=mirrors,metrics,...` asks to render expanded.
///
/// A `<details>` a reader opened closes again on every auto-refresh, since
/// the page is rebuilt from scratch and there is no script to remember it.
/// The set rides in the URL instead: the refresh meta tag reloads the same
/// URL, and every link the page emits carries it along with `refresh` and
/// `theme`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct OpenSections(u8);

// One bit per section: a ninth would shift past the `u8`.
const _: () = assert!(
    SECTIONS.len() <= u8::BITS as usize,
    "one bit per section in OpenSections"
);

impl OpenSections {
    fn bit(key: &str) -> Option<u8> {
        SECTIONS
            .iter()
            .position(|section| *section == key)
            .map(|index| 1 << index)
    }

    /// Unknown names are ignored, like every other malformed parameter.
    fn parse(value: &str) -> Self {
        Self(
            value
                .split(',')
                .filter_map(Self::bit)
                .fold(0, |bits, bit| bits | bit),
        )
    }

    pub(super) fn contains(self, key: &str) -> bool {
        Self::bit(key).is_some_and(|bit| self.0 & bit != 0)
    }

    /// `self` with `key` added if absent, removed if present.
    fn toggled(self, key: &str) -> Self {
        Self(self.0 ^ Self::bit(key).unwrap_or(0))
    }

    const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl Display for OpenSections {
    /// The comma-separated names, in page order.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut sep = "";
        for key in SECTIONS {
            if self.contains(key) {
                write!(f, "{sep}{key}")?;
                sep = ",";
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
pub(super) struct QueryOptions {
    pub(super) theme: Theme,
    pub(super) refresh_secs: Option<u32>,
    pub(super) open: OpenSections,
}

/// The link in a collapsible section's header that keeps it open across
/// refreshes (or stops doing so): the current page's URL with the section
/// toggled in `open=`, anchored at the section.
pub(super) struct PinLink {
    pub(super) key: &'static str,
    pub(super) options: QueryOptions,
}

impl Display for PinLink {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { key, options } = *self;
        let pinned = options.open.contains(key);
        let target = QueryUrl {
            path: "/",
            options: QueryOptions {
                open: options.open.toggled(key),
                ..options
            },
        };
        let (label, title) = if pinned {
            ("unpin", "Stop keeping this section open across refreshes")
        } else {
            ("keep open", "Keep this section open across refreshes")
        };
        write!(
            f,
            "<a class=\"pin\" href=\"{target}#{key}-head\" title=\"{title}\">{label}</a>"
        )
    }
}

/// `title` renders the page name and the instance identity; see
/// [`PageTitle`] for why each half is safe to interpolate.
pub(super) fn build_page(
    title: PageTitle,
    page: Page,
    body_html: impl Display,
    options: QueryOptions,
) -> String {
    let page = page.key();
    let theme_attr = options.theme.html_attr();
    let refresh = RefreshMeta(options.refresh_secs.unwrap_or(0));
    let stylesheet = STYLESHEET.url();
    let script = SCRIPT.url();
    format!(
        "<!DOCTYPE html>\
         <html lang=\"en\"{theme_attr}>\
         <head>\
         <meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title>\
         <link rel=\"stylesheet\" href=\"{stylesheet}\">\
         {FAVICON_LINK}\
         <script defer src=\"{script}\"></script>\
         {refresh}\
         </head>\
         <body data-page=\"{page}\">{body_html}</body>\
         </html>"
    )
}

struct RefreshMeta(u32);
impl Display for RefreshMeta {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            Ok(())
        } else {
            write!(f, "<meta http-equiv=\"refresh\" content=\"{}\">", self.0)
        }
    }
}

/// Hard cap on query-string length. The known parameters fit in about 120
/// bytes (a full `open=` list is ~85); anything longer is junk and we ignore
/// the whole query.
const MAX_QUERY_LEN: usize = 256;

pub(super) fn parse_query(query: Option<&str>) -> QueryOptions {
    let mut options = QueryOptions::default();

    let Some(query) = query else {
        return options;
    };
    if query.len() > MAX_QUERY_LEN {
        return options;
    }

    // `&` only — the legacy `;` separator was dropped from WHATWG URL and
    // browsers no longer emit it. Keeping the parser surface minimal.
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        match k {
            "theme" => match v {
                "light" => options.theme = Theme::Light,
                "dark" => options.theme = Theme::Dark,
                _ => {}
            },
            "open" => options.open = OpenSections::parse(v),
            "refresh" => {
                const MIN_REFRESH_SECS: u32 = 1;
                const MAX_REFRESH_SECS: u32 = 3600;
                if let Ok(secs) = v.parse()
                    && (MIN_REFRESH_SECS..=MAX_REFRESH_SECS).contains(&secs)
                {
                    options.refresh_secs = Some(secs);
                }
            }
            _ => {}
        }
    }

    options
}

/// Renders a navigation link's URL preserving `refresh` and `theme` params.
/// Implemented as `Display` so the surrounding `<a href="…">…</a>` boilerplate
/// can be emitted in a single `write!` instead of multiple `push_str` calls.
struct QueryUrl<'a> {
    path: &'a str,
    options: QueryOptions,
}
impl Display for QueryUrl<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.path)?;
        let mut sep = '?';
        if let Some(secs) = self.options.refresh_secs {
            write!(f, "{sep}refresh={secs}")?;
            sep = '&';
        }
        if let Some(p) = self.options.theme.query_param() {
            write!(f, "{sep}{p}")?;
            sep = '&';
        }
        if !self.options.open.is_empty() {
            write!(f, "{sep}open={}", self.options.open)?;
        }
        Ok(())
    }
}

/// Seconds the dashboard's auto-refresh link switches on. Shared by the link
/// target and its label so the two cannot disagree.
const AUTO_REFRESH_SECS: u32 = 30;

#[derive(Clone, Copy)]
pub(super) enum Page {
    Dashboard { log_count: usize },
    Logs,
}

impl Page {
    const fn path(self) -> &'static str {
        match self {
            Self::Dashboard { .. } => "/",
            Self::Logs => "/logs",
        }
    }

    /// The `<body data-page>` value, which tells the scripts where they
    /// run.
    const fn key(self) -> &'static str {
        match self {
            Self::Dashboard { .. } => "dashboard",
            Self::Logs => "logs",
        }
    }
}

pub(super) fn build_nav_html(page: Page, options: QueryOptions) -> String {
    let mut html = String::with_capacity(512);
    // The links that carry the page state (`data-carry`) and the two
    // toggles (`data-action`) are marked for the scripts, which keep their
    // hrefs current as they change that state in place.
    html.push_str("<nav data-section=\"nav\">");

    match page {
        Page::Dashboard { log_count } => {
            swrite!(
                html,
                "<a data-carry href=\"{}\">Logs <span class=\"count\">{log_count}</span></a>",
                QueryUrl {
                    path: "/logs",
                    options
                },
            );
            html.push_str("<span class=\"dim\">|</span>");
            for (href, label) in [
                ("#mirrors-head", "Mirrors"),
                ("#origins-head", "Origins"),
                ("#clients-head", "Clients"),
                ("#packages-head", "Packages"),
                ("#uncacheables-head", "Uncacheables"),
                ("#metrics-head", "Metrics"),
            ] {
                swrite!(html, "<a href=\"{href}\">{label}</a>");
            }
            html.push_str("<span class=\"dim\">|</span>");
            html.push_str("<a href=\"/healthcheck\">Health JSON</a>");
            html.push_str("<span class=\"dim\">|</span>");
            // The link toggles: it turns auto-refresh off while it is on,
            // and on at `AUTO_REFRESH_SECS` while it is off.
            let target = QueryUrl {
                path: "/",
                options: QueryOptions {
                    refresh_secs: if options.refresh_secs.is_some() {
                        None
                    } else {
                        Some(AUTO_REFRESH_SECS)
                    },
                    ..options
                },
            };
            let label = match options.refresh_secs {
                Some(secs) => format!("Stop auto-refresh ({secs}s)"),
                None => format!("Auto-refresh ({AUTO_REFRESH_SECS}s)"),
            };
            swrite!(
                html,
                "<a data-action=\"refresh-toggle\" data-secs=\"{AUTO_REFRESH_SECS}\" href=\"{target}\">{label}</a>"
            );
        }
        Page::Logs => {
            swrite!(
                html,
                "<a data-carry href=\"{}\">Dashboard</a>",
                QueryUrl { path: "/", options },
            );
        }
    }

    html.push_str("<span class=\"spacer\"></span>");
    let (next_theme, label) = match options.theme {
        Theme::Auto => (Theme::Light, "Theme: auto \u{2192} light"),
        Theme::Light => (Theme::Dark, "Theme: light \u{2192} dark"),
        Theme::Dark => (Theme::Auto, "Theme: dark \u{2192} auto"),
    };
    swrite!(
        html,
        "<a data-action=\"theme-cycle\" href=\"{}\">{label}</a>",
        QueryUrl {
            path: page.path(),
            options: QueryOptions {
                theme: next_theme,
                ..options
            },
        },
    );

    html.push_str("</nav>");
    html
}

// ---------------------------------------------------------------------------
// Favicon — small inline SVG (box/archive icon), served at /favicon.svg
// (and /favicon.ico for browsers that auto-probe that path).
// ---------------------------------------------------------------------------

pub(super) const FAVICON_SVG: &str = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'>\
<rect x='1' y='4' width='14' height='10' rx='1' fill='#4a7bcc'/>\
<rect x='0' y='2' width='16' height='4' rx='1' fill='#2c3e50'/>\
<rect x='6' y='6' width='4' height='2' rx='.5' fill='#fff'/>\
</svg>";

const FAVICON_LINK: &str = "<link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\">";

#[cfg(test)]
mod tests {
    use super::{MAX_QUERY_LEN, PinLink, QueryUrl, Theme, parse_query};

    #[test]
    fn parse_query_none() {
        let q = parse_query(None);
        assert!(q.theme == Theme::Auto);
        assert!(q.refresh_secs.is_none());
    }

    #[test]
    fn parse_query_empty_string() {
        let q = parse_query(Some(""));
        assert!(q.theme == Theme::Auto);
        assert!(q.refresh_secs.is_none());
    }

    #[test]
    fn parse_query_theme_light_dark() {
        assert!(parse_query(Some("theme=light")).theme == Theme::Light);
        assert!(parse_query(Some("theme=dark")).theme == Theme::Dark);
    }

    #[test]
    fn parse_query_theme_unknown_value_keeps_default() {
        assert!(parse_query(Some("theme=neon")).theme == Theme::Auto);
    }

    #[test]
    fn parse_query_refresh_in_range() {
        assert_eq!(parse_query(Some("refresh=1")).refresh_secs, Some(1));
        assert_eq!(parse_query(Some("refresh=30")).refresh_secs, Some(30));
        assert_eq!(parse_query(Some("refresh=3600")).refresh_secs, Some(3600));
    }

    #[test]
    fn parse_query_refresh_out_of_range() {
        assert_eq!(parse_query(Some("refresh=0")).refresh_secs, None);
        assert_eq!(parse_query(Some("refresh=3601")).refresh_secs, None);
        assert_eq!(parse_query(Some("refresh=99999999")).refresh_secs, None);
    }

    #[test]
    fn parse_query_refresh_non_numeric() {
        assert_eq!(parse_query(Some("refresh=abc")).refresh_secs, None);
        assert_eq!(parse_query(Some("refresh=-5")).refresh_secs, None);
        assert_eq!(parse_query(Some("refresh=")).refresh_secs, None);
    }

    #[test]
    fn parse_query_combined_pairs() {
        let q = parse_query(Some("theme=dark&refresh=30"));
        assert!(q.theme == Theme::Dark);
        assert_eq!(q.refresh_secs, Some(30));
    }

    #[test]
    fn parse_query_pairs_without_value_skipped() {
        // Bare keys, malformed pairs, and unknown keys must not poison later
        // valid pairs.
        let q = parse_query(Some("noeq&also&theme=light&missing=&refresh=15"));
        assert!(q.theme == Theme::Light);
        assert_eq!(q.refresh_secs, Some(15));
    }

    #[test]
    fn parse_query_oversize_dropped_entirely() {
        // Even valid pairs are ignored when the whole query exceeds the cap.
        let mut q = String::with_capacity(MAX_QUERY_LEN + 32);
        q.push_str("theme=dark&");
        while q.len() <= MAX_QUERY_LEN {
            q.push_str("pad=x&");
        }
        let parsed = parse_query(Some(&q));
        assert!(parsed.theme == Theme::Auto);
        assert!(parsed.refresh_secs.is_none());
    }

    #[test]
    fn parse_query_open_sections() {
        let q = parse_query(Some("open=metrics,bogus,mirrors&theme=dark"));
        assert!(q.open.contains("metrics"));
        assert!(q.open.contains("mirrors"));
        assert!(!q.open.contains("clients"));
        assert!(!q.open.contains("bogus"));
        // Rendered back in page order, whatever order it came in.
        assert_eq!(q.open.to_string(), "mirrors,metrics");
        assert!(parse_query(Some("open=")).open.is_empty());
    }

    #[test]
    fn links_carry_the_open_sections_and_pins_toggle_them() {
        let options = parse_query(Some("refresh=30&open=metrics"));
        let url = QueryUrl {
            path: "/logs",
            options,
        }
        .to_string();
        assert_eq!(url, "/logs?refresh=30&open=metrics");
        let unpin = PinLink {
            key: "metrics",
            options,
        }
        .to_string();
        assert!(
            unpin.contains("href=\"/?refresh=30#metrics-head\"") && unpin.contains(">unpin</a>"),
            "{unpin}"
        );
        let pin = PinLink {
            key: "maintenance",
            options,
        }
        .to_string();
        assert!(
            pin.contains("href=\"/?refresh=30&open=maintenance,metrics#maintenance-head\"")
                && pin.contains(">keep open</a>"),
            "{pin}"
        );
    }

    #[test]
    fn parse_query_unknown_keys_ignored() {
        let q = parse_query(Some("foo=bar&baz=qux"));
        assert!(q.theme == Theme::Auto);
        assert!(q.refresh_secs.is_none());
    }
}
