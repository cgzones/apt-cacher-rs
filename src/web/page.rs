//! Page chrome shared by the dashboard and the logs page: the query-string
//! options (`theme`, `refresh`), the `<html>` skeleton, the `<nav>` bar, the
//! stylesheet served at `/style.css` and the favicon.

use std::{
    fmt::{self, Display, Formatter},
    sync::LazyLock,
};

use crate::swrite;

use super::fmt::HtmlEscape;

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
pub(super) fn build_setup_hint_html(port: std::num::NonZero<u16>) -> String {
    format!(
        "<div class=\"section setup\"><h2>Getting Started</h2>\
         <p>No mirror has been contacted yet. Point apt at this proxy by writing \
         <code>Acquire::http::Proxy \"http://{}:{port}\";</code> into \
         <code>/etc/apt/apt.conf.d/01proxy</code> on a client.</p></div>",
        HtmlEscape(&HOSTNAME),
    )
}

/// The page heading, carrying the same identity as the `<title>`.
pub(super) fn build_heading_html() -> String {
    format!(
        "<h1>apt-cacher-rs <span class=\"host\">on {}</span></h1>",
        HtmlEscape(&HOSTNAME)
    )
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

#[derive(Clone, Copy, Default)]
pub(super) struct QueryOptions {
    pub(super) theme: Theme,
    pub(super) refresh_secs: Option<u32>,
}

/// `title` renders the page name and the instance identity; see
/// [`PageTitle`] for why each half is safe to interpolate.
pub(super) fn build_page(
    title: PageTitle,
    body_html: impl Display,
    options: QueryOptions,
) -> String {
    let theme_attr = options.theme.html_attr();
    let refresh = RefreshMeta(options.refresh_secs.unwrap_or(0));
    format!(
        "<!DOCTYPE html>\
         <html lang=\"en\"{theme_attr}>\
         <head>\
         <meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title>\
         <link rel=\"stylesheet\" href=\"/style.css\">\
         {FAVICON_LINK}\
         {refresh}\
         </head>\
         <body>{body_html}</body>\
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

/// Hard cap on query-string length. The known parameters fit in well under 64
/// bytes; anything longer is junk and we ignore the whole query.
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
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) enum Page {
    Dashboard { log_count: usize },
    Logs,
}

impl Page {
    const fn path(&self) -> &'static str {
        match self {
            Self::Dashboard { .. } => "/",
            Self::Logs => "/logs",
        }
    }
}

pub(super) fn build_nav_html(page: Page, options: QueryOptions) -> String {
    let mut html = String::with_capacity(512);
    html.push_str("<nav>");

    match page {
        Page::Dashboard { log_count } => {
            swrite!(
                html,
                "<a href=\"{}\">Logs <span class=\"count\">{log_count}</span></a>",
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
            let target = QueryUrl {
                path: "/",
                options: QueryOptions {
                    theme: options.theme,
                    refresh_secs: if options.refresh_secs.is_some() {
                        None
                    } else {
                        Some(30)
                    },
                },
            };
            if let Some(secs) = options.refresh_secs {
                swrite!(html, "<a href=\"{target}\">Stop auto-refresh ({secs}s)</a>");
            } else {
                swrite!(html, "<a href=\"{target}\">Auto-refresh (30s)</a>");
            }
        }
        Page::Logs => {
            swrite!(
                html,
                "<a href=\"{}\">Dashboard</a>",
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
        "<a href=\"{}\">{label}</a>",
        QueryUrl {
            path: page.path(),
            options: QueryOptions {
                theme: next_theme,
                refresh_secs: options.refresh_secs,
            },
        },
    );

    html.push_str("</nav>");
    html
}

// ---------------------------------------------------------------------------
// CSS — light theme by default, dark via `prefers-color-scheme: dark`
//
// Theme palette is declared once via the `light-dark()` CSS function. The
// `color-scheme` property keys the resolution: `light dark` follows the OS,
// `light`/`dark` pin a side. Each `data-theme` attribute just overrides
// `color-scheme` — no per-attribute variable lists to drift out of sync.
// ---------------------------------------------------------------------------

pub(super) const CSS: &str = r#"
:root {
    color-scheme: light dark;
    --mono: ui-monospace, "DejaVu Sans Mono", "Liberation Mono", "Consolas", monospace;
    --bg: light-dark(#eef1f2, #12171a);
    --fg: light-dark(#151a1f, #d7dee1);
    --nav-bg: light-dark(#fff, #1a2124);
    --nav-border: light-dark(#d8dee0, #2b3538);
    --section-bg: light-dark(#fff, #1a2124);
    --section-border: light-dark(#dde3e5, #2b3538);
    --section-shadow: light-dark(0 1px 2px rgba(21,26,31,0.06), 0 1px 3px rgba(0,0,0,0.35));
    --h-fg: light-dark(#1b2429, #cbd6da);
    --h-accent: light-dark(#0e6a6a, #4fb3ad);
    --th-bg: light-dark(#e7ecee, #232c30);
    --th-fg: light-dark(#1b2429, #cbd6da);
    --td-border: light-dark(#eceff0, #242e31);
    --row-hover-bg: light-dark(#f4f8f8, #212c30);
    --details-key-fg: light-dark(#55636b, #8fa0a7);
    --details-val-fg: light-dark(#151a1f, #d7dee1);
    --details-hover-bg: light-dark(#f4f8f8, #212c30);
    --link: light-dark(#0b5c5c, #5fbfb8);
    --count-bg: light-dark(rgba(14,106,106,0.10), rgba(79,179,173,0.18));
    --footer-fg: light-dark(#5c6a72, #8b9aa1);
    --ok: light-dark(#1d6b34, #58c07a);
    --warn: light-dark(#8a5200, #d9a441);
    --alert: light-dark(#a32b2b, #e8807f);
    --error-fg: light-dark(#a32b2b, #e8807f);
}
:root[data-theme="light"] { color-scheme: light; }
:root[data-theme="dark"] { color-scheme: dark; }

* { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body { font-family: "DejaVu Sans", system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       color: var(--fg); background: var(--bg); line-height: 1.45; padding: 12px 16px; font-size: 13px; }
p { margin: 4px 0; }

nav { background: var(--nav-bg); border-bottom: 1px solid var(--nav-border); padding: 8px 16px;
      margin: -12px -16px 12px; display: flex; flex-wrap: wrap; gap: 6px 18px;
      align-items: center; font-size: 13px; }
nav .spacer { flex: 1; }
nav a { color: var(--link); text-decoration: none; font-weight: 500; }
nav a:hover { text-decoration: underline; }
.count { display: inline-block; background: var(--count-bg); border-radius: 10px;
         padding: 1px 8px; font-size: 0.72em; font-weight: 600; vertical-align: middle;
         margin-left: 6px; min-width: 18px; text-align: center; line-height: 1.6;
         font-family: var(--mono); }
.dim { opacity: 0.4; }
.muted { color: var(--details-key-fg); }

h1 { font-size: 1.15em; color: var(--h-fg); font-weight: 600; margin-bottom: 10px; }
h1 .host { color: var(--details-key-fg); font-weight: 400; font-family: var(--mono); }
h2 { color: var(--h-fg); margin-bottom: 6px; border-bottom: 1px solid var(--section-border);
     padding-bottom: 4px; font-size: 0.95em; }
h3.mini { font-size: 0.85em; margin: 4px 0; color: var(--details-key-fg); }
h3.group { font-size: 0.85em; color: var(--h-fg); margin: 12px 0 2px;
           border-bottom: 1px solid var(--section-border); padding-bottom: 3px; }
h3.group:first-of-type { margin-top: 4px; }

.section { background: var(--section-bg); border: 1px solid var(--section-border); border-radius: 4px;
           box-shadow: var(--section-shadow); padding: 10px 14px; margin-bottom: 10px; }

/* The flow the whole daemon exists to produce: upstream in, clients out,
   the difference kept. One bold figure; everything around it stays quiet. */
.hero { background: var(--section-bg); border: 1px solid var(--section-border); border-radius: 4px;
        box-shadow: var(--section-shadow); padding: 14px 16px; margin-bottom: 10px;
        display: flex; flex-wrap: wrap; gap: 12px 40px; align-items: flex-end; }
.hero .k { display: block; font-size: 0.72em; color: var(--details-key-fg); font-weight: 600; }
.hero .v { font-family: var(--mono); font-size: 1em; color: var(--details-val-fg); }
.hero .flow { display: flex; align-items: flex-end; gap: 10px; }
.hero .arrow { color: var(--h-accent); font-size: 1.1em; line-height: 1.6; }
.hero .saved .big { display: block; font-family: var(--mono); font-size: 2em; font-weight: 600;
                    color: var(--h-accent); line-height: 1.1; }
.hero .right { margin-left: auto; text-align: right; }
.hero .right .v { display: block; }
.hero meter.bar { width: 90px; }
.hero .state { font-weight: 600; }
.hero .state.ok { color: var(--ok); }
.hero .state.bad { color: var(--alert); }

details { margin-top: 4px; }
details > summary { cursor: pointer; list-style: none; }
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: "\25B6\FE0E"; display: inline-block; margin-right: 6px;
                             font-size: 0.7em; transition: transform 0.2s ease; }
details[open] > summary::before { transform: rotate(90deg); }
details > summary > h2 { display: inline; }

.tablewrap { overflow-x: auto; max-width: 100%; }
table { width: 100%; border-collapse: collapse; margin-top: 6px; }
th { background: var(--th-bg); color: var(--th-fg); padding: 5px 10px; text-align: left;
     font-size: 0.8em; font-weight: 600; letter-spacing: 0.01em; }
td { padding: 4px 10px; border-bottom: 1px solid var(--td-border); font-family: var(--mono);
     font-size: 0.92em; font-variant-numeric: tabular-nums; max-width: 220px;
     overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
tr:hover td { background: var(--row-hover-bg); }
/* A rule down the leading edge is the row's state, not a hover effect. */
tr.row-aging td:first-child { box-shadow: inset 3px 0 var(--warn); }
tr.row-stale td:first-child { box-shadow: inset 3px 0 var(--alert); }

dl.details { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
             width: 100%; margin-top: 6px; }
dl.details > div { display: flex; flex-direction: column; padding: 4px 10px;
                   border-left: 3px solid transparent; }
dl.details > div:hover { border-left-color: var(--h-accent); background: var(--details-hover-bg); }
dl.details dt { font-size: 0.78em; color: var(--details-key-fg); font-weight: 600; }
dl.details dd { color: var(--details-val-fg); font-weight: 500; font-size: 0.95em;
                font-family: var(--mono); font-variant-numeric: tabular-nums; }

.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.section-error { color: var(--error-fg); font-size: 0.85em; margin: 4px 0; }
.empty { color: var(--details-key-fg); font-size: 0.9em; margin: 4px 0; }
.setup code { font-family: var(--mono); font-size: 0.95em; background: var(--count-bg);
              padding: 1px 5px; border-radius: 3px; }
.ok { color: var(--ok); font-weight: 600; }
.warn { color: var(--warn); font-weight: 600; }
.alert { color: var(--alert); font-weight: 700; }
time { border-bottom: 1px dotted transparent; transition: border-color 0.15s; }
time:hover { border-bottom-color: currentColor; }

meter.bar { width: 42px; height: 7px; vertical-align: middle; margin-left: 5px; }
meter.bar::-webkit-meter-bar { background: var(--count-bg); border: none; border-radius: 3px; }
meter.bar::-webkit-meter-optimum-value { background: var(--h-accent); border-radius: 3px; }
meter.bar::-moz-meter-bar { background: var(--h-accent); border-radius: 3px; }
pre.log { white-space: pre-wrap; overflow-wrap: anywhere; font-size: 0.85em;
          max-height: 80vh; overflow-y: auto; }

footer { color: var(--footer-fg); font-size: 0.82em; margin-top: 8px; }
footer hr { border: none; border-top: 1px solid var(--nav-border); margin-bottom: 6px; }

/* Once the hero has wrapped, a right-aligned block reads as a stray column. */
@media (max-width: 640px) {
    .hero .right { margin-left: 0; text-align: left; }
    .grid-2 { grid-template-columns: 1fr; }
}

@media (prefers-reduced-motion: reduce) {
    html { scroll-behavior: auto; }
    details > summary::before { transition: none; }
    time { transition: none; }
}
"#;

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
    use super::{MAX_QUERY_LEN, Theme, parse_query};

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
    fn parse_query_unknown_keys_ignored() {
        let q = parse_query(Some("foo=bar&baz=qux"));
        assert!(q.theme == Theme::Auto);
        assert!(q.refresh_secs.is_none());
    }
}
