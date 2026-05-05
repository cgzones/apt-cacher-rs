use std::{
    cmp::Reverse,
    fmt::{self, Display, Formatter, Write as _},
    path::{Path, PathBuf},
    sync::LazyLock,
    time::SystemTime,
};

use coarsetime::Instant;
use hashbrown::HashMap;
use http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use hyper::{
    Response, StatusCode,
    header::{CONNECTION, CONTENT_TYPE, DATE, SERVER},
};
use log::{debug, error, trace, warn};
use time::{OffsetDateTime, format_description::FormatItem, macros::format_description};

use crate::{
    APP_NAME, APP_VERSION, AppState, HumanFmt, LOGSTORE, ProxyCacheBody, RUNTIMEDETAILS,
    RuntimeDetails,
    client_counter::{active_client_downloads, connected_clients},
    config::HttpsUpgradeMode,
    database::{Database, MirrorStatEntry},
    database_task::DB_TASK_QUEUE_SENDER,
    deb_mirror::VALID_DEB_EXTENSIONS,
    format_http_date, full_body, get_features, global_cache_quota, global_config, metrics,
    task_cleanup::{CLEANUP_INTERVAL_SECS, next_cleanup_epoch},
    tunnel_limiter::active_tunnels,
    uncacheables::{UNCACHEABLES_MAX, get_uncacheables},
    warn_once_or_debug,
};

const WEBUI_DATE_FORMAT: &[FormatItem<'_>] =
    format_description!("[day] [month repr:short] [year] [hour]:[minute]:[second]");

/// ISO-8601 with a literal `Z` suffix — only valid for UTC datetimes.
/// All callers must go through [`Utc`] which enforces that invariant.
const WEBUI_ISO_FORMAT: &[FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

/// `OffsetDateTime` constrained to UTC at construction. The `WEBUI_ISO_FORMAT`
/// constant hard-codes a literal `Z` suffix, so feeding it a non-UTC value
/// would silently emit a wrong timestamp. Wrap once at the source instead.
///
/// Renders as `<time datetime="…ISO…">…human…</time>`, which is the only
/// pattern the dashboard needs. Routing every callsite through this
/// `Display` impl is what keeps the `Z`-suffix invariant from leaking.
#[derive(Copy, Clone)]
struct Utc(OffsetDateTime);

impl Utc {
    fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Take any `OffsetDateTime` and shift it to UTC. Use at the boundary
    /// when receiving a value from foreign code that may not already be UTC.
    fn from_offset(odt: OffsetDateTime) -> Self {
        Self(odt.to_offset(time::UtcOffset::UTC))
    }

    fn inner(self) -> OffsetDateTime {
        self.0
    }
}

impl Display for Utc {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut buf = Vec::<u8>::with_capacity(48);
        if self.0.format_into(&mut buf, WEBUI_ISO_FORMAT).is_err() {
            return f.write_str("<time>invalid time</time>");
        }
        let iso_len = buf.len();
        if self.0.format_into(&mut buf, WEBUI_DATE_FORMAT).is_err() {
            return f.write_str("<time>invalid time</time>");
        }
        // Both formatters emit ASCII only, so the buffer is valid UTF-8.
        let Ok(s) = std::str::from_utf8(&buf) else {
            return f.write_str("<time>invalid time</time>");
        };
        let (iso, display) = s.split_at(iso_len);
        write!(f, "<time datetime=\"{iso}\">{display}</time>")
    }
}

// ---------------------------------------------------------------------------
// Display wrappers — render directly into a Formatter without allocating.
// ---------------------------------------------------------------------------

/// HTML-escapes its inner string when formatted. Single-pass: any byte that
/// needs escaping fans out to its named entity; the rest is copied verbatim.
struct HtmlEscape<'a>(&'a str);
impl Display for HtmlEscape<'_> {
    #[expect(
        clippy::string_slice,
        reason = "byte indices match ASCII bytes only, so slice boundaries are valid UTF-8"
    )]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut last = 0;
        for (i, &b) in self.0.as_bytes().iter().enumerate() {
            let entity = match b {
                b'&' => "&amp;",
                b'<' => "&lt;",
                b'>' => "&gt;",
                b'"' => "&quot;",
                b'\'' => "&#x27;",
                _ => continue,
            };
            f.write_str(&self.0[last..i])?;
            f.write_str(entity)?;
            last = i + 1;
        }
        f.write_str(&self.0[last..])
    }
}

/// HTML-escapes the formatted output of any inner `Display` value, streaming
/// directly into the destination `Formatter`. Avoids an intermediate `String`.
struct HtmlEscaped<D: Display>(D);
impl<D: Display> Display for HtmlEscaped<D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        struct Escaper<'a, 'b> {
            f: &'a mut Formatter<'b>,
        }
        impl fmt::Write for Escaper<'_, '_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                Display::fmt(&HtmlEscape(s), self.f)
            }
        }
        write!(Escaper { f }, "{}", self.0)
    }
}

/// Renders a Unix timestamp as a `<time datetime="…">…</time>` element.
/// `0` renders as `"N/A"` — we use it as a sentinel for "no value".
struct FmtTimestamp(i64);
impl Display for FmtTimestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return f.write_str("N/A");
        }
        let Ok(ts) = OffsetDateTime::from_unix_timestamp(self.0) else {
            return f.write_str("N/A");
        };
        Display::fmt(&Utc::from_offset(ts), f)
    }
}

/// Renders an "X ago" age for a `SystemTime`, or "N/A" when missing.
struct FmtMTimeAge(Option<SystemTime>);
impl Display for FmtMTimeAge {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(mt) => match mt.elapsed() {
                Ok(dur) => Display::fmt(&HumanFmt::Time(dur), f),
                Err(_) => f.write_str("in future"),
            },
            None => f.write_str("N/A"),
        }
    }
}

/// Combines a "last seen" timestamp with a staleness badge ("aging"/"stale").
struct FmtLastSeenHealth {
    last_seen: i64,
    now_epoch: i64,
}
impl Display for FmtLastSeenHealth {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&FmtTimestamp(self.last_seen), f)?;
        if self.last_seen <= 0 {
            return Ok(());
        }
        let age_days = self.now_epoch.saturating_sub(self.last_seen) / (24 * 60 * 60);
        if age_days > 30 {
            write!(
                f,
                " <span class=\"alert\" title=\"Stale: not seen in {age_days} days\">stale</span>"
            )
        } else if age_days > 7 {
            write!(
                f,
                " <span class=\"warn\" title=\"Aging: not seen in {age_days} days\">aging</span>"
            )
        } else {
            Ok(())
        }
    }
}

/// CSS class derived from a value's ratio against a limit.
#[derive(Clone, Copy)]
enum RatioClass {
    Normal,
    Warn,
    Alert,
}

impl RatioClass {
    /// Construct a `RatioClass` from a ratio of `value` to `limit`. Uses
    /// integer arithmetic only.
    #[must_use]
    const fn new(value: u64, limit: u64) -> Self {
        if limit == 0 {
            return Self::Normal;
        }
        // value/limit >= 0.80 ⇔ value*5 >= limit*4
        if value.saturating_mul(5) >= limit.saturating_mul(4) {
            Self::Alert
        } else if value.saturating_mul(2) >= limit {
            Self::Warn
        } else {
            Self::Normal
        }
    }

    #[must_use]
    const fn span_class(self) -> Option<&'static str> {
        match self {
            Self::Normal => None,
            Self::Warn => Some("warn"),
            Self::Alert => Some("alert"),
        }
    }
}

/// Wrap any `Display` value in a `<span class="warn|alert">` based on a class,
/// or render bare when normal.
struct Colorize<T: Display> {
    inner: T,
    class: RatioClass,
}
impl<T: Display> Display for Colorize<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.class.span_class() {
            Some(c) => write!(f, "<span class=\"{c}\">{}</span>", self.inner),
            None => Display::fmt(&self.inner, f),
        }
    }
}

/// Render `0` plain; render any positive value inside `<span class="alert">`.
struct AlertNonzero(u64);
impl Display for AlertNonzero {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            f.write_str("0")
        } else {
            write!(f, "<span class=\"alert\">{}</span>", self.0)
        }
    }
}

/// Render `0` plain; render any positive value inside `<span class="warn">`.
struct WarnNonzero(u64);
impl Display for WarnNonzero {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            f.write_str("0")
        } else {
            write!(f, "<span class=\"warn\">{}</span>", self.0)
        }
    }
}

/// Render `inner` as-is; if `predicate` is true, wrap it in `<span class="warn">`.
struct WarnIf<T: Display> {
    inner: T,
    predicate: bool,
}
impl<T: Display> WarnIf<T> {
    fn new(inner: T, predicate: bool) -> Self {
        Self { inner, predicate }
    }
}
impl<T: Display> Display for WarnIf<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.predicate {
            write!(f, "<span class=\"warn\">{}</span>", self.inner)
        } else {
            Display::fmt(&self.inner, f)
        }
    }
}

// ---------------------------------------------------------------------------
// Shared cell-value Display helpers — used across multiple section builders.
// ---------------------------------------------------------------------------

/// Render `Some(size)` as a human-readable size; render `None` as `fallback`.
struct OptSize {
    bytes: Option<u64>,
    fallback: &'static str,
}
impl Display for OptSize {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.bytes {
            Some(b) => Display::fmt(&HumanFmt::Size(b), f),
            None => f.write_str(self.fallback),
        }
    }
}

/// Render `Some(v)` via its `Display`; render `None` as `"unlimited"`.
struct OptOrUnlimited<T: Display>(Option<T>);
impl<T: Display> Display for OptOrUnlimited<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(v) => Display::fmt(v, f),
            None => f.write_str("unlimited"),
        }
    }
}

struct YesNo(bool);
impl Display for YesNo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0 { "Yes" } else { "No" })
    }
}

struct EnabledDisabled(bool);
impl Display for EnabledDisabled {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0 { "Enabled" } else { "Disabled" })
    }
}

/// Render an optional rate-limit configuration as `<size>/s` or `"None"`.
struct MinRate(Option<std::num::NonZero<usize>>);
impl Display for MinRate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(r) => write!(f, "{}/s", HumanFmt::Size(r.get() as u64)),
            None => f.write_str("None"),
        }
    }
}

/// Percentage with one decimal; `"N/A"` if denominator is non-positive.
struct Pct {
    num: i64,
    den: i64,
}
impl Display for Pct {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.den <= 0 {
            f.write_str("N/A")
        } else {
            #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
            let pct = self.num as f64 / self.den as f64 * 100.0;
            write!(f, "{pct:.1}%")
        }
    }
}

/// Cache hit ratio cell, e.g. `"83.7% (1234 / 1474)"`; `"N/A"` if total ≤ 0.
struct CacheHitRatio {
    hits: i64,
    total: i64,
}
impl Display for CacheHitRatio {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.total <= 0 {
            f.write_str("N/A")
        } else {
            #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
            let pct = self.hits as f64 / self.total as f64 * 100.0;
            write!(f, "{pct:.1}% ({} / {})", self.hits, self.total)
        }
    }
}

/// Bandwidth-window cell, e.g. `"4.2 GB served, 1.1 GB fetched (3.1 GB saved)"`.
/// `None` (e.g. on a query failure already logged at the boundary) renders
/// as `"N/A"`.
struct Window(Option<(i64, i64)>);
impl Display for Window {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some((downloaded, delivered)) => {
                let dl = u64::try_from(downloaded).unwrap_or(0);
                let del = u64::try_from(delivered).unwrap_or(0);
                let saved = del.saturating_sub(dl);
                write!(
                    f,
                    "{} served, {} fetched ({} saved)",
                    HumanFmt::Size(del),
                    HumanFmt::Size(dl),
                    HumanFmt::Size(saved),
                )
            }
            None => f.write_str("N/A"),
        }
    }
}

/// Disk-usage cell with optional quota; colourised by ratio when a quota is set.
struct DiskUsage {
    cache_size: u64,
    quota: Option<u64>,
}
impl Display for DiskUsage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.quota {
            None => Display::fmt(&HumanFmt::Size(self.cache_size), f),
            Some(q) => {
                #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
                let pct = self.cache_size as f64 / q as f64 * 100.0;
                let peak_bps = metrics::CACHE_QUOTA_UTIL_PEAK_BPS.get();
                #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
                let peak_pct = peak_bps as f64 / 100.0;
                let class = RatioClass::new(self.cache_size, q);
                let inner = format_args!(
                    "{} / {} ({pct:.1}%, peak {peak_pct:.1}%)",
                    HumanFmt::Size(self.cache_size),
                    HumanFmt::Size(q)
                );
                Display::fmt(
                    &Colorize {
                        inner: format_args!("{inner}"),
                        class,
                    },
                    f,
                )
            }
        }
    }
}

/// `write!` shorthand that panics on the (impossible) failure of in-memory `String` writes.
macro_rules! w {
    ($dst:expr, $($arg:tt)*) => {
        ::std::write!($dst, $($arg)*).expect("string formatting never fails")
    };
}

// ---------------------------------------------------------------------------
// Table builders — append rows directly via `write!`, no per-cell allocation.
// ---------------------------------------------------------------------------

struct Table {
    out: String,
}

impl Table {
    fn new(headers: &[&str]) -> Self {
        // Realistic dashboard tables (Mirrors, Origins) easily exceed 10 KB.
        // Pre-size to skip the reallocation chain.
        let mut out = String::with_capacity(16 * 1024);
        out.push_str("<table><thead><tr>");
        for h in headers {
            out.push_str("<th>");
            out.push_str(h);
            out.push_str("</th>");
        }
        out.push_str("</tr></thead><tbody>");
        Self { out }
    }

    fn start_row(&mut self) {
        self.out.push_str("<tr>");
    }

    fn cell(&mut self, value: impl Display) {
        w!(self.out, "<td>{value}</td>");
    }

    fn end_row(&mut self) {
        self.out.push_str("</tr>");
    }

    fn finish(mut self) -> String {
        self.out.push_str("</tbody></table>");
        self.out
    }
}

/// Append a row of cells, each formatted via `format_args!`.
macro_rules! tr {
    ($table:expr, $($cell:expr),* $(,)?) => {{
        let t = &mut $table;
        t.start_row();
        $( t.cell(format_args!("{}", $cell)); )*
        t.end_row();
    }};
}

/// Key-value details table with grid layout.
struct DetailsTable {
    out: String,
}

impl DetailsTable {
    fn new() -> Self {
        let mut out = String::with_capacity(1024);
        out.push_str("<table class=\"details\"><thead></thead><tbody>");
        Self { out }
    }

    fn row(&mut self, label: &'static str, value: impl Display) {
        w!(self.out, "<tr><td>{label}</td><td>{value}</td></tr>");
    }

    /// Like [`Self::row`], but renders the label cell with a `title` tooltip
    /// shown when the user hovers over it. The `tooltip` is interpolated
    /// directly into the `title=""` attribute without HTML-escaping; the
    /// `&'static str` bound prevents user-controlled values from sneaking
    /// in.
    fn row_tip(&mut self, label: &'static str, tooltip: &'static str, value: impl Display) {
        w!(
            self.out,
            "<tr><td title=\"{tooltip}\">{label}</td><td>{value}</td></tr>"
        );
    }

    fn finish(mut self) -> String {
        self.out.push_str("</tbody></table>");
        self.out
    }
}

/// Append a `<div class="section">` wrapping a titled HTML body.
fn write_section(out: &mut String, title: &'static str, body: &str) {
    w!(out, "<div class=\"section\"><h3>{title}</h3>{body}</div>");
}

/// Append a collapsible `<details>` section. Expanded by default unless empty.
fn write_collapsible_section(
    out: &mut String,
    title: &'static str,
    id: &'static str,
    row_count: usize,
    total_count: Option<usize>,
    body: &str,
) {
    let open_attr = if row_count > 0 { " open" } else { "" };
    let total_count_fmt = match total_count {
        Some(total) => format!(" / {total}"),
        None => String::new(),
    };
    w!(
        out,
        "<div class=\"section\"><details{open_attr}>\
         <summary><h3 id=\"{id}\">{title}</h3>\
         <span class=\"count\">{row_count}{total_count_fmt}</span></summary>\
         {body}</details></div>"
    );
}

/// Per-section error placeholder (so a single failed query doesn't kill the page).
fn write_section_error(out: &mut String, what: &'static str, err: &sqlx::Error) {
    w!(
        out,
        "<p class=\"section-error\">Failed to query {what}: {}</p>",
        HtmlEscape(&err.to_string()),
    );
}

// ---------------------------------------------------------------------------
// Page chrome
// ---------------------------------------------------------------------------

/// User-selected colour theme. `Auto` defers to `prefers-color-scheme`.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
enum Theme {
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
struct QueryOptions {
    theme: Theme,
    refresh_secs: Option<u32>,
}

/// `title` is interpolated into `<title>` without HTML-escaping. The
/// `&'static str` bound prevents user-controlled values from sneaking in.
fn build_page(title: &'static str, body_html: impl Display, options: QueryOptions) -> String {
    let theme_attr = options.theme.html_attr();
    let refresh = RefreshMeta(options.refresh_secs.unwrap_or(0));
    format!(
        "<!DOCTYPE html>\
         <html lang=\"en\"{theme_attr}>\
         <head>\
         <meta charset=\"utf-8\">\
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

fn parse_query(query: Option<&str>) -> QueryOptions {
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
enum Page {
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

fn build_nav_html(page: Page, options: QueryOptions) -> String {
    let mut html = String::with_capacity(512);
    html.push_str("<nav>");

    match page {
        Page::Dashboard { log_count } => {
            w!(
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
                ("#metrics-head", "Metrics"),
            ] {
                w!(html, "<a href=\"{href}\">{label}</a>");
            }
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
            match options.refresh_secs {
                Some(secs) => w!(html, "<a href=\"{target}\">Stop auto-refresh ({secs}s)</a>"),
                None => w!(html, "<a href=\"{target}\">Auto-refresh (30s)</a>"),
            }
        }
        Page::Logs => {
            w!(
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
    w!(
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

const CSS: &str = r#"
:root {
    color-scheme: light dark;
    --bg: light-dark(#f5f7fa, #1a1f2e);
    --fg: light-dark(#333, #d0d8e8);
    --nav-bg: light-dark(#fff, #242938);
    --nav-border: light-dark(#ddd, #3a4050);
    --section-bg: light-dark(#fff, #242938);
    --section-border: light-dark(#e0e0e0, #3a4050);
    --section-shadow: light-dark(0 1px 3px rgba(0,0,0,0.06), 0 1px 3px rgba(0,0,0,0.3));
    --h-fg: light-dark(#2c3e50, #c0d0e8);
    --h-accent: light-dark(#4a7bcc, #6fa3e8);
    --th-bg: light-dark(#4a7bcc, #3a5080);
    --th-fg: #fff;
    --td-border: light-dark(#eee, #2a3040);
    --row-hover-bg: light-dark(#f0f4ff, #2a3550);
    --details-key-fg: light-dark(#6b7b8d, #7a8a9d);
    --details-val-fg: light-dark(#2c3e50, #c0d0e8);
    --details-hover-bg: light-dark(#f0f6ff, #2a3550);
    --link: light-dark(#4a7bcc, #6fa3e8);
    --count-bg: light-dark(rgba(128,128,128,0.15), rgba(111,163,232,0.2));
    --footer-fg: light-dark(#888, #6a7a8a);
    --ok: light-dark(#2e8b3d, #6cc070);
    --warn: light-dark(#b87a18, #e6b855);
    --alert: light-dark(#c0392b, #e88a8a);
    --error-fg: light-dark(#b23a3a, #e88a8a);
}
:root[data-theme="light"] { color-scheme: light; }
:root[data-theme="dark"] { color-scheme: dark; }

html { scroll-behavior: smooth; }
details { margin-top: 4px; }
details > summary { cursor: pointer; list-style: none; }
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: "\25B6\FE0E"; display: inline-block; margin-right: 6px;
                             font-size: 0.7em; transition: transform 0.2s ease; }
details[open] > summary::before { transform: rotate(90deg); }
details > summary > h3 { display: inline; }
.count { display: inline-block; background: var(--count-bg); border-radius: 10px;
         padding: 1px 8px; font-size: 0.72em; font-weight: 600; vertical-align: middle;
         margin-left: 6px; min-width: 18px; text-align: center; line-height: 1.6; }
.section-error { color: var(--error-fg); font-size: 0.85em; margin: 4px 0; }
.ok { color: var(--ok); font-weight: 600; }
.warn { color: var(--warn); font-weight: 600; }
.alert { color: var(--alert); font-weight: 700; }
.muted { color: var(--details-key-fg); }
.dim { opacity: 0.4; }
time { border-bottom: 1px dotted transparent; transition: border-color 0.15s; }
time:hover { border-bottom-color: currentColor; }
table:not(.details) td { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
table:not(.details) td:hover { overflow: visible; white-space: normal; word-break: break-all;
                                max-width: none; }

* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
       color: var(--fg); background: var(--bg); line-height: 1.45; padding: 12px 16px; font-size: 13px; }
nav { background: var(--nav-bg); border-bottom: 1px solid var(--nav-border); padding: 8px 16px;
      margin: -12px -16px 12px; display: flex; gap: 18px; align-items: center; font-size: 13px; }
nav .spacer { flex: 1; }
nav a { color: var(--link); text-decoration: none; font-weight: 500; }
nav a:hover { text-decoration: underline; }
.section { background: var(--section-bg); border: 1px solid var(--section-border); border-radius: 5px;
           box-shadow: var(--section-shadow); padding: 10px 14px; margin-bottom: 10px; }
h3 { color: var(--h-fg); margin-bottom: 6px; border-bottom: 2px solid var(--h-accent);
     padding-bottom: 4px; font-size: 0.95em; }
table { width: 100%; border-collapse: collapse; margin-top: 6px; }
table.details { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                width: 100%; }
table.details thead { display: none; }
table.details tbody { display: contents; }
table.details tr { display: flex; flex-direction: column; padding: 4px 10px;
                   border-left: 3px solid transparent; }
table.details tr:hover { border-left-color: var(--h-accent); background: var(--details-hover-bg); }
table.details td { border: none; padding: 0; }
table.details td:first-child { font-size: 0.72em; text-transform: uppercase; letter-spacing: 0.03em;
                                color: var(--details-key-fg); font-weight: 600; }
table.details td:last-child { color: var(--details-val-fg); font-weight: 600; font-size: 0.92em; }
th { background: var(--th-bg); color: var(--th-fg); padding: 4px 10px; text-align: left; font-size: 0.85em; }
td { padding: 4px 10px; border-bottom: 1px solid var(--td-border); }
tr:hover td { background: var(--row-hover-bg); }
footer { color: var(--footer-fg); font-size: 0.82em; margin-top: 8px; }
footer hr { border: none; border-top: 1px solid var(--nav-border); margin-bottom: 6px; }
p { margin: 4px 0; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
h4.mini { font-size: 0.85em; margin: 4px 0; }
pre.log { white-space: pre-wrap; word-break: break-all; font-size: 0.85em;
          max-height: 80vh; overflow-y: auto; }
"#;

// ---------------------------------------------------------------------------
// Favicon — small inline SVG (box/archive icon), served at /favicon.svg
// (and /favicon.ico for browsers that auto-probe that path).
// ---------------------------------------------------------------------------

const FAVICON_SVG: &str = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'>\
<rect x='1' y='4' width='14' height='10' rx='1' fill='#4a7bcc'/>\
<rect x='0' y='2' width='16' height='4' rx='1' fill='#2c3e50'/>\
<rect x='6' y='6' width='4' height='2' rx='.5' fill='#fff'/>\
</svg>";

const FAVICON_LINK: &str = "<link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\">";

// ---------------------------------------------------------------------------
// Data gathering
// ---------------------------------------------------------------------------

struct DashboardData {
    mirror_html: String,
    mirror_rows: usize,
    origin_html: String,
    origin_rows: usize,
    client_html: String,
    client_rows: usize,
    uncacheable_html: String,
    uncacheable_rows: usize,
    top_packages_by_count_html: String,
    top_packages_by_count_rows: usize,
    top_packages_by_size_html: String,
    top_packages_by_size_rows: usize,
    daemon_status_html: String,
    configuration_html: String,
    maintenance_html: String,
    cache_stats_html: String,
    metrics_html: String,
    generation_start: Instant,
    /// Wall-clock time spent on the parallel DB-query block (mirrors,
    /// origins, clients, top packages, bandwidth) — excluding the FS work
    /// tracked separately in `fs_elapsed`.
    db_elapsed: std::time::Duration,
    /// Wall-clock time the mirror-section branch spent on FS work after
    /// the initial `get_mirrors_with_stats` query: the per-mirror directory
    /// walks plus the (small) `DIR_STATS_CACHE` prune. Subtracted from the
    /// total parallel time to produce `db_elapsed`.
    fs_elapsed: std::time::Duration,
}

/// Fetch the mirror list and walk each mirror's cache directory to populate
/// the Mirrors table. Returns the loaded mirrors (used downstream for the
/// Maintenance and Cache Statistics sections), the rendered table HTML,
/// the row count, the aggregated `DirStats`, and the wall-clock time spent
/// in the FS walks (separated from `db_elapsed` for the dashboard footer).
///
/// This is a free async fn rather than an inline `tokio::join!` branch so
/// rustc can prove `Send` for the future without tripping over higher-rank
/// lifetime auto-trait inference at the spawn site.
async fn build_mirror_section(
    database: &Database,
    now_epoch: i64,
) -> (
    Vec<MirrorStatEntry>,
    String,
    usize,
    DirStats,
    Option<u64>,
    std::time::Duration,
) {
    let config = global_config();

    let mirrors_result = database.get_mirrors_with_stats().await;
    let fs_start = Instant::now();
    let (mirrors, html, rows, agg) = match mirrors_result {
        Ok(m) => {
            let (html, rows, aggregate) =
                build_mirror_table(&m, now_epoch, &config.cache_directory).await;
            (m, html, rows, aggregate)
        }
        Err(err) => {
            error!("Failed to query mirrors:  {err}");
            let mut buf = String::new();
            write_section_error(&mut buf, "mirrors", &err);
            (Vec::new(), buf, 0, DirStats::default())
        }
    };

    // statvfs() can stall on slow/hung filesystems (NFS, FUSE, dying disks);
    // run it on the blocking pool so it cannot wedge the tokio worker.
    let free_disk_bytes = {
        let result =
            tokio::task::spawn_blocking(|| nix::sys::statvfs::statvfs(&config.cache_directory))
                .await
                .expect("task should not panic");

        let stat = result
            .inspect_err(|err| {
                warn_once_or_debug!(
                    "statvfs({}) failed:  {err}",
                    config.cache_directory.display()
                );
            })
            .ok();

        stat.and_then(|s| s.blocks_available().checked_mul(s.fragment_size()))
    };

    (
        mirrors,
        html,
        rows,
        agg,
        free_disk_bytes,
        fs_start.elapsed().into(),
    )
}

async fn gather_dashboard_data(appstate: &AppState) -> DashboardData {
    let start = Instant::now();

    let now = Utc::now();
    let now_epoch = now.inner().unix_timestamp();

    let day_cutoff = now_epoch.saturating_sub(24 * 60 * 60);
    let week_cutoff = now_epoch.saturating_sub(7 * 24 * 60 * 60);

    // Run all DB queries and the (DB+FS) mirror builder concurrently. The
    // mirror branch waits on `get_mirrors_with_stats`, then drives the
    // per-mirror directory scans; the rest of the dashboard's DB queries
    // proceed in parallel with that FS work instead of blocking on it.
    let parallel_start = Instant::now();
    let (
        (mirrors, mirror_html, mirror_rows, aggregate_dir_stats, free_disk_bytes, fs_elapsed),
        (origin_html, origin_rows),
        (client_html, client_rows),
        (top_packages_by_count_html, top_packages_by_count_rows),
        (top_packages_by_size_html, top_packages_by_size_rows),
        bandwidth_day_result,
        bandwidth_week_result,
    ) = tokio::join!(
        build_mirror_section(&appstate.database, now_epoch),
        build_origin_table(&appstate.database, now_epoch),
        build_client_table(&appstate.database, now_epoch),
        build_top_packages_table(&appstate.database, TopPackagesView::ByCount),
        build_top_packages_table(&appstate.database, TopPackagesView::BySize),
        appstate.database.get_bandwidth_since(day_cutoff),
        appstate.database.get_bandwidth_since(week_cutoff),
    );
    // "DB elapsed" approximates the wall-clock cost of the parallel block
    // attributable to non-FS work — i.e. everything except the mirror
    // directory scans, which are reported separately as `fs_elapsed`.
    let total_parallel: std::time::Duration = parallel_start.elapsed().into();
    let db_elapsed = total_parallel.saturating_sub(fs_elapsed);

    let (uncacheable_html, uncacheable_rows) = build_uncacheable_table();

    let rd = RUNTIMEDETAILS.get().expect("initialized in main()");
    let database_size = match tokio::fs::metadata(&rd.config.database_path).await {
        Ok(data) => Some(data.len()),
        Err(err) => {
            error!(
                "Failed to access database file `{}`:  {err}",
                rd.config.database_path.display()
            );
            None
        }
    };

    let active_mirror_downloads = appstate.active_downloads.len();
    let database_tx = DB_TASK_QUEUE_SENDER
        .get()
        .expect("Sender initialized in main_loop()");
    let db_channel_max = database_tx.max_capacity();
    let db_channel_in_flight = db_channel_max.saturating_sub(database_tx.capacity());
    let memory_stats = memory_stats::memory_stats();

    let https_mode = match rd.config.https_upgrade_mode {
        HttpsUpgradeMode::Auto => "Auto",
        HttpsUpgradeMode::Always => "Always",
        HttpsUpgradeMode::Never => "Never",
    };

    // Sample utilization so the peak metric reflects long idle stretches.
    let cache_size = global_cache_quota().current_size();
    global_cache_quota().sample_utilization_peak_with(cache_size);

    let next_cleanup_epoch = next_cleanup_epoch();

    let daemon_status_html = build_daemon_status_html(
        rd,
        now,
        memory_stats,
        database_size,
        active_mirror_downloads,
        db_channel_in_flight,
        db_channel_max,
    );

    let configuration_html = build_configuration_html(rd, https_mode);
    let maintenance_html = build_maintenance_html(&mirrors, now_epoch, next_cleanup_epoch);

    let cache_stats_html = build_cache_stats_html(
        &mirrors,
        bandwidth_day_result,
        bandwidth_week_result,
        &aggregate_dir_stats,
        cache_size,
        free_disk_bytes,
        rd,
    );

    let metrics_html = build_metrics_html();

    DashboardData {
        mirror_html,
        mirror_rows,
        origin_html,
        origin_rows,
        client_html,
        client_rows,
        uncacheable_html,
        uncacheable_rows,
        top_packages_by_count_html,
        top_packages_by_count_rows,
        top_packages_by_size_html,
        top_packages_by_size_rows,
        daemon_status_html,
        configuration_html,
        maintenance_html,
        cache_stats_html,
        metrics_html,
        generation_start: start,
        db_elapsed,
        fs_elapsed,
    }
}

fn build_daemon_status_html(
    rd: &RuntimeDetails,
    now: Utc,
    memory_stats: Option<memory_stats::MemoryStats>,
    database_size: Option<u64>,
    active_mirror_downloads: usize,
    db_channel_in_flight: usize,
    db_channel_max: usize,
) -> String {
    let start = Utc::from_offset(rd.start_time);

    let depth_class = RatioClass::new(db_channel_in_flight as u64, db_channel_max as u64);
    let peak = metrics::DB_QUEUE_DEPTH_PEAK.get();
    let peak_class = RatioClass::new(peak, db_channel_max as u64);

    let logstore = LOGSTORE.get().expect("initialized in main()");
    let log_entries = logstore.entries().len();
    let log_cap = rd.config.logstore_capacity.get();
    let log_class = RatioClass::new(log_entries as u64, log_cap as u64);

    let mut t = DetailsTable::new();
    t.row("Version", APP_VERSION);
    t.row("Features", get_features(false).replace('\n', " "));
    t.row(
        "Start Time",
        format_args!(
            "{start} (up {})",
            HumanFmt::Time((now.inner() - rd.start_time).unsigned_abs())
        ),
    );
    t.row("Current Time", now);
    {
        let phys = OptSize {
            bytes: memory_stats.map(|m| m.physical_mem as u64),
            fallback: "N/A",
        };
        let virt = OptSize {
            bytes: memory_stats.map(|m| m.virtual_mem as u64),
            fallback: "N/A",
        };
        t.row("Memory Usage", format_args!("{phys} ({virt} virtual)"));
        t.row(
            "Database Size",
            OptSize {
                bytes: database_size,
                fallback: "N/A",
            },
        );
    }
    t.row(
        "Connected Clients",
        format_args!(
            "{} (peak {})",
            connected_clients(),
            metrics::CONNECTED_CLIENTS_PEAK.get(),
        ),
    );
    t.row(
        "Active Upstream Downloads",
        format_args!(
            "{active_mirror_downloads} / {} (peak {})",
            OptOrUnlimited(rd.config.max_upstream_downloads),
            metrics::ACTIVE_UPSTREAM_DOWNLOADS_PEAK.get(),
        ),
    );
    t.row(
        "Active Client Downloads",
        format_args!(
            "{} (peak {})",
            active_client_downloads(),
            metrics::ACTIVE_CLIENT_DOWNLOADS_PEAK.get(),
        ),
    );
    t.row("Active HTTPS Tunnels", active_tunnels());
    t.row(
        "DB Command Queue (current / max, peak, sent, full-waits, full-transitions)",
        format_args!(
            "{} / {db_channel_max}, peak {}, sent {}, full-waits {}, full-transitions {}",
            Colorize {
                inner: db_channel_in_flight,
                class: depth_class,
            },
            Colorize {
                inner: peak,
                class: peak_class,
            },
            metrics::DB_COMMANDS_SENT.get(),
            WarnNonzero(metrics::DB_QUEUE_FULL_WAITS.get()),
            WarnNonzero(metrics::DB_QUEUE_FULL_TRANSITIONS.get()),
        ),
    );
    t.row(
        "Log Entries",
        format_args!(
            "{} / {log_cap}",
            Colorize {
                inner: log_entries,
                class: log_class,
            }
        ),
    );
    t.finish()
}

fn build_configuration_html(rd: &RuntimeDetails, https_mode: &str) -> String {
    let mut t = DetailsTable::new();
    t.row(
        "Bind Address + Port",
        format_args!("{} : {}", rd.config.bind_addr, rd.config.bind_port),
    );
    t.row(
        "Cache Directory",
        HtmlEscape(&rd.config.cache_directory.to_string_lossy()),
    );
    t.row(
        "Database Path",
        HtmlEscape(&rd.config.database_path.to_string_lossy()),
    );
    t.row(
        "HTTP Timeout",
        format_args!("{:.0}s", rd.config.http_timeout.as_secs_f64()),
    );
    t.row("HTTPS Upgrade Mode", https_mode);
    t.row(
        "HTTPS Tunnel",
        EnabledDisabled(rd.config.https_tunnel_enabled),
    );
    t.row("Min Download Rate", MinRate(rd.config.min_download_rate));
    t.row(
        "Rate Check Timeframe",
        format_args!("{}s", rd.config.rate_check_timeframe),
    );
    t.row(
        "Max Upstream Downloads",
        OptOrUnlimited(rd.config.max_upstream_downloads),
    );
    t.row(
        "Disk Quota",
        OptSize {
            bytes: rd.config.disk_quota.map(std::num::NonZero::get),
            fallback: "None",
        },
    );
    t.row("Buffer Size", HumanFmt::Size(rd.config.buffer_size as u64));
    t.row(
        "Mmap Threshold",
        HumanFmt::Size(rd.config.mmap_threshold.get()),
    );
    t.row(
        "Reject pdiff Requests",
        YesNo(rd.config.reject_pdiff_requests),
    );
    t.row(
        "Usage Retention",
        format_args!("{} days", rd.config.usage_retention_days),
    );
    t.row(
        "ByHash Retention",
        format_args!("{} days", rd.config.byhash_retention_days),
    );
    t.row("Log Buffer Capacity", rd.config.logstore_capacity);
    t.row("Allowed Mirrors", rd.config.allowed_mirrors.len());
    t.row("HTTP-Only Mirrors", rd.config.http_only_mirrors.len());
    t.row(
        "Allowed Tunnel Ports",
        rd.config.https_tunnel_allowed_ports.len(),
    );
    t.row(
        "Allowed Tunnel Mirrors",
        rd.config.https_tunnel_allowed_mirrors.len(),
    );
    t.row("Aliases", rd.config.aliases.len());
    t.row("Allowed Clients", rd.config.allowed_proxy_clients.len());
    t.finish()
}

fn build_maintenance_html(
    mirrors: &[MirrorStatEntry],
    now_epoch: i64,
    next_cleanup_epoch: i64,
) -> String {
    /// Renders `<timestamp> (<rel>)` if epoch > 0, otherwise just `FmtTimestamp` (= "N/A").
    struct EpochAndRel {
        epoch: i64,
        rel: std::time::Duration,
        rel_label: &'static str,
    }
    impl Display for EpochAndRel {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            Display::fmt(&FmtTimestamp(self.epoch), f)?;
            if self.epoch != 0 {
                write!(f, " ({} {})", HumanFmt::Time(self.rel), self.rel_label)?;
            }
            Ok(())
        }
    }

    let last_cleanup_epoch = mirrors.iter().map(|m| m.last_cleanup).max().unwrap_or(0);
    let cleanup_interval = HumanFmt::Time(std::time::Duration::from_secs(CLEANUP_INTERVAL_SECS));
    // Only meaningful when last_cleanup_epoch != 0; EpochAndRel ignores it otherwise,
    // so don't fabricate a multi-decade duration from the 0 sentinel.
    let last_rel = if last_cleanup_epoch == 0 {
        std::time::Duration::ZERO
    } else {
        std::time::Duration::from_secs(
            u64::try_from(now_epoch.saturating_sub(last_cleanup_epoch)).unwrap_or(0),
        )
    };
    let next_rel = std::time::Duration::from_secs(
        u64::try_from(next_cleanup_epoch.saturating_sub(now_epoch)).unwrap_or(0),
    );

    let mut t = DetailsTable::new();
    t.row(
        "Last Cleanup",
        EpochAndRel {
            epoch: last_cleanup_epoch,
            rel: last_rel,
            rel_label: "ago",
        },
    );
    t.row("Cleanup Interval", cleanup_interval);
    t.row(
        "Next Cleanup",
        EpochAndRel {
            epoch: next_cleanup_epoch,
            rel: next_rel,
            rel_label: "from now",
        },
    );
    t.finish()
}

fn build_cache_stats_html(
    mirrors: &[MirrorStatEntry],
    bandwidth_day_result: Result<(i64, i64), sqlx::Error>,
    bandwidth_week_result: Result<(i64, i64), sqlx::Error>,
    aggregate: &DirStats,
    cache_size: u64,
    free_disk_bytes: Option<u64>,
    rd: &RuntimeDetails,
) -> String {
    let total_downloaded: i64 = mirrors.iter().map(|m| m.total_download_size).sum();
    let total_delivered: i64 = mirrors.iter().map(|m| m.total_delivery_size).sum();
    let bandwidth_saved = total_delivered.saturating_sub(total_downloaded);

    let total_download_count: i64 = mirrors.iter().map(|m| m.download_count).sum();
    let total_delivery_count: i64 = mirrors.iter().map(|m| m.delivery_count).sum();
    let cache_hits = total_delivery_count.saturating_sub(total_download_count);

    let total_downloaded_u = u64::try_from(total_downloaded).unwrap_or(0);
    let total_delivered_u = u64::try_from(total_delivered).unwrap_or(0);
    let bandwidth_saved_u = u64::try_from(bandwidth_saved).unwrap_or(0);

    let uncacheable_count = get_uncacheables().read().len();

    let bandwidth_day = match bandwidth_day_result {
        Ok(v) => Some(v),
        Err(err) => {
            error!("Failed to query bandwidth window:  {err}");
            None
        }
    };
    let bandwidth_week = match bandwidth_week_result {
        Ok(v) => Some(v),
        Err(err) => {
            error!("Failed to query bandwidth window:  {err}");
            None
        }
    };

    let mut t = DetailsTable::new();
    t.row("Fetched from Upstream", HumanFmt::Size(total_downloaded_u));
    t.row("Served to Clients", HumanFmt::Size(total_delivered_u));
    t.row("Bandwidth Saved", HumanFmt::Size(bandwidth_saved_u));
    t.row(
        "Bandwidth Savings",
        Pct {
            num: bandwidth_saved,
            den: total_delivered,
        },
    );
    t.row(
        "Cache Hit Ratio (persisted)",
        CacheHitRatio {
            hits: cache_hits,
            total: total_delivery_count,
        },
    );
    t.row("Bandwidth (last 24h)", Window(bandwidth_day));
    t.row("Bandwidth (last 7d)", Window(bandwidth_week));
    t.row("Uncacheable Resources", uncacheable_count);
    t.row(
        "Cached Files",
        format_args!(
            "{} debs / {} metadata / {} by-hash",
            aggregate.deb_files, aggregate.metadata_files, aggregate.byhash_files
        ),
    );
    t.row("Oldest Cached File", FmtMTimeAge(aggregate.oldest_mtime));
    t.row("Newest Cached File", FmtMTimeAge(aggregate.newest_mtime));
    t.row(
        "Total Disk Usage",
        DiskUsage {
            cache_size,
            quota: rd.config.disk_quota.map(std::num::NonZero::get),
        },
    );

    let free_disk_space = if let Some(free) = free_disk_bytes {
        let quota = rd.config.disk_quota.map(std::num::NonZero::get);
        let remaining_quota = quota.map(|q| q.saturating_sub(cache_size));
        let class = match remaining_quota {
            Some(rq) if free < rq => RatioClass::Warn,
            _ => RatioClass::Normal,
        };
        Colorize {
            inner: format_args!("{}", HumanFmt::Size(free)),
            class,
        }
    } else {
        Colorize {
            inner: format_args!("N/A"),
            class: RatioClass::Alert,
        }
    };

    t.row("Free Disk Space", free_disk_space);

    t.finish()
}

fn build_metrics_html() -> String {
    struct OptPctSuffix {
        num: u64,
        total: u64,
    }
    impl Display for OptPctSuffix {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            if self.total == 0 {
                Ok(())
            } else {
                #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
                let pct = self.num as f64 / self.total as f64 * 100.0;
                write!(f, " ({pct:.1}%)")
            }
        }
    }

    struct OptReqPerConn {
        requests: u64,
        connections: u64,
    }
    impl Display for OptReqPerConn {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            if self.connections == 0 {
                Ok(())
            } else {
                #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
                let r = self.requests as f64 / self.connections as f64;
                write!(f, " ({r:.2} req/conn)")
            }
        }
    }

    let proc_cache_hits = metrics::CACHE_HITS.get();
    let proc_cache_misses = metrics::CACHE_MISSES.get();
    let proc_cache_lookups = proc_cache_hits + proc_cache_misses;
    let requests_total = metrics::REQUESTS_TOTAL.get();
    let webui_requests = metrics::WEBUI_REQUESTS.get();
    let connections_accepted = metrics::CONNECTIONS_ACCEPTED.get();

    let mut t = DetailsTable::new();
    t.row_tip(
        "Total Requests (Web UI Requests) / Connections Accepted",
        "Total HTTP requests and Web interface requests handled and TCP connections accepted from clients since the daemon started.",
        format_args!(
            "{requests_total} ({webui_requests}) / {connections_accepted}{}",
            OptReqPerConn {
                requests: requests_total,
                connections: connections_accepted,
            }
        ),
    );
    t.row_tip(
        "Cache Hits / Misses",
        "Cache lookups for permanent (non-volatile) resources that found a usable file vs. those that did not.",
        format_args!(
            "{proc_cache_hits} / {proc_cache_misses}{}",
            OptPctSuffix {
                num: proc_cache_hits,
                total: proc_cache_lookups,
            }
        ),
    );
    {
        let refetched = metrics::VOLATILE_REFETCHED.get();
        let refetched_uptodate = metrics::VOLATILE_REFETCHED_UPTODATE.get();
        let refetched_outofdate = metrics::VOLATILE_REFETCHED_OUTOFDATE.get();
        t.row_tip(
            "Volatile Hits / Refetches (up-to-date / out-of-date)",
            "Volatile-resource (Release/Packages/Translation/...) cache hits within the freshness window vs. revalidations against upstream, split into still up-to-date (304) and changed (200).",
            format_args!(
                "{} / {} ({} / {})",
                metrics::VOLATILE_HIT.get(),
                WarnIf::new(refetched, refetched != refetched_uptodate + refetched_outofdate),
                refetched_uptodate,
                refetched_outofdate,
            ),
        );
    }
    {
        let status_2xx = metrics::CLIENT_STATUS_2XX.get();
        let status_200 = metrics::CLIENT_STATUS_200.get();
        let status_206 = metrics::CLIENT_STATUS_206.get();
        let status_3xx = metrics::CLIENT_STATUS_3XX.get();
        let status_304 = metrics::CLIENT_STATUS_304.get();
        t.row_tip(
            "Client Status (2xx / 3xx / 4xx / 5xx / other)",
            "Response status classes returned to clients.",
            format_args!(
                "{} / {} / {} / {} / {}",
                WarnIf::new(status_2xx, status_2xx != status_200 + status_206),
                WarnIf::new(status_3xx, status_3xx != status_304),
                metrics::CLIENT_STATUS_4XX.get(), // do not warn due to pdiff rejections, and 404 web interface requests
                AlertNonzero(metrics::CLIENT_STATUS_5XX.get()),
                WarnNonzero(metrics::CLIENT_STATUS_OTHER.get()),
            ),
        );
        t.row_tip(
            "Client 200 OK / 206 Partial Content / 304 Not Modified / 410 Gone / 416 Range Not Satisfiable",
            "Selected response status codes returned to clients.",
            format_args!(
                "{} / {} / {} / {} / {}",
                status_200,
                status_206,
                status_304,
                metrics::CLIENT_STATUS_410.get(),
                metrics::CLIENT_STATUS_416.get(),
            ),
        );
    }
    {
        let status_2xx = metrics::UPSTREAM_STATUS_2XX.get();
        let status_3xx = metrics::UPSTREAM_STATUS_3XX.get();
        let status_200 = metrics::UPSTREAM_STATUS_200.get();
        let status_301 = metrics::UPSTREAM_STATUS_301.get();
        let status_302 = metrics::UPSTREAM_STATUS_302.get();
        let status_304 = metrics::UPSTREAM_STATUS_304.get();
        t.row_tip(
            "Upstream Status (2xx / 3xx / 4xx / 5xx / other)",
            "Response status classes received from upstream mirrors.",
            format_args!(
                "{} / {} / {} / {} / {}",
                WarnIf::new(status_2xx, status_2xx != status_200),
                WarnIf::new(
                    status_3xx,
                    status_3xx != status_301 + status_302 + status_304
                ),
                WarnNonzero(metrics::UPSTREAM_STATUS_4XX.get()),
                AlertNonzero(metrics::UPSTREAM_STATUS_5XX.get()),
                WarnNonzero(metrics::UPSTREAM_STATUS_OTHER.get()),
            ),
        );
        t.row_tip(
            "Upstream 200 OK / 301 Moved Permanently / 302 Found / 304 Not Modified",
            "Selected response status codes received from upstream mirrors.",
            format_args!("{status_200} / {status_301} / {status_302} / {status_304}"),
        );
    }
    t.row_tip(
        "Rejected Requests (pdiff / unsafe path / quota hit)",
        "Client requests rejected before serving: pdiff requests, requests with unsafe paths, and downloads denied because the configured disk quota is exhausted.",
        format_args!(
            "{} / {} / {}",
            metrics::PDIFF_REJECTED.get(),
            WarnNonzero(metrics::UNSAFE_PATH_REJECTED.get()),
            WarnNonzero(metrics::DOWNLOAD_REJECTED_QUOTA.get())
        ),
    );
    t.row_tip(
        "Uncacheable Evictions",
        "Recent uncacheable (host, path) entries evicted from the in-memory ring buffer because of overflow.",
        format_args!(
            "{}",
            WarnNonzero(
                metrics::UNCACHEABLE
                    .get()
                    .saturating_sub(UNCACHEABLES_MAX.get() as u64)
            )
        ),
    );
    t.row_tip(
        "Client Disconnected Mid-Body",
        "Clients that disconnected before the response body was fully delivered.",
        metrics::CLIENT_DISCONNECTED_MID_BODY.get(),
    );
    t.row_tip(
        "Rate-Limit Cancellations (upstream / client)",
        "Transfers cancelled because the configured minimum download rate was not met on the upstream or client side.",
        format_args!(
            "{} / {}",
            metrics::RATE_LIMIT_UPSTREAM.get(),
            metrics::RATE_LIMIT_CLIENT.get(),
        ),
    );
    t.row_tip(
        "Upstream Connect (splice) Failures TCP / TLS",
        "Splice-path upstream connection failures, separated into TCP setup and TLS handshake failures.",
        format_args!(
            "{} / {}",
            WarnNonzero(metrics::UPSTREAM_CONNECT_FAILED.get()),
            WarnNonzero(metrics::UPSTREAM_TLS_FAILED.get())
        ),
    );
    t.row_tip(
        "Delivery (mmap) requests / bytes",
        "Cached responses served via memory-mapped file I/O.",
        format_args!(
            "{} / {}",
            metrics::REQUESTS_MMAP.get(),
            HumanFmt::Size(metrics::BYTES_SERVED_MMAP.get())
        ),
    );
    t.row_tip(
        "Delivery (sendfile) requests / bytes",
        "Cached responses served via Linux sendfile(2) zero-copy.",
        format_args!(
            "{} / {}",
            metrics::REQUESTS_SENDFILE.get(),
            HumanFmt::Size(metrics::BYTES_SERVED_SENDFILE.get())
        ),
    );
    t.row_tip(
        "Delivery (splice) requests / bytes",
        "Responses streamed from upstream to client via Linux splice(2) zero-copy without ever touching userspace.",
        format_args!(
            "{} / {}",
            metrics::REQUESTS_SPLICE.get(),
            HumanFmt::Size(metrics::BYTES_SERVED_SPLICE.get())
        ),
    );
    t.row_tip(
        "Delivery (copy) requests / bytes",
        "Cached responses served via plain userspace read/write copy.",
        format_args!(
            "{} / {}",
            metrics::REQUESTS_COPY.get(),
            HumanFmt::Size(metrics::BYTES_SERVED_COPY.get())
        ),
    );
    t.row_tip(
        "Delivery (channel, late-joiner) requests / bytes",
        "Late-joiner responses streamed via the hyper ChannelBody path while an upstream download is still in flight.",
        format_args!(
            "{} / {}",
            metrics::REQUESTS_CHANNEL.get(),
            HumanFmt::Size(metrics::BYTES_SERVED_CHANNEL.get())
        ),
    );
    t.row_tip(
        "Delivery (passthrough, uncached) requests / bytes",
        "Uncached responses proxied through to clients without storing anything on disk.",
        format_args!(
            "{} / {}",
            metrics::REQUESTS_PASSTHROUGH.get(),
            HumanFmt::Size(metrics::BYTES_SERVED_PASSTHROUGH.get())
        ),
    );
    t.row_tip(
        "Clients Demoted (splice \u{2192} file-serve)",
        "Splice clients demoted to ordinary cached-file delivery, e.g. because they joined an in-progress download.",
        metrics::CLIENTS_DEMOTED.get(),
    );
    t.row_tip(
        "Upstream Bytes Downloaded",
        "Total bytes fetched from upstream mirrors.",
        format_args!(
            "{}",
            HumanFmt::Size(metrics::BYTES_DOWNLOADED_UPSTREAM.get())
        ),
    );
    t.row_tip(
        "Late Joiners (coalesced, peak per download)",
        "Clients that joined an already in-progress download and shared its data, plus the peak number of concurrent late joiners on a single download.",
        format_args!(
            "{} (peak {})",
            metrics::LATE_JOINERS_TOTAL.get(),
            metrics::LATE_JOINER_PEAK_PER_DOWNLOAD.get(),
        ),
    );
    t.row_tip(
        "Upstream Pool (reused / new, miss: empty / dead / failed, return-evicted)",
        "Upstream connection pool counters: reused vs. newly opened connections, miss reasons (pool empty, peer-closed connection, failed health check), and connections evicted when returned.",
        format_args!(
            "{} / {}, miss: {} / {} / {}, return-evicted {}",
            metrics::POOL_REUSED.get(),
            metrics::POOL_NEW.get(),
            metrics::POOL_MISS_EMPTY.get(),
            metrics::POOL_MISS_DEAD.get(),
            metrics::POOL_MISS_FAILED.get(),
            metrics::POOL_RETURN_EVICTED.get(),
        ),
    );
    t.row_tip(
        "HTTP Timeouts (upstream connect / upstream read / client)",
        "Configured-timeout firings on upstream connect, upstream read, and client read paths.",
        format_args!(
            "{} / {} / {}",
            metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.get(),
            metrics::HTTP_TIMEOUT_UPSTREAM_READ.get(),
            metrics::HTTP_TIMEOUT_CLIENT.get(),
        ),
    );
    t.row_tip(
        "Upstream Retries",
        "Upstream requests retried after a transient failure.",
        metrics::UPSTREAM_RETRIES.get(),
    );
    t.row_tip(
        "Upstream Download Cap (transitions / rejections)",
        "Concurrent-upstream-download cap state transitions and downloads rejected because the cap was reached.",
        format_args!(
            "{} / {}",
            metrics::UPSTREAM_DOWNLOAD_CAP_TRANSITIONS.get(),
            metrics::UPSTREAM_DOWNLOAD_REJECTED_CAP.get(),
        ),
    );
    t.row_tip(
        "Downloads Aborted",
        "Active upstream downloads aborted before completion.",
        metrics::DOWNLOADS_ABORTED.get(),
    );
    {
        let attempted = metrics::HTTPS_UPGRADE_ATTEMPTED.get();
        let succeeded = metrics::HTTPS_UPGRADE_SUCCEEDED.get();
        let failed = metrics::HTTPS_UPGRADE_FAILED.get();
        t.row_tip(
        "HTTPS Upgrade (attempted / succeeded / failed, scheme-cache removed)",
        "HTTPS upgrade attempts on plain-HTTP requests, plus removals from the per-host scheme cache.",
        format_args!(
            "{} / {succeeded} / {failed}, {}",
            WarnIf::new(attempted, attempted != succeeded + failed),
            metrics::SCHEME_CACHE_REMOVED.get(),
        ),
    );
    }
    t.row_tip(
        "Authorization Rejected (mirror / client / tunnel-mirror)",
        "Requests rejected by mirror, client, or HTTPS-tunnel-mirror authorization rules.",
        format_args!(
            "{} / {} / {}",
            metrics::AUTHZ_REJECTED_MIRROR.get(),
            metrics::AUTHZ_REJECTED_CLIENT.get(),
            metrics::AUTHZ_REJECTED_TUNNEL_MIRROR.get(),
        ),
    );
    t.row_tip(
        "DB Operation Failures",
        "SQLite operations that failed.",
        AlertNonzero(metrics::DB_OPERATION_FAILED.get()),
    );
    t.row_tip(
        "Cache Reconcile (events / bytes repaired)",
        "Cache reconciliation events that repaired on-disk size accounting and the bytes corrected.",
        format_args!(
            "{} / {}",
            metrics::RECONCILE_EVENTS.get(),
            HumanFmt::Size(metrics::RECONCILE_BYTES_REPAIRED.get()),
        ),
    );
    t.row_tip(
        "Cache Size Corruption",
        "Cache files whose recorded size disagreed with the actual size on disk.",
        AlertNonzero(metrics::CACHE_SIZE_CORRUPTION.get()),
    );
    t.row_tip(
        "Upstream Protocol Violations",
        "Mirror responses that broke the HTTP contract: body over- or under-ran the announced Content-Length, missing or mismatched Content-Range, missing Content-Length on a fetch.",
        WarnNonzero(metrics::UPSTREAM_PROTOCOL_VIOLATION.get()),
    );
    t.row_tip(
        "Upstream (hyper) Failures connect / body",
        "Hyper-backend upstream failures: pre-response (connect/TLS/request) and post-response body-stream errors. Splice-path equivalents are reported separately.",
        format_args!(
            "{} / {}",
            WarnNonzero(metrics::UPSTREAM_HYPER_CONNECT_FAILED.get()),
            WarnNonzero(metrics::UPSTREAM_HYPER_BODY_ERR.get()),
        ),
    );
    t.row_tip(
        "Cache I/O Failures",
        "Local cache stat/open errors that produced a 5xx response to the client.",
        AlertNonzero(metrics::CACHE_IO_FAILURE.get()),
    );
    t.row_tip(
        "Logstore Evictions",
        "Important-log ring-buffer evictions due to overflow.",
        WarnNonzero(metrics::LOGSTORE_EVICTIONS.get()),
    );
    t.row_tip(
        "kTLS RX Enabled / permanent Fallbacks / transient Fallbacks",
        "Connections where kernel-TLS receive offload was enabled vs. fell back to userspace TLS, either permanently or for a single record.",
        format_args!(
            "{} / {} / {}",
            metrics::KTLS_RX_ENABLED.get(),
            AlertNonzero(metrics::KTLS_FALLBACK_PERMANENT.get()),
            WarnNonzero(metrics::KTLS_FALLBACK_TRANSIENT.get()),
        ),
    );
    t.row_tip(
        "Cleanup Evictions (total) / Bytes Reclaimed (total)",
        "Background cache-cleanup totals across all runs since the daemon started.",
        format_args!(
            "{} / {}",
            metrics::CLEANUP_EVICTIONS.get(),
            HumanFmt::Size(metrics::CLEANUP_BYTES_RECLAIMED.get())
        ),
    );
    t.row_tip(
        "Last Cleanup",
        "Duration, files removed and bytes reclaimed by the most recent cache-cleanup run.",
        format_args!(
            "{}s, {} files, {}",
            metrics::LAST_CLEANUP_DURATION_SECS.get(),
            metrics::LAST_CLEANUP_FILES_REMOVED.get(),
            HumanFmt::Size(metrics::LAST_CLEANUP_BYTES_RECLAIMED.get())
        ),
    );
    t.row_tip(
        "Tunnel Connects",
        "HTTPS-tunnel CONNECT requests accepted.",
        metrics::TUNNEL_CONNECTS_TOTAL.get(),
    );
    t.row_tip(
        "Tunnel Bytes (client \u{2192} upstream / upstream \u{2192} client)",
        "Bytes copied through completed CONNECT tunnels in each direction. Only counted when the tunnel exits cleanly.",
        format_args!(
            "{} / {}",
            HumanFmt::Size(metrics::BYTES_TUNNELED_CLIENT_TO_UPSTREAM.get()),
            HumanFmt::Size(metrics::BYTES_TUNNELED_UPSTREAM_TO_CLIENT.get()),
        ),
    );
    t.row_tip(
        "Tunnel Rejected (policy / capacity)",
        "HTTPS-tunnel CONNECT requests rejected by policy or capacity limits.",
        format_args!(
            "{} / {}",
            metrics::TUNNEL_REJECTED_POLICY.get(),
            metrics::TUNNEL_REJECTED_CAPACITY.get()
        ),
    );
    t.finish()
}

// ---------------------------------------------------------------------------
// Page builders
// ---------------------------------------------------------------------------

fn build_dashboard_page(data: &DashboardData, options: QueryOptions) -> String {
    let log_count = LOGSTORE
        .get()
        .expect("initialized in main()")
        .entries()
        .len();
    let nav = build_nav_html(Page::Dashboard { log_count }, options);

    let mut body = String::with_capacity(8 * 1024);
    body.push_str(&nav);

    write_section(&mut body, "Daemon Status", &data.daemon_status_html);
    write_section(&mut body, "Configuration", &data.configuration_html);
    write_section(&mut body, "Maintenance", &data.maintenance_html);
    write_section(&mut body, "Cache Statistics", &data.cache_stats_html);

    // Metrics: long & diagnostic; collapsed by default.
    w!(
        body,
        "<div class=\"section\"><details>\
         <summary><h3 id=\"metrics-head\">Metrics</h3></summary>\
         {}</details></div>",
        data.metrics_html,
    );

    write_collapsible_section(
        &mut body,
        "Mirrors",
        "mirrors-head",
        data.mirror_rows,
        None,
        &data.mirror_html,
    );
    write_collapsible_section(
        &mut body,
        "Origins",
        "origins-head",
        data.origin_rows,
        None,
        &data.origin_html,
    );
    write_collapsible_section(
        &mut body,
        "Clients",
        "clients-head",
        data.client_rows,
        None,
        &data.client_html,
    );

    let total_package_rows = data
        .top_packages_by_count_rows
        .max(data.top_packages_by_size_rows);
    let mut top_packages_body = String::with_capacity(
        data.top_packages_by_count_html.len() + data.top_packages_by_size_html.len() + 128,
    );
    w!(
        top_packages_body,
        "<div class=\"grid-2\">\
         <div><h4 class=\"mini\">By Delivery Count</h4>{}</div>\
         <div><h4 class=\"mini\">By Total Size</h4>{}</div>\
         </div>",
        data.top_packages_by_count_html,
        data.top_packages_by_size_html,
    );
    write_collapsible_section(
        &mut body,
        "Top Packages",
        "packages-head",
        total_package_rows,
        None,
        &top_packages_body,
    );

    write_collapsible_section(
        &mut body,
        "Uncacheables",
        "uncacheables-head",
        data.uncacheable_rows,
        Some(UNCACHEABLES_MAX.get()),
        &data.uncacheable_html,
    );

    w!(
        body,
        "<footer><hr><p>All dates are in UTC.&nbsp;&nbsp;&nbsp;--&nbsp;&nbsp;&nbsp;\
         Generated in {} (db {}, disk {}).</p></footer>",
        HumanFmt::Time(data.generation_start.elapsed().into()),
        HumanFmt::Time(data.db_elapsed),
        HumanFmt::Time(data.fs_elapsed),
    );

    build_page("apt-cacher-rs web interface", body, options)
}

/// Content-Security-Policy applied to every HTML page.
///
/// `style-src 'self'` permits the linked `/style.css` but blocks any `<style>`
/// block or inline `style="..."` attribute. If a future change wants inline
/// styles, it has to either move them into the stylesheet or extend the CSP —
/// silent CSP rejections are easy to miss when only some users have devtools
/// open.
pub(crate) const HTML_CSP: &str = "default-src 'none'; style-src 'self'; img-src 'self' data:; \
     base-uri 'none'; form-action 'none'";

/// A response from the local web interface.
///
/// Carries enough information for the hyper backend to construct a
/// `Response<ProxyCacheBody>` and for the sendfile backend to format the wire
/// bytes by hand using `format!` (see `sendfile_conn::write_webui_response`).
/// The two paths derive their headers from the same `WebResponse`, so clients
/// see the same response regardless of which backend served the request.
pub(crate) struct WebResponse {
    pub(crate) status: StatusCode,
    pub(crate) body: bytes::Bytes,
    pub(crate) kind: WebResponseKind,
}

pub(crate) enum WebResponseKind {
    /// Dashboard or logs page; served with `no-store` cache and full
    /// security headers.
    Html,
    /// Static asset (CSS/SVG) with long-lived caching and `nosniff`.
    Static { content_type: &'static str },
    /// Plain-text error response.
    Error,
}

impl WebResponse {
    fn html(html: String) -> Self {
        Self {
            status: StatusCode::OK,
            body: bytes::Bytes::from(html),
            kind: WebResponseKind::Html,
        }
    }

    fn static_resource(content_type: &'static str, content: &'static str) -> Self {
        Self {
            status: StatusCode::OK,
            body: bytes::Bytes::from_static(content.as_bytes()),
            kind: WebResponseKind::Static { content_type },
        }
    }

    fn not_found(msg: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            body: bytes::Bytes::from_static(msg.as_bytes()),
            kind: WebResponseKind::Error,
        }
    }

    pub(crate) fn content_type(&self) -> &'static str {
        match self.kind {
            WebResponseKind::Html => "text/html; charset=utf-8",
            WebResponseKind::Static { content_type } => content_type,
            WebResponseKind::Error => "text/plain; charset=utf-8",
        }
    }

    /// Render this response as a `Response<ProxyCacheBody>` for the hyper path.
    pub(crate) fn into_hyper_response(self) -> Response<ProxyCacheBody> {
        let mut builder = Response::builder()
            .status(self.status)
            .header(SERVER, APP_NAME)
            .header(DATE, format_http_date())
            .header(CONNECTION, "keep-alive")
            .header(CONTENT_TYPE, self.content_type());
        match self.kind {
            WebResponseKind::Html => {
                builder = builder
                    .header(CACHE_CONTROL, "no-store")
                    .header(CONTENT_SECURITY_POLICY, HTML_CSP)
                    .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
                    .header(X_FRAME_OPTIONS, "DENY")
                    .header("X-Robots-Tag", "noindex")
                    .header(REFERRER_POLICY, "no-referrer");
            }
            WebResponseKind::Static { .. } => {
                builder = builder
                    .header(CACHE_CONTROL, "public, max-age=86400")
                    .header(X_CONTENT_TYPE_OPTIONS, "nosniff");
            }
            WebResponseKind::Error => {}
        }
        builder
            .body(full_body(self.body))
            .expect("HTTP response is valid")
    }
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

#[must_use]
pub(crate) async fn serve_web_interface(uri: &http::Uri, appstate: &AppState) -> WebResponse {
    metrics::WEBUI_REQUESTS.increment();

    let location = uri.path();
    debug!("Requested local web interface resource `{location}`");

    let options = parse_query(uri.query());

    let response = match location {
        "/" => serve_dashboard(appstate, options).await,
        "/logs" => serve_logs(options).await,
        "/style.css" => WebResponse::static_resource("text/css; charset=utf-8", CSS),
        "/favicon.svg" | "/favicon.ico" => {
            WebResponse::static_resource("image/svg+xml", FAVICON_SVG)
        }
        _ => {
            debug!("Unknown local web interface resource: {uri:?}");
            WebResponse::not_found("Local interface resource not available")
        }
    };

    trace!(
        "Local web interface response: status={}, content-type={}, body={} bytes",
        response.status,
        response.content_type(),
        response.body.len()
    );

    response
}

async fn serve_dashboard(appstate: &AppState, options: QueryOptions) -> WebResponse {
    let data = gather_dashboard_data(appstate).await;
    let html = build_dashboard_page(&data, options);
    WebResponse::html(html)
}

// ---------------------------------------------------------------------------
// Per-mirror directory scan
// ---------------------------------------------------------------------------

/// TTL for cached per-mirror directory-scan results.
const DIR_STATS_TTL_SECS: u64 = 60;

/// Maximum number of mirror directory walks running concurrently when the
/// `DIR_STATS_CACHE` is cold. Bounds disk fan-out and FD usage.
const DIR_SCAN_CONCURRENCY: usize = 8;

#[derive(Clone, Copy, Default)]
struct DirStats {
    files: usize,
    size: u64,
    byhash_files: usize,
    /// Files whose extension is `.deb`. Disjoint from `metadata_files`,
    /// orthogonal to `byhash_files`.
    deb_files: usize,
    /// Files whose extension is anything other than `.deb` — Packages,
    /// Release, by-hash entries, etc. Disjoint from `deb_files`. Together
    /// they sum to `files`.
    metadata_files: usize,
    max_file_size: u64,
    oldest_mtime: Option<SystemTime>,
    newest_mtime: Option<SystemTime>,
}

impl DirStats {
    fn merge(&mut self, other: Self) {
        let Self {
            files,
            size,
            byhash_files,
            deb_files,
            metadata_files,
            max_file_size,
            oldest_mtime,
            newest_mtime,
        } = other;

        self.files += files;
        self.size += size;
        self.byhash_files += byhash_files;
        self.deb_files += deb_files;
        self.metadata_files += metadata_files;
        self.max_file_size = self.max_file_size.max(max_file_size);
        self.oldest_mtime = merge_min(self.oldest_mtime, oldest_mtime);
        self.newest_mtime = merge_max(self.newest_mtime, newest_mtime);
    }
}

fn merge_min(a: Option<SystemTime>, b: Option<SystemTime>) -> Option<SystemTime> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

fn merge_max(a: Option<SystemTime>, b: Option<SystemTime>) -> Option<SystemTime> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

type DirStatsCache = parking_lot::Mutex<HashMap<PathBuf, (Instant, DirStats)>>;

static DIR_STATS_CACHE: LazyLock<DirStatsCache> =
    LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

async fn cached_mirror_directory_size(path: &Path) -> Result<DirStats, tokio::io::Error> {
    // Bind the lookup to a local so the `MutexGuard` drops at this `;`,
    // before any `.await` below — `parking_lot::Mutex` held across an
    // await is a deadlock waiting for someone to extend the body.
    let cached = DIR_STATS_CACHE.lock().get(path).copied();
    if let Some((ts, stats)) = cached
        && ts.elapsed().as_secs() < DIR_STATS_TTL_SECS
    {
        return Ok(stats);
    }
    let stats = mirror_directory_size(path, 0, false).await?;
    DIR_STATS_CACHE
        .lock()
        .insert(path.to_path_buf(), (Instant::now(), stats));
    Ok(stats)
}

async fn mirror_directory_size(
    path: &Path,
    depth: u8,
    in_byhash: bool,
) -> Result<DirStats, tokio::io::Error> {
    const MAX_DIR_DEPTH: u8 = 16;

    if depth >= MAX_DIR_DEPTH {
        warn!(
            "Reached depth limit of {} while scanning mirror directory `{}`",
            MAX_DIR_DEPTH,
            path.display()
        );
        return Ok(DirStats::default());
    }

    let mut dir = match tokio::fs::read_dir(path).await {
        Ok(dir) => dir,
        Err(err) if err.kind() == tokio::io::ErrorKind::NotFound => {
            return Ok(DirStats::default());
        }
        Err(err) => return Err(err),
    };
    let mut stats = DirStats::default();

    while let Some(entry) = dir.next_entry().await? {
        let entry_path = entry.path();
        let mdata = tokio::fs::symlink_metadata(&entry_path).await?;

        if mdata.is_file() {
            let len = mdata.len();
            stats.size += len;
            stats.files += 1;
            stats.max_file_size = stats.max_file_size.max(len);
            if in_byhash {
                stats.byhash_files += 1;
            }
            if entry_path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| VALID_DEB_EXTENSIONS.contains(&ext))
            {
                stats.deb_files += 1;
            } else {
                stats.metadata_files += 1;
            }
            if let Ok(mtime) = mdata.modified() {
                stats.oldest_mtime = merge_min(stats.oldest_mtime, Some(mtime));
                stats.newest_mtime = merge_max(stats.newest_mtime, Some(mtime));
            }
        } else if mdata.is_dir() {
            let descend_in_byhash =
                in_byhash || entry_path.file_name().is_some_and(|n| n == "by-hash");
            let sub = Box::pin(mirror_directory_size(
                &entry_path,
                depth + 1,
                descend_in_byhash,
            ))
            .await?;
            stats.merge(sub);
        }
        // Symlinks are intentionally skipped
    }

    Ok(stats)
}

// ---------------------------------------------------------------------------
// Table builders
// ---------------------------------------------------------------------------

/// `Display` wrappers used exclusively by the Mirrors table. Pulled out of
/// `build_mirror_table` so the function body stays focused on data flow rather
/// than on per-cell rendering details.
mod mirror_cells {
    use std::fmt::{self, Display, Formatter};

    use crate::humanfmt::HumanFmt;

    pub(super) struct OptCount<T: Display>(pub Option<T>);
    impl<T: Display> Display for OptCount<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            match &self.0 {
                Some(v) => Display::fmt(v, f),
                None => f.write_str("N/A"),
            }
        }
    }

    pub(super) struct DirSizeCell {
        pub size: u64,
        pub total: u64,
    }
    impl Display for DirSizeCell {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            Display::fmt(&HumanFmt::Size(self.size), f)?;
            if self.total > 0 {
                #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
                let pct = self.size as f64 / self.total as f64 * 100.0;
                write!(f, " ({pct:.1}%)")?;
            }
            Ok(())
        }
    }

    pub(super) struct AvgMaxCell {
        pub files: usize,
        pub size: u64,
        pub max_file: u64,
    }
    impl Display for AvgMaxCell {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            if self.files == 0 {
                f.write_str("N/A")
            } else {
                let avg = self.size / self.files as u64;
                write!(
                    f,
                    "{} / {}",
                    HumanFmt::Size(avg),
                    HumanFmt::Size(self.max_file)
                )
            }
        }
    }

    pub(super) struct EfficiencyCell {
        pub downloaded: i64,
        pub delivered: i64,
    }
    impl Display for EfficiencyCell {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            if self.delivered == 0 {
                f.write_str("N/A")
            } else {
                #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
                let pct = (self.delivered.saturating_sub(self.downloaded)) as f64
                    / self.delivered as f64
                    * 100.0;
                write!(f, "{pct:.1}%")
            }
        }
    }

    pub(super) struct DebMetaCell(pub Option<(usize, usize)>);
    impl Display for DebMetaCell {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            match self.0 {
                Some((deb, meta)) => write!(f, "{deb} / {meta}"),
                None => f.write_str("N/A"),
            }
        }
    }
}

async fn build_mirror_table(
    mirrors: &[MirrorStatEntry],
    now_epoch: i64,
    cache_path: &Path,
) -> (String, usize, DirStats) {
    use mirror_cells::{AvgMaxCell, DebMetaCell, DirSizeCell, EfficiencyCell, OptCount};

    if mirrors.is_empty() {
        return (String::new(), 0, DirStats::default());
    }

    let mut sorted: Vec<&MirrorStatEntry> = mirrors.iter().collect();
    sorted.sort_unstable_by_key(|m| Reverse(m.last_seen));

    let mirror_paths: Vec<PathBuf> = sorted
        .iter()
        .map(|mirror| [cache_path, &mirror.cache_path()].iter().collect())
        .collect();

    // Bound disk fan-out: cold-cache rebuilds otherwise spawn one concurrent
    // recursive walk per known mirror. We process in fixed-size chunks so
    // (a) at most `DIR_SCAN_CONCURRENCY` walks run at once and (b) the
    // collected order matches `mirror_paths` (and therefore `sorted`).
    let mut dir_stats: Vec<Option<DirStats>> = Vec::with_capacity(mirror_paths.len());
    for chunk in mirror_paths.chunks(DIR_SCAN_CONCURRENCY) {
        let chunk_stats = futures_util::future::join_all(chunk.iter().map(|mirror_path| async {
            match cached_mirror_directory_size(mirror_path).await {
                Ok(stats) => Some(stats),
                Err(err) => {
                    error!(
                        "Failed to gather size of directory `{}`:  {err}",
                        mirror_path.display()
                    );
                    None
                }
            }
        }))
        .await;
        dir_stats.extend(chunk_stats);
    }

    // Drop cache entries for paths no longer attached to any known mirror.
    // Keeps `DIR_STATS_CACHE` from growing unbounded as mirrors come and go.
    {
        let mut cache = DIR_STATS_CACHE.lock();
        cache.retain(|k, _| mirror_paths.iter().any(|p| p == k));
    }

    let total_cache_size: u64 = dir_stats.iter().filter_map(|s| s.map(|st| st.size)).sum();

    // -- Build the table ------------------------------------------------------------------
    let mut table = Table::new(&[
        "Mirror",
        "Last Seen",
        "First Seen",
        "Last Cleanup",
        "Upstream Fetches",
        "Client Deliveries",
        "Cache Efficiency",
        "Disk Space",
        "File Count",
        "Avg / Max File Size",
        "Debs / Metadata",
    ]);

    for (mirror, dir_stat) in sorted.iter().zip(&dir_stats) {
        let downloaded_bytes = u64::try_from(mirror.total_download_size).unwrap_or(0);
        let delivered_bytes = u64::try_from(mirror.total_delivery_size).unwrap_or(0);

        let (file_count, dir_size, avg_max, deb_meta) = match dir_stat {
            Some(stats) => (
                Some(stats.files),
                Some(DirSizeCell {
                    size: stats.size,
                    total: total_cache_size,
                }),
                Some(AvgMaxCell {
                    files: stats.files,
                    size: stats.size,
                    max_file: stats.max_file_size,
                }),
                Some((stats.deb_files, stats.metadata_files)),
            ),
            None => (None, None, None, None),
        };

        tr!(
            table,
            HtmlEscaped(mirror.uri()),
            FmtLastSeenHealth {
                last_seen: mirror.last_seen,
                now_epoch
            },
            FmtTimestamp(mirror.first_seen),
            FmtTimestamp(mirror.last_cleanup),
            format_args!(
                "{} ({})",
                HumanFmt::Size(downloaded_bytes),
                mirror.download_count
            ),
            format_args!(
                "{} ({})",
                HumanFmt::Size(delivered_bytes),
                mirror.delivery_count
            ),
            EfficiencyCell {
                downloaded: mirror.total_download_size,
                delivered: mirror.total_delivery_size,
            },
            OptCount(dir_size),
            OptCount(file_count),
            OptCount(avg_max),
            DebMetaCell(deb_meta),
        );
    }

    let mut aggregate = DirStats::default();
    for stats in dir_stats.iter().flatten() {
        aggregate.merge(*stats);
    }

    let rows = sorted.len();
    (table.finish(), rows, aggregate)
}

async fn build_origin_table(database: &Database, now_epoch: i64) -> (String, usize) {
    let mut origins = match database.get_origins().await {
        Ok(o) => o,
        Err(err) => {
            error!("Failed to query origins:  {err}");
            let mut buf = String::new();
            write_section_error(&mut buf, "origins", &err);
            return (buf, 0);
        }
    };

    if origins.is_empty() {
        return (String::new(), 0);
    }

    origins.sort_unstable_by_key(|o| Reverse(o.last_seen));

    let rows = origins.len();
    let mut table = Table::new(&[
        "Mirror",
        "Distribution",
        "Component",
        "Architecture",
        "Last Seen",
    ]);

    for origin in origins {
        tr!(
            table,
            HtmlEscaped(origin.mirror_uri()),
            HtmlEscape(&origin.distribution),
            HtmlEscape(&origin.component),
            HtmlEscape(&origin.architecture),
            FmtLastSeenHealth {
                last_seen: origin.last_seen,
                now_epoch
            },
        );
    }

    (table.finish(), rows)
}

async fn build_client_table(database: &Database, now_epoch: i64) -> (String, usize) {
    let mut clients = match database.get_clients_with_stats().await {
        Ok(o) => o,
        Err(err) => {
            error!("Failed to query clients:  {err}");
            let mut buf = String::new();
            write_section_error(&mut buf, "clients", &err);
            return (buf, 0);
        }
    };

    if clients.is_empty() {
        return (String::new(), 0);
    }

    clients.sort_unstable_by_key(|c| Reverse(c.last_seen));

    let rows = clients.len();
    let mut table = Table::new(&[
        "IP",
        "Last Seen",
        "Upstream Fetched",
        "Served to Client",
        "Requests",
    ]);

    for client in clients {
        let downloaded = u64::try_from(client.total_downloaded).unwrap_or(0);
        let delivered = u64::try_from(client.total_delivered).unwrap_or(0);
        tr!(
            table,
            client.client_ip,
            FmtLastSeenHealth {
                last_seen: client.last_seen,
                now_epoch
            },
            HumanFmt::Size(downloaded),
            HumanFmt::Size(delivered),
            client.request_count,
        );
    }

    (table.finish(), rows)
}

#[must_use]
fn build_uncacheable_table() -> (String, usize) {
    let uncacheables = get_uncacheables().read();

    if uncacheables.is_empty() {
        return (String::new(), 0);
    }

    let rows = uncacheables.len();
    let mut table = Table::new(&["Requested Host", "Requested Path"]);

    for (host, path) in uncacheables.iter() {
        // `host` is a DomainName-like type; route through HtmlEscape via to_string to avoid
        // duplicating display logic.
        let host_s = host.to_string();
        tr!(table, HtmlEscape(&host_s), HtmlEscape(path));
    }
    drop(uncacheables);

    (table.finish(), rows)
}

/// What a Top-Packages table renders besides the package name.
#[derive(Clone, Copy)]
enum TopPackagesView {
    /// Columns: Package, Deliveries, Package Size.
    ByCount,
    /// Columns: Package, Total Size, Deliveries, Package Size.
    BySize,
}

/// Number of rows in each "Top Packages" table.
const TOP_PACKAGES_LIMIT: u32 = 5;

async fn build_top_packages_table(database: &Database, view: TopPackagesView) -> (String, usize) {
    let (label, result) = match view {
        TopPackagesView::ByCount => (
            "top packages by count",
            database.get_top_packages(TOP_PACKAGES_LIMIT).await,
        ),
        TopPackagesView::BySize => (
            "top packages by size",
            database.get_top_packages_by_size(TOP_PACKAGES_LIMIT).await,
        ),
    };

    let packages = match result {
        Ok(p) => p,
        Err(err) => {
            error!("Failed to query {label}:  {err}");
            let mut buf = String::new();
            write_section_error(&mut buf, label, &err);
            return (buf, 0);
        }
    };

    if packages.is_empty() {
        return (String::new(), 0);
    }

    let rows = packages.len();
    let headers: &[&str] = match view {
        TopPackagesView::ByCount => &["Package", "Deliveries", "Package Size"],
        TopPackagesView::BySize => &["Package", "Total Size", "Deliveries", "Package Size"],
    };
    let mut table = Table::new(headers);

    for pkg in packages {
        let pkg_size = u64::try_from(pkg.package_size).unwrap_or(0);
        match view {
            TopPackagesView::ByCount => tr!(
                table,
                HtmlEscape(&pkg.debname),
                pkg.delivery_count,
                HumanFmt::Size(pkg_size),
            ),
            TopPackagesView::BySize => {
                let total = u64::try_from(pkg.total_delivered).unwrap_or(0);
                tr!(
                    table,
                    HtmlEscape(&pkg.debname),
                    HumanFmt::Size(total),
                    pkg.delivery_count,
                    HumanFmt::Size(pkg_size),
                );
            }
        }
    }

    (table.finish(), rows)
}

// ---------------------------------------------------------------------------
// Logs endpoint
// ---------------------------------------------------------------------------

#[must_use]
async fn serve_logs(options: QueryOptions) -> WebResponse {
    let ls = LOGSTORE.get().expect("initialized in main()");

    // HTML-escape every entry on the blocking pool: with a large
    // `logstore_capacity` this can dominate the request handler.
    //
    // The `LogStore` read guard returned by `entries()` blocks any logger
    // trying to write a new entry. Confine the clone to a tight scope so
    // the guard drops before we `spawn_blocking` the (longer-running)
    // escape pass and before the request handler does any other work.
    let entries: Vec<String> = {
        let guard = ls.entries();
        guard.iter().cloned().collect()
    };
    let entry_count = entries.len();
    let escaped_logs = tokio::task::spawn_blocking(move || {
        let mut buf = String::with_capacity(entries.iter().map(|e| e.len() + 8).sum());
        for entry in &entries {
            w!(buf, "{}\n", HtmlEscape(entry));
        }
        buf
    })
    .await
    .unwrap_or_else(|err| {
        error!("Log-page render task panicked:  {err}");
        String::from("!! Failed to render log entries !!\n")
    });

    let nav = build_nav_html(Page::Logs, options);

    let body_html = format_args!(
        "{nav}\
         <div class=\"section\">\
         <h3>Log Entries <span class=\"count\">{entry_count}</span></h3>\
         <pre class=\"log\">{escaped_logs}</pre>\
         </div>\
         <footer><hr><p>All dates are in UTC.</p></footer>"
    );

    // The logs page is a tailing view; auto-refresh would fight the reader.
    let html = build_page(
        "apt-cacher-rs logs",
        body_html,
        QueryOptions {
            theme: options.theme,
            refresh_secs: None,
        },
    );
    WebResponse::html(html)
}

#[cfg(test)]
mod tests {
    use super::{HtmlEscape, MAX_QUERY_LEN, RatioClass, Theme, parse_query};

    fn escape(s: &str) -> String {
        format!("{}", HtmlEscape(s))
    }

    #[test]
    fn html_escape_empty() {
        assert_eq!(escape(""), "");
    }

    #[test]
    fn html_escape_no_special_chars() {
        assert_eq!(escape("plain text 123"), "plain text 123");
    }

    #[test]
    fn html_escape_each_special_byte() {
        assert_eq!(escape("&"), "&amp;");
        assert_eq!(escape("<"), "&lt;");
        assert_eq!(escape(">"), "&gt;");
        assert_eq!(escape("\""), "&quot;");
        assert_eq!(escape("'"), "&#x27;");
    }

    #[test]
    fn html_escape_combined() {
        assert_eq!(
            escape("<a href=\"x?y=1&z=2\">it's</a>"),
            "&lt;a href=&quot;x?y=1&amp;z=2&quot;&gt;it&#x27;s&lt;/a&gt;",
        );
    }

    #[test]
    fn html_escape_multibyte_utf8_passthrough() {
        // The byte-index slicing path in HtmlEscape must not split a
        // multibyte sequence: the bytes it slices on are always single-byte
        // ASCII escape characters.
        assert_eq!(escape("h\u{e9}llo"), "h\u{e9}llo");
        assert_eq!(
            escape("\u{65e5}\u{672c}\u{8a9e}"),
            "\u{65e5}\u{672c}\u{8a9e}",
        );
        assert_eq!(escape("a&b h\u{e9}llo<c"), "a&amp;b h\u{e9}llo&lt;c",);
        assert_eq!(escape("emoji \u{1f980}"), "emoji \u{1f980}");
    }

    #[test]
    fn html_escape_repeated_specials() {
        assert_eq!(escape("&&&"), "&amp;&amp;&amp;");
        assert_eq!(escape("<><>"), "&lt;&gt;&lt;&gt;");
    }

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

    #[test]
    fn ratio_class_zero_limit_is_normal() {
        // Division-by-zero guard: any value with limit=0 must be Normal.
        assert!(matches!(RatioClass::new(0, 0), RatioClass::Normal));
        assert!(matches!(RatioClass::new(u64::MAX, 0), RatioClass::Normal));
    }

    #[test]
    fn ratio_class_normal_zone() {
        // Below 50%.
        assert!(matches!(RatioClass::new(0, 100), RatioClass::Normal));
        assert!(matches!(RatioClass::new(49, 100), RatioClass::Normal));
    }

    #[test]
    fn ratio_class_warn_zone() {
        // [50%, 80%).
        assert!(matches!(RatioClass::new(50, 100), RatioClass::Warn));
        assert!(matches!(RatioClass::new(79, 100), RatioClass::Warn));
    }

    #[test]
    fn ratio_class_alert_zone() {
        // >= 80%, including over-quota (value > limit).
        assert!(matches!(RatioClass::new(80, 100), RatioClass::Alert));
        assert!(matches!(RatioClass::new(100, 100), RatioClass::Alert));
        assert!(matches!(RatioClass::new(200, 100), RatioClass::Alert));
    }

    #[test]
    fn ratio_class_saturation_safe() {
        // value*5 and limit*4 saturate without panicking; the saturated
        // value*5 == u64::MAX clearly exceeds limit*4 so this is Alert.
        assert!(matches!(
            RatioClass::new(u64::MAX, u64::MAX),
            RatioClass::Alert
        ));
        assert!(matches!(RatioClass::new(u64::MAX, 1), RatioClass::Alert));
        // Tiny value, huge limit: the multiplications do not overflow.
        assert!(matches!(RatioClass::new(1, u64::MAX), RatioClass::Normal));
    }
}
