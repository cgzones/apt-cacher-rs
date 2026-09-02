//! `Display` newtypes the dashboard renders cells through: UTC timestamps,
//! HTML escaping, ratio-based colouring and the small value formatters
//! (sizes, percentages, yes/no). Each writes straight into the `Formatter`,
//! so a cell never allocates an intermediate `String`.

use std::{
    fmt::{self, Display, Formatter, Write as _},
    time::SystemTime,
};

use time::{OffsetDateTime, format_description::FormatItem, macros::format_description};

use crate::{humanfmt::HumanFmt, metrics};

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
pub(super) struct Utc(OffsetDateTime);

impl Utc {
    pub(super) fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Take any `OffsetDateTime` and shift it to UTC. Use at the boundary
    /// when receiving a value from foreign code that may not already be UTC.
    pub(super) fn from_offset(odt: OffsetDateTime) -> Self {
        Self(odt.to_offset(time::UtcOffset::UTC))
    }

    pub(super) fn inner(self) -> OffsetDateTime {
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
pub(super) struct HtmlEscape<'a>(pub(super) &'a str);
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
pub(super) struct HtmlEscaped<D: Display>(pub(super) D);
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
pub(super) struct FmtTimestamp(pub(super) i64);
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

/// Renders the age of a `SystemTime` as a duration (e.g. "5d 3h") inside a
/// `<time>` carrying the absolute instant, or "N/A" when missing.
///
/// The age is the useful figure at a glance and the absolute timestamp is
/// what you need to correlate against a log; every other timestamp on the
/// page shows the absolute value, so this one carries both rather than
/// leaving the reader to do the arithmetic.
pub(super) struct FmtMTimeAge(pub(super) Option<SystemTime>);
impl Display for FmtMTimeAge {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Some(mt) = self.0 else {
            return f.write_str("N/A");
        };
        let Ok(dur) = mt.elapsed() else {
            return f.write_str("in future");
        };
        let stamp = Utc::from_offset(OffsetDateTime::from(mt));
        write!(f, "{} ago ({stamp})", HumanFmt::Time(dur))
    }
}

/// A `<meter>` bar rendered beside a value.
///
/// The page's CSP is `style-src 'self'`, which forbids the inline
/// `style="width:37%"` a `<div>` bar would need; `<meter>` carries its fill
/// in `value`/`max` attributes instead, and brings the right ARIA role with
/// it. Renders nothing when there is no scale to draw against.
pub(super) struct Meter {
    pub(super) value: u64,
    pub(super) max: u64,
}
impl Display for Meter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.max == 0 {
            return Ok(());
        }
        write!(
            f,
            "<meter class=\"bar\" value=\"{}\" max=\"{}\"></meter>",
            self.value.min(self.max),
            self.max,
        )
    }
}

/// Combines a "last seen" timestamp with a staleness badge ("aging"/"stale").
pub(super) struct FmtLastSeenHealth {
    pub(super) last_seen: i64,
    pub(super) now_epoch: i64,
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
pub(super) enum RatioClass {
    Normal,
    Warn,
    Alert,
}

impl RatioClass {
    /// Construct a `RatioClass` from a ratio of `value` to `limit`. Uses
    /// integer arithmetic only.
    #[must_use]
    pub(super) const fn new(value: u64, limit: u64) -> Self {
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
pub(super) struct Colorize<T: Display> {
    pub(super) inner: T,
    pub(super) class: RatioClass,
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
pub(super) struct AlertNonzero(pub(super) u64);
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
pub(super) struct WarnNonzero(pub(super) u64);
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
pub(super) fn warn_if<T: Display>(inner: T, predicate: bool) -> Colorize<T> {
    Colorize {
        inner,
        class: if predicate {
            RatioClass::Warn
        } else {
            RatioClass::Normal
        },
    }
}

/// Render `inner` as-is; if `predicate` is true, wrap it in `<span class="alert">`.
pub(super) fn alert_if<T: Display>(inner: T, predicate: bool) -> Colorize<T> {
    Colorize {
        inner,
        class: if predicate {
            RatioClass::Alert
        } else {
            RatioClass::Normal
        },
    }
}

/// Convert an `i64` from a DB column to `u64` for display, clamping
/// negative values to 0. The sqlx schemas write only non-negative values
/// here, but i64 is the column type; this keeps the conversion site terse
/// and consistent across the dashboard builders.
#[must_use]
pub(super) fn as_size(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Shared cell-value Display helpers — used across multiple section builders.
// ---------------------------------------------------------------------------

/// Render `Some(size)` as a human-readable size; render `None` as `fallback`.
pub(super) struct OptSize {
    pub(super) bytes: Option<u64>,
    pub(super) fallback: &'static str,
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
pub(super) struct OptOrUnlimited<T: Display>(pub(super) Option<T>);
impl<T: Display> Display for OptOrUnlimited<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(v) => Display::fmt(v, f),
            None => f.write_str("unlimited"),
        }
    }
}

pub(super) struct YesNo(pub(super) bool);
impl Display for YesNo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0 { "Yes" } else { "No" })
    }
}

pub(super) struct EnabledDisabled(pub(super) bool);
impl Display for EnabledDisabled {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0 { "Enabled" } else { "Disabled" })
    }
}

/// Render an optional rate-limit configuration as `<size>/s` or `"None"`.
pub(super) struct MinRate(pub(super) Option<std::num::NonZero<usize>>);
impl Display for MinRate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(r) => write!(f, "{}/s", HumanFmt::Size(r.get() as u64)),
            None => f.write_str("None"),
        }
    }
}

/// Percentage with one decimal; `"N/A"` if denominator is non-positive.
pub(super) struct Pct {
    pub(super) num: i64,
    pub(super) den: i64,
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
pub(super) struct CacheHitRatio {
    pub(super) hits: i64,
    pub(super) total: i64,
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

/// Bandwidth-window cell, e.g. `"4.2GB served, 1.1GB fetched (3.1GB saved)"`.
/// `None` (e.g. on a query failure already logged at the boundary) renders
/// as `"N/A"`.
pub(super) struct Window(pub(super) Option<(i64, i64)>);
impl Display for Window {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some((downloaded, delivered)) => {
                let dl = as_size(downloaded);
                let del = as_size(delivered);
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
pub(super) struct DiskUsage {
    pub(super) cache_size: u64,
    pub(super) quota: Option<u64>,
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
                )?;
                Display::fmt(
                    &Meter {
                        value: self.cache_size,
                        max: q,
                    },
                    f,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HtmlEscape, RatioClass};

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
