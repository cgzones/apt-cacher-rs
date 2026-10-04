//! `Display` newtypes the dashboard renders cells through: UTC timestamps,
//! HTML escaping, ratio-based colouring and the small value formatters
//! (sizes, percentages, yes/no). Each writes straight into the `Formatter`
//! rather than building a `String` of its own.

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

impl Utc {
    /// Hand the ISO-8601 and the human rendering to `write`, or render
    /// `<time>invalid time</time>` when either formatter fails.
    fn with_parts(
        self,
        f: &mut Formatter<'_>,
        write: impl FnOnce(&mut Formatter<'_>, &str, &str) -> fmt::Result,
    ) -> fmt::Result {
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
        write(f, iso, display)
    }
}

impl Display for Utc {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.with_parts(f, |f, iso, display| {
            write!(f, "<time datetime=\"{iso}\">{display}</time>")
        })
    }
}

/// The current wall-clock second, the `now` every relative time on one
/// rendered list is measured against.
pub(super) fn now_epoch() -> i64 {
    i64::try_from(coarsetime::Clock::now_since_epoch().as_secs()).unwrap_or(i64::MAX)
}

/// A coarse age in its most significant unit only: `45 s`, `12 min`, `3 h`,
/// `5 d`. A reader glancing at "last: 3 h ago" wants the order of magnitude;
/// the exact instant is in the `<time>` element's `title`.
pub(super) struct Age(pub(super) u64);
impl Display for Age {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        const MIN: u64 = 60;
        const HOUR: u64 = 60 * MIN;
        const DAY: u64 = 24 * HOUR;
        match self.0 {
            s if s < MIN => write!(f, "{s} s"),
            s if s < HOUR => write!(f, "{} min", s / MIN),
            s if s < DAY => write!(f, "{} h", s / HOUR),
            s => write!(f, "{} d", s / DAY),
        }
    }
}

/// A duration in its two most significant units: `2 h 13 min`, `45 s`,
/// `3 d 4 h`. For accumulated spans (time spent at a cap), where the second
/// unit is what tells two readings apart.
pub(super) struct Span(pub(super) u64);
impl Display for Span {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        const MIN: u64 = 60;
        const HOUR: u64 = 60 * MIN;
        const DAY: u64 = 24 * HOUR;
        let s = self.0;
        let (major, major_unit, minor, minor_unit) = if s < MIN {
            return write!(f, "{s} s");
        } else if s < HOUR {
            (s / MIN, "min", s % MIN, "s")
        } else if s < DAY {
            (s / HOUR, "h", s % HOUR / MIN, "min")
        } else {
            (s / DAY, "d", s % DAY / HOUR, "h")
        };
        if minor == 0 {
            write!(f, "{major} {major_unit}")
        } else {
            write!(f, "{major} {major_unit} {minor} {minor_unit}")
        }
    }
}

/// A limiter's live gauge: `current / cap`, a `<meter>` against the cap
/// and the peak since start as a label, e.g. `3 / 20 [meter] peak 20`. No
/// cap renders `unlimited` and no bar. The meter's `low`/`high` marks sit at
/// the same 50 % / 80 % thresholds as [`RatioClass`], so the browser paints
/// the bar green, amber or red with no inline style (the CSP forbids one).
/// Browsers count a value equal to `low` as below it (and one equal to
/// `high` as below that), so the marks sit half a step under the first
/// integer at each threshold: with a cap of 20, 10 is amber and 16 red, and
/// a cap of 1 turns red when full.
pub(super) struct Gauge {
    pub(super) current: u64,
    pub(super) cap: Option<u64>,
    pub(super) peak: Option<u64>,
}
impl Display for Gauge {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { current, cap, peak } = *self;
        match cap {
            Some(cap) if cap > 0 => write!(
                f,
                "{} / {}<meter class=\"gauge\" min=\"0\" max=\"{cap}\" low=\"{}\" high=\"{}\" optimum=\"0\" value=\"{}\"></meter>",
                Count(current),
                Count(cap),
                HalfBelow(cap.div_ceil(2)),
                HalfBelow(cap.saturating_mul(4).div_ceil(5)),
                current.min(cap),
            )?,
            Some(_) | None => write!(f, "{} / unlimited", Count(current))?,
        }
        if let Some(peak) = peak {
            write!(f, " <span class=\"peak\">peak {}</span>", Count(peak))?;
        }
        Ok(())
    }
}

/// A short wall time: rounded milliseconds under a second, seconds with one
/// decimal under a minute, then a [`Span`]. A value that rounds to no
/// millisecond, or one the clock that measured it cannot tell from zero,
/// renders as the floor it is: `<1 ms`, or one tick of a coarser clock --
/// never "0 ms".
pub(super) struct Latency {
    pub(super) value: std::time::Duration,
    /// The measuring clock's resolution (see [`Self::PRECISE`]).
    pub(super) resolution: std::time::Duration,
}
impl Latency {
    /// The resolution to pass for a `PreciseInstant` measurement.
    pub(super) const PRECISE: std::time::Duration = std::time::Duration::from_nanos(1);
}
impl Display for Latency {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { value, resolution } = *self;
        // Rounded, not truncated: a coarse sample of one tick reads a hair
        // short of it (coarsetime truncates twice), and must not render
        // under its own floor.
        let millis = value.as_micros().saturating_add(500) / 1000;
        if millis == 0 {
            // The tick rounded up to whole milliseconds, at least one.
            let floor = resolution.as_micros().div_ceil(1000).max(1);
            write!(f, "&lt;{floor} ms")
        } else if millis < 1000 {
            write!(f, "{millis} ms")
        } else if value.as_secs() < 60 {
            write!(f, "{:.1} s", value.as_secs_f64())
        } else {
            Display::fmt(&Span(value.as_secs()), f)
        }
    }
}

/// `n - 0.5`, rendered exactly: a meter mark half a step under `n`.
struct HalfBelow(u64);
impl Display for HalfBelow {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0.checked_sub(1) {
            Some(below) => write!(f, "{below}.5"),
            None => f.write_str("0"),
        }
    }
}

/// How a capped limiter fared since start: the time spent at its cap and
/// the share of admissions it refused, e.g. `at cap 2 h 13 min; refused
/// 4.2% (12 of 285)`.
pub(super) struct Saturation {
    pub(super) at_cap: std::time::Duration,
    pub(super) refused: u64,
    /// Admissions and refusals together.
    pub(super) attempts: u64,
    /// What a refusal is called for this limiter ("refused", "waited").
    pub(super) verb: &'static str,
}
impl Display for Saturation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self {
            at_cap,
            refused,
            attempts,
            verb,
        } = *self;
        if at_cap.is_zero() {
            f.write_str("never at cap")?;
        } else if at_cap.as_secs() == 0 {
            f.write_str("at cap under 1 s")?;
        } else {
            write!(f, "at cap {}", Span(at_cap.as_secs()))?;
        }
        if attempts > 0 {
            #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
            let pct = refused as f64 / attempts as f64 * 100.0;
            write!(
                f,
                "; {verb} {pct:.1}% ({} of {})",
                Count(refused),
                Count(attempts)
            )?;
        }
        Ok(())
    }
}

/// A Unix timestamp as plain text, `25 Sep 2026 10:00:00 UTC`, for a
/// `title` attribute, which cannot hold the markup [`RelTime`] renders.
pub(super) struct UtcText(pub(super) i64);
impl Display for UtcText {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Ok(ts) = OffsetDateTime::from_unix_timestamp(self.0) else {
            return f.write_str("an invalid time");
        };
        Utc::from_offset(ts).with_parts(f, |f, _iso, display| write!(f, "{display} UTC"))
    }
}

/// A Unix timestamp as a relative age inside a `<time>` element, e.g.
/// `<time datetime="2026-09-25T10:00:00Z" title="25 Sep 2026 10:00:00 UTC">3 h ago</time>`,
/// or `in 3 h` for one in the future. The relative figure is what a reader
/// scans for; the absolute instant (for correlating with a log) is one hover
/// away and machine-readable in `datetime`. `0` renders as `N/A`, the
/// dashboard's "never" sentinel.
pub(super) struct RelTime {
    pub(super) epoch: i64,
    pub(super) now: i64,
}
impl Display for RelTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { epoch, now } = *self;
        if epoch == 0 {
            return f.write_str("N/A");
        }
        let Ok(ts) = OffsetDateTime::from_unix_timestamp(epoch) else {
            return f.write_str("N/A");
        };
        Utc::from_offset(ts).with_parts(f, |f, iso, display| {
            write!(f, "<time datetime=\"{iso}\" title=\"{display} UTC\">")?;
            match now.cmp(&epoch) {
                std::cmp::Ordering::Equal => f.write_str("just now")?,
                std::cmp::Ordering::Greater => {
                    write!(f, "{} ago", Age(now.abs_diff(epoch)))?;
                }
                std::cmp::Ordering::Less => write!(f, "in {}", Age(now.abs_diff(epoch)))?,
            }
            f.write_str("</time>")
        })
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

/// A file's modification time as a [`RelTime`] ("5 d ago", the instant in
/// its title), or "N/A" when missing.
pub(super) struct FmtMTimeAge {
    pub(super) mtime: Option<SystemTime>,
    pub(super) now: i64,
}
impl Display for FmtMTimeAge {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Some(mtime) = self.mtime else {
            return f.write_str("N/A");
        };
        let epoch = OffsetDateTime::from(mtime).unix_timestamp();
        Display::fmt(
            &RelTime {
                epoch,
                now: self.now,
            },
            f,
        )
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

/// One part of a [`StackBar`]: its name in the legend and its figure.
#[derive(Clone, Copy, Debug)]
pub(super) struct Segment {
    pub(super) name: &'static str,
    pub(super) value: u64,
}

/// What a figure counts, which decides how it is rendered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Unit {
    Count,
    Bytes,
}

/// The palette's length (`s1`..`s5` in the stylesheet).
const STACK_SEGMENTS_MAX: usize = 5;

/// A 100%-stacked bar: how a total splits into its parts, drawn as inline
/// SVG so it needs no script and no style attribute. Each segment is a
/// `<rect>` whose width is its share of 100 (tenths of a percent, summing
/// to exactly 100) and whose colour comes from its class; the stylesheet
/// maps `s1`..`s5` onto the categorical palette in both themes. The shares
/// are also text: the `aria-label`, a `<title>` per segment (the hover
/// tooltip) and the legend beside it, so no figure is carried by colour
/// alone. Nothing is drawn while the total is zero.
pub(super) struct StackBar<'a> {
    /// What the bar splits, e.g. "Responses by class".
    pub(super) label: &'static str,
    /// At most [`STACK_SEGMENTS_MAX`], the palette's length.
    pub(super) segments: &'a [Segment],
    pub(super) unit: Unit,
}

impl StackBar<'_> {
    /// The bar's shares, ready to render as [`Drawn::svg`] and
    /// [`Drawn::legend`]; `None` while the total is zero.
    pub(super) fn draw(&self) -> Option<Drawn<'_>> {
        debug_assert!(
            self.segments.len() <= STACK_SEGMENTS_MAX,
            "one palette colour per segment"
        );
        self.tenths().map(|tenths| Drawn { bar: self, tenths })
    }

    /// Each segment's share in tenths of a percent, summing to exactly 1000:
    /// the largest-remainder rounding, ties to the earlier segment. `None`
    /// while the total is zero.
    fn tenths(&self) -> Option<Vec<u64>> {
        let Self {
            label: _,
            segments,
            unit: _,
        } = self;
        let values: Vec<u128> = segments
            .iter()
            .map(|segment| u128::from(segment.value))
            .collect();
        let total: u128 = values.iter().sum();
        if total == 0 {
            return None;
        }
        let mut shares: Vec<(u128, u128)> = values
            .iter()
            .map(|value| (value * 1000 / total, value * 1000 % total))
            .collect();
        let floor: u128 = shares.iter().map(|(share, _)| share).sum();
        let mut order: Vec<usize> = (0..shares.len()).collect();
        order.sort_by(|&a, &b| shares[b].1.cmp(&shares[a].1).then(a.cmp(&b)));
        for &index in order
            .iter()
            .take(usize::try_from(1000 - floor).unwrap_or(0))
        {
            shares[index].0 += 1;
        }
        Some(
            shares
                .into_iter()
                .map(|(share, _)| u64::try_from(share).unwrap_or(1000))
                .collect(),
        )
    }
}

/// A [`StackBar`] with its shares computed.
pub(super) struct Drawn<'a> {
    bar: &'a StackBar<'a>,
    /// Per segment, in tenths of a percent (see [`StackBar::tenths`]).
    tenths: Vec<u64>,
}

impl Drawn<'_> {
    /// The `<svg>` element.
    pub(super) fn svg(&self) -> DrawnSvg<'_> {
        DrawnSvg(self)
    }

    /// The legend entries, one per segment, zero ones included so the
    /// legend reads the same from one refresh to the next.
    pub(super) fn legend(&self) -> DrawnLegend<'_> {
        DrawnLegend(self)
    }

    /// Each segment with its share.
    fn parts(&self) -> impl Iterator<Item = (usize, &Segment, Share)> {
        let Self { bar, tenths } = self;
        bar.segments
            .iter()
            .zip(tenths)
            .enumerate()
            .map(|(index, (segment, &tenths))| {
                (
                    index,
                    segment,
                    Share {
                        tenths,
                        value: segment.value,
                    },
                )
            })
    }
}

/// See [`Drawn::svg`].
pub(super) struct DrawnSvg<'a>(&'a Drawn<'a>);

impl Display for DrawnSvg<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self(drawn) = self;
        let StackBar {
            label,
            segments: _,
            unit,
        } = *drawn.bar;
        write!(
            f,
            "<svg class=\"stack\" viewBox=\"0 0 100 10\" preserveAspectRatio=\"none\" role=\"img\" aria-label=\"{label}:"
        )?;
        let mut sep = " ";
        for (_, segment, share) in drawn.parts() {
            write!(f, "{sep}{} {share}", segment.name)?;
            sep = ", ";
        }
        f.write_str("\">")?;
        let mut x = 0;
        for (index, segment, share) in drawn.parts() {
            if share.tenths > 0 {
                write!(
                    f,
                    "<rect class=\"s{}\" x=\"{}\" y=\"0\" width=\"{}\" height=\"10\"><title>{}: {} ({share})</title></rect>",
                    index + 1,
                    TenthsPlain(x),
                    TenthsPlain(share.tenths),
                    segment.name,
                    Figure {
                        value: segment.value,
                        unit
                    },
                )?;
            }
            x += share.tenths;
        }
        f.write_str("</svg>")
    }
}

/// See [`Drawn::legend`].
pub(super) struct DrawnLegend<'a>(&'a Drawn<'a>);

impl Display for DrawnLegend<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self(drawn) = self;
        for (index, segment, share) in drawn.parts() {
            write!(
                f,
                "<span class=\"key s{}\">{} {share} <span class=\"muted\">({})</span></span>",
                index + 1,
                segment.name,
                Figure {
                    value: segment.value,
                    unit: drawn.bar.unit
                },
            )?;
        }
        Ok(())
    }
}

/// A [`StackBar`] figure in its unit.
struct Figure {
    value: u64,
    unit: Unit,
}

impl Display for Figure {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { value, unit } = *self;
        match unit {
            Unit::Count => Display::fmt(&Count(value), f),
            Unit::Bytes => Display::fmt(&HumanFmt::Size(value), f),
        }
    }
}

/// A segment's share as `12.3%`; a part too small for a tenth of a percent
/// reads `<0.1%`, never `0.0%` beside a figure that is not zero.
#[derive(Clone, Copy)]
struct Share {
    tenths: u64,
    value: u64,
}

impl Display for Share {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { tenths, value } = *self;
        if tenths == 0 && value > 0 {
            f.write_str("&lt;0.1%")
        } else {
            write!(f, "{}.{}%", tenths / 10, tenths % 10)
        }
    }
}

/// Tenths as an SVG length: `12.3`.
struct TenthsPlain(u64);

impl Display for TenthsPlain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self(tenths) = *self;
        write!(f, "{}.{}", tenths / 10, tenths % 10)
    }
}

/// How recently a mirror, origin or client was last seen.
///
/// The one place the staleness thresholds live: [`FmtLastSeenHealth`] paints
/// the badge from it and [`Freshness::row_class`] paints the row's left rule,
/// so the two cannot disagree about what "aging" means.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Freshness {
    /// No timestamp recorded.
    Unknown,
    Fresh,
    /// Not seen in over a week.
    Aging(i64),
    /// Not seen in over a month.
    Stale(i64),
}

impl Freshness {
    pub(super) const fn of(last_seen: i64, now_epoch: i64) -> Self {
        if last_seen <= 0 {
            return Self::Unknown;
        }
        let age_days = now_epoch.saturating_sub(last_seen) / (24 * 60 * 60);
        if age_days > 30 {
            Self::Stale(age_days)
        } else if age_days > 7 {
            Self::Aging(age_days)
        } else {
            Self::Fresh
        }
    }

    /// The `class` attribute for a row in this state, empty when the row
    /// needs no marker. A rule on every fresh row would mark nothing.
    pub(super) const fn row_class(self) -> &'static str {
        match self {
            Self::Unknown | Self::Fresh => "",
            Self::Aging(_) => " class=\"row-aging\"",
            Self::Stale(_) => " class=\"row-stale\"",
        }
    }
}

/// Combines a "last seen" timestamp with a staleness badge ("aging"/"stale").
pub(super) struct FmtLastSeenHealth {
    pub(super) last_seen: i64,
    pub(super) now_epoch: i64,
}
impl Display for FmtLastSeenHealth {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(
            &RelTime {
                epoch: self.last_seen,
                now: self.now_epoch,
            },
            f,
        )?;
        match Freshness::of(self.last_seen, self.now_epoch) {
            Freshness::Unknown | Freshness::Fresh => Ok(()),
            Freshness::Aging(days) => write!(
                f,
                " <span class=\"warn\" title=\"Aging: not seen in {days} days\">aging</span>"
            ),
            Freshness::Stale(days) => write!(
                f,
                " <span class=\"alert\" title=\"Stale: not seen in {days} days\">stale</span>"
            ),
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

/// A count, digit-grouped once it has five digits or more: `12 345`,
/// `1 234 567` (a narrow no-break space between groups, so the figure never
/// wraps and no locale reads it as a decimal point). Four digits stay as
/// they are: `2026` reads as a number, `2 026` as two.
#[derive(Clone, Copy)]
pub(super) struct Count(pub(super) u64);
impl Count {
    /// A count from an `i64` database column, clamped at 0 like
    /// [`as_size`].
    pub(super) fn db(value: i64) -> Self {
        Self(as_size(value))
    }

    /// A count of in-memory entries.
    pub(super) fn len(value: usize) -> Self {
        Self(value as u64)
    }
}
impl Display for Count {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        const SEPARATOR: &str = "\u{202f}";
        let value = self.0;
        if value < 10_000 {
            return write!(f, "{value}");
        }
        let mut divisor = 1;
        while value / divisor >= 1000 {
            divisor *= 1000;
        }
        write!(f, "{}", value / divisor)?;
        while divisor > 1 {
            divisor /= 1000;
            write!(f, "{SEPARATOR}{:03}", value / divisor % 1000)?;
        }
        Ok(())
    }
}

/// How loudly a non-zero bad-sign counter is painted: `Warn` for a condition
/// the operator should look at, `Alert` for one that is broken.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Level {
    Warn,
    Alert,
}

/// `value` painted at `level` when non-zero, plain `0` otherwise: the one
/// rendering of a [`crate::metrics::Signal`].
pub(super) struct Nonzero {
    pub(super) value: u64,
    pub(super) level: Level,
}
impl Display for Nonzero {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.level {
            Level::Warn => Display::fmt(&warn_if(Count(self.value), self.value != 0), f),
            Level::Alert => Display::fmt(&alert_if(Count(self.value), self.value != 0), f),
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
            Some(r) => write!(f, "{}", HumanFmt::RatePerSec(r.get() as u64)),
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
            // Floored at 0: the persisted delivery and download counts are
            // pruned separately (usage_retention_days), so more downloads
            // than deliveries can be on record; a hit ratio cannot be
            // negative.
            let hits = self.hits.clamp(0, self.total);
            #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
            let pct = hits as f64 / self.total as f64 * 100.0;
            write!(
                f,
                "{pct:.1}% ({} / {})",
                Count::db(hits),
                Count::db(self.total)
            )
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
    use std::fmt::Display;

    use super::{
        Age, CacheHitRatio, Count, FmtLastSeenHealth, FmtMTimeAge, Freshness, Gauge, HtmlEscape,
        Latency, Meter, Pct, RatioClass, RelTime, Saturation, Segment, Span, StackBar, Unit,
        UtcText,
    };

    /// A bar as `DetailsList::bar` places it: the svg, then the legend.
    fn render_bar(bar: &StackBar<'_>) -> String {
        bar.draw().map_or_else(String::new, |drawn| {
            format!(
                "{}<span class=\"legend\">{}</span>",
                drawn.svg(),
                drawn.legend()
            )
        })
    }

    fn segments(values: &[u64]) -> Vec<Segment> {
        const NAMES: [&str; 5] = ["a", "b", "c", "d", "e"];
        values
            .iter()
            .zip(NAMES)
            .map(|(&value, name)| Segment { name, value })
            .collect()
    }

    /// The `width` attributes of a rendered bar, in tenths.
    fn widths(svg: &str) -> Vec<u64> {
        svg.split(" width=\"")
            .skip(1)
            .map(|rest| {
                let (width, _) = rest.split_once('"').expect("quoted");
                let (whole, tenth) = width.split_once('.').expect("one decimal");
                whole.parse::<u64>().expect("whole") * 10 + tenth.parse::<u64>().expect("tenth")
            })
            .collect()
    }

    #[test]
    fn stack_bar_widths_sum_to_exactly_100() {
        for values in [
            &[1, 1, 1][..],
            &[2, 1],
            &[1, 0, 0, 0, 0],
            &[997, 1, 1, 1],
            &[u64::MAX, u64::MAX, 3],
            &[123_456, 7, 89, 1_000_000, 42],
        ] {
            let segments = segments(values);
            let svg = render_bar(&StackBar {
                label: "Split",
                segments: &segments,
                unit: Unit::Count,
            });
            assert_eq!(widths(&svg).iter().sum::<u64>(), 1000, "{values:?}: {svg}");
        }
        // Largest remainder: a third each rounds one of them up.
        let segments = segments(&[1, 1, 1]);
        let svg = render_bar(&StackBar {
            label: "Thirds",
            segments: &segments,
            unit: Unit::Count,
        });
        assert_eq!(widths(&svg), [334, 333, 333]);
    }

    #[test]
    fn stack_bar_is_labelled_and_legended() {
        let segments = [
            Segment {
                name: "hits",
                value: 3,
            },
            Segment {
                name: "misses",
                value: 1,
            },
            Segment {
                name: "never",
                value: 0,
            },
        ];
        let html = render_bar(&StackBar {
            label: "Package lookups",
            segments: &segments,
            unit: Unit::Count,
        });
        assert!(
            html.starts_with(
                "<svg class=\"stack\" viewBox=\"0 0 100 10\" preserveAspectRatio=\"none\" \
                 role=\"img\" aria-label=\"Package lookups: hits 75.0%, misses 25.0%, never 0.0%\">\
                 <rect class=\"s1\" x=\"0.0\" y=\"0\" width=\"75.0\" height=\"10\"><title>hits: 3 (75.0%)</title></rect>\
                 <rect class=\"s2\" x=\"75.0\" y=\"0\" width=\"25.0\" height=\"10\"><title>misses: 1 (25.0%)</title></rect></svg>"
            ),
            "{html}"
        );
        // A zero part draws nothing but keeps its legend entry, so the
        // legend reads the same from one refresh to the next.
        assert!(
            html.ends_with(
                "<span class=\"key s3\">never 0.0% <span class=\"muted\">(0)</span></span></span>"
            ),
            "{html}"
        );
        let bytes = [Segment {
            name: "sendfile",
            value: 2_000_000,
        }];
        assert!(
            render_bar(&StackBar {
                label: "Bytes",
                segments: &bytes,
                unit: Unit::Bytes,
            })
            .contains("<title>sendfile: 2.00MB (100.0%)</title>")
        );
    }

    #[test]
    fn a_sliver_reads_below_a_tenth_not_zero() {
        let segments = segments(&[1_000_000, 1]);
        let html = render_bar(&StackBar {
            label: "Sliver",
            segments: &segments,
            unit: Unit::Count,
        });
        assert!(
            html.contains("aria-label=\"Sliver: a 100.0%, b &lt;0.1%\""),
            "{html}"
        );
        assert!(html.contains(">b &lt;0.1% <span"), "{html}");
    }

    #[test]
    fn an_empty_stack_bar_renders_nothing() {
        let segments = segments(&[0, 0]);
        assert_eq!(
            render_bar(&StackBar {
                label: "Nothing",
                segments: &segments,
                unit: Unit::Count,
            }),
            ""
        );
    }

    /// 2023-11-14T22:13:20Z, so every rendered timestamp below is fixed.
    const NOW: i64 = 1_700_000_000;
    const DAY: i64 = 24 * 60 * 60;

    fn escape(s: &str) -> String {
        format!("{}", HtmlEscape(s))
    }

    fn render(value: impl Display) -> String {
        format!("{value}")
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

    #[test]
    fn freshness_treats_non_positive_last_seen_as_unknown() {
        // The DB writes 0 for "never seen"; a negative value is nonsense.
        assert!(matches!(Freshness::of(0, NOW), Freshness::Unknown));
        assert!(matches!(Freshness::of(-1, NOW), Freshness::Unknown));
    }

    #[test]
    fn freshness_thresholds() {
        assert!(matches!(Freshness::of(NOW, NOW), Freshness::Fresh));
        // A week is still fresh; the eighth day is not.
        assert!(matches!(
            Freshness::of(NOW - 7 * DAY, NOW),
            Freshness::Fresh
        ));
        assert!(matches!(
            Freshness::of(NOW - 8 * DAY, NOW),
            Freshness::Aging(8)
        ));
        // A month is still aging; the thirty-first day is stale.
        assert!(matches!(
            Freshness::of(NOW - 30 * DAY, NOW),
            Freshness::Aging(30)
        ));
        assert!(matches!(
            Freshness::of(NOW - 31 * DAY, NOW),
            Freshness::Stale(31)
        ));
    }

    #[test]
    fn freshness_future_timestamp_is_fresh() {
        // A clock-skewed future timestamp yields a negative age, which trips
        // neither threshold instead of wrapping into "stale".
        assert!(matches!(Freshness::of(NOW + DAY, NOW), Freshness::Fresh));
    }

    #[test]
    fn freshness_row_class_marks_only_degraded_rows() {
        assert_eq!(Freshness::Unknown.row_class(), "");
        assert_eq!(Freshness::Fresh.row_class(), "");
        assert_eq!(Freshness::Aging(8).row_class(), " class=\"row-aging\"");
        assert_eq!(Freshness::Stale(31).row_class(), " class=\"row-stale\"");
    }

    #[test]
    fn a_file_age_is_a_relative_time() {
        let mtime = std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(NOW.unsigned_abs() - 5 * DAY.unsigned_abs());
        assert_eq!(
            render(FmtMTimeAge {
                mtime: Some(mtime),
                now: NOW,
            }),
            "<time datetime=\"2023-11-09T22:13:20Z\" title=\"09 Nov 2023 22:13:20 UTC\">5 d ago</time>",
        );
        assert_eq!(
            render(FmtMTimeAge {
                mtime: None,
                now: NOW
            }),
            "N/A"
        );
    }

    #[test]
    fn a_last_seen_is_a_relative_time_with_its_staleness() {
        let rendered = render(FmtLastSeenHealth {
            last_seen: NOW - 31 * DAY,
            now_epoch: NOW,
        });
        assert!(rendered.starts_with("<time datetime="), "{rendered}");
        assert!(rendered.contains(">31 d ago</time>"), "{rendered}");
        assert!(rendered.ends_with(">stale</span>"), "{rendered}");
        assert_eq!(
            render(FmtLastSeenHealth {
                last_seen: 0,
                now_epoch: NOW,
            }),
            "N/A"
        );
    }

    #[test]
    fn meter_without_scale_renders_nothing() {
        assert_eq!(render(Meter { value: 5, max: 0 }), "");
    }

    #[test]
    fn meter_clamps_value_to_max() {
        // An over-quota cache must not emit value > max, which browsers
        // render as a full bar anyway but flag as an invalid attribute pair.
        assert_eq!(
            render(Meter { value: 12, max: 10 }),
            "<meter class=\"bar\" value=\"10\" max=\"10\"></meter>",
        );
    }

    #[test]
    fn percentages_guard_non_positive_denominators() {
        assert_eq!(render(Pct { num: 1, den: 0 }), "N/A");
        assert_eq!(render(Pct { num: 1, den: -5 }), "N/A");
        assert_eq!(render(Pct { num: 1, den: 4 }), "25.0%");
        assert_eq!(render(CacheHitRatio { hits: 1, total: 0 }), "N/A");
        assert_eq!(render(CacheHitRatio { hits: 3, total: 4 }), "75.0% (3 / 4)");
    }

    #[test]
    fn age_keeps_only_the_most_significant_unit() {
        assert_eq!(render(Age(0)), "0 s");
        assert_eq!(render(Age(59)), "59 s");
        assert_eq!(render(Age(60)), "1 min");
        assert_eq!(render(Age(3599)), "59 min");
        assert_eq!(render(Age(3600)), "1 h");
        assert_eq!(render(Age(3 * 3600 + 59 * 60)), "3 h");
        assert_eq!(render(Age(DAY.unsigned_abs())), "1 d");
        assert_eq!(render(Age(40 * DAY.unsigned_abs())), "40 d");
    }

    #[test]
    fn rel_time_renders_the_age_with_the_instant_in_its_title() {
        assert_eq!(
            render(RelTime {
                epoch: NOW - 3 * 3600,
                now: NOW,
            }),
            "<time datetime=\"2023-11-14T19:13:20Z\" title=\"14 Nov 2023 19:13:20 UTC\">3 h ago</time>",
        );
        assert_eq!(
            render(RelTime {
                epoch: NOW + 90,
                now: NOW,
            }),
            "<time datetime=\"2023-11-14T22:14:50Z\" title=\"14 Nov 2023 22:14:50 UTC\">in 1 min</time>",
        );
        assert!(
            render(RelTime {
                epoch: NOW,
                now: NOW
            })
            .contains(">just now</time>")
        );
        assert_eq!(render(RelTime { epoch: 0, now: NOW }), "N/A");
    }

    #[test]
    fn a_plain_utc_time_is_markup_free() {
        assert_eq!(render(UtcText(NOW)), "14 Nov 2023 22:13:20 UTC");
    }

    #[test]
    fn span_keeps_two_units() {
        assert_eq!(render(Span(45)), "45 s");
        assert_eq!(render(Span(60)), "1 min");
        assert_eq!(render(Span(61)), "1 min 1 s");
        assert_eq!(render(Span(2 * 3600 + 13 * 60 + 59)), "2 h 13 min");
        assert_eq!(render(Span(3 * 86_400 + 4 * 3600 + 5)), "3 d 4 h");
    }

    #[test]
    fn gauge_draws_the_cap_with_the_ratio_thresholds() {
        assert_eq!(
            render(Gauge {
                current: 3,
                cap: Some(20),
                peak: Some(20),
            }),
            "3 / 20<meter class=\"gauge\" min=\"0\" max=\"20\" low=\"9.5\" high=\"15.5\" optimum=\"0\" value=\"3\"></meter> <span class=\"peak\">peak 20</span>",
        );
        // A cap of 1 is red when full: both marks sit under it.
        assert!(
            render(Gauge {
                current: 1,
                cap: Some(1),
                peak: None,
            })
            .contains("low=\"0.5\" high=\"0.5\"")
        );
        // Over the cap (a lowered cap on reload): the bar is full, never past it.
        assert!(
            render(Gauge {
                current: 25,
                cap: Some(20),
                peak: None,
            })
            .contains("value=\"20\"")
        );
        assert_eq!(
            render(Gauge {
                current: 4,
                cap: None,
                peak: Some(9),
            }),
            "4 / unlimited <span class=\"peak\">peak 9</span>",
        );
    }

    #[test]
    fn a_latency_under_one_clock_tick_renders_as_its_floor() {
        let ms = std::time::Duration::from_millis;
        let latency = |value, resolution| render(Latency { value, resolution });
        assert_eq!(latency(ms(0), ms(1)), "&lt;1 ms");
        assert_eq!(latency(ms(0), ms(4)), "&lt;4 ms");
        // A resolution that is no whole number of milliseconds rounds up,
        // and one below a millisecond still floors at 1 ms.
        assert_eq!(
            latency(ms(0), std::time::Duration::from_micros(3_333)),
            "&lt;4 ms"
        );
        assert_eq!(
            latency(ms(0), std::time::Duration::from_micros(10)),
            "&lt;1 ms"
        );
        assert_eq!(latency(ms(4), ms(4)), "4 ms");
        // A precise sub-millisecond value is under the millisecond floor.
        assert_eq!(
            latency(std::time::Duration::from_micros(300), Latency::PRECISE),
            "&lt;1 ms"
        );
        assert_eq!(
            latency(std::time::Duration::from_micros(998_400), ms(1)),
            "998 ms"
        );
        // A coarse tick read just short of itself still reads as the tick.
        assert_eq!(
            latency(std::time::Duration::from_micros(3_999), ms(4)),
            "4 ms"
        );
        assert_eq!(latency(ms(2_345), ms(1)), "2.3 s");
        assert_eq!(latency(ms(125_000), ms(1)), "2 min 5 s");
    }

    #[test]
    fn saturation_reports_time_at_cap_and_refusal_share() {
        assert_eq!(
            render(Saturation {
                at_cap: std::time::Duration::ZERO,
                refused: 0,
                attempts: 0,
                verb: "refused",
            }),
            "never at cap",
        );
        assert_eq!(
            render(Saturation {
                at_cap: std::time::Duration::from_mins(2 * 60 + 13),
                refused: 12,
                attempts: 285,
                verb: "refused",
            }),
            "at cap 2 h 13 min; refused 4.2% (12 of 285)",
        );
    }

    #[test]
    fn counts_group_digits_from_five_on() {
        assert_eq!(render(Count(0)), "0");
        assert_eq!(render(Count(9_999)), "9999");
        assert_eq!(render(Count(10_000)), "10\u{202f}000");
        assert_eq!(render(Count(1_234_567)), "1\u{202f}234\u{202f}567");
        assert_eq!(render(Count(100_000_005)), "100\u{202f}000\u{202f}005");
        assert_eq!(
            render(Count(u64::MAX)),
            "18\u{202f}446\u{202f}744\u{202f}073\u{202f}709\u{202f}551\u{202f}615"
        );
    }

    #[test]
    fn a_hit_ratio_is_never_negative() {
        // More downloads than deliveries on record: 0 hits, not -25 %.
        assert_eq!(render(CacheHitRatio { hits: -1, total: 4 }), "0.0% (0 / 4)");
    }
}
