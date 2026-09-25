//! HTML table builders: [`Table`] for column tables, [`DetailsList`] for
//! key/value grids, the [`tr!`] row macro and the `<div class="section">`
//! wrappers the dashboard page assembles sections with.
//!
//! Every section wrapper takes a `key`: the block renders as
//! `<div class="section" data-section="{key}">` with its heading anchored at
//! `{key}-head`, and every table as `<table data-table="{key}">`. The keys
//! are what the optional scripts address (the background refresh swaps
//! sections by `data-section`; sorting remembers its order per
//! `data-table`), so a key is stable once shipped.

use std::fmt::Display;

use crate::{metrics::Signal, swrite};

use super::fmt::{HtmlEscaped, Level, Nonzero, RelTime, StackBar, now_epoch};

// ---------------------------------------------------------------------------
// Table builders — append rows directly via `swrite!`. `Table::cell` needs to
// inspect a rendered value before emitting it and reuses one scratch buffer
// for that, so no cell allocates a `String` of its own.
// ---------------------------------------------------------------------------

pub(super) struct Table {
    out: String,
    /// Reused across cells so [`Table::cell`] can inspect a rendered value
    /// without allocating per cell.
    scratch: String,
    /// Bit `i` set: column `i` holds figures, right-aligned so their digits
    /// line up (see [`Table::numeric`]).
    numeric: u64,
    /// The column the next [`Table::cell`] fills.
    column: usize,
}

impl Table {
    /// A table whose columns at `columns` hold figures -- counts, sizes,
    /// shares -- which are right-aligned (headers included) so the digits of
    /// consecutive rows line up in the tabular numerals the stylesheet sets.
    pub(super) fn numeric(key: &'static str, headers: &[&'static str], columns: &[usize]) -> Self {
        assert!(
            headers.len() <= u64::BITS as usize,
            "one bit per column in the numeric mask"
        );
        let numeric = columns.iter().fold(0_u64, |bits, &col| bits | (1 << col));
        Self::build(key, headers, numeric)
    }

    pub(super) fn new(key: &'static str, headers: &[&'static str]) -> Self {
        Self::build(key, headers, 0)
    }

    /// `key` names the table for the scripts (`data-table`); see the module
    /// docs.
    fn build(key: &'static str, headers: &[&'static str], numeric: u64) -> Self {
        // Realistic dashboard tables (Mirrors, Origins) easily exceed 10 KB.
        // Pre-size to skip the reallocation chain.
        let mut out = String::with_capacity(16 * 1024);
        // The wrapper is what scrolls when the table is wider than its
        // section; without it a wide table forces a page-wide scrollbar.
        swrite!(
            out,
            "<div class=\"tablewrap\"><table data-table=\"{key}\"><thead><tr>"
        );
        for (col, h) in headers.iter().enumerate() {
            out.push_str(if numeric & (1 << col) == 0 {
                "<th scope=\"col\">"
            } else {
                "<th scope=\"col\" class=\"num\">"
            });
            out.push_str(h);
            out.push_str("</th>");
        }
        out.push_str("</tr></thead><tbody>");
        Self {
            out,
            scratch: String::with_capacity(128),
            numeric,
            column: 0,
        }
    }

    pub(super) fn start_row(&mut self) {
        self.column = 0;
        self.out.push_str("<tr>");
    }

    /// Start a row carrying a state class, which the stylesheet paints as a
    /// rule down the row's leading edge. `attr` is a whole ` class="..."`
    /// fragment (see `fmt::Freshness::row_class`), empty for no marker.
    pub(super) fn start_row_marked(&mut self, attr: &'static str) {
        self.column = 0;
        swrite!(self.out, "<tr{attr}>");
    }

    /// Cell contents longer than this get a `title` attribute repeating the
    /// full value. The stylesheet truncates cells at 220px, which is roughly
    /// 30 characters at the table font size; the lower bound errs towards
    /// titling a cell that would have fitted rather than missing one that
    /// gets an ellipsis.
    const TITLE_THRESHOLD: usize = 24;

    /// Append a cell. A value that renders as plain text also goes into a
    /// `title` attribute, which is the only way to read it once the
    /// stylesheet has truncated it — the cell text alone is unreachable by
    /// keyboard and touch. Values that render markup (`<time>`, a colourised
    /// `<span>`) cannot be reused verbatim in an attribute, so they are
    /// emitted bare.
    pub(super) fn cell(&mut self, value: impl Display) {
        self.cell_keyed(value, None::<SortKey<'_>>);
    }

    /// [`Self::cell`] with the value the optional table sorting orders the
    /// column by, as `data-sort`: the figure behind a rendering that does
    /// not sort as text (a size, a relative time, a grouped count, a
    /// composite like `1.2GB (345)`). `None` marks a cell without a value
    /// (rendered `N/A`), which sorts last.
    pub(super) fn cell_keyed<'k>(
        &mut self,
        value: impl Display,
        key: Option<impl Into<SortKey<'k>>>,
    ) {
        let Self {
            out,
            scratch,
            numeric,
            column,
        } = self;
        scratch.clear();
        swrite!(scratch, "{value}");
        let class = if *numeric & (1 << *column) == 0 {
            ""
        } else {
            " class=\"num\""
        };
        *column += 1;

        swrite!(out, "<td{class}");
        if let Some(key) = key {
            swrite!(out, " data-sort=\"{}\"", key.into());
        }
        if scratch.len() > Self::TITLE_THRESHOLD && !scratch.contains('<') {
            swrite!(out, " title=\"{scratch}\"");
        }
        swrite!(out, ">{scratch}</td>");
    }

    pub(super) fn end_row(&mut self) {
        self.out.push_str("</tr>");
    }

    pub(super) fn finish(mut self) -> String {
        self.out.push_str("</tbody></table></div>");
        self.out
    }
}

/// Append a row of cells, each formatted via `format_args!`. The `marked`
/// form carries a state class on the `<tr>`. A cell written
/// `value => key` carries its sort key (an `Option`, see
/// [`Table::cell_keyed`]).
macro_rules! tr {
    (@cell $t:ident, $cell:expr => $key:expr) => {
        $t.cell_keyed(format_args!("{}", $cell), $key)
    };
    (@cell $t:ident, $cell:expr) => {
        $t.cell(format_args!("{}", $cell))
    };
    ($table:expr, $($cell:expr $(=> $key:expr)?),* $(,)?) => {{
        let t = &mut $table;
        t.start_row();
        $( tr!(@cell t, $cell $(=> $key)?); )*
        t.end_row();
    }};
    (marked $attr:expr, $table:expr, $($cell:expr $(=> $key:expr)?),* $(,)?) => {{
        let t = &mut $table;
        t.start_row_marked($attr);
        $( tr!(@cell t, $cell $(=> $key)?); )*
        t.end_row();
    }};
}
pub(super) use tr;

/// A table cell's sort value ([`Table::cell_keyed`]): a figure, or text,
/// which is HTML-escaped on output, so no caller can forget to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SortKey<'a> {
    Number(i128),
    Text(&'a str),
}

impl Display for SortKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Number(number) => Display::fmt(&number, f),
            Self::Text(text) => Display::fmt(&HtmlEscaped(text), f),
        }
    }
}

impl<'a> From<&'a str> for SortKey<'a> {
    fn from(text: &'a str) -> Self {
        Self::Text(text)
    }
}

impl From<i128> for SortKey<'_> {
    fn from(number: i128) -> Self {
        Self::Number(number)
    }
}

impl From<u128> for SortKey<'_> {
    fn from(number: u128) -> Self {
        Self::Number(i128::try_from(number).unwrap_or(i128::MAX))
    }
}

impl From<i64> for SortKey<'_> {
    fn from(number: i64) -> Self {
        Self::Number(number.into())
    }
}

impl From<u64> for SortKey<'_> {
    fn from(number: u64) -> Self {
        Self::Number(number.into())
    }
}

impl From<usize> for SortKey<'_> {
    fn from(number: usize) -> Self {
        Self::Number(i128::try_from(number).unwrap_or(i128::MAX))
    }
}

/// A timestamp column's sort key: the epoch, `None` for the `0` the
/// dashboard renders as `N/A`.
pub(super) fn when(epoch: i64) -> Option<i64> {
    (epoch > 0).then_some(epoch)
}

/// Key-value list with grid layout.
///
/// A `<dl>` rather than a `<table>`: the grid needs `display: contents` on
/// the row container, which strips a table of its roles in the accessibility
/// tree and so loses every label-to-value association. A description list
/// carries that association in the markup itself and survives the same CSS.
pub(super) struct DetailsList {
    out: String,
    /// The wall-clock second every relative time in this list is measured
    /// against, read once so two rows cannot disagree about "now".
    now: i64,
    /// How many of this list's rows are highlighted; see [`Highlights`].
    highlights: Highlights,
}

/// Rows painted as alerts or warnings, for the Metrics section's badge.
///
/// A row counts once, at its worst level, its parts included: a status
/// class and the code beneath it that moved are one thing to look at, not
/// two. Counted from the rendered row -- a highlight is exactly a
/// `class="alert"` / `class="warn"` span -- so the count cannot drift from
/// what the page paints.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Highlights {
    pub(super) alerts: usize,
    pub(super) warnings: usize,
}

impl Highlights {
    fn count_row(&mut self, row: &str) {
        if row.contains("class=\"alert\"") {
            self.alerts += 1;
        } else if row.contains("class=\"warn\"") {
            self.warnings += 1;
        }
    }

    pub(super) fn add(&mut self, other: Self) {
        let Self { alerts, warnings } = other;
        self.alerts += alerts;
        self.warnings += warnings;
    }
}

impl Display for Highlights {
    /// `2 alerts / 5 warnings`, each figure painted at its level once
    /// non-zero.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { alerts, warnings } = *self;
        let plural = |n: usize| if n == 1 { "" } else { "s" };
        if alerts > 0 {
            write!(
                f,
                "<span class=\"alert\">{alerts} alert{}</span>",
                plural(alerts)
            )?;
        } else {
            f.write_str("0 alerts")?;
        }
        f.write_str(" / ")?;
        if warnings > 0 {
            write!(
                f,
                "<span class=\"warn\">{warnings} warning{}</span>",
                plural(warnings)
            )
        } else {
            f.write_str("0 warnings")
        }
    }
}

impl DetailsList {
    pub(super) fn new() -> Self {
        Self::with_now(now_epoch())
    }

    /// A list whose relative times are measured against `now`: tests pin it.
    pub(super) fn with_now(now: i64) -> Self {
        Self::open("details", now)
    }

    fn open(class: &'static str, now: i64) -> Self {
        let mut out = String::with_capacity(1024);
        swrite!(out, "<dl class=\"{class}\">");
        Self {
            out,
            now,
            highlights: Highlights::default(),
        }
    }

    pub(super) fn row(&mut self, label: &'static str, value: impl Display) {
        self.entry(label).value(value);
    }

    /// Like [`Self::row`], but renders the label with a `title` tooltip
    /// shown when the user hovers over it. See [`Entry::tip`].
    pub(super) fn row_tip(
        &mut self,
        label: &'static str,
        tooltip: &'static str,
        value: impl Display,
    ) {
        self.entry(label).tip(tooltip).value(value);
    }

    /// A bad-sign counter: its value painted at `level` once non-zero, with
    /// the time it last moved beside it.
    pub(super) fn signal(
        &mut self,
        label: &'static str,
        tooltip: &'static str,
        level: Level,
        signal: &Signal,
    ) {
        self.entry(label).tip(tooltip).signal(level, signal);
    }

    /// A full-width row showing how a total splits: the label, then the bar
    /// and its legend (see [`StackBar`]). Nothing while the total is zero.
    pub(super) fn bar(&mut self, bar: &StackBar<'_>) {
        if let Some(drawn) = bar.draw() {
            swrite!(
                self.out,
                "<div class=\"whole chart\"><dt>{}</dt><dd>{}</dd><dd class=\"legend\">{}</dd></div>",
                bar.label,
                drawn.svg(),
                drawn.legend(),
            );
        }
    }

    /// Start a row whose shape the returned [`Entry`] refines; nothing is
    /// written until [`Entry::value`].
    pub(super) fn entry(&mut self, label: &'static str) -> Entry<'_> {
        Entry {
            list: self,
            label,
            tip: None,
            parts: None,
            last: None,
            note: None,
            kind: Kind::Plain,
        }
    }

    pub(super) fn finish(self) -> String {
        self.finish_counted().0
    }

    /// [`Self::finish`], with how many rows are highlighted.
    pub(super) fn finish_counted(mut self) -> (String, Highlights) {
        self.out.push_str("</dl>");
        (self.out, self.highlights)
    }
}

/// What kind of figure a row shows, so values of different time scopes
/// cannot be read as one another. Rendered as a class on the row, which the
/// stylesheet turns into a small chip after the label.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum Kind {
    /// A counter since the daemon started (the Metrics section's default),
    /// or a value that needs no chip (a version, a config value).
    #[default]
    Plain,
    /// Read now: a gauge, a live count.
    Live,
    /// The maximum since the daemon started.
    Peak,
    /// From the database, surviving restarts.
    Persisted,
}

impl Kind {
    const fn class(self) -> Option<&'static str> {
        match self {
            Self::Plain => None,
            Self::Live => Some("k-live"),
            Self::Peak => Some("k-peak"),
            Self::Persisted => Some("k-db"),
        }
    }
}

/// One `<dt>`/`<dd>` row of a [`DetailsList`] under construction.
#[must_use = "a row is only written by `value`"]
pub(super) struct Entry<'a> {
    list: &'a mut DetailsList,
    label: &'static str,
    tip: Option<&'static str>,
    /// The rows this one is the total of, already rendered (see
    /// [`Entry::parts`]).
    parts: Option<String>,
    last: Option<u64>,
    /// A line of context under the value (see [`Entry::note`]).
    note: Option<String>,
    kind: Kind,
}

impl Entry<'_> {
    /// The label's `title` tooltip, marked by a dotted underline, and the
    /// same text behind a `?` disclosure for touch screens, which have no
    /// hover. Interpolated without HTML-escaping; the `&'static str` bound
    /// keeps user-controlled values out.
    pub(super) fn tip(mut self, tip: &'static str) -> Self {
        self.tip = Some(tip);
        self
    }

    /// The rows this one is the total of -- the codes of a status class,
    /// the causes of an abort count -- rendered indented beneath its value,
    /// inside its own cell. A nested list, not rows of the enclosing grid:
    /// the grid flows left to right, so a "part" placed after its total
    /// would land beside it, or on the next line under an unrelated cell.
    pub(super) fn parts(mut self, build: impl FnOnce(&mut DetailsList)) -> Self {
        let mut parts = DetailsList::open("parts", self.list.now);
        build(&mut parts);
        self.parts = Some(parts.finish());
        self
    }

    /// Render a bad-sign counter: its value painted at `level` once non-zero,
    /// with the time it last moved.
    pub(super) fn signal(self, level: Level, signal: &Signal) {
        let value = signal.get();
        self.last(signal.last()).value(Nonzero { value, level });
    }

    /// When the counter this row shows last moved (Unix seconds), rendered
    /// as a second `<dd>` ("last: 3 h ago") so the value cell itself stays
    /// the bare figure.
    pub(super) fn last(mut self, last: Option<u64>) -> Self {
        self.last = last;
        self
    }

    /// What kind of figure this is (live, peak, persisted); see [`Kind`].
    pub(super) fn kind(mut self, kind: Kind) -> Self {
        self.kind = kind;
        self
    }

    /// A line of context under the value, e.g. how long a limiter spent at
    /// its cap: a second `<dd>`, so the value cell stays the bare figure.
    pub(super) fn note(mut self, note: impl Display) -> Self {
        let mut rendered = String::new();
        swrite!(rendered, "{note}");
        self.note = Some(rendered);
        self
    }

    pub(super) fn value(self, value: impl Display) {
        let Self {
            list,
            label,
            tip,
            parts,
            last,
            note,
            kind,
        } = self;
        let DetailsList {
            out,
            now,
            highlights,
        } = list;
        let row_start = out.len();
        match (parts.is_some(), kind.class()) {
            (false, None) => out.push_str("<div><dt"),
            (true, None) => out.push_str("<div class=\"whole\"><dt"),
            (false, Some(kind)) => swrite!(out, "<div class=\"{kind}\"><dt"),
            (true, Some(kind)) => swrite!(out, "<div class=\"whole {kind}\"><dt"),
        }
        if let Some(tip) = tip {
            swrite!(out, " title=\"{tip}\"");
        }
        swrite!(out, ">{label}</dt><dd>{value}</dd>");
        if let Some(tip) = tip {
            // The title only shows on hover, which a touch screen has not:
            // the same text behind a disclosure the stylesheet shows there.
            swrite!(
                out,
                "<dd class=\"help\"><details><summary title=\"What is this?\">?</summary>{tip}</details></dd>"
            );
        }
        if let Some(last) = last {
            swrite!(
                out,
                "<dd class=\"last\">last: {}</dd>",
                RelTime {
                    epoch: i64::try_from(last).unwrap_or(i64::MAX),
                    now: *now,
                }
            );
        }
        if let Some(note) = note {
            swrite!(out, "<dd class=\"note\">{note}</dd>");
        }
        if let Some(parts) = parts {
            swrite!(out, "<dd class=\"parts\">{parts}</dd>");
        }
        out.push_str("</div>");
        highlights.count_row(out.get(row_start..).unwrap_or_default());
    }
}

/// Append a `<div class="section">` wrapping a titled HTML body; `key`
/// names the section (see the module docs).
pub(super) fn write_section(out: &mut String, title: &'static str, key: &'static str, body: &str) {
    swrite!(
        out,
        "<div class=\"section\" data-section=\"{key}\"><h2 id=\"{key}-head\">{title}</h2>{body}</div>"
    );
}

/// Append a titled `<details>` section around an already-rendered body.
///
/// The row-table sections go through [`write_collapsible_section`], which
/// derives `open` from the row count and needs an empty-state note; this is
/// for the key/value sections, whose disclosure state is an editorial call
/// about how much the reader needs them.
///
/// `pin` is the header's keep-open link (`page::PinLink`), rendered after
/// the title.
pub(super) fn write_collapsible_details(
    out: &mut String,
    title: &'static str,
    key: &'static str,
    open: bool,
    pin: impl Display,
    body: &str,
) {
    write_collapsible_details_badged(out, title, key, open, "", pin, body);
}

/// [`write_collapsible_details`] with `badge` beside the title, readable
/// while the section is collapsed.
pub(super) fn write_collapsible_details_badged(
    out: &mut String,
    title: &'static str,
    key: &'static str,
    open: bool,
    badge: impl Display,
    pin: impl Display,
    body: &str,
) {
    let open_attr = if open { " open" } else { "" };
    let mut badge_html = String::new();
    swrite!(badge_html, "{badge}");
    let badge_wrapped = if badge_html.is_empty() {
        String::new()
    } else {
        format!(" <span class=\"count\">{badge_html}</span>")
    };
    swrite!(
        out,
        "<div class=\"section\" data-section=\"{key}\"><details{open_attr}>\
         <summary><h2 id=\"{key}-head\">{title}</h2>{badge_wrapped} {pin}</summary>\
         {body}</details></div>"
    );
}

/// A row table's count chip: the rows shown, and the most it can hold when
/// it is capped (`3 / 20`).
#[derive(Clone, Copy)]
pub(super) struct Rows {
    pub(super) shown: usize,
    pub(super) total: Option<usize>,
}

/// Append a collapsible `<details>` section. Expanded when it has rows, or
/// when the reader pinned it open (`pinned`, from `open=`).
///
/// `empty_note` is what the section says when it has no rows. A section that
/// renders nothing at all leaves a first run looking broken rather than
/// idle, so every caller has to say what "no rows" means for its data.
pub(super) fn write_collapsible_section(
    out: &mut String,
    title: &'static str,
    key: &'static str,
    rows: Rows,
    pinned: bool,
    empty_note: &'static str,
    body: &str,
) {
    let Rows {
        shown: row_count,
        total: total_count,
    } = rows;
    let open_attr = if row_count > 0 || pinned { " open" } else { "" };
    let total_count_fmt = match total_count {
        Some(total) => format!(" / {total}"),
        None => String::new(),
    };
    swrite!(
        out,
        "<div class=\"section\" data-section=\"{key}\"><details{open_attr}>\
         <summary><h2 id=\"{key}-head\">{title}</h2>\
         <span class=\"count\">{row_count}{total_count_fmt}</span></summary>\
         {}</details></div>",
        EmptyOr {
            body,
            note: empty_note,
        },
    );
}

/// Renders `body`, or the empty-state note in its place when the body is
/// empty. The row count is not consulted: a section with rows always has a
/// body, and one with a non-empty body (a per-section error notice, say)
/// wants that body shown even at zero rows.
struct EmptyOr<'a> {
    body: &'a str,
    note: &'static str,
}

impl Display for EmptyOr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.body.is_empty() {
            write!(f, "<p class=\"empty\">{}</p>", self.note)
        } else {
            f.write_str(self.body)
        }
    }
}

/// Per-section error placeholder (so a single failed query doesn't kill the page).
pub(super) fn write_section_error(out: &mut String, what: &'static str, err: &sqlx::Error) {
    swrite!(
        out,
        "<p class=\"section-error\">Failed to query {what}: {}</p>",
        HtmlEscaped(err),
    );
}

#[cfg(test)]
mod tests {
    use super::{
        DetailsList, Highlights, Kind, Rows, Table, when, write_collapsible_details_badged,
        write_collapsible_section, write_section,
    };
    use crate::web::fmt::{Level, Nonzero};

    #[test]
    fn table_wraps_header_row() {
        let html = Table::new("t", &["A", "B"]).finish();
        assert_eq!(
            html,
            "<div class=\"tablewrap\"><table data-table=\"t\"><thead><tr>\
             <th scope=\"col\">A</th><th scope=\"col\">B</th>\
             </tr></thead><tbody></tbody></table></div>",
        );
    }

    #[test]
    fn cell_titles_only_long_plain_values() {
        let long = "a value well past the title threshold";
        let mut table = Table::new("t", &["H"]);
        table.start_row();
        table.cell("short");
        table.cell(long);
        // Markup must not be repeated into the attribute: the browser would
        // show the tags as text.
        table.cell(format_args!("<span class=\"warn\">{long}</span>"));
        table.end_row();
        let html = table.finish();

        assert!(html.contains("<td>short</td>"), "{html}");
        assert!(
            html.contains(&format!("<td title=\"{long}\">{long}</td>")),
            "{html}"
        );
        assert!(!html.contains("title=\"<span"), "{html}");
    }

    #[test]
    fn numeric_columns_are_marked_in_header_and_cells() {
        let mut table = Table::numeric("t", &["Name", "Count"], &[1]);
        for _ in 0..2 {
            table.start_row();
            table.cell("a");
            table.cell(7);
            table.end_row();
        }
        let html = table.finish();
        assert!(
            html.contains("<th scope=\"col\">Name</th><th scope=\"col\" class=\"num\">Count</th>"),
            "{html}"
        );
        // The column restarts with every row.
        assert_eq!(
            html.matches("<tr><td>a</td><td class=\"num\">7</td></tr>")
                .count(),
            2,
            "{html}"
        );
    }

    #[test]
    fn keyed_cells_carry_their_sort_value() {
        let mut table = Table::numeric("t", &["Name", "Size", "Seen", "Plain"], &[1]);
        let long = "a value well past the title threshold";
        tr!(
            table,
            long => Some("sortable <name>"),
            "1.23kB (4)" => Some(1234_u64),
            "N/A" => when(0),
            7,
        );
        let html = table.finish();
        assert!(
            html.contains(&format!(
                "<tr><td data-sort=\"sortable &lt;name&gt;\" title=\"{long}\">{long}</td>\
                 <td class=\"num\" data-sort=\"1234\">1.23kB (4)</td>\
                 <td>N/A</td><td>7</td></tr>"
            )),
            "{html}"
        );
        assert_eq!(when(1_700_000_000), Some(1_700_000_000));
    }

    #[test]
    fn marked_row_carries_its_state_class() {
        let mut table = Table::new("t", &["H"]);
        table.start_row_marked(" class=\"row-stale\"");
        table.cell("x");
        table.end_row();
        assert!(
            table
                .finish()
                .contains("<tr class=\"row-stale\"><td>x</td></tr>"),
            "marked row lost its class",
        );
    }

    #[test]
    fn details_list_pairs_label_and_value() {
        let mut list = DetailsList::new();
        list.row("Label", 7);
        list.row_tip("Tipped", "why", "v");
        assert_eq!(
            list.finish(),
            "<dl class=\"details\">\
             <div><dt>Label</dt><dd>7</dd></div>\
             <div><dt title=\"why\">Tipped</dt><dd>v</dd>\
             <dd class=\"help\"><details><summary title=\"What is this?\">?</summary>why</details></dd></div>\
             </dl>",
        );
    }

    #[test]
    fn a_signal_row_carries_its_last_occurrence_beside_the_value() {
        /// 2023-11-14T22:13:20Z.
        const NOW: i64 = 1_700_000_000;
        let mut list = DetailsList::with_now(NOW);
        list.entry("Moved")
            .tip("why")
            .last(Some(NOW.unsigned_abs() - 120))
            .value(Nonzero {
                value: 3,
                level: Level::Warn,
            });
        list.entry("Never").last(None).value(0);
        let html = list.finish();
        // The value cell stays the bare figure; the stamp is its own `<dd>`.
        assert!(
            html.contains(
                "<div><dt title=\"why\">Moved</dt><dd><span class=\"warn\">3</span></dd>\
                 <dd class=\"help\"><details><summary title=\"What is this?\">?</summary>why</details></dd>\
                 <dd class=\"last\">last: <time datetime=\"2023-11-14T22:11:20Z\" \
                 title=\"14 Nov 2023 22:11:20 UTC\">2 min ago</time></dd></div>"
            ),
            "{html}"
        );
        assert!(
            html.contains("<div><dt>Never</dt><dd>0</dd></div>"),
            "{html}"
        );
    }

    #[test]
    fn a_total_renders_its_parts_nested_in_its_own_cell() {
        let mut list = DetailsList::with_now(0);
        list.entry("Total")
            .parts(|p| {
                p.row("Part A", 1);
                p.row("Part B", 2);
            })
            .value(3);
        assert_eq!(
            list.finish(),
            "<dl class=\"details\"><div class=\"whole\"><dt>Total</dt><dd>3</dd>\
             <dd class=\"parts\"><dl class=\"parts\">\
             <div><dt>Part A</dt><dd>1</dd></div><div><dt>Part B</dt><dd>2</dd></div>\
             </dl></dd></div></dl>",
        );
    }

    #[test]
    fn a_row_counts_once_at_its_worst_level_parts_included() {
        let mut list = DetailsList::with_now(0);
        list.row("Plain", 0);
        list.entry("Warned").value(Nonzero {
            value: 2,
            level: Level::Warn,
        });
        // A warned total with an alerted part is one alert.
        list.entry("Total")
            .parts(|p| {
                p.entry("Part").value(Nonzero {
                    value: 1,
                    level: Level::Alert,
                });
            })
            .value(Nonzero {
                value: 1,
                level: Level::Warn,
            });
        let (_, highlights) = list.finish_counted();
        assert_eq!(
            highlights,
            Highlights {
                alerts: 1,
                warnings: 1,
            }
        );
    }

    #[test]
    fn the_badge_paints_only_non_zero_figures() {
        assert_eq!(Highlights::default().to_string(), "0 alerts / 0 warnings");
        assert_eq!(
            Highlights {
                alerts: 1,
                warnings: 3,
            }
            .to_string(),
            "<span class=\"alert\">1 alert</span> / <span class=\"warn\">3 warnings</span>",
        );
    }

    #[test]
    fn a_row_carries_its_kind_as_a_class() {
        let mut list = DetailsList::with_now(0);
        list.entry("Now").kind(Kind::Live).value(1);
        list.entry("Max").kind(Kind::Peak).value(2);
        list.entry("Stored").kind(Kind::Persisted).value(3);
        list.entry("Count").kind(Kind::Plain).value(4);
        let html = list.finish();
        for needle in [
            "<div class=\"k-live\"><dt>Now</dt>",
            "<div class=\"k-peak\"><dt>Max</dt>",
            "<div class=\"k-db\"><dt>Stored</dt>",
            "<div><dt>Count</dt>",
        ] {
            assert!(html.contains(needle), "{needle}: {html}");
        }
    }

    /// Every wrapper names its block for the scripts and anchors its
    /// heading at `{key}-head`, which the nav links and `open=` rely on.
    #[test]
    fn sections_carry_their_key_and_heading_anchor() {
        let mut out = String::new();
        write_section(&mut out, "Plain", "plain", "<p>b</p>");
        assert_eq!(
            out,
            "<div class=\"section\" data-section=\"plain\"><h2 id=\"plain-head\">Plain</h2><p>b</p></div>"
        );
        let mut out = String::new();
        write_collapsible_details_badged(&mut out, "Folded", "folded", false, "3", "", "<p>b</p>");
        assert!(
            out.starts_with(
                "<div class=\"section\" data-section=\"folded\"><details><summary><h2 id=\"folded-head\">Folded</h2>"
            ),
            "{out}"
        );
        let mut out = String::new();
        write_collapsible_section(
            &mut out,
            "Rows",
            "rows",
            Rows {
                shown: 1,
                total: None,
            },
            false,
            "none",
            "<p>b</p>",
        );
        assert!(
            out.starts_with(
                "<div class=\"section\" data-section=\"rows\"><details open><summary><h2 id=\"rows-head\">Rows</h2>"
            ),
            "{out}"
        );
    }

    #[test]
    fn collapsible_section_notes_an_empty_body() {
        let mut out = String::new();
        write_collapsible_section(
            &mut out,
            "T",
            "t",
            Rows {
                shown: 0,
                total: None,
            },
            false,
            "nothing yet",
            "",
        );
        assert!(out.contains("<p class=\"empty\">nothing yet</p>"), "{out}");
        // Nothing to read: the section starts collapsed, with a 0 count.
        assert!(!out.contains("<details open>"), "{out}");
        assert!(out.contains("<span class=\"count\">0</span>"), "{out}");
    }

    #[test]
    fn collapsible_section_keeps_a_populated_body() {
        let mut out = String::new();
        write_collapsible_section(
            &mut out,
            "T",
            "t",
            Rows {
                shown: 2,
                total: Some(5),
            },
            false,
            "nothing yet",
            "<p>b</p>",
        );
        assert!(out.contains("<details open>"), "{out}");
        assert!(out.contains("<span class=\"count\">2 / 5</span>"), "{out}");
        assert!(out.contains("<p>b</p>"), "{out}");
        assert!(!out.contains("nothing yet"), "{out}");
    }

    #[test]
    fn collapsible_section_keeps_an_error_notice_with_zero_rows() {
        // A section error reports 0 rows but must not be replaced by the
        // empty-state note: the notice is the thing the reader needs.
        let mut out = String::new();
        write_collapsible_section(
            &mut out,
            "T",
            "t",
            Rows {
                shown: 0,
                total: None,
            },
            false,
            "nothing yet",
            "<p>boom</p>",
        );
        assert!(out.contains("<p>boom</p>"), "{out}");
        assert!(!out.contains("nothing yet"), "{out}");
    }

    #[test]
    fn a_pinned_section_opens_even_empty() {
        let mut out = String::new();
        write_collapsible_section(
            &mut out,
            "T",
            "t",
            Rows {
                shown: 0,
                total: None,
            },
            true,
            "nothing yet",
            "",
        );
        assert!(out.contains("<details open>"), "{out}");
    }
}
