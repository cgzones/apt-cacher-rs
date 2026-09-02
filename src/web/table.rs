//! HTML table builders: [`Table`] for column tables, [`DetailsTable`] for
//! key/value grids, the [`tr!`] row macro and the `<div class="section">`
//! wrappers the dashboard page assembles sections with.

use std::fmt::Display;

use crate::swrite;

use super::fmt::HtmlEscape;

// ---------------------------------------------------------------------------
// Table builders — append rows directly via `swrite!`, no per-cell allocation.
// ---------------------------------------------------------------------------

pub(super) struct Table {
    out: String,
    /// Reused across cells so [`Table::cell`] can inspect a rendered value
    /// without allocating per cell.
    scratch: String,
}

impl Table {
    pub(super) fn new(headers: &[&'static str]) -> Self {
        // Realistic dashboard tables (Mirrors, Origins) easily exceed 10 KB.
        // Pre-size to skip the reallocation chain.
        let mut out = String::with_capacity(16 * 1024);
        // The wrapper is what scrolls when the table is wider than its
        // section; without it a wide table forces a page-wide scrollbar.
        out.push_str("<div class=\"tablewrap\"><table><thead><tr>");
        for h in headers {
            out.push_str("<th scope=\"col\">");
            out.push_str(h);
            out.push_str("</th>");
        }
        out.push_str("</tr></thead><tbody>");
        Self {
            out,
            scratch: String::with_capacity(128),
        }
    }

    pub(super) fn start_row(&mut self) {
        self.out.push_str("<tr>");
    }

    /// Start a row carrying a state class, which the stylesheet paints as a
    /// rule down the row's leading edge. `attr` is a whole ` class="..."`
    /// fragment (see `fmt::Freshness::row_class`), empty for no marker.
    pub(super) fn start_row_marked(&mut self, attr: &'static str) {
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
        let Self { out, scratch } = self;
        scratch.clear();
        swrite!(scratch, "{value}");

        if scratch.len() > Self::TITLE_THRESHOLD && !scratch.contains('<') {
            swrite!(out, "<td title=\"{scratch}\">{scratch}</td>");
        } else {
            swrite!(out, "<td>{scratch}</td>");
        }
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
/// form carries a state class on the `<tr>`.
macro_rules! tr {
    ($table:expr, $($cell:expr),* $(,)?) => {{
        let t = &mut $table;
        t.start_row();
        $( t.cell(format_args!("{}", $cell)); )*
        t.end_row();
    }};
    (marked $attr:expr, $table:expr, $($cell:expr),* $(,)?) => {{
        let t = &mut $table;
        t.start_row_marked($attr);
        $( t.cell(format_args!("{}", $cell)); )*
        t.end_row();
    }};
}
pub(super) use tr;

/// Key-value list with grid layout.
///
/// A `<dl>` rather than a `<table>`: the grid needs `display: contents` on
/// the row container, which strips a table of its roles in the accessibility
/// tree and so loses every label-to-value association. A description list
/// carries that association in the markup itself and survives the same CSS.
pub(super) struct DetailsList {
    out: String,
}

impl DetailsList {
    pub(super) fn new() -> Self {
        let mut out = String::with_capacity(1024);
        out.push_str("<dl class=\"details\">");
        Self { out }
    }

    pub(super) fn row(&mut self, label: &'static str, value: impl Display) {
        swrite!(self.out, "<div><dt>{label}</dt><dd>{value}</dd></div>");
    }

    /// Like [`Self::row`], but renders the label with a `title` tooltip
    /// shown when the user hovers over it. The `tooltip` is interpolated
    /// directly into the `title=""` attribute without HTML-escaping; the
    /// `&'static str` bound prevents user-controlled values from sneaking
    /// in.
    pub(super) fn row_tip(
        &mut self,
        label: &'static str,
        tooltip: &'static str,
        value: impl Display,
    ) {
        swrite!(
            self.out,
            "<div><dt title=\"{tooltip}\">{label}</dt><dd>{value}</dd></div>"
        );
    }

    pub(super) fn finish(mut self) -> String {
        self.out.push_str("</dl>");
        self.out
    }
}

/// Append a `<div class="section">` wrapping a titled HTML body.
pub(super) fn write_section(out: &mut String, title: &'static str, body: &str) {
    swrite!(out, "<div class=\"section\"><h2>{title}</h2>{body}</div>");
}

/// Append a titled `<details>` section around an already-rendered body.
///
/// The row-table sections go through [`write_collapsible_section`], which
/// derives `open` from the row count and needs an empty-state note; this is
/// for the key/value sections, whose disclosure state is an editorial call
/// about how much the reader needs them.
pub(super) fn write_collapsible_details(
    out: &mut String,
    title: &'static str,
    id: &'static str,
    open: bool,
    body: &str,
) {
    let open_attr = if open { " open" } else { "" };
    swrite!(
        out,
        "<div class=\"section\"><details{open_attr}>\
         <summary><h2 id=\"{id}\">{title}</h2></summary>\
         {body}</details></div>"
    );
}

/// Append a collapsible `<details>` section. Expanded by default unless empty.
///
/// `empty_note` is what the section says when it has no rows. A section that
/// renders nothing at all leaves a first run looking broken rather than
/// idle, so every caller has to say what "no rows" means for its data.
pub(super) fn write_collapsible_section(
    out: &mut String,
    title: &'static str,
    id: &'static str,
    row_count: usize,
    total_count: Option<usize>,
    empty_note: &'static str,
    body: &str,
) {
    let open_attr = if row_count > 0 { " open" } else { "" };
    let total_count_fmt = match total_count {
        Some(total) => format!(" / {total}"),
        None => String::new(),
    };
    swrite!(
        out,
        "<div class=\"section\"><details{open_attr}>\
         <summary><h2 id=\"{id}\">{title}</h2>\
         <span class=\"count\">{row_count}{total_count_fmt}</span></summary>\
         {}</details></div>",
        EmptyOr {
            body,
            note: empty_note,
            rows: row_count,
        },
    );
}

/// Renders `body`, or the empty-state note in its place when there are no
/// rows to show.
struct EmptyOr<'a> {
    body: &'a str,
    note: &'static str,
    rows: usize,
}

impl Display for EmptyOr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.rows == 0 && self.body.is_empty() {
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
        HtmlEscape(&err.to_string()),
    );
}
