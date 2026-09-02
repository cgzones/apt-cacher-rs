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
}

impl Table {
    pub(super) fn new(headers: &[&'static str]) -> Self {
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

    pub(super) fn start_row(&mut self) {
        self.out.push_str("<tr>");
    }

    pub(super) fn cell(&mut self, value: impl Display) {
        swrite!(self.out, "<td>{value}</td>");
    }

    pub(super) fn end_row(&mut self) {
        self.out.push_str("</tr>");
    }

    pub(super) fn finish(mut self) -> String {
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
pub(super) use tr;

/// Key-value details table with grid layout.
pub(super) struct DetailsTable {
    out: String,
}

impl DetailsTable {
    pub(super) fn new() -> Self {
        let mut out = String::with_capacity(1024);
        out.push_str("<table class=\"details\"><thead></thead><tbody>");
        Self { out }
    }

    pub(super) fn row(&mut self, label: &'static str, value: impl Display) {
        swrite!(self.out, "<tr><td>{label}</td><td>{value}</td></tr>");
    }

    /// Like [`Self::row`], but renders the label cell with a `title` tooltip
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
            "<tr><td title=\"{tooltip}\">{label}</td><td>{value}</td></tr>"
        );
    }

    pub(super) fn finish(mut self) -> String {
        self.out.push_str("</tbody></table>");
        self.out
    }
}

/// Append a `<div class="section">` wrapping a titled HTML body.
pub(super) fn write_section(out: &mut String, title: &'static str, body: &str) {
    swrite!(out, "<div class=\"section\"><h3>{title}</h3>{body}</div>");
}

/// Append a collapsible `<details>` section. Expanded by default unless empty.
pub(super) fn write_collapsible_section(
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
    swrite!(
        out,
        "<div class=\"section\"><details{open_attr}>\
         <summary><h3 id=\"{id}\">{title}</h3>\
         <span class=\"count\">{row_count}{total_count_fmt}</span></summary>\
         {body}</details></div>"
    );
}

/// Per-section error placeholder (so a single failed query doesn't kill the page).
pub(super) fn write_section_error(out: &mut String, what: &'static str, err: &sqlx::Error) {
    swrite!(
        out,
        "<p class=\"section-error\">Failed to query {what}: {}</p>",
        HtmlEscape(&err.to_string()),
    );
}
