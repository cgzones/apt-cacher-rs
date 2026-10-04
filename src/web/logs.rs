//! The `/logs` page: the in-memory log ring rendered as a `<pre>` tail.

use tracing::error;

use crate::{LOGSTORE, error::ErrorReport, global_config, swrite};

use super::{
    fmt::{HtmlEscape, Utc},
    page::{Heading, Page, PageTitle, QueryOptions, build_nav_html, build_page},
    response::WebResponse,
};

// Logs endpoint
// ---------------------------------------------------------------------------

#[must_use]
pub(super) async fn serve_logs(options: QueryOptions) -> WebResponse {
    let ls = LOGSTORE.get().expect("initialized in main()");

    // HTML-escape every entry on the blocking pool: with a large
    // `logstore_capacity` this can dominate the request handler.
    let entries = ls.snapshot();
    let entry_count = entries.len();
    let escaped_logs = tokio::task::spawn_blocking(move || {
        let mut buf = String::with_capacity(entries.iter().map(|e| e.len() + 8).sum());
        for entry in &entries {
            swrite!(buf, "{}\n", HtmlEscape(entry));
        }
        buf
    })
    .await
    .unwrap_or_else(|err| {
        error!(
            "Log-page render task panicked; rendering an error notice instead of the log entries:  {}",
            ErrorReport(&err)
        );
        String::from("!! Failed to render log entries !!\n")
    });

    let nav = build_nav_html(Page::Logs, options);

    let heading = Heading;
    let capacity = global_config().logstore_capacity;
    let generated_at = Utc::now();
    let body_html = format_args!(
        "{nav}{heading}\
         <div class=\"section\" data-section=\"logs\">\
         <h2>Log Entries <span class=\"count\">{entry_count} / {capacity}</span></h2>\
         <pre class=\"log\">{escaped_logs}</pre>\
         </div>\
         <footer data-section=\"footer\"><hr><p>All dates are in UTC. Page generated at {generated_at}.</p></footer>"
    );

    // The logs page is a tailing view; auto-refresh would fight the reader.
    let html = build_page(
        PageTitle("apt-cacher-rs logs"),
        Page::Logs,
        body_html,
        QueryOptions {
            refresh_secs: None,
            ..options
        },
    );
    WebResponse::html(html)
}
