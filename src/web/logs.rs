//! The `/logs` page: the in-memory log ring rendered as a `<pre>` tail.

use tracing::error;

use crate::{LOGSTORE, error::ErrorReport, swrite};

use super::{
    fmt::HtmlEscape,
    page::{Page, QueryOptions, build_nav_html, build_page},
    response::WebResponse,
};

// Logs endpoint
// ---------------------------------------------------------------------------

#[must_use]
pub(super) async fn serve_logs(options: QueryOptions) -> WebResponse {
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
