//! Local web interface: the dashboard (`/`), the log tail (`/logs`), the
//! healthcheck JSON (`/healthcheck`) and the static assets. This file
//! owns the route handler ([`serve_web_interface`]) both backends call and
//! re-exports the response type they render ([`WebResponse`]). The
//! rendering lives in submodules:
//!
//! - [`fmt`]: the `Display` newtypes cells are rendered through.
//! - [`host_gate`]: the `Host` names the web interface answers to.
//! - [`table`]: `Table`/`DetailsList`, the `tr!` row macro, section wrappers.
//! - [`page`]: query options, theme, the `<html>` skeleton and `<nav>`, the
//!   favicon.
//! - [`assets`]: the embedded stylesheet and script bundle under their
//!   content-hashed URLs.
//! - [`response`]: `WebResponse`, its header table and the hyper body wrapper.
//! - [`dashboard`]: `DashboardData` gathering and the details sections.
//! - [`metrics_page`]: the Metrics section.
//! - [`tables`]: the row tables and the per-mirror directory walk.
//! - [`logs`]: the `/logs` page.
//!
//! # Scripts are optional
//!
//! Both pages are complete without JavaScript: curl, a text browser or a
//! browser with scripts off sees every figure as server-rendered text (the
//! breakdown bars are server-rendered SVG), opens sections through `open=`,
//! keeps them open with the keep-open links, and auto-refreshes through
//! `refresh=` (a `<noscript>` meta refresh). The script bundle (`/app.js`,
//! `assets/js/`) only enhances that markup and must keep it that way: a
//! feature whose script fails leaves the page as the server rendered it.
//! Its constraints are the HTML pages' Content-Security-Policy
//! (`response.rs`): no inline script or style, no HTML-parsing DOM sink
//! (Trusted Types), no CSSOM writes, no third-party origin.
//!
//! # The markup the scripts rely on
//!
//! No test runs the scripts, so renaming one of these hooks breaks a
//! feature silently; treat them as an interface. The integration test
//! `the_markup_carries_every_script_hook` renders them all.
//!
//! - `<body data-page="dashboard|logs">`: which page the script runs on.
//! - `<link rel="stylesheet">` and `<script src>` in `<head>`: compared
//!   with a refreshed page's to spot an upgraded daemon.
//! - `data-section="{key}"` on every top-level block (the [`table`]
//!   wrappers, the nav, the setup hint, the hero, the logs, the footer):
//!   the unit the background refresh swaps, matched by key, so a key is
//!   unique and stable. A collapsible section is `div > details >
//!   summary > h2[id="{key}-head"]`; `dd.help details` is the "?"
//!   explanation a refresh must not close.
//! - `nav .spacer`: where the refresh status goes.
//! - `<table data-table="{key}">` inside `.tablewrap`, with its header row
//!   in `<thead>` (`th.num` for figure columns) and its rows in the one
//!   `<tbody>`: sort order and filters are kept per key.
//! - `td[data-sort]`: a cell's sort value where its text does not sort
//!   (`Table::cell_keyed`).
//! - The Metrics section: `h3.group` right before its `dl.details`, rows as
//!   `dl.details > div` with the label in `dt` (its explanation in
//!   `dt[title]`) and the value in the first `dd`; `.warn`/`.alert`
//!   inside a row mark it highlighted.
//! - `div[data-series][data-v]` (`data-unit="B"` for bytes, `data-polled`
//!   for figures web-interface requests move) on the Metrics counter
//!   rows, never on the value's `<dd>` (`Entry::figure`), and
//!   `[data-started]` on the Metrics scope note.
//! - `a[data-carry]`, `a[data-action="refresh-toggle"][data-secs]` and
//!   `a[data-action="theme-cycle"]` in the nav; `a.pin`, which the script
//!   removes.
//! - `<time datetime title>` around every relative time; the footer's
//!   `<time datetime>` is the server's clock.
//! - The setup hint's `<code>` (the apt line) and `/logs`' `pre.log`, one
//!   entry per line.
//!
//! The URL (`refresh=`, `theme=`, `open=`) stays the page's shareable
//! state; browser storage (`apt-cacher-rs.theme`, `apt-cacher-rs.sort.*`,
//! `apt-cacher-rs.keys`) only holds a viewer's conveniences.

mod assets;
mod dashboard;
mod fmt;
pub(crate) mod host_gate;
mod logs;
mod metrics_page;
mod page;
mod response;
mod table;
mod tables;

use http::StatusCode;
use tracing::{debug, trace};

pub(crate) use dashboard::invalidate_aggregates as invalidate_dashboard_aggregates;
pub(crate) use response::WebResponse;

use crate::{AppState, healthcheck::cached_health_report, metrics};

use self::{
    dashboard::serve_dashboard,
    logs::serve_logs,
    page::{FAVICON_SVG, parse_query},
    response::Caching,
};

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
        "/healthcheck" => serve_healthcheck().await,
        "/favicon.svg" | "/favicon.ico" => {
            WebResponse::static_resource("image/svg+xml", FAVICON_SVG, Caching::Day)
        }
        _ => {
            if let Some(asset) = assets::find(location) {
                asset.response(uri.query())
            } else {
                debug!("Unknown local web interface resource: {uri:?}");
                WebResponse::not_found("Local interface resource not available")
            }
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

async fn serve_healthcheck() -> WebResponse {
    let report = cached_health_report().await;
    let status = if report.healthy() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    WebResponse::json(status, report.to_json())
}
