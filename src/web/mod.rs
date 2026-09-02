//! Local web interface: the dashboard (`/`), the log tail (`/logs`), the
//! healthcheck JSON (`/healthcheck`) and the two static assets. This file
//! owns the route handler ([`serve_web_interface`]) both backends call and
//! re-exports the response type they render ([`WebResponse`]). The
//! rendering lives in submodules:
//!
//! - [`fmt`]: the `Display` newtypes cells are rendered through.
//! - [`table`]: `Table`/`DetailsList`, the `tr!` row macro, section wrappers.
//! - [`page`]: query options, theme, the `<html>` skeleton and `<nav>`, the
//!   stylesheet and favicon.
//! - [`response`]: `WebResponse`, its header table and the hyper body wrapper.
//! - [`dashboard`]: `DashboardData` gathering and the details sections.
//! - [`metrics_page`]: the Metrics section.
//! - [`tables`]: the row tables and the per-mirror directory walk.
//! - [`logs`]: the `/logs` page.

mod dashboard;
mod fmt;
mod logs;
mod metrics_page;
mod page;
mod response;
mod table;
mod tables;

use http::StatusCode;
use tracing::{debug, trace};

pub(crate) use response::WebResponse;

use crate::{AppState, healthcheck::cached_health_report, metrics};

use self::{
    dashboard::serve_dashboard,
    logs::serve_logs,
    page::{CSS, FAVICON_SVG, parse_query},
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

async fn serve_healthcheck() -> WebResponse {
    let report = cached_health_report().await;
    let status = if report.healthy() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    WebResponse::json(status, report.to_json())
}
