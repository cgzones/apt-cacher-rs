use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use build_html::Html as _;
use build_html::HtmlContainer as _;
use build_html::Table;
use build_html::{Container, ContainerType, HtmlPage};
use coarsetime::Instant;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{
    Request, Response, StatusCode,
    header::{HeaderValue, SERVER},
};
use log::{debug, error, trace};
use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::macros::format_description;

use crate::APP_VERSION;
use crate::AppState;
use crate::HumanFmt;
use crate::ProxyCacheBody;
use crate::RUNTIMEDETAILS;
use crate::UNCACHEABLES;
use crate::global_config;
use crate::{APP_NAME, LOGSTORE, database::Database, error::ProxyCacheError, quick_response};

const WEBUI_DATE_FORMAT: &[FormatItem<'_>] =
    format_description!("[day] [month repr:short] [year] [hour]:[minute]:[second]");

#[must_use]
pub(crate) async fn serve_web_interface(
    req: Request<Incoming>,
    appstate: &AppState,
) -> Response<ProxyCacheBody> {
    let location = req.uri().path();
    debug!("Requested local web interface resource `{location}`");

    match location {
        "/" => serve_root(appstate).await,
        "/logs" => serve_logs(),
        _ => {
            debug!("Invalid local web interface request: {req:?}");

            quick_response(
                StatusCode::BAD_REQUEST,
                "Local interface resource not available",
            )
        }
    }
}

/// Returns a tuple of the number of files and their total size in bytes on success.
async fn flat_directory_size(path: &Path) -> Result<(usize, u64), tokio::io::Error> {
    let mut dir = tokio::fs::read_dir(path).await?;

    let mut total_files = 0;
    let mut total_size = 0;

    while let Some(entry) = dir.next_entry().await? {
        let mdata = entry.metadata().await?;
        total_size += mdata.len();
        #[expect(clippy::case_sensitive_file_extension_comparisons)]
        if mdata.is_file()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|s| s.ends_with(".deb"))
        {
            total_files += 1;
        }
    }

    Ok((total_files, total_size))
}

async fn build_mirror_table(database: &Database) -> Result<(Table, usize), ProxyCacheError> {
    let mut html_table_mirrors = Table::new().with_header_row(&[
        "Mirror",
        "Last Seen",
        "First Seen",
        "Last Cleanup",
        "Total Download Size",
        "Total Delivery Size",
        "Cache Rate",
        "Disk Space",
        "File Count",
    ]);
    let mut rows = 0;

    let mut mirrors = match database.get_mirrors_with_stats().await {
        Ok(m) => m,
        Err(err) => {
            error!("Failed to query mirrors:  {err}");
            return Err(ProxyCacheError::Sqlx(err));
        }
    };
    mirrors.sort_unstable_by_key(|mirror| -mirror.last_seen);

    let cache_path = &global_config().cache_directory;

    for mirror in mirrors {
        let last_seen = time::OffsetDateTime::from_unix_timestamp(mirror.last_seen)
            .expect("timestamp should be valid");
        let last_seen_fmt = last_seen
            .format(WEBUI_DATE_FORMAT)
            .expect("timestamp should be formattable");

        let first_seen = time::OffsetDateTime::from_unix_timestamp(mirror.first_seen)
            .expect("timestamp should be valid");
        let first_seen_fmt = first_seen
            .format(WEBUI_DATE_FORMAT)
            .expect("timestamp should be formattable");

        let last_cleanup_fmt = if mirror.last_cleanup == 0 {
            "never".to_string()
        } else {
            let last_cleanup = time::OffsetDateTime::from_unix_timestamp(mirror.last_cleanup)
                .expect("timestamp should be valid");
            last_cleanup
                .format(WEBUI_DATE_FORMAT)
                .expect("timestamp should be formattable")
        };

        let total_download_size_fmt = format!(
            "{}",
            HumanFmt::Size(
                u64::try_from(mirror.total_download_size)
                    .expect("Database should never store negative size")
            )
        );

        let total_delivery_size_fmt = format!(
            "{}",
            HumanFmt::Size(
                u64::try_from(mirror.total_delivery_size)
                    .expect("Database should never store negative size")
            )
        );

        let mirror_path: PathBuf = [cache_path, &mirror.cache_path()].iter().collect();

        let (file_count_fmt, dir_size_fmt) = if mirror_path.exists() {
            match flat_directory_size(&mirror_path).await {
                Ok((count, size)) => (format!("{count}"), format!("{}", HumanFmt::Size(size))),
                Err(err) => {
                    error!(
                        "Failed to gather size of directory `{}`:  {err}",
                        mirror_path.display()
                    );
                    ("N/A".to_string(), "N/A".to_string())
                }
            }
        } else {
            ("N/A".to_string(), "N/A".to_string())
        };

        #[expect(clippy::cast_precision_loss)]
        let rate_fmt = if mirror.total_download_size == 0 {
            "N/A".to_string()
        } else {
            format!(
                "{:.2}",
                mirror.total_delivery_size as f32 / mirror.total_download_size as f32
            )
        };

        html_table_mirrors.add_body_row(&[
            mirror.uri(),
            last_seen_fmt,
            first_seen_fmt,
            last_cleanup_fmt,
            total_download_size_fmt,
            total_delivery_size_fmt,
            rate_fmt,
            dir_size_fmt,
            file_count_fmt,
        ]);
        rows += 1;
    }

    Ok((html_table_mirrors, rows))
}

async fn build_origin_table(database: &Database) -> Result<(Table, usize), ProxyCacheError> {
    let mut html_table_origins = Table::new().with_header_row(&[
        "Mirror",
        "Distribution",
        "Component",
        "Architecture",
        "Last Seen",
    ]);
    let mut rows = 0;

    let mut origins = match database.get_origins().await {
        Ok(o) => o,
        Err(err) => {
            error!("Failed to query origins:  {err}");
            return Err(ProxyCacheError::Sqlx(err));
        }
    };
    origins.sort_unstable_by_key(|origin| -origin.last_seen);

    for origin in origins {
        let last_seen = time::OffsetDateTime::from_unix_timestamp(origin.last_seen)
            .expect("timestamp should be valid");
        let last_seen_fmt = last_seen
            .format(WEBUI_DATE_FORMAT)
            .expect("timestamp should be formattable");

        html_table_origins.add_body_row(&[
            origin.mirror_uri(),
            origin.distribution,
            origin.component,
            origin.architecture,
            last_seen_fmt,
        ]);
        rows += 1;
    }

    Ok((html_table_origins, rows))
}

async fn build_client_table(database: &Database) -> Result<(Table, usize), ProxyCacheError> {
    let mut html_table_clients = Table::new().with_header_row(&["IP"]);
    let mut rows = 0;

    let clients = match database.get_clients().await {
        Ok(o) => o,
        Err(err) => {
            error!("Failed to query clients:  {err}");
            return Err(ProxyCacheError::Sqlx(err));
        }
    };

    for client in clients {
        html_table_clients.add_body_row([client]);
        rows += 1;
    }

    Ok((html_table_clients, rows))
}

fn build_uncacheable_table() -> (Table, usize) {
    let mut html_table_uncacheables =
        Table::new().with_header_row(&["Requested Host", "Requested Path"]);
    let mut rows = 0;

    {
        let uncacheables = UNCACHEABLES.get().expect("Initialized in main()").read();

        for (host, path) in uncacheables.iter() {
            html_table_uncacheables.add_body_row([&format!("{host}"), path]);
            rows += 1;
        }
    }

    (html_table_uncacheables, rows)
}

#[must_use]
async fn serve_root(appstate: &AppState) -> Response<ProxyCacheBody> {
    let start = Instant::now();

    let Ok((html_table_mirrors, mirror_rows)) = build_mirror_table(&appstate.database).await else {
        return quick_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Local Webinterface failure",
        );
    };

    let Ok((html_table_origins, origin_rows)) = build_origin_table(&appstate.database).await else {
        return quick_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Local Webinterface failure",
        );
    };

    let Ok((html_table_clients, client_rows)) = build_client_table(&appstate.database).await else {
        return quick_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Local Webinterface failure",
        );
    };

    let (html_table_uncacheables, uncacheable_rows) = build_uncacheable_table();

    let rd = RUNTIMEDETAILS.get().expect("Should be set");
    let database_size_fmt = match tokio::fs::metadata(&rd.config.database_path).await {
        Ok(data) => format!("{}", HumanFmt::Size(data.len())),
        Err(err) => {
            error!(
                "Failed to access database file `{}`:  {err}",
                rd.config.database_path.display()
            );
            "N/A".to_string()
        }
    };

    let active_downloads = appstate.active_downloads.len();

    let now = OffsetDateTime::now_utc();
    let memory_stats = memory_stats::memory_stats();

    let html: String = HtmlPage::new()
        .with_title("apt-cacher-rs web interface")
        .with_header(1, "Statistics")
        .with_container(
            Container::new(ContainerType::Div)
                .with_header(2, "Program Details")
                .with_paragraph(format!(
                    "Version: {}<br>Start Time: {}<br>Current Time: {}<br>Uptime: {}<br>Bind Address: {}<br>Bind Port: {}<br>Database Size: {}<br>Memory Usage: {} ({})<br>Active Downloads: {}",
                    APP_VERSION,
                    rd.start_time
                        .format(WEBUI_DATE_FORMAT)
                        .expect("timestamp should be formattable"),
                    now
                        .format(WEBUI_DATE_FORMAT)
                        .expect("timestamp should be formattable"),
                    HumanFmt::Time(Duration::from_secs_f32((now - rd.start_time).as_seconds_f32())),
                    rd.config.bind_addr,
                    rd.config.bind_port,
                    database_size_fmt,
                    memory_stats.map_or_else(|| String::from("???"), |ms| HumanFmt::Size(ms.physical_mem as u64).to_string()),
                    memory_stats.map_or_else(|| String::from("???"), |ms| HumanFmt::Size(ms.virtual_mem as u64).to_string()),
                    active_downloads
                )).with_link("/logs", "Logs"),
        )
        .with_container(
            Container::new(ContainerType::Div)
                .with_header_attr(2, "Mirrors", [("id", "mirrors-head")])
                .with_paragraph(format!("List of proxied mirrors [{mirror_rows}]:"))
                .with_table(html_table_mirrors),
        )
        .with_container(
            Container::new(ContainerType::Div)
                .with_header_attr(2, "Origins", [("id", "origins-head")])
                .with_paragraph(format!("List of proxied origins [{origin_rows}]:"))
                .with_table(html_table_origins),
        )
        .with_container(
            Container::new(ContainerType::Div)
                .with_header_attr(2, "Clients", [("id", "clients-head")])
                .with_paragraph(format!("List of clients [{client_rows}]:"))
                .with_table(html_table_clients),
        )
        .with_container(
            Container::new(ContainerType::Div)
                .with_header_attr(2, "Uncacheables", [("id", "clients-head")])
                .with_paragraph(format!("List of most recent files unable to cache [{uncacheable_rows}]:"))
                .with_table(html_table_uncacheables),
        )
        .with_container(
            Container::new(ContainerType::Footer).with_paragraph(format!("<hr>All dates are in UTC.   --   Generated in {}.", HumanFmt::Time(start.elapsed().into()))),
        )
        .to_html_string();

    let body = ProxyCacheBody::Full(Full::new(html.into()));

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(SERVER, HeaderValue::from_static(APP_NAME))
        .body(body)
        .expect("HTTP response is valid");

    trace!("Local web interface response: {response:?}");

    response
}

#[must_use]
fn serve_logs() -> Response<ProxyCacheBody> {
    let mut buf = Vec::with_capacity(8192);

    let ls = LOGSTORE.get().expect("Should be set");
    for entry in ls.entries().iter() {
        buf.extend_from_slice(entry.as_bytes());
        buf.push(b'\n');
    }

    let body = ProxyCacheBody::Full(Full::new(buf.into()));

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(SERVER, HeaderValue::from_static(APP_NAME))
        .body(body)
        .expect("HTTP response is valid");

    trace!("Local web interface response: {response:?}");

    response
}
