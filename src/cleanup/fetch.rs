//! Cleanup's `Packages` index fetch: the `.xz` -> `.gz` -> raw format cascade.
//!
//! Each format attempt goes through the build's own adapter, `fetch_format`:
//!
//! - hyper builds call `hyper_conn::process_cache_request`, the real serving
//!   path, and stream the body into a memfd. A complete body proves nothing
//!   about the cache commit: the adapter never waits for it or reads the
//!   final cache path.
//! - hyper-less builds call `splice::cleanup_index_fetch`, which reads a fresh
//!   cached copy or the uncached upstream body into memory.
//!
//! Only a complete body becomes a [`FetchedPackages`]: a 200 whose body then
//! fails or comes up short ends the cascade with a [`FetchFailure`], so the
//! reduce never sees a partial reference set.

use std::future::Future;

use http::{StatusCode, Uri};
use tracing::debug;

use crate::{
    AppState, Never,
    cache_layout::{ConnectionDetails, ResourceKind, dists_debname},
    client_info::ClientInfo,
    deb_mirror::Mirror,
    error::UpstreamFetchError,
    limits::{PackagesCompression, PackagesInput},
    precise_instant::PreciseInstant,
};

#[cfg(not(feature = "hyper"))]
use via_bridge::fetch_format;
#[cfg(feature = "hyper")]
use via_hyper::fetch_format;

/// Which `Packages` index a fetch targets. `cache_name` is the on-disk
/// debname the fetched index is cached under; `index_name` names the buffered
/// copy (hyper's throwaway memfd, the reduce's log lines).
pub(super) enum DebnameKind<'a> {
    OriginScoped {
        distribution: &'a str,
        component: &'a str,
        architecture: &'a str,
    },
    Flat,
}

impl DebnameKind<'_> {
    const fn resource_kind(&self) -> ResourceKind {
        match self {
            Self::OriginScoped { .. } => ResourceKind::Packages,
            Self::Flat => ResourceKind::FlatMetadata,
        }
    }

    fn cache_name(&self, fmt: PackagesCompression) -> String {
        match self {
            Self::OriginScoped {
                distribution,
                component,
                architecture,
            } => dists_debname(
                distribution,
                component,
                architecture,
                format_args!("Packages{}", fmt.extension()),
            ),
            Self::Flat => format!("Packages{}", fmt.extension()),
        }
    }

    fn index_name(&self, fmt: PackagesCompression) -> String {
        match self {
            Self::OriginScoped {
                distribution,
                component,
                architecture,
            } => format!(
                "{distribution}_{component}_{architecture}_packages{}",
                fmt.extension()
            ),
            Self::Flat => format!("flat_packages{}", fmt.extension()),
        }
    }
}

/// Why a cleanup `Packages` fetch failed. `status` is the best-known status (a
/// real upstream code, or a `BAD_GATEWAY` sentinel); `upstream` is `Some` only
/// when the upstream fetch itself failed, and then carries the real transport
/// reason for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FetchFailure {
    pub(crate) status: StatusCode,
    pub(crate) upstream: Option<UpstreamFetchError>,
}

impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.upstream {
            Some(upstream) => upstream.fmt(f),
            None => write!(f, "{}", self.status),
        }
    }
}

/// What one format attempt answered, short of a [`FetchFailure`]: the complete
/// index, or the non-200 status the cascade decides on (404/403/410 try the
/// next format, anything else ends it).
#[derive(Debug)]
pub(crate) enum IndexAnswer<B> {
    Complete(B),
    Status(StatusCode),
}

/// A complete `Packages` index, buffered and ready to decode.
#[derive(Debug)]
pub(super) struct FetchedPackages {
    pub(super) compression: PackagesCompression,
    /// Identifies the origin's index in the reduce's log lines.
    pub(super) name: String,
    /// The whole index: hyper's memfd, rewound to offset 0, or the bridge's
    /// bytes.
    pub(super) input: PackagesInput,
    /// Bytes in `input`; the size every cap is checked against.
    pub(super) len: u64,
}

/// Fetch the index at `base_uri` + extension, trying `.xz`, `.gz`, raw in
/// turn; the first format answering a complete body wins.
pub(super) async fn fetch_packages(
    mirror: &Mirror,
    base_uri: &str,
    debname: &DebnameKind<'_>,
    appstate: &AppState,
    buffer_size: usize,
) -> Result<FetchedPackages, FetchFailure> {
    probe_formats(base_uri, |compression, uri| {
        let conn_details = ConnectionDetails {
            client: ClientInfo::new_cleanup(),
            request_received_at: PreciseInstant::now(),
            mirror: mirror.clone(),
            upstream_host: mirror.host().clone(),
            debname: debname.cache_name(compression),
            resource_kind: debname.resource_kind(),
            origin_fields: None,
        };
        let name = debname.index_name(compression);
        fetch_format(conn_details, uri, compression, name, appstate, buffer_size)
    })
    .await
}

async fn probe_formats<B, F, Fut>(base_uri: &str, mut attempt: F) -> Result<B, FetchFailure>
where
    F: FnMut(PackagesCompression, Uri) -> Fut,
    Fut: Future<Output = Result<IndexAnswer<B>, FetchFailure>>,
{
    let mut last_missing = StatusCode::NOT_FOUND;

    for compression in [
        PackagesCompression::Xz,
        PackagesCompression::Gz,
        PackagesCompression::Raw,
    ] {
        let uri = Uri::try_from(format!("{base_uri}{}", compression.extension()))
            .expect("cleanup index URI should be valid");

        let status = match attempt(compression, uri.clone()).await? {
            IndexAnswer::Complete(index) => return Ok(index),
            IndexAnswer::Status(status) => status,
        };

        // "Missing-ish" statuses try the next format: AWS S3 answers 403
        // (not 404) for a missing object when the requester lacks
        // `s3:ListBucket`. Anything else (5xx, 401, a cache access failure
        // answered as 500) is fatal for this format chain.
        let _: Never = match status {
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN | StatusCode::GONE => {
                debug!("Cleanup request {uri} unavailable ({status})");
                last_missing = status;
                continue;
            }
            _ => {
                // The caller logs the same failure with the mirror and the
                // consequence.
                debug!(
                    "cleanup request {uri} failed with status code {status}; aborting the Packages format-fallback chain"
                );
                return Err(FetchFailure {
                    status,
                    upstream: None,
                });
            }
        };
    }

    Err(FetchFailure {
        status: last_missing,
        upstream: None,
    })
}

#[cfg(feature = "hyper")]
mod via_hyper {
    use std::io;
    use std::num::NonZero;

    use bytes::Buf as _;
    use http::{Method, Request, StatusCode, Uri, header::CACHE_CONTROL};
    use http_body_util::{BodyExt as _, Empty};
    use nix::sys::memfd::{MFdFlags, memfd_create};
    use tokio::io::{AsyncSeekExt as _, AsyncWriteExt as _, BufWriter};
    use tracing::{debug, error};

    use super::{FetchFailure, FetchedPackages, IndexAnswer};
    use crate::{
        AppState,
        cache_layout::ConnectionDetails,
        error::{ErrorReport, UpstreamFetchError},
        hyper_conn::process_cache_request,
        limits::{PackagesCompression, PackagesInput, VOLATILE_CACHE_MAX_AGE, packages_file_cap},
        proxy_body::ProxyCacheBody,
        transfer_error::DeliveryFailure,
    };

    /// The conservative failure of a 200 whose body could not be buffered whole;
    /// the cause was logged where it was observed.
    const BODY_FAILURE: FetchFailure = FetchFailure {
        status: StatusCode::BAD_GATEWAY,
        upstream: None,
    };

    pub(super) async fn fetch_format(
        conn_details: ConnectionDetails,
        uri: Uri,
        compression: PackagesCompression,
        name: String,
        appstate: &AppState,
        buffer_size: usize,
    ) -> Result<IndexAnswer<FetchedPackages>, FetchFailure> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(
                CACHE_CONTROL,
                format!("max-age={}", VOLATILE_CACHE_MAX_AGE.as_secs()),
            )
            .body(Empty::new())
            .expect("Request should be valid");

        let mut response = process_cache_request(conn_details, req, appstate.clone()).await;

        // An upstream-fetch failure (timeout/connect/transport) arrives as a
        // synthetic 502 carrying the real reason as a response extension.
        // The download runner already logged it -- don't re-warn.
        if let Some(upstream) = response.extensions_mut().remove::<UpstreamFetchError>() {
            return Err(FetchFailure {
                status: StatusCode::BAD_GATEWAY,
                upstream: Some(upstream),
            });
        }

        let status = response.status();
        if status != StatusCode::OK {
            return Ok(IndexAnswer::Status(status));
        }

        // The 200 reflects only the response *header*; the body streams afterwards
        // and can fail or truncate.
        let announced: Option<u64> = response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        // `packages_body_to_memfd` already logged the cause.
        let Ok((file, len)) =
            packages_body_to_memfd(&name, compression, response.body_mut(), buffer_size).await
        else {
            return Err(BODY_FAILURE);
        };
        if body_is_incomplete(announced, len) {
            debug!(
                "Packages index `{name}` truncated (announced {}, buffered {len}); treating as fetch failure",
                announced.unwrap_or(0)
            );
            return Err(BODY_FAILURE);
        }

        Ok(IndexAnswer::Complete(FetchedPackages {
            compression,
            name,
            input: PackagesInput::File(file),
            len,
        }))
    }

    /// Why buffering a Packages response into its memfd failed.
    ///
    /// `Display` renders the wrapped error through [`ErrorReport`] and exposes no
    /// `source()`.
    #[derive(Debug, thiserror::Error)]
    enum PackagesBufferError {
        #[error("{}", ErrorReport(.0))]
        Memfd(nix::Error),
        /// The response body yielded an error frame (e.g. an upstream rate limit,
        /// `ContentTooLarge`).
        #[error("{}", ErrorReport(.0))]
        Body(DeliveryFailure),
        /// Writing to or rewinding the memfd failed.
        #[error("{}", ErrorReport(.0))]
        Io(io::Error),
        #[error("compressed Packages exceeds the size cap of {max} bytes")]
        TooLarge { max: NonZero<u64> },
    }

    /// Buffer `body` into `file`, returning the file (rewound to offset 0) and the
    /// number of bytes written.
    ///
    /// `max_bytes` bounds how much an abusive upstream can stream into memory
    /// before the decompression guards in `reduce_file_list` run. Exceeding it
    /// is an `Err` rather than a truncation: a short buffer would silently
    /// shrink the reference set and over-evict.
    async fn body_to_file(
        body: &mut ProxyCacheBody,
        file: tokio::fs::File,
        max_bytes: NonZero<u64>,
        buffer_size: usize,
    ) -> Result<(tokio::fs::File, u64), PackagesBufferError> {
        let mut writer = BufWriter::with_capacity(buffer_size, file);

        let mut written: u64 = 0;
        while let Some(next) = body.frame().await {
            let frame = next.map_err(PackagesBufferError::Body)?;
            if let Ok(mut chunk) = frame.into_data() {
                written = written.saturating_add(chunk.remaining() as u64);
                if written > max_bytes.get() {
                    return Err(PackagesBufferError::TooLarge { max: max_bytes });
                }
                writer
                    .write_all_buf(&mut chunk)
                    .await
                    .map_err(PackagesBufferError::Io)?;
            }
        }

        writer.flush().await.map_err(PackagesBufferError::Io)?;

        let mut file = writer.into_inner();

        file.rewind().await.map_err(PackagesBufferError::Io)?;

        Ok((file, written))
    }

    /// Whether the body ended short of an announced `Content-Length`. `None`
    /// (chunked / volatile-unknown / legitimately empty) is never "incomplete".
    #[must_use]
    fn body_is_incomplete(announced: Option<u64>, written: u64) -> bool {
        matches!(announced, Some(expected) if written < expected)
    }

    /// A close-on-exec in-memory file named `name` (the name only shows in
    /// `/proc/<pid>/fd`).
    fn memfd_file(name: &str) -> nix::Result<tokio::fs::File> {
        let fd = memfd_create(name, MFdFlags::MFD_CLOEXEC)?;
        Ok(tokio::fs::File::from_std(std::fs::File::from(fd)))
    }

    async fn packages_body_to_memfd(
        memfdname: &str,
        compression: PackagesCompression,
        body: &mut ProxyCacheBody,
        buffer_size: usize,
    ) -> Result<(tokio::fs::File, u64), PackagesBufferError> {
        let file = memfd_file(memfdname).map_err(|err| {
            error!(
                "Failed to create in-memory file `{memfdname}` for the Packages index; skipping this mirror's reconcile this cycle:  {}",
                ErrorReport(&err)
            );
            PackagesBufferError::Memfd(err)
        })?;
        body_to_file(body, file, packages_file_cap(compression), buffer_size)
            .await
            .inspect_err(|err| {
                error!(
                    "Failed to write the Packages response to in-memory file `{memfdname}`; skipping this mirror's reconcile this cycle:  {}",
                    ErrorReport(err)
                );
            })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use crate::{nonzero, proxy_body::full_body};

        const BUFFER_SIZE: usize = 32 * 1024;

        #[test]
        fn body_is_incomplete_only_flags_short_announced_bodies() {
            assert!(!body_is_incomplete(None, 0));
            assert!(!body_is_incomplete(None, 1234));
            assert!(body_is_incomplete(Some(100), 0));
            assert!(body_is_incomplete(Some(100), 40));
            assert!(!body_is_incomplete(Some(100), 100));
            assert!(!body_is_incomplete(Some(0), 0));
        }

        #[tokio::test]
        async fn packages_body_to_memfd_counts_bytes_and_rewinds() {
            use tokio::io::AsyncReadExt as _;

            let payload = b"Package: hello\nFilename: pool/main/h/hello/hello_1_amd64.deb\n\n";
            let mut body = full_body(bytes::Bytes::from_static(payload));

            let (mut file, written) = packages_body_to_memfd(
                "apt_cacher_rs_test_count",
                PackagesCompression::Raw,
                &mut body,
                BUFFER_SIZE,
            )
            .await
            .expect("buffer body");

            assert_eq!(
                written,
                payload.len() as u64,
                "byte count must match payload"
            );

            let mut roundtrip = Vec::new();
            file.read_to_end(&mut roundtrip)
                .await
                .expect("read memfd back");
            assert_eq!(roundtrip, payload, "file must be rewound to offset 0");
        }

        #[tokio::test]
        async fn body_to_file_rejects_body_over_cap() {
            let mut body = full_body(bytes::Bytes::from(vec![b'x'; 4096]));
            let file = memfd_file("apt_cacher_rs_test_over_cap").expect("memfd");

            let err = body_to_file(&mut body, file, nonzero!(1024), BUFFER_SIZE)
                .await
                .expect_err("a body exceeding the cap must error rather than buffer unbounded");
            assert!(
                matches!(err, PackagesBufferError::TooLarge { max } if max.get() == 1024),
                "expected TooLarge {{ max: 1024 }}, got {err:?}"
            );
        }

        #[tokio::test]
        async fn body_to_file_accepts_body_at_cap() {
            let mut body = full_body(bytes::Bytes::from(vec![b'y'; 1024]));
            let file = memfd_file("apt_cacher_rs_test_at_cap").expect("memfd");

            let (_file, written) = body_to_file(&mut body, file, nonzero!(1024), BUFFER_SIZE)
                .await
                .expect("a body exactly at the cap must buffer successfully");
            assert_eq!(written, 1024);
        }
    }
}

#[cfg(not(feature = "hyper"))]
mod via_bridge {
    use http::Uri;

    use super::{FetchFailure, FetchedPackages, IndexAnswer};
    use crate::{
        AppState,
        cache_layout::ConnectionDetails,
        limits::{PackagesCompression, PackagesInput, packages_file_cap},
        splice::cleanup_index_fetch,
    };

    pub(super) async fn fetch_format(
        conn_details: ConnectionDetails,
        uri: Uri,
        compression: PackagesCompression,
        name: String,
        _appstate: &AppState,
        _buffer_size: usize,
    ) -> Result<IndexAnswer<FetchedPackages>, FetchFailure> {
        Ok(
            match cleanup_index_fetch(&conn_details, &uri, packages_file_cap(compression)).await? {
                IndexAnswer::Complete(body) => IndexAnswer::Complete(FetchedPackages {
                    compression,
                    name,
                    len: body.len() as u64,
                    input: PackagesInput::Bytes(body),
                }),
                IndexAnswer::Status(status) => IndexAnswer::Status(status),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 200 whose body could not be buffered whole.
    const BODY_FAILURE: FetchFailure = FetchFailure {
        status: StatusCode::BAD_GATEWAY,
        upstream: None,
    };

    #[test]
    fn debname_kind_derives_cache_and_index_names() {
        let o = DebnameKind::OriginScoped {
            distribution: "bookworm",
            component: "main",
            architecture: "amd64",
        };
        assert_eq!(
            o.cache_name(PackagesCompression::Xz),
            "bookworm_main_amd64_Packages.xz"
        );
        assert_eq!(
            o.index_name(PackagesCompression::Xz),
            "bookworm_main_amd64_packages.xz"
        );
        assert_eq!(
            DebnameKind::Flat.cache_name(PackagesCompression::Gz),
            "Packages.gz"
        );
        assert_eq!(
            DebnameKind::Flat.index_name(PackagesCompression::Gz),
            "flat_packages.gz"
        );
    }

    /// Run [`probe_formats`] against scripted per-format answers (in
    /// `.xz`, `.gz`, raw order) and return its result with the URIs it
    /// requested.
    async fn probe(
        answers: Vec<Result<IndexAnswer<&'static str>, FetchFailure>>,
    ) -> (Result<&'static str, FetchFailure>, Vec<String>) {
        let mut requested = Vec::new();
        let mut answers = answers.into_iter();
        let result = probe_formats("http://mirror/debian/Packages", |_compression, uri| {
            requested.push(uri.to_string());
            let answer = answers.next().expect("probed past the scripted answers");
            async move { answer }
        })
        .await;
        (result, requested)
    }

    fn status(code: StatusCode) -> IndexAnswer<&'static str> {
        IndexAnswer::Status(code)
    }

    #[tokio::test]
    async fn probe_formats_falls_back_xz_gz_raw_on_missing_statuses() {
        let (result, requested) = probe(vec![
            Ok(status(StatusCode::NOT_FOUND)),
            Ok(status(StatusCode::GONE)),
            Ok(IndexAnswer::Complete("raw")),
        ])
        .await;
        assert_eq!(result, Ok("raw"));
        assert_eq!(
            requested,
            [
                "http://mirror/debian/Packages.xz",
                "http://mirror/debian/Packages.gz",
                "http://mirror/debian/Packages",
            ]
        );
    }

    #[tokio::test]
    async fn probe_formats_stops_at_the_first_complete_index() {
        let (result, requested) = probe(vec![Ok(IndexAnswer::Complete("xz"))]).await;
        assert_eq!(result, Ok("xz"));
        assert_eq!(requested.len(), 1);
    }

    #[tokio::test]
    async fn probe_formats_ends_on_a_fatal_status() {
        let (result, requested) = probe(vec![
            Ok(status(StatusCode::FORBIDDEN)),
            Ok(status(StatusCode::SERVICE_UNAVAILABLE)),
        ])
        .await;
        assert_eq!(
            result,
            Err(FetchFailure {
                status: StatusCode::SERVICE_UNAVAILABLE,
                upstream: None,
            }),
            "a non-missing status must not fall through to the next format"
        );
        assert_eq!(requested.len(), 2);
    }

    #[tokio::test]
    async fn probe_formats_ends_on_a_failed_fetch_with_its_cause() {
        let failure = FetchFailure {
            status: StatusCode::BAD_GATEWAY,
            upstream: Some(UpstreamFetchError {
                reason: "connection error:  timed out".to_owned(),
            }),
        };
        let (result, requested) = probe(vec![Err(failure.clone())]).await;
        assert_eq!(result, Err(failure));
        assert_eq!(requested.len(), 1);

        let (result, requested) =
            probe(vec![Ok(status(StatusCode::NOT_FOUND)), Err(BODY_FAILURE)]).await;
        assert_eq!(result, Err(BODY_FAILURE));
        assert_eq!(requested.len(), 2);
    }

    #[tokio::test]
    async fn probe_formats_reports_the_last_missing_status() {
        let (result, requested) = probe(vec![
            Ok(status(StatusCode::NOT_FOUND)),
            Ok(status(StatusCode::FORBIDDEN)),
            Ok(status(StatusCode::GONE)),
        ])
        .await;
        assert_eq!(
            result,
            Err(FetchFailure {
                status: StatusCode::GONE,
                upstream: None,
            })
        );
        assert_eq!(requested.len(), 3);
    }

    #[test]
    fn fetch_failure_display_prefers_upstream_reason() {
        let with_upstream = FetchFailure {
            status: StatusCode::BAD_GATEWAY,
            upstream: Some(UpstreamFetchError {
                reason: "connection error:  timed out".to_owned(),
            }),
        };
        assert_eq!(with_upstream.to_string(), "connection error:  timed out");

        let status_only = FetchFailure {
            status: StatusCode::NOT_FOUND,
            upstream: None,
        };
        assert_eq!(status_only.to_string(), "404 Not Found");
    }
}
