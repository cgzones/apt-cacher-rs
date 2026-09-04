//! [`WebResponse`], the backend-neutral response the route handler returns,
//! its per-kind header table and the hyper-side body wrapper that credits
//! `SERVED_WEBUI` on full delivery. `WebResponse` deliberately stays outside
//! `response_head.rs`: the web interface is an origin server, not a proxy.

#[cfg(feature = "hyper")]
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use http::StatusCode;
#[cfg(feature = "hyper")]
use http::{
    Response,
    header::{CONNECTION, CONTENT_TYPE, DATE, SERVER},
};
#[cfg(feature = "hyper")]
use http_body::{Body, Frame, SizeHint};
#[cfg(feature = "hyper")]
use http_body_util::{BodyExt as _, Full, combinators::BoxBody};

#[cfg(feature = "hyper")]
use crate::{
    build_info::APP_NAME, http_range::format_http_date, metrics, proxy_body::ProxyCacheBody,
};

/// Content-Security-Policy applied to every HTML page.
///
/// `style-src 'self'` permits the linked `/style.css` but blocks any `<style>`
/// block or inline `style="..."` attribute. If a future change wants inline
/// styles, it has to either move them into the stylesheet or extend the CSP —
/// silent CSP rejections are easy to miss when only some users have devtools
/// open.
const HTML_CSP: &str = "default-src 'none'; style-src 'self'; img-src 'self' data:; \
     base-uri 'none'; form-action 'none'";

/// A response from the local web interface.
///
/// Carries enough information for the hyper backend to construct a
/// `Response<ProxyCacheBody>` and for the sendfile backend to format the wire
/// bytes by hand using `format!` (see `sendfile_conn::write_webui_response`).
/// The two paths derive their headers from the same `WebResponse`, so clients
/// see the same response regardless of which backend served the request.
pub(crate) struct WebResponse {
    pub(crate) status: StatusCode,
    pub(crate) body: bytes::Bytes,
    kind: WebResponseKind,
}

enum WebResponseKind {
    /// Dashboard or logs page; served with `no-store` cache and full
    /// security headers.
    Html,
    /// Static asset (CSS/SVG) with long-lived caching and `nosniff`.
    Static { content_type: &'static str },
    /// Machine-readable healthcheck payload; `no-store` like Html, none of
    /// the document-oriented security headers.
    Json,
    /// Plain-text error response.
    Error,
}

impl WebResponse {
    pub(super) fn html(html: String) -> Self {
        Self {
            status: StatusCode::OK,
            body: bytes::Bytes::from(html),
            kind: WebResponseKind::Html,
        }
    }

    pub(super) fn static_resource(content_type: &'static str, content: &'static str) -> Self {
        Self {
            status: StatusCode::OK,
            body: bytes::Bytes::from_static(content.as_bytes()),
            kind: WebResponseKind::Static { content_type },
        }
    }

    pub(super) fn json(status: StatusCode, body: String) -> Self {
        Self {
            status,
            body: bytes::Bytes::from(body),
            kind: WebResponseKind::Json,
        }
    }

    pub(super) fn not_found(msg: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            body: bytes::Bytes::from_static(msg.as_bytes()),
            kind: WebResponseKind::Error,
        }
    }

    pub(crate) fn content_type(&self) -> &'static str {
        match self.kind {
            WebResponseKind::Html => "text/html; charset=utf-8",
            WebResponseKind::Static { content_type } => content_type,
            WebResponseKind::Json => "application/json",
            WebResponseKind::Error => "text/plain; charset=utf-8",
        }
    }

    /// Per-kind headers beyond the common Server/Date/Connection/Content-* set.
    /// The single owner of this table: the hyper path feeds it to the response
    /// builder, the sendfile path formats it onto the wire
    /// (`sendfile_conn::write_webui_response`), so the two cannot drift.
    pub(crate) fn extra_headers(&self) -> &'static [(&'static str, &'static str)] {
        match self.kind {
            WebResponseKind::Html => &[
                ("Cache-Control", "no-store"),
                ("Content-Security-Policy", HTML_CSP),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("X-Robots-Tag", "noindex"),
                ("Referrer-Policy", "no-referrer"),
            ],
            WebResponseKind::Static { .. } => &[
                ("Cache-Control", "public, max-age=86400"),
                ("X-Content-Type-Options", "nosniff"),
            ],
            WebResponseKind::Json => &[
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
            ],
            WebResponseKind::Error => &[],
        }
    }

    /// Render this response as a `Response<ProxyCacheBody>` for the hyper path.
    #[cfg(feature = "hyper")]
    pub(crate) fn into_hyper_response(self) -> Response<ProxyCacheBody> {
        let mut builder = Response::builder()
            .status(self.status)
            .header(SERVER, APP_NAME)
            .header(DATE, &*format_http_date())
            .header(CONNECTION, "keep-alive")
            .header(CONTENT_TYPE, self.content_type());
        for &(name, value) in self.extra_headers() {
            builder = builder.header(name, value);
        }
        let body = WebUiCountedBody {
            inner: Full::new(self.body),
            delivered: false,
        };
        builder
            .body(ProxyCacheBody::Boxed(BoxBody::new(
                body.map_err(|never| match never {}),
            )))
            .expect("HTTP response is valid")
    }
}

/// `Full<Bytes>` wrapper for hyper-served web-interface responses: credits
/// `SERVED_WEBUI`/`SERVED_TOTAL` in `Drop` only once the body was polled to
/// completion, so a client aborting before the page was written out does not
/// count as served (`SERVED_*` means "fully delivered", see `metrics.rs`).
/// The sendfile path instead bumps after its synchronous write succeeds
/// (`sendfile_conn::serve_webui`).
#[cfg(feature = "hyper")]
struct WebUiCountedBody {
    inner: Full<bytes::Bytes>,
    delivered: bool,
}

#[cfg(feature = "hyper")]
impl Drop for WebUiCountedBody {
    fn drop(&mut self) {
        if self.delivered {
            metrics::SERVED_WEBUI.increment();
            metrics::SERVED_TOTAL.increment();
        }
    }
}

#[cfg(feature = "hyper")]
impl Body for WebUiCountedBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        match &result {
            // hyper stops polling once `is_end_stream()` turns true after the
            // final frame, so a `Ready(None)` poll cannot be relied upon.
            Poll::Ready(Some(Ok(_))) => {
                if self.inner.is_end_stream() {
                    self.delivered = true;
                }
            }
            Poll::Ready(None) => self.delivered = true,
            Poll::Ready(Some(Err(_))) | Poll::Pending => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
