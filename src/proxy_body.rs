//! [`ProxyCacheBody`], the response body every hyper-served response (and
//! the hyper-less cleanup bridge) is built from: a boxed dynamic body. [`full_body`] and `quick_response` wrap small,
//! fully buffered payloads.

#[cfg(feature = "hyper")]
use http::{Response, StatusCode};
use http_body_util::{BodyExt as _, Full, combinators::BoxBody};

#[cfg(feature = "hyper")]
use crate::response_head::ResponseHead;
use crate::transfer_error::DeliveryFailure;

#[must_use]
#[cfg(feature = "hyper")]
pub(crate) fn quick_response<T: Into<bytes::Bytes>>(
    status: StatusCode,
    message: T,
) -> Response<ProxyCacheBody> {
    ResponseHead::error(status).into_hyper(full_body(message))
}

/// [`quick_response`] that also ends the connection
/// ([`ResponseHead::into_hyper_closing`]).
#[must_use]
#[cfg(feature = "hyper")]
pub(crate) fn quick_response_closing<T: Into<bytes::Bytes>>(
    status: StatusCode,
    message: T,
) -> Response<ProxyCacheBody> {
    ResponseHead::error(status).into_hyper_closing(full_body(message))
}

/// Box `Full<Bytes>` into a [`ProxyCacheBody`] for
/// small, fully-buffered responses (status pages, HTML, static assets).
pub(crate) fn full_body<T: Into<bytes::Bytes>>(content: T) -> ProxyCacheBody {
    let body = Full::new(content.into()).map_err(|never| match never {});
    ProxyCacheBody::new(body)
}

/// The one concrete body type of every hyper response: hyper needs a single
/// type per service, and the bodies behind it (buffered, cached file, relayed
/// upstream, channel-fed) differ per request.
pub(crate) type ProxyCacheBody = BoxBody<bytes::Bytes, DeliveryFailure>;
