use http::{Response, StatusCode};
use http_body_util::{BodyExt as _, Full, combinators::BoxBody};

use crate::response_head::ResponseHead;
use crate::transfer_error::DeliveryFailure;

#[must_use]
pub(crate) fn quick_response<T: Into<bytes::Bytes>>(
    status: StatusCode,
    message: T,
) -> Response<ProxyCacheBody> {
    ResponseHead::error(status).into_hyper(full_body(message))
}

/// [`quick_response`] that also ends the connection.
#[must_use]
pub(crate) fn quick_response_closing<T: Into<bytes::Bytes>>(
    status: StatusCode,
    message: T,
) -> Response<ProxyCacheBody> {
    ResponseHead::error(status).into_hyper_closing(full_body(message))
}

pub(crate) fn full_body<T: Into<bytes::Bytes>>(content: T) -> ProxyCacheBody {
    let body = Full::new(content.into()).map_err(|never| match never {});
    ProxyCacheBody::new(body)
}

/// The one concrete body type of every hyper response: hyper needs a single
/// type per service, and the bodies behind it (buffered, cached file, relayed
/// upstream, channel-fed) differ per request.
pub(crate) type ProxyCacheBody = BoxBody<bytes::Bytes, DeliveryFailure>;
