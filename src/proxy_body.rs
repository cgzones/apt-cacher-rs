//! [`ProxyCacheBody`], the response body every hyper-served response (and
//! the hyper-less cleanup bridge) is built from: a boxed dynamic body. [`full_body`] and `quick_response` wrap small,
//! fully buffered payloads.

use std::{fmt::Debug, pin::Pin};

#[cfg(feature = "hyper")]
use http::{Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, Full, combinators::BoxBody};
use pin_project::pin_project;

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

/// Box `Full<Bytes>` into [`ProxyCacheBody::Boxed`] for
/// small, fully-buffered responses (status pages, HTML, static assets).
pub(crate) fn full_body<T: Into<bytes::Bytes>>(content: T) -> ProxyCacheBody {
    let body = Full::new(content.into()).map_err(|never| match never {});
    ProxyCacheBody::Boxed(BoxBody::new(body))
}

#[pin_project(project = EnumProj)]
pub(crate) enum ProxyCacheBody {
    Boxed(#[pin] BoxBody<bytes::Bytes, DeliveryFailure>),
}

impl Debug for ProxyCacheBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Boxed(_) => f.debug_tuple("Boxed").finish(),
        }
    }
}

impl Body for ProxyCacheBody {
    type Data = ProxyCacheBodyData;

    type Error = DeliveryFailure;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            EnumProj::Boxed(bytes) => bytes
                .poll_frame(cx)
                .map_ok(|frame| frame.map_data(ProxyCacheBodyData::Bytes)),
        }
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Boxed(box_body) => box_body.size_hint(),
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        match self {
            Self::Boxed(box_body) => box_body.is_end_stream(),
        }
    }
}

pub(crate) enum ProxyCacheBodyData {
    Bytes(bytes::Bytes),
}

impl bytes::buf::Buf for ProxyCacheBodyData {
    fn remaining(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.remaining(),
        }
    }

    fn chunk(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes.chunk(),
        }
    }

    fn advance(&mut self, cnt: usize) {
        match self {
            Self::Bytes(bytes) => bytes.advance(cnt),
        }
    }
}
