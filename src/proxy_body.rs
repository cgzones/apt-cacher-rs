//! [`ProxyCacheBody`], the response body every hyper-served response (and
//! the hyper-less cleanup bridge) is built from: a memory-mapped cached file
//! or a boxed dynamic body. [`full_body`] and `quick_response` wrap small,
//! fully buffered payloads.

use std::{fmt::Debug, pin::Pin};

#[cfg(feature = "hyper")]
use http::{Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, Full, combinators::BoxBody};
use pin_project::pin_project;

use crate::error;
#[cfg(feature = "hyper")]
use crate::response_head::ResponseHead;
#[cfg(all(feature = "mmap", feature = "hyper"))]
use crate::{
    accounted_body,
    client_info::ClientInfo,
    mmap_body,
    rate_checked_body::{MaybeRated, RateCheckedBodyErr},
};

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
#[cfg_attr(
    all(feature = "mmap", feature = "hyper"),
    expect(
        clippy::large_enum_variant,
        reason = "Mmap is the zero-allocation hot path; boxing it would add a heap \
                  alloc per cached-file response which is exactly what this variant exists to avoid"
    )
)]
pub(crate) enum ProxyCacheBody {
    #[cfg(all(feature = "mmap", feature = "hyper"))]
    Mmap(
        #[pin] MaybeRated<accounted_body::AccountedBody<mmap_body::MmapBody>>,
        ClientInfo,
    ),
    Boxed(#[pin] BoxBody<bytes::Bytes, Box<error::ProxyCacheError>>),
}

impl Debug for ProxyCacheBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(all(feature = "mmap", feature = "hyper"))]
            Self::Mmap(_, _) => f.debug_tuple("Mmap").finish(),
            Self::Boxed(_) => f.debug_tuple("Boxed").finish(),
        }
    }
}

impl Body for ProxyCacheBody {
    type Data = ProxyCacheBodyData;

    type Error = Box<error::ProxyCacheError>;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            #[cfg(all(feature = "mmap", feature = "hyper"))]
            EnumProj::Mmap(memory_map, client) => memory_map
                .poll_frame(cx)
                .map_ok(|frame| frame.map_data(ProxyCacheBodyData::Mmap))
                .map_err(|rerr| match *rerr {
                    RateCheckedBodyErr::RateTimeout(error) => {
                        Box::new(error::ProxyCacheError::ClientDownloadRate {
                            error,
                            client: *client,
                        })
                    }
                    RateCheckedBodyErr::Inner(never) => match never {},
                }),

            EnumProj::Boxed(bytes) => bytes
                .poll_frame(cx)
                .map_ok(|frame| frame.map_data(ProxyCacheBodyData::Bytes)),
        }
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        match self {
            #[cfg(all(feature = "mmap", feature = "hyper"))]
            Self::Mmap(mmap_body, _) => mmap_body.size_hint(),
            Self::Boxed(box_body) => box_body.size_hint(),
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        match self {
            #[cfg(all(feature = "mmap", feature = "hyper"))]
            Self::Mmap(mmap_body, _) => mmap_body.is_end_stream(),
            Self::Boxed(box_body) => box_body.is_end_stream(),
        }
    }
}

pub(crate) enum ProxyCacheBodyData {
    #[cfg(all(feature = "mmap", feature = "hyper"))]
    Mmap(mmap_body::MmapData),
    Bytes(bytes::Bytes),
}

impl bytes::buf::Buf for ProxyCacheBodyData {
    fn remaining(&self) -> usize {
        match self {
            #[cfg(all(feature = "mmap", feature = "hyper"))]
            Self::Mmap(memory_map) => memory_map.remaining(),
            Self::Bytes(bytes) => bytes.remaining(),
        }
    }

    fn chunk(&self) -> &[u8] {
        match self {
            #[cfg(all(feature = "mmap", feature = "hyper"))]
            Self::Mmap(memory_map) => memory_map.chunk(),
            Self::Bytes(bytes) => bytes.chunk(),
        }
    }

    fn advance(&mut self, cnt: usize) {
        match self {
            #[cfg(all(feature = "mmap", feature = "hyper"))]
            Self::Mmap(memory_map) => memory_map.advance(cnt),
            Self::Bytes(bytes) => bytes.advance(cnt),
        }
    }
}
