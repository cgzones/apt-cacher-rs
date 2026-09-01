use std::{convert::Infallible, pin::Pin, sync::Arc, task::Poll::Ready};

use http_body::{Body, Frame, SizeHint};
use memmap2::Mmap;

const MMAP_FRAME_SIZE: usize = 2 * 1024 * 1024; // 2MiB

/// A `Body` over a memory-mapped cache file, yielding zero-copy
/// [`MmapData`] frames. Delivery accounting (bytes, `SERVED_*`, the
/// completion log, the DB row) is the wrapping `AccountedBody`'s job.
pub(crate) struct MmapBody {
    mapping: Arc<Mmap>,
    position: usize,
    length: usize,
}

impl MmapBody {
    #[must_use]
    pub(crate) fn new(mapping: Mmap, length: usize) -> Self {
        Self {
            mapping: Arc::new(mapping),
            position: 0,
            length,
        }
    }
}

pub(crate) struct MmapData {
    mapping: Arc<Mmap>,
    position: usize,
    remaining: usize,
}

impl bytes::buf::Buf for MmapData {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        &self.mapping[self.position..(self.position + self.remaining)]
    }

    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining, "suggested by trait");
        self.position += cnt;
        self.remaining -= cnt;
    }
}

impl Body for MmapBody {
    type Data = MmapData;
    type Error = Infallible;

    fn is_end_stream(&self) -> bool {
        debug_assert!(
            self.position <= self.length,
            "position must not exceed length"
        );
        self.position == self.length
    }

    fn size_hint(&self) -> SizeHint {
        debug_assert!(
            self.position <= self.length,
            "position must not exceed length"
        );
        SizeHint::with_exact((self.length - self.position) as u64)
    }

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // same logic as in Self::is_end_stream()
        debug_assert!(
            self.position <= self.length,
            "position must not exceed length"
        );
        let remaining_total = self.length - self.position;
        if remaining_total == 0 {
            return Ready(None);
        }

        let chunk_size = remaining_total.min(MMAP_FRAME_SIZE);

        let frame = Frame::data(MmapData {
            mapping: Arc::clone(&self.mapping),
            position: self.position,
            remaining: chunk_size,
        });

        self.as_mut().position += chunk_size;

        Ready(Some(Ok(frame)))
    }
}
