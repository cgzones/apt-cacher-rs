use std::{convert::Infallible, pin::Pin, sync::Arc, task::Poll::Ready};

use http_body::{Body, Frame, SizeHint};
use memmap2::Mmap;

const MMAP_FRAME_SIZE: usize = 2 * 1024 * 1024;

/// A `Body` over a memory-mapped cache file, yielding zero-copy
/// [`MmapData`] frames. Delivery accounting (bytes, `SERVED_*`, the
/// completion log, the DB row) is the wrapping `AccountedBody`'s job.
pub(crate) struct MmapBody {
    mapping: Arc<Mmap>,
    position: usize,
}

impl MmapBody {
    #[must_use]
    pub(crate) fn new(mapping: Mmap) -> Self {
        Self {
            mapping: Arc::new(mapping),
            position: 0,
        }
    }

    /// Bytes not handed out yet. The mapping's own length is the only body
    /// length there is: the caller maps exactly the slice it wants to serve
    /// (`MmapOptions::offset`/`len`), so a separately-carried length could
    /// only disagree with it. `position <= len` holds by construction —
    /// [`Self::poll_frame`] advances it by at most this value.
    fn remaining(&self) -> usize {
        debug_assert!(
            self.position <= self.mapping.len(),
            "position must not exceed the mapping length"
        );
        self.mapping.len() - self.position
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
        self.remaining() == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining() as u64)
    }

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let chunk_size = self.remaining().min(MMAP_FRAME_SIZE);
        if chunk_size == 0 {
            return Ready(None);
        }

        let frame = Frame::data(MmapData {
            mapping: Arc::clone(&self.mapping),
            position: self.position,
            remaining: chunk_size,
        });

        self.position += chunk_size;

        Ready(Some(Ok(frame)))
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::Poll;

    use bytes::Buf as _;
    use http_body::Body as _;
    use memmap2::{Mmap, MmapOptions};

    use super::{MMAP_FRAME_SIZE, MmapBody};

    /// A read-only anonymous mapping of `len` bytes filled with a repeating
    /// pattern, standing in for a mapped cache file.
    fn mapped(len: usize) -> Mmap {
        let mut map = MmapOptions::new()
            .len(len)
            .map_anon()
            .expect("anon mapping");
        for (i, byte) in map.iter_mut().enumerate() {
            *byte = u8::try_from(i % 251).expect("i % 251 is in 0..251, fits in u8");
        }
        map.make_read_only().expect("freeze mapping")
    }

    /// The byte the pattern of [`mapped`] carries at `offset`.
    fn pattern_at(offset: usize) -> u8 {
        u8::try_from(offset % 251).expect("offset % 251 is in 0..251, fits in u8")
    }

    /// Poll one frame out of `body`, returning its bytes, or `None` at end of
    /// stream. `MmapBody` never yields `Pending` (every byte is resident) and
    /// never yields a trailer frame.
    fn next_frame(body: &mut MmapBody) -> Option<Vec<u8>> {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let polled = Pin::new(body).poll_frame(&mut cx);
        assert!(polled.is_ready(), "a mapped frame is always ready");
        let Poll::Ready(frame) = polled else {
            return None;
        };
        let frame = frame?.expect("MmapBody is infallible");
        let data = frame.data_ref().expect("MmapBody yields only data frames");
        assert_eq!(
            data.chunk().len(),
            data.remaining(),
            "a mapping is one contiguous chunk"
        );
        Some(data.chunk().to_vec())
    }

    #[test]
    fn a_short_body_is_one_frame() {
        let mut body = MmapBody::new(mapped(64));
        assert!(!body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(64));

        let frame = next_frame(&mut body).expect("one data frame");
        assert_eq!(frame.len(), 64);
        assert_eq!(frame.first(), Some(&pattern_at(0)));
        assert_eq!(frame.last(), Some(&pattern_at(63)));

        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(next_frame(&mut body).is_none());
        // The terminal state is stable across repeated polls.
        assert!(next_frame(&mut body).is_none());
    }

    #[test]
    fn a_long_body_is_split_into_frame_sized_chunks() {
        let len = MMAP_FRAME_SIZE + 1000;
        let mut body = MmapBody::new(mapped(len));

        let first = next_frame(&mut body).expect("first frame");
        assert_eq!(first.len(), MMAP_FRAME_SIZE, "frames are capped");
        assert!(!body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(1000));

        let second = next_frame(&mut body).expect("tail frame");
        assert_eq!(second.len(), 1000, "the tail frame is the remainder");
        assert_eq!(
            second.first(),
            Some(&pattern_at(MMAP_FRAME_SIZE)),
            "the tail frame continues where the first left off"
        );

        assert!(body.is_end_stream());
        assert!(next_frame(&mut body).is_none());
    }
}
