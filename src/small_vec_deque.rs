use std::num::NonZero;

use smallvec::SmallVec;

/// Fixed-capacity FIFO ring (O(1) `push_back` with oldest-slot overwrite
/// when full), backed by a
/// [`SmallVec`] pre-sized (and pre-filled with `T::default()`) to
/// exactly `capacity`.  Entries are addressed through a `head` index
/// plus `len`, so `push_back` when the buffer is full overwrites the
/// oldest slot without the memmove a `Vec`-backed FIFO would do and
/// without the per-instance heap allocation a `VecDeque` does.
///
/// Configurations whose `capacity` exceeds the inline `N` still work
/// — `SmallVec` falls back to a heap buffer.  In that case the only
/// regression vs a fresh `VecDeque` is the up-front `T::default()`
/// fill of unused slots, which is cheap for trivially-default `Copy`
/// types (the only ones we use this with).
#[derive(Debug)]
pub(crate) struct SmallVecDeque<T, const N: usize> {
    /// Always exactly `capacity` entries long; only the slots
    /// referenced by `head`/`len` are live, the rest hold leftover
    /// `T::default()` fill values.
    inner: SmallVec<[T; N]>,
    /// Index of the oldest live entry.  Wraps modulo `capacity`.
    head: usize,
    /// Number of live entries.  Bounded by `capacity`.
    len: usize,
    capacity: NonZero<usize>,
}

impl<T, const N: usize> SmallVecDeque<T, N>
where
    T: Copy + Default,
{
    #[must_use]
    pub(crate) fn with_capacity(capacity: NonZero<usize>) -> Self {
        let cap = capacity.get();
        let mut inner = SmallVec::with_capacity(cap);
        inner.resize(cap, T::default());
        Self {
            inner,
            head: 0,
            len: 0,
            capacity,
        }
    }

    /// Append `item` to the back.  Returns `Some(evicted)` when the
    /// buffer was full and the oldest entry had to be dropped to make
    /// room; returns `None` otherwise.
    pub(crate) fn push_back(&mut self, item: T) -> Option<T> {
        let cap = self.capacity.get();
        if self.len == cap {
            let evicted = self.inner[self.head];
            self.inner[self.head] = item;
            self.head = if self.head + 1 == cap {
                0
            } else {
                self.head + 1
            };
            Some(evicted)
        } else {
            let tail = (self.head + self.len) % cap;
            self.inner[tail] = item;
            self.len += 1;
            None
        }
    }

    /// Mutable reference to the most recently pushed entry, or `None`
    /// if the buffer is empty.
    #[must_use]
    pub(crate) fn back_mut(&mut self) -> Option<&mut T> {
        if self.len == 0 {
            None
        } else {
            let cap = self.capacity.get();
            let last = (self.head + self.len - 1) % cap;
            Some(&mut self.inner[last])
        }
    }

    #[must_use]
    pub(crate) fn is_full(&self) -> bool {
        self.len == self.capacity.get()
    }

    #[must_use]
    pub(crate) const fn capacity(&self) -> NonZero<usize> {
        self.capacity
    }

    /// Live entries split across at most two contiguous slices —
    /// `(head..head+n)` and a possibly-empty wrap-around `(0..m)`.
    /// Cheap because it just borrows the existing storage.
    pub(crate) fn as_slices(&self) -> (&[T], &[T]) {
        let cap = self.capacity.get();
        if self.len == 0 {
            (&[], &[])
        } else if self.head + self.len <= cap {
            (&self.inner[self.head..self.head + self.len], &[])
        } else {
            let first_len = cap - self.head;
            let second_len = self.len - first_len;
            (&self.inner[self.head..], &self.inner[..second_len])
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        let (a, b) = self.as_slices();
        a.iter().chain(b.iter())
    }
}
