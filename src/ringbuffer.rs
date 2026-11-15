//! Bounded FIFO buffers that evict their oldest entry when full.
//!
//! [`SumRingBuffer`] is the rate checker's per-second sample window: it
//! stores its samples in an inline array sized for
//! `DEFAULT_RATE_CHECK_TIMEFRAME`, so the `RateChecker` built for every
//! rate-checked body allocates nothing. A larger `rate_check_timeframe`
//! spills the window to the heap.

use std::{
    collections::VecDeque,
    num::NonZero,
    ops::{AddAssign, SubAssign},
};

use crate::{config::DEFAULT_RATE_CHECK_TIMEFRAME, static_assert};

#[derive(Debug)]
pub(crate) struct RingBuffer<T> {
    inner: VecDeque<T>,
    capacity: NonZero<usize>,
}

impl<T> RingBuffer<T> {
    #[must_use]
    pub(crate) fn new(capacity: NonZero<usize>) -> Self {
        Self {
            inner: VecDeque::with_capacity(capacity.get()),
            capacity,
        }
    }

    pub(crate) fn push(&mut self, item: T) {
        if self.is_full() {
            self.inner.pop_front();
        }

        self.inner.push_back(item);

        debug_assert!(
            self.inner.len() <= self.capacity.get(),
            "ring buffer should not exceed capacity"
        );
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[must_use]
    pub(crate) fn is_full(&self) -> bool {
        self.inner.len() == self.capacity.get()
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub(crate) const fn capacity(&self) -> NonZero<usize> {
        self.capacity
    }

    #[must_use]
    pub(crate) fn iter(&self) -> std::collections::vec_deque::Iter<'_, T> {
        self.inner.iter()
    }

    /// Index 0 is the oldest entry.
    #[must_use]
    pub(crate) fn remove(&mut self, index: usize) -> Option<T> {
        self.inner.remove(index)
    }
}

const SUM_RING_INLINE: usize = 30;
static_assert!(SUM_RING_INLINE == DEFAULT_RATE_CHECK_TIMEFRAME.get());

/// Backing slots of a [`Ring`]: inline when the capacity fits `N`, a heap
/// allocation otherwise. Exposed as a slice of exactly `capacity` entries.
#[derive(Debug)]
enum Slots<T, const N: usize> {
    Inline([T; N]),
    Heap(Box<[T]>),
}

/// Fixed-capacity FIFO ring over [`Slots`] pre-filled with `T::default()`:
/// a full `push_back` overwrites the oldest slot, without the per-instance
/// heap allocation a `VecDeque` does.
#[derive(Debug)]
struct Ring<T, const N: usize> {
    /// Only the slots referenced by `head`/`len` are live, the rest hold
    /// leftover `T::default()` fill values.
    slots: Slots<T, N>,
    /// Index of the oldest live entry.
    head: usize,
    len: usize,
    capacity: NonZero<usize>,
}

impl<T, const N: usize> Ring<T, N>
where
    T: Copy + Default,
{
    #[must_use]
    fn with_capacity(capacity: NonZero<usize>) -> Self {
        let cap = capacity.get();
        let slots = if cap <= N {
            Slots::Inline([T::default(); N])
        } else {
            Slots::Heap(vec![T::default(); cap].into_boxed_slice())
        };
        Self {
            slots,
            head: 0,
            len: 0,
            capacity,
        }
    }

    /// All `capacity` slots, live or not.
    fn slots(&self) -> &[T] {
        match &self.slots {
            Slots::Inline(array) => &array[..self.capacity.get()],
            Slots::Heap(boxed) => boxed,
        }
    }

    fn slots_mut(&mut self) -> &mut [T] {
        let cap = self.capacity.get();
        match &mut self.slots {
            Slots::Inline(array) => &mut array[..cap],
            Slots::Heap(boxed) => boxed,
        }
    }

    /// Returns the evicted oldest entry when the buffer was full.
    fn push_back(&mut self, item: T) -> Option<T> {
        let cap = self.capacity.get();
        if self.len == cap {
            let head = self.head;
            let slots = self.slots_mut();
            let evicted = slots[head];
            slots[head] = item;
            self.head = if head + 1 == cap { 0 } else { head + 1 };
            Some(evicted)
        } else {
            let tail = (self.head + self.len) % cap;
            self.slots_mut()[tail] = item;
            self.len += 1;
            None
        }
    }

    #[must_use]
    fn back_mut(&mut self) -> Option<&mut T> {
        if self.len == 0 {
            None
        } else {
            let cap = self.capacity.get();
            let last = (self.head + self.len - 1) % cap;
            Some(&mut self.slots_mut()[last])
        }
    }

    #[must_use]
    fn is_full(&self) -> bool {
        self.len == self.capacity.get()
    }

    #[must_use]
    const fn capacity(&self) -> NonZero<usize> {
        self.capacity
    }

    /// Live entries, oldest first: `(head..head+n)` and a possibly-empty
    /// wrap-around `(0..m)`.
    fn as_slices(&self) -> (&[T], &[T]) {
        let cap = self.capacity.get();
        let slots = self.slots();
        if self.len == 0 {
            (&[], &[])
        } else if self.head + self.len <= cap {
            (&slots[self.head..self.head + self.len], &[])
        } else {
            let first_len = cap - self.head;
            let second_len = self.len - first_len;
            (&slots[self.head..], &slots[..second_len])
        }
    }

    fn iter(&self) -> impl Iterator<Item = &T> {
        let (a, b) = self.as_slices();
        a.iter().chain(b.iter())
    }
}

/// Fixed-capacity ring buffer that also tracks a running sum of its
/// contents.
#[derive(Debug)]
pub(crate) struct SumRingBuffer<T> {
    inner: Ring<T, SUM_RING_INLINE>,
    sum: T,
}

impl<T> SumRingBuffer<T>
where
    T: AddAssign + SubAssign + PartialEq + for<'a> std::iter::Sum<&'a T> + Copy + Default,
{
    #[must_use]
    pub(crate) fn new(capacity: NonZero<usize>) -> Self {
        Self {
            inner: Ring::with_capacity(capacity),
            sum: T::default(),
        }
    }

    pub(crate) fn push(&mut self, item: T) {
        if let Some(evicted) = self.inner.push_back(item) {
            self.sum -= evicted;
        }
        self.sum += item;
    }

    /// Add `item` to the most recent entry, or push it as a new entry
    /// when the buffer is empty.
    pub(crate) fn add_back(&mut self, item: T) {
        if let Some(last) = self.inner.back_mut() {
            *last += item;
        } else {
            // The buffer is empty, so nothing is evicted.
            let _evicted: Option<T> = self.inner.push_back(item);
        }
        self.sum += item;
    }

    #[must_use]
    pub(crate) fn is_full(&self) -> bool {
        self.inner.is_full()
    }

    #[must_use]
    pub(crate) const fn capacity(&self) -> NonZero<usize> {
        self.inner.capacity()
    }

    #[must_use]
    pub(crate) fn sum(&self) -> T {
        debug_assert!(
            self.sum == self.inner.iter().sum(),
            "ring buffer sum should match inner items sum"
        );
        self.sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonzero;

    fn collect<T: Copy + Default, const N: usize>(ring: &Ring<T, N>) -> Vec<T> {
        ring.iter().copied().collect()
    }

    #[test]
    fn ring_wraps_and_evicts_oldest() {
        let mut ring: Ring<u32, 4> = Ring::with_capacity(nonzero!(3));
        assert!(matches!(ring.slots, Slots::Inline(_)));
        assert_eq!(ring.as_slices(), (&[][..], &[][..]));

        assert_eq!(ring.push_back(1), None);
        assert_eq!(ring.push_back(2), None);
        assert!(!ring.is_full());
        assert_eq!(ring.push_back(3), None);
        assert!(ring.is_full());
        assert_eq!(ring.as_slices(), (&[1, 2, 3][..], &[][..]));

        assert_eq!(ring.push_back(4), Some(1));
        assert_eq!(ring.as_slices(), (&[2, 3][..], &[4][..]));
        assert_eq!(ring.push_back(5), Some(2));
        assert_eq!(ring.as_slices(), (&[3][..], &[4, 5][..]));
        // Head wraps back to slot 0.
        assert_eq!(ring.push_back(6), Some(3));
        assert_eq!(ring.as_slices(), (&[4, 5, 6][..], &[][..]));
        assert_eq!(collect(&ring), [4, 5, 6]);
    }

    #[test]
    fn ring_back_mut_targets_the_newest_entry_across_the_wrap() {
        let mut ring: Ring<u32, 3> = Ring::with_capacity(nonzero!(3));
        assert!(ring.back_mut().is_none());

        for item in 1..=4 {
            let _evicted = ring.push_back(item);
        }
        *ring.back_mut().expect("non-empty") += 10;
        assert_eq!(collect(&ring), [2, 3, 14]);
    }

    #[test]
    fn ring_spills_to_the_heap_above_the_inline_size() {
        let mut ring: Ring<u8, 2> = Ring::with_capacity(nonzero!(5));
        assert!(matches!(ring.slots, Slots::Heap(_)));
        assert_eq!(ring.slots().len(), 5);

        for item in 1..=6 {
            let evicted = ring.push_back(item);
            assert_eq!(evicted, (item == 6).then_some(1));
        }
        assert_eq!(collect(&ring), [2, 3, 4, 5, 6]);
    }

    #[test]
    fn sum_ring_buffer_tracks_the_running_sum_across_eviction() {
        let mut buf = SumRingBuffer::new(nonzero!(3));
        assert_eq!(buf.capacity(), nonzero!(3));
        assert_eq!(buf.sum(), 0);

        buf.push(1);
        buf.push(2);
        assert!(!buf.is_full());
        buf.push(3);
        assert!(buf.is_full());
        assert_eq!(buf.sum(), 6);

        buf.push(4);
        assert_eq!(buf.sum(), 9);

        buf.add_back(5);
        assert_eq!(buf.sum(), 14);
        assert_eq!(collect(&buf.inner), [2, 3, 9]);
    }

    #[test]
    fn sum_ring_buffer_add_back_on_empty_pushes_a_sample() {
        let mut buf = SumRingBuffer::new(nonzero!(2));
        buf.add_back(7usize);
        assert_eq!(buf.sum(), 7);
        assert!(!buf.is_full());
        assert_eq!(collect(&buf.inner), [7]);
    }

    #[test]
    fn ring_buffer_evicts_oldest_and_removes_by_index() {
        let mut buf = RingBuffer::new(nonzero!(2));
        assert!(buf.is_empty());
        buf.push("a");
        buf.push("b");
        assert!(buf.is_full());
        buf.push("c");
        assert_eq!(buf.iter().copied().collect::<Vec<_>>(), ["b", "c"]);
        assert_eq!(buf.len(), 2);

        assert_eq!(buf.remove(0), Some("b"));
        assert_eq!(buf.len(), 1);
        assert!(!buf.is_full());
        assert_eq!(buf.remove(5), None);
        assert_eq!(buf.iter().copied().collect::<Vec<_>>(), ["c"]);
    }
}
