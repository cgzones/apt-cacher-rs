//! The in-memory log ring behind the web interface's `/logs` page.
//!
//! `main()` installs [`LogStore`] as the writer of its own layer, filtered at
//! `WARN`, so the ring holds only warnings and errors — never the full log
//! stream the console/file sink receives.
//!
//! Being an `io::Write` sink, it receives raw formatted bytes rather than
//! records: a subscriber may split one line across several `write` calls and
//! pack several lines into one. Entries are therefore cut on `\n`, and the
//! tail of an unterminated line stays in `buffer` until its newline arrives.
//!
//! Readers take the same lock the writer does, so `entries()` blocks every
//! logging thread for as long as its guard lives — copy out and drop it.

use std::{num::NonZero, sync::Arc};

use crate::{metrics, ringbuffer::RingBuffer};

#[derive(Debug)]
struct LogStoreImpl {
    entries: RingBuffer<String>,
    buffer: Vec<u8>,
}

impl LogStoreImpl {
    #[must_use]
    fn new(capacity: NonZero<usize>) -> Self {
        Self {
            entries: RingBuffer::new(capacity),
            buffer: Vec::with_capacity(1024),
        }
    }
}

impl std::io::Write for LogStoreImpl {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        let mut start = 0;
        while let Some(pos) = self.buffer[start..].iter().position(|&x| x == b'\n') {
            let line = &self.buffer[start..start + pos];
            let s = String::from_utf8_lossy(line);
            if self.entries.is_full() {
                metrics::LOGSTORE_EVICTIONS.increment();
            }
            self.entries.push(s.trim().to_string());
            start += pos + 1;
        }
        if start > 0 {
            self.buffer.drain(..start);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LogStore {
    inner: Arc<parking_lot::RwLock<LogStoreImpl>>,
}

impl LogStore {
    #[must_use]
    pub(crate) fn new(capacity: NonZero<usize>) -> Self {
        Self {
            inner: Arc::new(parking_lot::RwLock::new(LogStoreImpl::new(capacity))),
        }
    }

    pub(crate) fn entries(&self) -> LogStoreEntryListGuard<'_> {
        let guard = self.inner.read();
        LogStoreEntryListGuard { guard }
    }
}

impl std::io::Write for LogStore {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.write().flush()
    }
}

#[must_use]
pub(crate) struct LogStoreEntryListGuard<'a> {
    guard: parking_lot::RwLockReadGuard<'a, LogStoreImpl>,
}

impl LogStoreEntryListGuard<'_> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &String> {
        self.guard.entries.iter()
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.guard.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn new_store(capacity: usize) -> LogStore {
        LogStore::new(NonZero::new(capacity).expect("non-zero capacity"))
    }

    fn lines(store: &LogStore) -> Vec<String> {
        let guard = store.entries();
        guard.iter().cloned().collect()
    }

    /// The subscriber writes formatted bytes, not records: a line can arrive
    /// in pieces and must not surface until its newline does.
    #[test]
    fn a_line_split_across_writes_surfaces_only_once_terminated() {
        let mut store = new_store(4);

        store.write_all(b"hello ").expect("write");
        assert!(lines(&store).is_empty(), "no newline seen yet");

        store.write_all(b"world\n").expect("write");
        assert_eq!(lines(&store), ["hello world"]);
    }

    /// One `write` can carry several records plus the head of the next one.
    #[test]
    fn one_write_is_split_on_every_newline_and_trimmed() {
        let mut store = new_store(4);

        store
            .write_all(b"first\r\n  second  \nthird-so-far")
            .expect("write");

        assert_eq!(lines(&store), ["first", "second"]);

        let count = store.entries().len();
        assert_eq!(count, 2, "the unterminated tail is not an entry yet");
    }

    /// Overflow is expected (the ring is a tail view), but it is the one
    /// condition an operator can fix by raising `logstore_capacity`, so it
    /// has to be counted.
    #[test]
    fn overflowing_the_ring_drops_the_oldest_entry_and_counts_it() {
        let mut store = new_store(2);
        let before = metrics::LOGSTORE_EVICTIONS.get();

        store.write_all(b"one\ntwo\n").expect("write");
        assert_eq!(
            metrics::LOGSTORE_EVICTIONS.get(),
            before,
            "filling the ring is not an eviction"
        );

        store.write_all(b"three\n").expect("write");
        assert_eq!(lines(&store), ["two", "three"]);
        assert_eq!(metrics::LOGSTORE_EVICTIONS.get(), before + 1);
    }

    /// Invalid UTF-8 must not lose the record or panic the logging path.
    #[test]
    fn invalid_utf8_is_replaced_rather_than_dropped() {
        let mut store = new_store(4);

        store.write_all(b"bad \xff byte\n").expect("write");

        assert_eq!(lines(&store), ["bad \u{fffd} byte"]);
    }
}
