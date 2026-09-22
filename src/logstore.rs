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
//!
//! An entry keeps at most [`MAX_ENTRY_LEN`] bytes: some warnings quote
//! upstream- or client-supplied values, and the ring holds
//! `logstore_capacity` entries for the life of the process. The console/file
//! sink still receives the whole line.

use std::{num::NonZero, sync::Arc};

use crate::{metrics, ringbuffer::RingBuffer};

/// Longest entry the ring keeps, in bytes; a longer line is cut at a char
/// boundary and marked with [`TRUNCATION_MARK`].
const MAX_ENTRY_LEN: usize = 4 * 1024;

const TRUNCATION_MARK: &str = " [truncated]";

/// The ring entry for one raw log line: lossily decoded, trimmed, and cut to
/// [`MAX_ENTRY_LEN`].
fn entry_from_line(line: &[u8]) -> String {
    let decoded = String::from_utf8_lossy(line);
    let trimmed = decoded.trim();
    if trimmed.len() <= MAX_ENTRY_LEN {
        return trimmed.to_owned();
    }
    let kept = trimmed
        .get(..trimmed.floor_char_boundary(MAX_ENTRY_LEN))
        .expect("floor_char_boundary yields a char boundary");
    let mut entry = String::with_capacity(kept.len() + TRUNCATION_MARK.len());
    entry.push_str(kept);
    entry.push_str(TRUNCATION_MARK);
    entry
}

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
            let entry = entry_from_line(&self.buffer[start..start + pos]);
            if self.entries.is_full() {
                metrics::LOGSTORE_EVICTIONS.increment();
            }
            self.entries.push(entry);
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

    /// A line longer than the entry cap is kept cut and marked, so a warning
    /// quoting a huge upstream value cannot pin that much memory per entry.
    #[test]
    fn an_overlong_line_is_truncated_at_a_char_boundary() {
        let mut store = new_store(4);

        // A two-byte char straddles the cap, so the cut must back off by one.
        let mut line = "a".repeat(MAX_ENTRY_LEN - 1);
        line.push_str(&"\u{e9}".repeat(1000));
        line.push('\n');
        store.write_all(line.as_bytes()).expect("write");
        store.write_all(b"next\n").expect("write");

        let entries = lines(&store);
        assert_eq!(entries.len(), 2);
        let expected = format!("{}{TRUNCATION_MARK}", "a".repeat(MAX_ENTRY_LEN - 1));
        assert_eq!(entries[0], expected);
        assert_eq!(entries[1], "next");

        // A line exactly at the cap is kept whole.
        let mut store = new_store(4);
        let at_cap = "b".repeat(MAX_ENTRY_LEN);
        store
            .write_all(format!("{at_cap}\n").as_bytes())
            .expect("write");
        assert_eq!(lines(&store), [at_cap]);
    }

    /// Invalid UTF-8 must not lose the record or panic the logging path.
    #[test]
    fn invalid_utf8_is_replaced_rather_than_dropped() {
        let mut store = new_store(4);

        store.write_all(b"bad \xff byte\n").expect("write");

        assert_eq!(lines(&store), ["bad \u{fffd} byte"]);
    }
}
