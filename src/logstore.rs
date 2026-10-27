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
//! Readers copy entries with [`LogStore::snapshot`], releasing the shared
//! lock before rendering so that formatting cannot block logging threads.
//!
//! An entry keeps at most [`MAX_ENTRY_LEN`] bytes: some warnings quote
//! upstream- or client-supplied values, and the ring holds
//! `logstore_capacity` entries for the life of the process. The console/file
//! sink still receives the whole line. A fragmented record keeps only a
//! bounded raw prefix while waiting for its newline; leading whitespace in
//! an oversized fragmented line counts toward that prefix too.

use std::{num::NonZero, sync::Arc};

use crate::{
    mem_usage::{Footprint, buffer_bytes},
    metrics,
    ringbuffer::RingBuffer,
};

/// Longest entry the ring keeps, in bytes; a longer line is cut at a char
/// boundary and marked with [`TRUNCATION_MARK`].
const MAX_ENTRY_LEN: usize = 4 * 1024;

// Keep enough bytes to complete a UTF-8 scalar crossing the entry boundary.
const MAX_FRAGMENT_BYTES: usize = MAX_ENTRY_LEN + 3;

const TRUNCATION_MARK: &str = " [truncated]";

/// The ring entry for one raw log line: lossily decoded, trimmed, and cut to
/// [`MAX_ENTRY_LEN`].
fn entry_from_line(line: &[u8], truncated: bool) -> String {
    // A cut record can end inside a scalar; drop that partial scalar rather
    // than decode it to U+FFFD.
    let line = match line.utf8_chunks().last() {
        Some(chunk)
            if truncated
                && std::str::from_utf8(chunk.invalid())
                    .is_err_and(|err| err.error_len().is_none()) =>
        {
            &line[..line.len() - chunk.invalid().len()]
        }
        _ => line,
    };
    let decoded = String::from_utf8_lossy(line);
    let trimmed = decoded.trim();
    if trimmed.len() <= MAX_ENTRY_LEN && !truncated {
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
    truncated: bool,
}

impl LogStoreImpl {
    #[must_use]
    fn new(capacity: NonZero<usize>) -> Self {
        Self {
            entries: RingBuffer::new(capacity),
            buffer: Vec::with_capacity(1024),
            truncated: false,
        }
    }

    /// Retain a bounded prefix until the newline, discarding the rest of an
    /// oversized fragmented record. Its eventual entry still carries the mark
    /// unless only whitespace was discarded, which the trim would drop anyway.
    /// (A non-ASCII byte counts as content, so trailing Unicode whitespace
    /// past the cap still marks.)
    fn append_fragment(&mut self, fragment: &[u8]) {
        let kept = fragment.len().min(MAX_FRAGMENT_BYTES - self.buffer.len());
        let (kept, dropped) = fragment.split_at(kept);
        self.buffer.extend_from_slice(kept);
        self.truncated |= dropped
            .iter()
            .any(|&byte| !(byte.is_ascii() && char::from(byte).is_whitespace()));
    }
}

impl std::io::Write for LogStoreImpl {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for fragment in buf.split_inclusive(|&byte| byte == b'\n') {
            let Some(line) = fragment.strip_suffix(b"\n") else {
                self.append_fragment(fragment);
                continue;
            };
            // Formatters normally supply complete lines. Borrow those bytes
            // so one oversized warning does not enlarge the scratch buffer.
            let entry = if self.buffer.is_empty() {
                entry_from_line(line, false)
            } else {
                self.append_fragment(line);
                let entry = entry_from_line(&self.buffer, self.truncated);
                self.buffer.clear();
                self.truncated = false;
                entry
            };
            if self.entries.is_full() {
                metrics::LOGSTORE_EVICTIONS.increment();
            }
            self.entries.push(entry);
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

    pub(crate) fn snapshot(&self) -> Vec<String> {
        self.inner.read().entries.iter().cloned().collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.inner.read().entries.len()
    }

    /// Entries held and the heap they take: the ring's slots, each entry's
    /// text and the scratch buffer.
    pub(crate) fn footprint(&self) -> Footprint {
        let inner = self.inner.read();
        let text: usize = inner.entries.iter().map(String::capacity).sum();
        Footprint {
            entries: inner.entries.len(),
            bytes: buffer_bytes(inner.entries.capacity().get(), size_of::<String>())
                + text
                + inner.buffer.capacity(),
        }
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

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn new_store(capacity: usize) -> LogStore {
        LogStore::new(NonZero::new(capacity).expect("non-zero capacity"))
    }

    /// The subscriber writes formatted bytes, not records: a line can arrive
    /// in pieces and must not surface until its newline does.
    #[test]
    fn a_line_split_across_writes_surfaces_only_once_terminated() {
        let mut store = new_store(4);

        store.write_all(b"hello ").expect("write");
        assert!(store.snapshot().is_empty(), "no newline seen yet");

        store.write_all(b"world\n").expect("write");
        assert_eq!(store.snapshot(), ["hello world"]);
    }

    /// One `write` can carry several records plus the head of the next one.
    #[test]
    fn one_write_is_split_on_every_newline_and_trimmed() {
        let mut store = new_store(4);

        store
            .write_all(b"first\r\n  second  \nthird-so-far")
            .expect("write");

        assert_eq!(store.snapshot(), ["first", "second"]);

        let count = store.len();
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
        assert_eq!(store.snapshot(), ["two", "three"]);
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
        assert!(
            store.inner.read().buffer.capacity() <= MAX_ENTRY_LEN,
            "a complete oversized line must not enlarge the scratch buffer"
        );
        store.write_all(b"next\n").expect("write");

        let entries = store.snapshot();
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
        assert_eq!(store.snapshot(), [at_cap]);
    }

    #[test]
    fn fragmented_records_are_bounded_and_reset_at_the_next_newline() {
        let mut store = new_store(4);
        let prefix = "a".repeat(MAX_ENTRY_LEN - 1);
        store.write_all(prefix.as_bytes()).unwrap();
        // Split the scalar at the entry boundary across writes.
        store.write_all(&[0xc3]).unwrap();
        store.write_all(&[0xa9]).unwrap();
        let chunk = vec![b'x'; 1024];
        for _ in 0..1024 {
            store.write_all(&chunk).unwrap();
        }
        assert!(
            store.snapshot().is_empty(),
            "the record still needs its newline"
        );
        assert!(store.inner.read().buffer.len() <= MAX_FRAGMENT_BYTES);
        store.write_all(b"discarded tail\nnext\n").unwrap();
        assert_eq!(
            store.snapshot(),
            [format!("{prefix}{TRUNCATION_MARK}"), "next".to_owned()]
        );

        // An ordinary fragmented scalar and an exactly-at-cap record stay whole.
        store.write_all(&[0xc3]).unwrap();
        store.write_all(&[0xa9, b'\n']).unwrap();
        let at_cap = "b".repeat(MAX_ENTRY_LEN);
        for part in at_cap.as_bytes().chunks(1024) {
            store.write_all(part).unwrap();
        }
        store.write_all(b"\n").unwrap();
        let entries = store.snapshot();
        assert_eq!(entries[2], "\u{e9}");
        assert_eq!(entries[3], at_cap);

        // Whitespace past the cap is trimmed, not truncated content.
        store.write_all(at_cap.as_bytes()).unwrap();
        store.write_all(b" \t\x0b ").unwrap();
        store.write_all(b"\n").unwrap();
        assert_eq!(store.snapshot()[3], at_cap);

        // Leading whitespace shifts the cap into a scalar: the partial scalar
        // is dropped, not decoded to U+FFFD.
        let shifted = "a".repeat(MAX_ENTRY_LEN - 8);
        store.write_all(b"          ").unwrap();
        store.write_all(shifted.as_bytes()).unwrap();
        store.write_all("\u{e9} tail".as_bytes()).unwrap();
        store.write_all(b"\n").unwrap();
        assert_eq!(store.snapshot()[3], format!("{shifted}{TRUNCATION_MARK}"));
    }

    /// Invalid UTF-8 must not lose the record or panic the logging path.
    #[test]
    fn invalid_utf8_is_replaced_rather_than_dropped() {
        let mut store = new_store(4);

        store.write_all(b"bad \xff byte\n").expect("write");

        assert_eq!(store.snapshot(), ["bad \u{fffd} byte"]);
    }
}
