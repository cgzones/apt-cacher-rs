use std::{num::NonZero, sync::Arc};

use crate::ringbuffer::RingBuffer;

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

    fn iter(&self) -> impl Iterator<Item = &String> {
        self.entries.iter()
    }
}

impl std::io::Write for LogStoreImpl {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        let mut start = 0;
        while let Some(pos) = self.buffer[start..].iter().position(|&x| x == b'\n') {
            let line = &self.buffer[start..start + pos];
            let s = String::from_utf8_lossy(line);
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
}

impl LogStore {
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
        self.guard.iter()
    }
}
