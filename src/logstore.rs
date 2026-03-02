use std::{num::NonZero, sync::Arc};

use parking_lot::{RwLock, RwLockReadGuard};

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

    #[must_use]
    fn iter(&self) -> std::collections::vec_deque::Iter<'_, std::string::String> {
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
    inner: Arc<RwLock<LogStoreImpl>>,
}

impl LogStore {
    #[must_use]
    pub(crate) fn new(capacity: NonZero<usize>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(LogStoreImpl::new(capacity))),
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
        Ok(())
    }
}

#[must_use]
pub(crate) struct LogStoreEntryListGuard<'a> {
    guard: RwLockReadGuard<'a, LogStoreImpl>,
}

impl LogStoreEntryListGuard<'_> {
    #[must_use]
    pub(crate) fn iter(&self) -> std::collections::vec_deque::Iter<'_, std::string::String> {
        self.guard.iter()
    }
}
