//! Process-wide defence-in-depth bounds shared across the hyper / splice /
//! sendfile code paths, plus the small helpers that enforce them.
//!
//! This module hosts the cross-path limits that benefit from a single
//! definition (upstream header size/count, `Packages` decompression caps,
//! upstream metadata line length, CONNECT authority cap). It is *not* the
//! sole audit point for every defensive limit — module-local constants
//! still live next to their callers (for example `deb_mirror`'s
//! mirror-path bounds, `sendfile_conn`'s request-header cap). The two
//! *configurable* bounds (`max_object_size`, `client_idle_timeout`) live
//! on [`crate::config::Config`] and are reached via `global_config()`;
//! everything here is a compile-time constant or a pure helper.

use std::io;
use std::num::NonZero;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncRead, ReadBuf};

use crate::nonzero;

/// Maximum size (bytes) of an upstream HTTP response header block.
#[cfg_attr(
    not(feature = "splice"),
    expect(
        dead_code,
        reason = "splice_conn.rs is the sole consumer; not compiled without splice"
    )
)]
pub(crate) const MAX_UPSTREAM_HEADER_SIZE: usize = 8192;

/// Maximum number of header fields parsed from an upstream HTTP response.
pub(crate) const MAX_UPSTREAM_HEADERS: usize = 32;

/// Absolute ceiling (bytes) on the decompressed output of a `Packages` file.
pub(crate) const MAX_DECOMPRESSED_PACKAGES_SIZE: NonZero<u64> = nonzero!(1024 * 1024 * 1024);

/// Maximum decompressed-to-compressed ratio tolerated for a `Packages` file.
pub(crate) const MAX_DECOMPRESSION_RATIO: NonZero<u64> = nonzero!(100);

/// Maximum length (bytes) of a single line read from upstream metadata.
pub(crate) const MAX_METADATA_LINE_LEN: usize = 8 * 1024;

/// Defensive upper bound on the byte length of a CONNECT request's
/// authority (`<host>:<port>`).  Real-world authorities are well below
/// this: an FQDN is capped at 253 bytes by RFC 1035 and a `:port` suffix
/// adds at most 6 bytes.
pub(crate) const MAX_AUTHORITY_LEN: usize = 260;

/// Returns `true` if a declared upstream Content-Length of `declared` bytes is
/// within the configured `max_object_size` cap. A `None` cap disables the
/// check.
#[must_use]
pub(crate) fn content_length_within_cap(
    declared: u64,
    max_object_size: Option<NonZero<u64>>,
) -> bool {
    match max_object_size {
        Some(max) => declared <= max.get(),
        None => true,
    }
}

/// An [`AsyncRead`] adapter that fails with [`io::ErrorKind::InvalidData`] once
/// more than `limit` total bytes have been read from the inner reader. Used to
/// bound the decompressed output of upstream `Packages` files.
pub(crate) struct LimitedReader<R> {
    inner: R,
    limit: NonZero<u64>,
    count: u64,
}

impl<R> LimitedReader<R> {
    pub(crate) fn new(inner: R, limit: NonZero<u64>) -> Self {
        Self {
            inner,
            limit,
            count: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for LimitedReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = (buf.filled().len() - before) as u64;
                this.count = this.count.saturating_add(read);
                if this.count > this.limit.get() {
                    // Undo the fill so the caller sees zero bytes read alongside
                    // the error — tokio's `read_to_end` asserts n == 0 on Err.
                    buf.set_filled(before);
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "decompressed size exceeds limit",
                    )))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            other @ (Poll::Ready(_) | Poll::Pending) => other,
        }
    }
}

/// Outcome of a single [`read_line_capped`] call.
#[derive(Debug)]
pub(crate) enum CappedLine {
    /// End of stream reached with no data read.
    Eof,
    /// A line was read and appended to the caller's buffer; `bytes` includes
    /// any trailing newline.
    #[cfg_attr(not(test), expect(unused, reason = "might be useful in the future"))]
    Line { bytes: usize },
    /// A line longer than `max_len` was drained (its trailing newline, if
    /// any, was consumed) without appending anything to the buffer. The
    /// `Packages` parser uses this to skip fields it does not care about
    /// (e.g. multi-kilobyte `Provides:` lists) without aborting the file.
    Skipped,
}

/// Read one line (through the next `\n`, inclusive) from `reader`, appending it
/// to `buf`. A line longer than `max_len` bytes is drained from the reader and
/// reported as [`CappedLine::Skipped`] — the absolute decompressed-size cap is
/// enforced separately by [`LimitedReader`], so the per-line cap only exists
/// to bound the in-memory line buffer. Fails with [`io::ErrorKind::InvalidData`]
/// if the bytes read are not valid UTF-8.
///
/// `line_buf` is a caller-owned scratch buffer whose capacity is reused across
/// calls; the body of a real `Packages` file is hundreds of thousands of short
/// lines, so allocating a fresh `Vec` per call would dominate cleanup-scan
/// allocator traffic. The buffer is cleared on entry; its prior contents are
/// not preserved.
///
/// A bounded replacement for [`tokio::io::AsyncBufReadExt::read_line`], which
/// allocates without limit when an upstream metadata file contains a line with
/// no newline terminator.
pub(crate) async fn read_line_capped<R>(
    reader: &mut R,
    buf: &mut String,
    line_buf: &mut Vec<u8>,
    max_len: usize,
) -> io::Result<CappedLine>
where
    R: AsyncBufRead + Unpin + ?Sized,
{
    line_buf.clear();
    let oversized = loop {
        let available = match reader.fill_buf().await {
            Ok(bytes) => bytes,
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if available.is_empty() {
            break false; // EOF
        }
        if let Some(idx) = available.iter().position(|&b| b == b'\n') {
            let take = idx + 1;
            if line_buf.len() + take > max_len {
                reader.consume(take);
                break true;
            }
            line_buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            break false;
        }
        let take = available.len();
        if line_buf.len() + take > max_len {
            reader.consume(take);
            drain_to_newline(reader).await?;
            break true;
        }
        line_buf.extend_from_slice(available);
        reader.consume(take);
    };
    if oversized {
        return Ok(CappedLine::Skipped);
    }
    if line_buf.is_empty() {
        return Ok(CappedLine::Eof);
    }
    let text = std::str::from_utf8(line_buf).map_err(|_err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata line is not valid UTF-8",
        )
    })?;
    buf.push_str(text);
    Ok(CappedLine::Line {
        bytes: line_buf.len(),
    })
}

/// Consume bytes from `reader` up to and including the next `\n`, or until
/// EOF. Used to skip the tail of an over-length line after the in-memory
/// accumulator has been abandoned.
async fn drain_to_newline<R>(reader: &mut R) -> io::Result<()>
where
    R: AsyncBufRead + Unpin + ?Sized,
{
    loop {
        let available = match reader.fill_buf().await {
            Ok(bytes) => bytes,
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if available.is_empty() {
            return Ok(());
        }
        if let Some(idx) = available.iter().position(|&b| b == b'\n') {
            reader.consume(idx + 1);
            return Ok(());
        }
        let len = available.len();
        reader.consume(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonzero;

    #[tokio::test]
    async fn limited_reader_allows_within_limit() {
        use tokio::io::AsyncReadExt as _;
        let data = b"hello world";
        let mut reader = LimitedReader::new(&data[..], nonzero!(100));
        let mut out = Vec::new();
        reader
            .read_to_end(&mut out)
            .await
            .expect("read within limit");
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn limited_reader_rejects_over_limit() {
        use tokio::io::AsyncReadExt as _;
        let data = vec![0u8; 1000];
        let mut reader = LimitedReader::new(&data[..], nonzero!(100));
        let mut out = Vec::new();
        let err = reader
            .read_to_end(&mut out)
            .await
            .expect_err("must exceed limit");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn limited_reader_allows_exact_limit() {
        use tokio::io::AsyncReadExt as _;
        let data = [0u8; 100];
        let mut reader = LimitedReader::new(&data[..], nonzero!(100));
        let mut out = Vec::new();
        reader
            .read_to_end(&mut out)
            .await
            .expect("reading exactly `limit` bytes must succeed");
        assert_eq!(out.len(), 100);
    }

    #[tokio::test]
    async fn read_line_capped_reads_short_line() {
        let input = b"short line\nnext";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let mut buf = String::new();
        let mut line_buf = Vec::new();
        let result = read_line_capped(&mut reader, &mut buf, &mut line_buf, 64)
            .await
            .expect("ok");
        assert!(matches!(result, CappedLine::Line { bytes: 11 }));
        assert_eq!(buf, "short line\n");
    }

    #[tokio::test]
    async fn read_line_capped_skips_long_line() {
        let mut input = vec![b'a'; 1000];
        input.push(b'\n');
        input.extend_from_slice(b"next\n");
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let mut buf = String::new();
        let mut line_buf = Vec::new();
        let result = read_line_capped(&mut reader, &mut buf, &mut line_buf, 64)
            .await
            .expect("over-length line must be skipped, not errored");
        assert!(matches!(result, CappedLine::Skipped));
        assert!(buf.is_empty());

        // The drain must consume past the newline so the next call sees the
        // following line.
        let result = read_line_capped(&mut reader, &mut buf, &mut line_buf, 64)
            .await
            .expect("follow-on read");
        assert!(matches!(result, CappedLine::Line { bytes: 5 }));
        assert_eq!(buf, "next\n");
    }

    #[tokio::test]
    async fn read_line_capped_skips_long_line_without_newline() {
        // No trailing newline anywhere — the drain reaches EOF.
        let input = vec![b'a'; 1000];
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let mut buf = String::new();
        let mut line_buf = Vec::new();
        let result = read_line_capped(&mut reader, &mut buf, &mut line_buf, 64)
            .await
            .expect("ok");
        assert!(matches!(result, CappedLine::Skipped));
        assert!(buf.is_empty());

        let result = read_line_capped(&mut reader, &mut buf, &mut line_buf, 64)
            .await
            .expect("follow-on read");
        assert!(matches!(result, CappedLine::Eof));
    }

    #[tokio::test]
    async fn read_line_capped_eof_returns_eof() {
        let input: &[u8] = b"";
        let mut reader = tokio::io::BufReader::new(input);
        let mut buf = String::new();
        let mut line_buf = Vec::new();
        let result = read_line_capped(&mut reader, &mut buf, &mut line_buf, 64)
            .await
            .expect("ok");
        assert!(matches!(result, CappedLine::Eof));
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn read_line_capped_accepts_exact_limit() {
        // 4 data bytes + '\n' = 5 bytes total == max_len
        let input = b"abcd\nmore";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let mut buf = String::new();
        let mut line_buf = Vec::new();
        let result = read_line_capped(&mut reader, &mut buf, &mut line_buf, 5)
            .await
            .expect("exact limit must be accepted");
        assert!(matches!(result, CappedLine::Line { bytes: 5 }));
        assert_eq!(buf, "abcd\n");
    }

    #[tokio::test]
    async fn read_line_capped_rejects_non_utf8() {
        let input = b"\xff\xfe\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let mut buf = String::new();
        let mut line_buf = Vec::new();
        let err = read_line_capped(&mut reader, &mut buf, &mut line_buf, 64)
            .await
            .expect_err("non-UTF-8 must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_line_capped_partial_eof() {
        let input = b"no newline";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let mut buf = String::new();
        let mut line_buf = Vec::new();
        let result = read_line_capped(&mut reader, &mut buf, &mut line_buf, 64)
            .await
            .expect("ok");
        assert!(matches!(result, CappedLine::Line { bytes: 10 }));
        assert_eq!(buf, "no newline");
    }

    #[tokio::test]
    async fn read_line_capped_reuses_line_buf_across_calls() {
        // The whole point of accepting `line_buf` by &mut is to reuse its
        // capacity across calls. Verify that a second call to the same buffer
        // does not re-allocate by checking the capacity does not shrink and
        // a previously-grown allocation is reused.
        let input = b"first\nsecond\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let mut buf = String::new();
        let mut line_buf = Vec::with_capacity(64);
        let cap_before = line_buf.capacity();

        let _: CappedLine = read_line_capped(&mut reader, &mut buf, &mut line_buf, 64)
            .await
            .expect("first line");
        buf.clear();
        let _: CappedLine = read_line_capped(&mut reader, &mut buf, &mut line_buf, 64)
            .await
            .expect("second line");

        assert!(line_buf.capacity() >= cap_before);
        assert_eq!(buf, "second\n");
    }

    #[test]
    fn content_length_cap_checks() {
        let cap = NonZero::new(100);
        assert!(content_length_within_cap(0, cap));
        assert!(content_length_within_cap(100, cap));
        assert!(!content_length_within_cap(101, cap));
        // `None` disables the cap entirely.
        assert!(content_length_within_cap(u64::MAX, None));
    }
}
