//! Process-wide defence-in-depth bounds shared across the hyper / splice /
//! sendfile code paths, plus the small helpers that enforce them.
//!
//! Not the sole audit point for every defensive limit: module-local
//! constants still live next to their callers, and the configurable bounds
//! (`max_object_size`, `client_idle_timeout`) live on
//! [`crate::config::Config`].

use std::io;
use std::num::NonZero;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncRead, ReadBuf};

use crate::nonzero;
use crate::xz_stream::xz_decoder;

/// Maximum size (bytes) of an upstream HTTP response header block, and of a
/// chunked body's trailer section. Twice the sendfile backend's request-head
/// cap: a response head also carries what the mirror's CDN adds.
#[cfg_attr(
    not(feature = "splice"),
    expect(
        dead_code,
        reason = "splice/http.rs is the sole consumer; not compiled without splice"
    )
)]
pub(crate) const MAX_UPSTREAM_HEADER_SIZE: usize = 16 * 1024;

/// Maximum number of header fields parsed from an upstream HTTP response.
/// hyper's own default, and the sendfile backend's cap on a request head:
/// a mirror behind a CDN and an application server can exceed a few dozen
/// fields, and a response over the cap is a 502 for every request.
pub(crate) const MAX_UPSTREAM_HEADERS: usize = 100;

/// Largest read buffer the hyper client grows per upstream connection, which
/// also bounds the response head it accepts. hyper's default is ~400 KiB.
/// Not [`MAX_UPSTREAM_HEADER_SIZE`]: the same buffer carries every body
/// read, and at 16 KiB eight 256 MiB loopback downloads cost 1.5-2x the
/// daemon CPU of the default, while 128 KiB measured within noise of it.
#[cfg(feature = "hyper")]
pub(crate) const MAX_UPSTREAM_READ_BUFFER: usize = 128 * 1024;

/// Absolute ceiling (bytes) on the decompressed output of a `Packages` file,
/// and so on a raw one, which cleanup buffers whole (a memfd in hyper builds,
/// a `Vec` in hyper-less ones) for up to ten mirrors at once. Debian's largest,
/// `main/binary-amd64/Packages`, decompresses to well under 100 MiB.
pub(crate) const MAX_DECOMPRESSED_PACKAGES_SIZE: NonZero<u64> = nonzero!(256 * 1024 * 1024);

/// Ceiling (bytes) on a compressed (`.gz`/`.xz`) `Packages` file, checked
/// before it is decoded or, by cleanup, buffered. Debian's largest,
/// `main/binary-amd64/Packages.xz`, is ~10 MiB.
pub(crate) const MAX_COMPRESSED_PACKAGES_SIZE: NonZero<u64> = nonzero!(128 * 1024 * 1024);

/// Maximum size (bytes) of a `Release` / `InRelease` file ingested into the
/// checksum registry, which is read into memory whole. Real Release files
/// for Debian-scale archives are tens of KB.
pub(crate) const MAX_RELEASE_SIZE: NonZero<u64> = nonzero!(8 * 1024 * 1024);

/// Maximum decompressed-to-compressed ratio tolerated for a `Packages` file.
const MAX_DECOMPRESSION_RATIO: NonZero<u64> = nonzero!(100);

/// Largest LZMA2 dictionary an `.xz` index may declare, 64 MiB (`xz -9`;
/// Debian's archive tooling uses `-6`, 8 MiB).  The decoder's window grows
/// with the decoded output up to the declared dictionary, so without this
/// cap one ingest could hold a window as large as
/// [`MAX_DECOMPRESSED_PACKAGES_SIZE`].
pub(crate) const MAX_XZ_DICT_SIZE: NonZero<u64> = nonzero!(64 * 1024 * 1024);

/// Idle upstream connections kept per host, by the splice backend's own pool
/// and the hyper client's alike. Each one holds a socket and its read buffer
/// (up to 256 KiB over TLS in splice, hyper's adaptive buffer otherwise);
/// hyper-util's default keeps every one ever opened.
pub(crate) const UPSTREAM_POOL_MAX_IDLE_PER_HOST: usize = 4;

/// Maximum length (bytes) of a single line read from upstream metadata.
pub(crate) const MAX_METADATA_LINE_LEN: usize = 8 * 1024;

/// Upper bound on the byte length of a CONNECT request's authority
/// (`<host>:<port>`): an FQDN is capped at 253 bytes by RFC 1035 and a
/// `:port` suffix adds at most 6 bytes.
pub(crate) const MAX_AUTHORITY_LEN: usize = 259;

pub(crate) const RETENTION_TIME: Duration = Duration::from_hours(8 * 7 * 24); /* 8 weeks */

pub(crate) const VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER: NonZero<u64> = nonzero!(1024 * 1024); /* 1MiB */

/// Maximum age for volatile cache entries before they are treated as stale.
pub(crate) const VOLATILE_CACHE_MAX_AGE: Duration = Duration::from_secs(30);

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

/// A reader adapter ([`AsyncRead`] and [`io::Read`]) that fails with
/// [`io::ErrorKind::InvalidData`] once more than `limit` total bytes have been
/// read from the inner reader.
struct LimitedReader<R> {
    inner: R,
    limit: NonZero<u64>,
    count: u64,
    /// The error message once the limit is crossed.
    exceeded: &'static str,
}

impl<R> LimitedReader<R> {
    fn decompressed(inner: R, limit: NonZero<u64>) -> Self {
        Self {
            inner,
            limit,
            count: 0,
            exceeded: "decompressed size exceeds limit",
        }
    }

    fn compressed(inner: R, limit: NonZero<u64>) -> Self {
        Self {
            inner,
            limit,
            count: 0,
            exceeded: "compressed Packages index exceeds the size cap",
        }
    }

    fn account(&mut self, read: usize) -> io::Result<()> {
        self.count = self.count.saturating_add(read as u64);
        if self.count > self.limit.get() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, self.exceeded));
        }
        Ok(())
    }
}

impl<R: io::Read> io::Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.account(read)?;
        Ok(read)
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
                let read = buf.filled().len() - before;
                if let Err(err) = this.account(read) {
                    // Undo the fill so the caller sees zero bytes read alongside
                    // the error — tokio's `read_to_end` asserts n == 0 on Err.
                    buf.set_filled(before);
                    Poll::Ready(Err(err))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            other @ (Poll::Ready(_) | Poll::Pending) => other,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CappedLine<'a> {
    /// End of stream reached with no data read.
    Eof,
    /// A line, including any trailing newline, borrowed from the caller's
    /// `line_buf`. Raw bytes: the caller decodes only what it reads as text.
    Line(&'a [u8]),
    /// A line longer than `max_len` was drained (its trailing newline, if
    /// any, was consumed) without keeping any of it. The
    /// `Packages` parser uses this to skip fields it does not care about
    /// (e.g. multi-kilobyte `Provides:` lists) without aborting the file.
    Skipped,
}

/// A bounded replacement for [`tokio::io::AsyncBufReadExt::read_line`], which
/// allocates without limit on a line with no newline terminator: a line
/// longer than `max_len` bytes is drained from the reader and reported as
/// [`CappedLine::Skipped`]. The bytes are not validated as UTF-8: a
/// `Packages` file may carry another encoding in fields nobody reads (a
/// Latin-1 `Description:`), so the caller decodes only the fields it uses.
///
/// `line_buf` is a caller-owned scratch buffer, cleared on entry, whose
/// capacity is reused across calls: a real `Packages` file is millions of
/// short lines.
pub(crate) async fn read_line_capped<'a, R>(
    reader: &mut R,
    line_buf: &'a mut Vec<u8>,
    max_len: usize,
) -> io::Result<CappedLine<'a>>
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
        if let Some(idx) = memchr::memchr(b'\n', available) {
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
    Ok(CappedLine::Line(line_buf))
}

/// Compression of a `Packages` file.
///
/// [`extension`](Self::extension) and [`from_filename`](Self::from_filename)
/// are inverses of one table, so a new format is one edit here rather than
/// two in separate modules.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PackagesCompression {
    Raw,
    Gz,
    Xz,
}

impl PackagesCompression {
    #[must_use]
    pub(crate) const fn extension(self) -> &'static str {
        match self {
            Self::Raw => "",
            Self::Gz => ".gz",
            Self::Xz => ".xz",
        }
    }

    /// `None` if the filename leaf is not a `Packages` file at all.
    #[must_use]
    pub(crate) fn from_filename(name: &str) -> Option<Self> {
        match name {
            "Packages" => Some(Self::Raw),
            "Packages.gz" => Some(Self::Gz),
            "Packages.xz" => Some(Self::Xz),
            _ => None,
        }
    }
}

/// Largest `Packages` file in `compression` that is decoded or buffered. A
/// raw file is its own decompressed output.
#[must_use]
pub(crate) const fn packages_file_cap(compression: PackagesCompression) -> NonZero<u64> {
    match compression {
        PackagesCompression::Raw => MAX_DECOMPRESSED_PACKAGES_SIZE,
        PackagesCompression::Gz | PackagesCompression::Xz => MAX_COMPRESSED_PACKAGES_SIZE,
    }
}

pub(crate) fn check_packages_file_size(
    compression: PackagesCompression,
    size: u64,
) -> io::Result<()> {
    let cap = packages_file_cap(compression);
    if size > cap.get() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Packages{} index of {size} bytes exceeds the {} byte cap",
                compression.extension(),
                cap.get()
            ),
        ));
    }
    Ok(())
}

/// The effective decompressed-output ceiling for a `Packages` file of
/// `compressed_size` bytes. `None` - an empty file - yields the absolute cap.
#[must_use]
pub(crate) fn decompressed_limit(compressed_size: Option<NonZero<u64>>) -> NonZero<u64> {
    match compressed_size {
        Some(size) => {
            MAX_DECOMPRESSED_PACKAGES_SIZE.min(size.saturating_mul(MAX_DECOMPRESSION_RATIO))
        }
        None => MAX_DECOMPRESSED_PACKAGES_SIZE,
    }
}

/// A `Packages` index to decode: an open file, or bytes already in memory
/// (cleanup's hyper-less fetch, which reads the whole body anyway).
#[derive(Debug)]
pub(crate) enum PackagesInput {
    File(tokio::fs::File),
    #[cfg_attr(
        all(feature = "hyper", not(test)),
        expect(
            dead_code,
            reason = "only cleanup's hyper-less fetch (`cleanup/fetch.rs`) decodes from memory"
        )
    )]
    Bytes(Vec<u8>),
}

enum InputReader {
    File(tokio::fs::File),
    Bytes(io::Cursor<Vec<u8>>),
}

impl From<PackagesInput> for InputReader {
    fn from(input: PackagesInput) -> Self {
        match input {
            PackagesInput::File(file) => Self::File(file),
            PackagesInput::Bytes(bytes) => Self::Bytes(io::Cursor::new(bytes)),
        }
    }
}

impl AsyncRead for InputReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::File(file) => Pin::new(file).poll_read(cx, buf),
            Self::Bytes(bytes) => {
                // A memory cursor never waits for I/O. Charge its reads to
                // Tokio's budget so a large raw/gzip index cannot monopolize
                // a worker while the parser keeps finding ready bytes.
                let budget = std::task::ready!(tokio::task::coop::poll_proceed(cx));
                let read = Pin::new(bytes).poll_read(cx, buf);
                if read.is_ready() {
                    budget.made_progress();
                }
                read
            }
        }
    }
}

/// Wrap a `Packages` index in its decompression layer with the
/// decompression-bomb guard applied, ready for [`read_line_capped`].
///
/// `limit` bounds the *decompressed* byte count (see [`decompressed_limit`]).
/// A second [`LimitedReader`] below the decoder holds a `.gz`/`.xz` input to
/// [`packages_file_cap`] as it is read: the callers check the size they stat
/// first, and this layer holds the bytes actually read to the same bound,
/// since a decoder does work per input byte that yields no output (xz's
/// empty blocks), which no output cap sees.
pub(crate) async fn packages_reader(
    input: PackagesInput,
    compression: PackagesCompression,
    limit: NonZero<u64>,
    buffer_size: usize,
) -> Box<dyn AsyncBufRead + Unpin + Send> {
    let input_cap = packages_file_cap(compression);
    wrap_packages(input, compression, limit, input_cap, buffer_size).await
}

/// [`packages_reader`] with the compressed-input cap as a parameter, so the
/// tests can cross it without a 128 MiB fixture. Raw input has no
/// compressed side; `limit` bounds it.
async fn wrap_packages(
    input: PackagesInput,
    compression: PackagesCompression,
    limit: NonZero<u64>,
    input_cap: NonZero<u64>,
    buffer_size: usize,
) -> Box<dyn AsyncBufRead + Unpin + Send> {
    match compression {
        PackagesCompression::Raw => Box::new(tokio::io::BufReader::with_capacity(
            buffer_size,
            LimitedReader::decompressed(InputReader::from(input), limit),
        )),
        PackagesCompression::Gz => {
            let input_reader = tokio::io::BufReader::with_capacity(
                buffer_size,
                LimitedReader::compressed(InputReader::from(input), input_cap),
            );
            let decoder = async_compression::tokio::bufread::GzipDecoder::new(input_reader);
            Box::new(tokio::io::BufReader::with_capacity(
                buffer_size,
                LimitedReader::decompressed(decoder, limit),
            ))
        }
        PackagesCompression::Xz => {
            let decoder = match input {
                PackagesInput::File(file) => {
                    xz_decoder(LimitedReader::compressed(file.into_std().await, input_cap))
                }
                PackagesInput::Bytes(bytes) => {
                    xz_decoder(LimitedReader::compressed(io::Cursor::new(bytes), input_cap))
                }
            };
            Box::new(tokio::io::BufReader::with_capacity(
                buffer_size,
                LimitedReader::decompressed(decoder, limit),
            ))
        }
    }
}

/// Consume bytes from `reader` up to and including the next `\n`, or until
/// EOF.
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
        if let Some(idx) = memchr::memchr(b'\n', available) {
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

    /// Reading an already-buffered index must still leave room for other
    /// futures on the worker, even when every input read is immediately ready.
    #[tokio::test]
    async fn in_memory_index_reads_yield_to_other_futures() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::AsyncBufReadExt as _;

        let yielded = tokio::spawn(async {
            let sibling_ran = AtomicBool::new(false);
            let (observed_sibling, ()) = tokio::join! {
                biased;
                async {
                    let mut reader = packages_reader(
                        PackagesInput::Bytes(vec![b'x'; 512 * 1024]),
                        PackagesCompression::Raw,
                        MAX_DECOMPRESSED_PACKAGES_SIZE,
                        1024,
                    ).await;
                    loop {
                        let len = reader.fill_buf().await.expect("read memory index").len();
                        if len == 0 {
                            break;
                        }
                        reader.consume(len);
                    }
                    sibling_ran.load(Ordering::Relaxed)
                },
                async { sibling_ran.store(true, Ordering::Relaxed); }
            };
            observed_sibling
        })
        .await
        .expect("reader task");
        assert!(
            yielded,
            "the index reader must yield before consuming the entire input"
        );
    }

    #[test]
    fn decompressed_limit_is_the_ratio_up_to_the_absolute_cap() {
        for (compressed_size, expected) in [
            (
                Some(nonzero!(1000)),
                MAX_DECOMPRESSION_RATIO.checked_mul(nonzero!(1000)).unwrap(),
            ),
            // The ratio multiply must saturate rather than wrap.
            (Some(nonzero!(u64::MAX)), MAX_DECOMPRESSED_PACKAGES_SIZE),
            (None, MAX_DECOMPRESSED_PACKAGES_SIZE),
        ] {
            assert_eq!(decompressed_limit(compressed_size), expected);
        }
    }

    #[test]
    fn packages_file_size_is_capped_per_compression() {
        for compression in [PackagesCompression::Gz, PackagesCompression::Xz] {
            let cap = MAX_COMPRESSED_PACKAGES_SIZE.get();
            check_packages_file_size(compression, cap).expect("at the cap");
            let err = check_packages_file_size(compression, cap + 1)
                .expect_err("a compressed index past the cap must be refused");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
        let cap = MAX_DECOMPRESSED_PACKAGES_SIZE.get();
        assert_eq!(cap, 256 * 1024 * 1024);
        check_packages_file_size(PackagesCompression::Raw, cap).expect("at the cap");
        check_packages_file_size(PackagesCompression::Raw, cap + 1)
            .expect_err("a raw index past the decompressed cap must be refused");
    }

    #[test]
    fn compression_extension_and_from_filename_are_inverses() {
        for c in [
            PackagesCompression::Raw,
            PackagesCompression::Gz,
            PackagesCompression::Xz,
        ] {
            let leaf = format!("Packages{}", c.extension());
            assert_eq!(PackagesCompression::from_filename(&leaf), Some(c), "{leaf}");
        }
        assert_eq!(PackagesCompression::from_filename("Release"), None);
        assert_eq!(PackagesCompression::from_filename("Packages.bz2"), None);
    }

    #[tokio::test]
    async fn limited_reader_fails_past_its_limit() {
        use tokio::io::AsyncReadExt as _;
        for (len, within) in [(11, true), (100, true), (101, false), (1000, false)] {
            let data = vec![0u8; len];
            let mut reader = LimitedReader::decompressed(&data[..], nonzero!(100));
            let mut out = Vec::new();
            let result = reader.read_to_end(&mut out).await;
            if within {
                assert_eq!(result.expect("within the limit"), len);
                assert_eq!(out, data);
            } else {
                let err = result.expect_err("past the limit");
                assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{len}");
            }
        }
    }

    async fn decode_capped(
        encoded: &[u8],
        compression: PackagesCompression,
        input_cap: u64,
    ) -> io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt as _;
        let file = tempfile::tempfile().expect("temp file");
        let mut file = tokio::fs::File::from_std(file);
        tokio::io::AsyncWriteExt::write_all(&mut file, encoded)
            .await
            .expect("write fixture");
        tokio::io::AsyncSeekExt::rewind(&mut file)
            .await
            .expect("rewind fixture");
        let mut reader = wrap_packages(
            PackagesInput::File(file),
            compression,
            MAX_DECOMPRESSED_PACKAGES_SIZE,
            NonZero::new(input_cap).expect("non-zero cap"),
            1024,
        )
        .await;
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.map(|_| out)
    }

    #[tokio::test]
    async fn compressed_input_is_held_to_the_cap() {
        let gz = crate::test_support::gzip(b"hello world\n").await;
        let xz = crate::xz_stream::tests::HELLO_XZ;

        for (compression, encoded) in [
            (PackagesCompression::Gz, &gz[..]),
            (PackagesCompression::Xz, xz),
        ] {
            let len = encoded.len() as u64;
            let out = decode_capped(encoded, compression, len)
                .await
                .expect("an index at the cap decodes");
            assert_eq!(out, b"hello world\n", "{compression:?}");
            let err = decode_capped(encoded, compression, len - 1)
                .await
                .expect_err("an index over the cap must fail");
            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidData,
                "{compression:?}: {err}"
            );
            assert!(
                err.to_string()
                    .contains("compressed Packages index exceeds"),
                "{compression:?}: {err}"
            );
        }
    }

    #[test]
    fn limited_reader_bounds_a_blocking_reader() {
        use std::io::Read as _;
        let within = [1u8; 100];
        let mut out = Vec::new();
        LimitedReader::compressed(&within[..], nonzero!(100))
            .read_to_end(&mut out)
            .expect("reading exactly `limit` bytes must succeed");
        assert_eq!(out.len(), 100);

        let over = [1u8; 101];
        let err = LimitedReader::compressed(&over[..], nonzero!(100))
            .read_to_end(&mut Vec::new())
            .expect_err("101 bytes exceed the 100-byte limit");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("compressed"), "{err}");
    }

    #[tokio::test]
    async fn limited_reader_undoes_the_fill_on_overrun() {
        let data = [7u8; 150];
        let mut reader = LimitedReader::decompressed(&data[..], nonzero!(100));
        let mut storage = [0u8; 150];
        let mut buf = ReadBuf::new(&mut storage);
        let polled = std::future::poll_fn(|cx| Pin::new(&mut reader).poll_read(cx, &mut buf)).await;
        let err = polled.expect_err("150 bytes exceed the 100-byte limit");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            buf.filled().is_empty(),
            "the caller must see zero bytes read alongside the error"
        );
    }

    /// Every result of reading `input` to EOF through a `BufReader` of
    /// `capacity` bytes, the final `Eof` left out.
    async fn capped_lines(input: &[u8], capacity: usize, max_len: usize) -> Vec<Option<Vec<u8>>> {
        let mut reader = tokio::io::BufReader::with_capacity(capacity, input);
        let mut line_buf = Vec::new();
        let mut lines = Vec::new();
        loop {
            match read_line_capped(&mut reader, &mut line_buf, max_len)
                .await
                .expect("an in-memory read cannot fail")
            {
                CappedLine::Eof => return lines,
                CappedLine::Line(line) => lines.push(Some(line.to_vec())),
                CappedLine::Skipped => lines.push(None),
            }
        }
    }

    #[tokio::test]
    async fn read_line_capped_cuts_lines_and_skips_overlong_ones() {
        /// Input, reader capacity, `max_len`, expected lines (`None` = skipped).
        type Case<'a> = (&'a [u8], usize, usize, &'a [Option<&'a [u8]>]);

        let long = [b'a'; 1000];
        let long_then_next = [&long[..], b"\nnext\n"].concat();
        let cases: [Case<'_>; 9] = [
            (b"", 8192, 64, &[]),
            (
                b"short line\nnext",
                8192,
                64,
                &[Some(b"short line\n"), Some(b"next")],
            ),
            // `StanzaStream` flushes its stanza on a blank line, so a blank
            // line must arrive as a line carrying "\n" - never as `Eof`.
            (
                b"first\n\nsecond\n",
                8192,
                64,
                &[Some(b"first\n"), Some(b"\n"), Some(b"second\n")],
            ),
            // A line joined across buffer refills.
            (
                b"a line longer than eight bytes\nnext\n",
                8,
                64,
                &[Some(b"a line longer than eight bytes\n"), Some(b"next\n")],
            ),
            (&long_then_next, 8192, 64, &[None, Some(b"next\n")]),
            // Over-length without a newline: drained to EOF.
            (&long, 8192, 64, &[None]),
            // 4 data bytes + '\n' is exactly `max_len`.
            (b"abcd\nmore", 8192, 5, &[Some(b"abcd\n"), Some(b"more")]),
            // One byte over `max_len`.
            (b"abcde\n", 8192, 5, &[None]),
            // The bytes are not validated as UTF-8.
            (b"\xff\xfe\n", 8192, 64, &[Some(b"\xff\xfe\n")]),
        ];
        for (input, capacity, max_len, expected) in cases {
            let expected: Vec<_> = expected
                .iter()
                .map(|line| line.map(<[u8]>::to_vec))
                .collect();
            assert_eq!(
                capped_lines(input, capacity, max_len).await,
                expected,
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[tokio::test]
    async fn read_line_capped_reuses_line_buf_across_calls() {
        let input = b"first\nsecond\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let mut line_buf = Vec::<u8>::with_capacity(64);
        let cap_before = line_buf.capacity();
        let address_before = line_buf.as_ptr().addr();

        let result = read_line_capped(&mut reader, &mut line_buf, 64)
            .await
            .expect("first line");
        assert!(matches!(result, CappedLine::Line(b"first\n")), "{result:?}");
        assert_eq!(line_buf.as_ptr().addr(), address_before);
        assert_eq!(line_buf.capacity(), cap_before);
        let result = read_line_capped(&mut reader, &mut line_buf, 64)
            .await
            .expect("second line");
        assert!(
            matches!(result, CappedLine::Line(b"second\n")),
            "{result:?}"
        );

        assert_eq!(line_buf.as_ptr().addr(), address_before);
        assert_eq!(line_buf.capacity(), cap_before);
    }

    #[test]
    fn content_length_cap_checks() {
        let cap = NonZero::new(100);
        assert!(content_length_within_cap(0, cap));
        assert!(content_length_within_cap(100, cap));
        assert!(!content_length_within_cap(101, cap));
        assert!(content_length_within_cap(u64::MAX, None));
    }
}
