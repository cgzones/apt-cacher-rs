//! Pure-Rust XZ streaming decompressor.
//!
//! Drives `lzma_rust2::XzReader` in a tokio blocking task feeding a
//! `tokio::io::duplex` pipe, so callers can treat it as any other
//! `AsyncRead`. The task reads its input synchronously, so the input is a
//! blocking reader (the `Packages.xz` file as a `std::fs::File`): a
//! `tokio::fs::File` behind a `SyncIoBridge` would run every read as a second
//! blocking-pool task that the decode thread sits blocked on. Replaces
//! `async_compression::tokio::bufread::XzDecoder` to remove the C
//! `liblzma`/`liblzma-sys` dependency.
//!
//! The decoder is built through `new_mem_limit`: the LZMA2 dictionary size
//! comes verbatim from the (untrusted) block header, and the decoder's
//! window grows with the decoded output up to it.
//! [`crate::limits::MAX_XZ_DICT_SIZE`] bounds it.
//!
//! One `XzReader::read` decodes until it has output or the input ends, and
//! the decoder otherwise notices a consumer that went away only when it
//! next *writes*, which an output-free stream (empty blocks, 18 bytes each)
//! never does. The hang-up check therefore sits in the input
//! ([`HangUpCheck`]), consulted on every 64 KiB refill. `XzReader` rather
//! than the push-style `XzStream`: the latter keeps 16 bytes per block until
//! the index (~0.9x the compressed size for a stream of empty blocks) to
//! check each index record against its block, where `XzReader` keeps a block
//! count and compares only the record count. A corrupt payload fails either
//! way on its block's integrity check, when the stream carries one (`xz`
//! writes CRC64 unless told `--check=none`).
//!
//! The callers' size caps alone bound what a stream can cost: the decode
//! works per input byte (empty blocks yield no output) and per output byte,
//! and `limits::packages_reader` holds the input to the compressed cap and
//! the output to the decompressed one as they are read. Up to lzma-rust2 0.21 every block allocated and zero-filled its
//! declared dictionary up front, ~35 ms of CPU per empty block at the
//! 64 MiB cap, which the decode loop answered with a CPU budget. Since 0.22
//! the window grows with the output: an empty block costs ~1 us of CPU
//! (measured with 0.25), so a stream of them at
//! [`crate::limits::MAX_COMPRESSED_PACKAGES_SIZE`] holds the thread for
//! ~7 s, the same order as decoding
//! [`crate::limits::MAX_DECOMPRESSED_PACKAGES_SIZE`] of real index (~5 s).

use std::future::Future as _;
use std::io::{self, Read as _};
use std::pin::Pin;
use std::task::{Context, Poll};

use lzma_rust2::{XzReader, lzma2_get_memory_usage};
use tokio::io::{AsyncRead, DuplexStream, ReadBuf};
use tokio::sync::oneshot;
use tokio_util::io::SyncIoBridge;

use crate::humanfmt::HumanFmt;
use crate::limits::MAX_XZ_DICT_SIZE;

/// Internal pipe capacity. 64 KiB amortises copy syscalls between the blocking
/// decoder thread and the async consumer without buffering meaningful amounts
/// of memory.
const PIPE_CAPACITY: usize = 64 * 1024;

/// Async wrapper over a blocking [`XzReader`] decode.
///
/// EOF on the inner pipe triggers a poll of `tail` to surface any terminal
/// `io::Error` the decoder produced; a clean decode reports the EOF verbatim.
pub(crate) struct XzDecoderStream {
    inner: DuplexStream,
    tail: Option<oneshot::Receiver<io::Result<()>>>,
}

/// Construct an `AsyncRead` that yields the xz-decompressed bytes of `reader`,
/// which the blocking decode task reads directly (see the module doc).
///
/// Multi-stream xz files are accepted (matches the `xz` CLI default and what
/// `async_compression`'s `XzDecoder` did before).
pub(crate) fn xz_decoder<R>(reader: R) -> XzDecoderStream
where
    R: io::Read + Send + 'static,
{
    let (read_half, write_half) = tokio::io::duplex(PIPE_CAPACITY);
    let (err_tx, err_rx) = oneshot::channel::<io::Result<()>>();

    tokio::task::spawn_blocking(move || {
        // Buffer up to the duplex capacity: writing straight through would
        // cross the bridge in small pieces, each a block_on round-trip
        // between the blocking thread and the runtime — the BufWriter cuts
        // those handoffs. The explicit flush surfaces write errors before
        // the result send (BufWriter's Drop swallows them).
        let mut bridge_out =
            io::BufWriter::with_capacity(PIPE_CAPACITY, SyncIoBridge::new(write_half));
        let result = decode_stream(reader, &mut bridge_out, || err_tx.is_closed())
            .and_then(|()| io::Write::flush(&mut bridge_out));
        // Drop the write half BEFORE sending the result so the consumer sees
        // EOF on `inner` before polling `tail`. Without this, the consumer can
        // observe Pending on the oneshot while the duplex still has an open
        // writer, and the wrapper's poll_read never reaches the oneshot branch.
        drop(bridge_out);
        if err_tx.send(result).is_err() {
            // Receiver was dropped; consumer hung up before observing the
            // result. Nothing to do — the duplex pipe close already signalled
            // EOF and any error is lost by design.
        }
    });

    XzDecoderStream {
        inner: read_half,
        tail: Some(err_rx),
    }
}

/// The decoder's memory limit in KiB: exactly what `lzma_rust2` counts for a
/// block with a [`MAX_XZ_DICT_SIZE`] dictionary (the dictionary plus, as of
/// 0.25, a 64 KiB input buffer and 40 KiB of decoder state), so a `-9` index
/// decodes and every larger dictionary is refused.
fn xz_mem_limit_kb() -> u32 {
    let dict_size = u32::try_from(MAX_XZ_DICT_SIZE.get()).expect("64 MiB fits u32");
    lzma2_get_memory_usage(dict_size)
}

/// Adds the limit to an out-of-memory error, which the crate words as
/// `needed memory too big for mem_limit_kb` for a refused dictionary and
/// without figures: `XzReader` does not say what the block needed. Any
/// other error passes through.
fn name_mem_limit(err: io::Error) -> io::Error {
    // An `ENOMEM` from the input read is the system's, not the decoder's,
    // and must keep its errno: ingest retries an error that carries one.
    if err.kind() != io::ErrorKind::OutOfMemory || err.raw_os_error().is_some() {
        return err;
    }
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        format!(
            "xz decode out of memory under the {} decoder limit: {err}",
            HumanFmt::BinarySize(u64::from(xz_mem_limit_kb()) * 1024)
        ),
    )
}

/// The decode's input: fails every read with `BrokenPipe` once `abandoned`
/// reports that the consumer is gone (see the module doc for why the check
/// sits here).
struct HangUpCheck<R, F> {
    inner: R,
    abandoned: F,
}

impl<R: io::Read, F: Fn() -> bool> io::Read for HangUpCheck<R, F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if (self.abandoned)() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xz consumer went away; abandoning the decode",
            ));
        }
        self.inner.read(buf)
    }
}

/// Pump `input` through a memory-limited [`XzReader`] into `output` until the
/// stream ends.  A truncated stream fails, mostly as `UnexpectedEof` (a cut
/// inside a following stream's magic bytes is `InvalidData`).
///
/// Gives up with `BrokenPipe` at the first input refill after `abandoned`
/// reports that the consumer is gone.
fn decode_stream(
    input: impl io::Read,
    output: &mut impl io::Write,
    abandoned: impl Fn() -> bool,
) -> io::Result<()> {
    // Buffered: `XzReader` parses headers, padding and the index a byte at a
    // time. Each refill reads up to 64 KiB and passes the hang-up check.
    let input = io::BufReader::with_capacity(
        PIPE_CAPACITY,
        HangUpCheck {
            inner: input,
            abandoned,
        },
    );
    let mut reader = XzReader::new_mem_limit(
        input,
        /* allow_multiple_streams = */ true,
        xz_mem_limit_kb(),
    );
    let mut out_buf = vec![0u8; PIPE_CAPACITY];
    loop {
        let len = reader.read(&mut out_buf).map_err(name_mem_limit)?;
        if len == 0 {
            return Ok(());
        }
        output.write_all(&out_buf[..len])?;
    }
}

impl AsyncRead for XzDecoderStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Empty target buffer: behave like a normal AsyncRead. Without this,
        // the inner stream returns Ready with zero bytes filled (no capacity
        // to write to), which the EOF detection below would misread as
        // end-of-stream and trigger a spurious `tail` poll.
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before => {
                // EOF on the pipe. Check the tail for a terminal error.
                let Some(mut tail) = self.tail.take() else {
                    return Poll::Ready(Ok(()));
                };
                match Pin::new(&mut tail).poll(cx) {
                    Poll::Ready(Ok(Ok(()))) => Poll::Ready(Ok(())),
                    Poll::Ready(Ok(Err(err))) => Poll::Ready(Err(err)),
                    // Sender dropped without sending — blocking task panicked
                    // or runtime is shutting down. Treat as decode failure.
                    Poll::Ready(Err(_)) => {
                        Poll::Ready(Err(io::Error::other("xz blocking task aborted")))
                    }
                    Poll::Pending => {
                        self.tail = Some(tail);
                        Poll::Pending
                    }
                }
            }
            other @ (Poll::Ready(_) | Poll::Pending) => other,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Cursor;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use tokio::io::AsyncReadExt as _;

    /// `printf 'hello world\n' | xz -c --check=crc32` — 72 bytes.
    pub(crate) const HELLO_XZ: &[u8] = &[
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36, 0x04, 0xc0, 0x10,
        0x0c, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0xb0,
        0x54, 0x28, 0x01, 0x00, 0x0b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c,
        0x64, 0x0a, 0x00, 0x2d, 0x3b, 0x08, 0xaf, 0x00, 0x01, 0x28, 0x0c, 0xaa, 0x57, 0x6d, 0x74,
        0x90, 0x42, 0x99, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59, 0x5a,
    ];

    #[tokio::test]
    async fn decodes_hello_world() {
        let mut decoder = xz_decoder(Cursor::new(HELLO_XZ));
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .await
            .expect("decode should succeed");
        assert_eq!(&out, b"hello world\n");
    }

    /// A valid stream header and block header whose LZMA2 property byte
    /// (0x1e) declares a 128 MiB dictionary, followed by nothing.  Only the
    /// head matters: the decoder must refuse the dictionary before it
    /// allocates anything.
    const BIG_DICT_XZ: &[u8] = &[
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36, 0x02, 0x00, 0x21,
        0x01, 0x1e, 0x00, 0x00, 0x00, 0x9b, 0x07, 0x51, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    /// `printf 'hello world\n' | xz -9 -c --check=crc32`: property byte
    /// 0x1c, the 64 MiB dictionary at the cap.  Must still decode.
    const HELLO_XZ_9: &[u8] = &[
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36, 0x04, 0xc0, 0x10,
        0x0c, 0x21, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x20,
        0x76, 0x3f, 0x01, 0x00, 0x0b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c,
        0x64, 0x0a, 0x00, 0x2d, 0x3b, 0x08, 0xaf, 0x00, 0x01, 0x28, 0x0c, 0xaa, 0x57, 0x6d, 0x74,
        0x90, 0x42, 0x99, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59, 0x5a,
    ];

    #[tokio::test]
    async fn dictionary_at_the_cap_still_decodes() {
        let mut decoder = xz_decoder(Cursor::new(HELLO_XZ_9));
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .await
            .expect("a 64 MiB dictionary is within the cap");
        assert_eq!(&out, b"hello world\n");
    }

    #[tokio::test]
    async fn oversized_dictionary_is_refused_before_allocation() {
        let mut decoder = xz_decoder(Cursor::new(BIG_DICT_XZ));
        let mut out = Vec::new();
        let err = decoder
            .read_to_end(&mut out)
            .await
            .expect_err("a dictionary above the cap must be refused");
        assert_eq!(err.kind(), io::ErrorKind::OutOfMemory, "{err}");
        assert!(
            err.to_string().contains("under the 64.1MiB decoder limit"),
            "the refusal must name the limit: {err}"
        );
        assert!(out.is_empty(), "nothing must be decoded");
    }

    #[test]
    fn an_os_out_of_memory_keeps_its_errno() {
        let err = name_mem_limit(io::Error::from_raw_os_error(nix::libc::ENOMEM));
        assert_eq!(err.raw_os_error(), Some(nix::libc::ENOMEM), "{err}");
    }

    #[tokio::test]
    async fn oversized_dictionary_after_output_is_still_refused() {
        // The output decoded before the refused block header reaches the
        // consumer, and the decode still ends in the refusal, not in a hang
        // or a clean EOF.
        let input = [HELLO_XZ, BIG_DICT_XZ].concat();
        let mut decoder = xz_decoder(Cursor::new(input));
        let mut out = Vec::new();
        let err = tokio::time::timeout(Duration::from_secs(10), decoder.read_to_end(&mut out))
            .await
            .expect("the refusal must end the decode")
            .expect_err("a dictionary above the cap must be refused after earlier output");
        assert_eq!(err.kind(), io::ErrorKind::OutOfMemory, "{err}");
        assert_eq!(&out, b"hello world\n");
    }

    /// A stream header followed straight by an index (indicator 0x00, so
    /// zero blocks) whose record count claims 2^31 records, then nothing.
    /// `XzReader`'s index parser before lzma-rust2 0.22 reserved
    /// `count * 16` bytes (32 GiB) for it before comparing the count with the
    /// blocks it saw. The test pins the refusal only: on a host that
    /// overcommits, a reservation succeeds unseen and the decode ends the
    /// same way.
    const HOSTILE_INDEX_XZ: &[u8] = &[
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36, 0x00, 0x80, 0x80,
        0x80, 0x80, 0x08,
    ];

    #[tokio::test]
    async fn hostile_index_record_count_is_refused() {
        let mut decoder = xz_decoder(Cursor::new(HOSTILE_INDEX_XZ));
        let mut out = Vec::new();
        let err = decoder
            .read_to_end(&mut out)
            .await
            .expect_err("an index claiming records for absent blocks must be refused");
        // `UnexpectedEof` from reading the records off the end of the input.
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
        assert!(out.is_empty(), "nothing must be decoded");
    }

    #[tokio::test]
    async fn truncated_input_surfaces_io_error() {
        // Cut the stream before its index and footer: the decoder must not
        // report a clean EOF.
        let mut decoder = xz_decoder(Cursor::new(&HELLO_XZ[..48]));
        let mut out = Vec::new();
        let err = decoder
            .read_to_end(&mut out)
            .await
            .expect_err("a truncated xz stream must be an error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
    }

    #[tokio::test]
    async fn corrupt_input_surfaces_io_error() {
        // Flip a byte in the LZMA2-encoded payload region (offset 32 is well
        // inside the compressed block, past the stream header).
        let mut bad = HELLO_XZ.to_vec();
        bad[32] ^= 0xFF;
        let mut decoder = xz_decoder(Cursor::new(bad));
        let mut out = Vec::new();
        let err = decoder
            .read_to_end(&mut out)
            .await
            .expect_err("corrupt xz must surface an io::Error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        assert!(out.is_empty(), "nothing must be decoded, got {out:?}");
    }

    #[tokio::test]
    async fn truncated_input_surfaces_unexpected_eof() {
        let mut decoder = xz_decoder(Cursor::new(&HELLO_XZ[..40]));
        let mut out = Vec::new();
        let err = decoder
            .read_to_end(&mut out)
            .await
            .expect_err("a truncated stream must surface an io::Error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
    }

    #[tokio::test]
    async fn concatenated_streams_decode_back_to_back() {
        let both = [HELLO_XZ, HELLO_XZ].concat();
        let mut decoder = xz_decoder(Cursor::new(both));
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .await
            .expect("two concatenated xz streams decode");
        assert_eq!(&out, b"hello world\nhello world\n");
    }

    #[tokio::test]
    async fn empty_buffer_read_does_not_surface_tail_error() {
        // Establish EOF and a pending terminal error before the empty read.
        let (inner, writer) = tokio::io::duplex(1);
        drop(writer);
        let (sender, receiver) = oneshot::channel();
        sender
            .send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "decode failed",
            )))
            .expect("receiver is alive");
        let mut decoder = XzDecoderStream {
            inner,
            tail: Some(receiver),
        };

        let mut empty: [u8; 0] = [];
        let result = std::future::poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut empty);
            Pin::new(&mut decoder).poll_read(cx, &mut buf)
        })
        .await;
        assert!(
            result.is_ok(),
            "empty-buffer read must not surface tail decode error, got {result:?}"
        );

        // The tail must still be intact: a subsequent real read should still
        // surface the decode error.
        let mut out = Vec::new();
        let err = decoder
            .read_to_end(&mut out)
            .await
            .expect_err("tail error must still be available after empty-buf read");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        assert!(out.is_empty(), "nothing must be decoded, got {out:?}");
    }

    #[tokio::test]
    async fn empty_buffer_read_is_immediately_ready() {
        // Using a noop waker, a single poll with an empty ReadBuf must return
        // Ready(Ok(())). Without the fix, the wrapper polls the (still
        // pending) tail oneshot and returns Pending — which would never
        // resolve under a noop waker.
        let mut decoder = xz_decoder(Cursor::new(HELLO_XZ));

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut empty: [u8; 0] = [];
        let mut buf = ReadBuf::new(&mut empty);
        let poll = Pin::new(&mut decoder).poll_read(&mut cx, &mut buf);
        assert!(
            matches!(poll, Poll::Ready(Ok(()))),
            "empty-buffer poll_read must return Ready(Ok(())), got {poll:?}"
        );

        // The decoder must remain fully functional afterwards.
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .await
            .expect("decode should succeed");
        assert_eq!(&out, b"hello world\n");
    }

    /// CRC-32 (IEEE), bitwise: only the few header bytes of the synthetic
    /// streams below need it.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFF_u32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 0 {
                    crc >> 1
                } else {
                    (crc >> 1) ^ 0xEDB8_8320
                };
            }
        }
        !crc
    }

    fn push_vli(mut value: u64, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push(u8::try_from(value & 0x7F).expect("masked to 7 bits") | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value).expect("below 0x80"));
    }

    /// A complete, valid xz stream (no check) of `blocks` empty blocks, each
    /// declaring the LZMA2 dictionary of property byte `dict_prop`: a
    /// 12-byte block header, the one-byte LZMA2 end marker and three bytes of
    /// padding, then an index listing them and the footer.  It decodes to
    /// nothing, and every block makes the decoder set up a fresh dictionary.
    fn empty_blocks_xz(blocks: u64, dict_prop: u8) -> Vec<u8> {
        let flags = [0x00, 0x00];
        let mut out = vec![0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
        out.extend_from_slice(&flags);
        out.extend_from_slice(&crc32(&flags).to_le_bytes());
        let mut header = vec![0x02, 0x00, 0x21, 0x01, dict_prop, 0x00, 0x00, 0x00];
        header.extend_from_slice(&crc32(&header).to_le_bytes());
        for _ in 0..blocks {
            out.extend_from_slice(&header);
            out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        }
        let mut index = vec![0x00];
        push_vli(blocks, &mut index);
        for _ in 0..blocks {
            // Unpadded size: 12-byte header + 1-byte LZMA2 end marker.
            push_vli(13, &mut index);
            push_vli(0, &mut index);
        }
        while index.len() % 4 != 0 {
            index.push(0x00);
        }
        index.extend_from_slice(&crc32(&index).to_le_bytes());
        let backward_size = u32::try_from(index.len() / 4 - 1).expect("small index");
        out.extend_from_slice(&index);
        let mut footer_body = backward_size.to_le_bytes().to_vec();
        footer_body.extend_from_slice(&flags);
        out.extend_from_slice(&crc32(&footer_body).to_le_bytes());
        out.extend_from_slice(&footer_body);
        out.extend_from_slice(b"YZ");
        out
    }

    /// Property byte of a 1 MiB LZMA2 dictionary.
    const DICT_1MIB: u8 = 0x10;

    #[test]
    fn empty_blocks_decode_to_nothing() {
        // The fixture itself is a valid stream: what stops the hang-up test
        // below is the hang-up, never a malformed input.
        let xz = empty_blocks_xz(3, DICT_1MIB);
        let mut out = Vec::new();
        decode_stream(&mut Cursor::new(&xz[..]), &mut out, || false)
            .expect("three empty blocks form a valid stream");
        assert_eq!(out, [] as [u8; 0]);
    }

    /// An xz stream that does not end: a stream header, then empty blocks
    /// until `limit` bytes were served, then a read error. It decodes to
    /// nothing and reaches no footer, so only the hang-up check ends its
    /// decode early; the limit turns a broken check into a test failure
    /// within seconds instead of a decode thread spinning forever.
    struct EmptyBlocksUntil {
        /// A stream header followed by one empty block.
        pattern: Vec<u8>,
        pos: usize,
        limit: usize,
        /// Bytes handed out so far, readable after the decode dropped this.
        served: Arc<AtomicUsize>,
    }

    /// Length of the stream header in [`EmptyBlocksUntil::pattern`].
    const STREAM_HEADER_LEN: usize = 12;

    impl EmptyBlocksUntil {
        fn new(limit: usize, served: Arc<AtomicUsize>) -> Self {
            // Header, one 12-byte block header and its 4 bytes of LZMA2 end
            // marker and padding; the index and footer are cut off.
            let mut pattern = empty_blocks_xz(1, DICT_1MIB);
            pattern.truncate(STREAM_HEADER_LEN + 16);
            Self {
                pattern,
                pos: 0,
                limit,
                served,
            }
        }
    }

    impl io::Read for EmptyBlocksUntil {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.served.load(Ordering::Relaxed) >= self.limit {
                return Err(io::Error::other("test input limit reached"));
            }
            self.served.fetch_add(buf.len(), Ordering::Relaxed);
            for byte in buf.iter_mut() {
                *byte = self.pattern[self.pos];
                self.pos += 1;
                if self.pos == self.pattern.len() {
                    self.pos = STREAM_HEADER_LEN;
                }
            }
            Ok(buf.len())
        }
    }

    #[test]
    fn the_memory_limit_admits_exactly_the_dictionary_cap() {
        // Property byte 0x1c is a 64 MiB dictionary, the cap; 0x1d is the
        // next size LZMA2 can declare, 96 MiB.
        decode_stream(
            Cursor::new(empty_blocks_xz(1, 0x1c)),
            &mut Vec::new(),
            || false,
        )
        .expect("a dictionary at the cap must decode");
        let err = decode_stream(
            Cursor::new(empty_blocks_xz(1, 0x1d)),
            &mut Vec::new(),
            || false,
        )
        .expect_err("the next dictionary size must be refused");
        assert_eq!(err.kind(), io::ErrorKind::OutOfMemory, "{err}");
    }

    #[test]
    fn abandoned_decode_stops_before_reading() {
        let mut input = Cursor::new(HELLO_XZ);
        let mut out = Vec::new();
        let err = decode_stream(&mut input, &mut out, || true)
            .expect_err("a decode nobody reads must stop");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{err}");
        assert_eq!(input.position(), 0);
        assert_eq!(out, [] as [u8; 0]);
    }

    /// Wraps an input and signals when the blocking decode drops it, which
    /// it does only on its way out.
    struct DropSignal<R> {
        inner: R,
        _dropped: oneshot::Sender<()>,
        first_read: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    }

    impl<R: io::Read> io::Read for DropSignal<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some((started, release)) = self.first_read.take() {
                let _started = started.send(());
                let _released = release.blocking_recv();
            }
            self.inner.read(buf)
        }
    }

    #[tokio::test]
    async fn dropping_the_decoder_stops_an_output_free_decode() {
        // The input does not end and the blocking decode never writes, so
        // without the hang-up check the decode runs until the input's limit.
        const LIMIT: usize = 16 * 1024 * 1024;
        let served = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = oneshot::channel();
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let input = DropSignal {
            inner: EmptyBlocksUntil::new(LIMIT, Arc::clone(&served)),
            _dropped: tx,
            first_read: Some((started_tx, release_rx)),
        };
        let decoder = xz_decoder(input);
        tokio::time::timeout(Duration::from_secs(10), started_rx)
            .await
            .expect("blocking decoder starts")
            .expect("first read signalled");
        drop(decoder);
        release_tx.send(()).expect("blocking reader awaits release");
        let closed = tokio::time::timeout(Duration::from_secs(30), rx).await;
        assert!(
            matches!(closed, Ok(Err(_))),
            "the blocking decode must let go of its input"
        );
        // The hang-up is noticed at the first check after the one read the
        // decode was blocked in.
        let served = served.load(Ordering::Relaxed);
        assert!(
            served <= PIPE_CAPACITY,
            "the decode must stop once the reader is dropped, read {served} bytes"
        );
    }

    #[tokio::test]
    async fn consumer_can_drop_after_reading_one_byte() {
        // A consumer may stop after one byte. This small output fits in
        // the pipe; worker cancellation is exercised separately above.
        let mut decoder = xz_decoder(Cursor::new(HELLO_XZ));
        let mut one = [0u8; 1];
        let n = decoder.read(&mut one).await.expect("first byte ok");
        assert_eq!(n, 1);
        assert_eq!(one[0], b'h');
        drop(decoder);
    }
}
