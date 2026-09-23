//! Pure-Rust XZ streaming decompressor.
//!
//! Drives `lzma_rust2::XzStream` (the push-style decoder) in a tokio blocking
//! task feeding a `tokio::io::duplex` pipe, so callers can treat it as any
//! other `AsyncRead`. The task reads its input synchronously, so the input is
//! a blocking reader (the `Packages.xz` file as a `std::fs::File`): a
//! `tokio::fs::File` behind a `SyncIoBridge` would run every read as a second
//! blocking-pool task that the decode thread sits blocked on. Replaces `async_compression::tokio::bufread::XzDecoder`
//! to remove the C `liblzma`/`liblzma-sys` dependency.
//!
//! The decoder is built through `new_mem_limit`: the LZMA2 dictionary size
//! comes verbatim from the (untrusted) block header and is allocated before
//! any output reaches the callers' decompression caps.
//! [`crate::limits::MAX_XZ_DICT_SIZE`] bounds it.
//!
//! `XzStream` rather than the `Read`-adapter `XzReader`, although the latter
//! takes the same memory limit since lzma-rust2 0.21: `XzReader`'s index
//! parser reserves and fills a record vector sized by the (untrusted) index
//! record count before comparing it with the blocks it decoded, and never
//! checks a record against its block.  An index yields no output, so none of
//! the callers' decompression caps see it; a few dozen bytes can claim 2^31
//! records.  `XzStream` rejects a count that differs from the decoded block
//! count before reading a single record, and validates each record as it
//! arrives.
//!
//! The memory limit bounds one block, not the work a stream can demand:
//! `XzStream` builds a fresh LZMA2 decoder for every block and allocates and
//! zero-fills the block's declared dictionary on first use, reusing nothing.
//! An empty block is 18 bytes and yields no output, so a stream of them
//! never reaches the output caps while each block costs a dictionary's worth
//! of page faults and `memset` -- measured with lzma-rust2 0.21 at the 64 MiB
//! cap, ~35 ms per block under glibc malloc and ~3 ms under mimalloc, i.e.
//! a 10 MiB `Packages.xz` holding a blocking thread for hours. The decode
//! loop therefore stops on two conditions checked between `process` calls,
//! each call being handed at most [`PROCESS_SLICE`] input bytes so that no
//! single call can run long past a check: the consumer hung up (the
//! decoder otherwise notices only when it next *writes*, which an
//! output-free stream never does), or the thread's CPU time exceeds
//! [`MAX_XZ_DECODE_CPU`]. CPU time rather than wall time, so neither a
//! consumer that is slow to drain the pipe nor a loaded host counts against
//! the budget. Reading the CPU clock is a syscall (`getrusage`), so the loop
//! reads it only once [`CPU_CHECK_INTERVAL`] of (vDSO, syscall-free) wall
//! time has passed since the last reading: a thread cannot burn more CPU
//! time than wall time passes, so the budget is still caught within that
//! interval and one slice of crossing it.

use std::future::Future as _;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use coarsetime::Instant;
use lzma_rust2::{Action, Status, XzStream};
use nix::sys::resource::{UsageWho, getrusage};
use nix::sys::time::TimeValLike as _;
use tokio::io::{AsyncRead, DuplexStream, ReadBuf};
use tokio::sync::oneshot;
use tokio_util::io::SyncIoBridge;

use crate::humanfmt::HumanFmt;
use crate::limits::{MAX_XZ_DECODE_CPU, MAX_XZ_DICT_SIZE};

/// Internal pipe capacity. 64 KiB amortises copy syscalls between the blocking
/// decoder thread and the async consumer without buffering meaningful amounts
/// of memory.
const PIPE_CAPACITY: usize = 64 * 1024;

/// Most input bytes one `XzStream::process` call is given, which bounds how
/// long a call can run between two checks of the decode loop's stop
/// conditions: 1 KiB holds at most 56 empty blocks, ~2 s of dictionary
/// setup at the 64 MiB cap under glibc. Slicing costs a legitimate decode
/// nothing measurable (a 15 MiB `Packages.xz`: same CPU time at 1 KiB as at
/// 64 KiB slices).
const PROCESS_SLICE: usize = 1024;

/// Least wall time between two readings of the decode thread's CPU time (see
/// the module doc). Reading it per slice cost ~10k `getrusage` calls per
/// 10 MiB `Packages.xz`; at 10 ms it is ~50 per 500 ms decode, while a
/// decode overrunning [`MAX_XZ_DECODE_CPU`] is still stopped within 10 ms
/// (plus the coarse clock's tick and one slice) of crossing it.
const CPU_CHECK_INTERVAL: coarsetime::Duration = coarsetime::Duration::from_millis(10);

/// Async wrapper over a blocking [`XzStream`] decode.
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
        let mut input = reader;
        // Buffer up to the duplex capacity: writing straight through would
        // cross the bridge in small pieces, each a block_on round-trip
        // between the blocking thread and the runtime — the BufWriter cuts
        // those handoffs. The explicit flush surfaces write errors before
        // the result send (BufWriter's Drop swallows them).
        let mut bridge_out =
            io::BufWriter::with_capacity(PIPE_CAPACITY, SyncIoBridge::new(write_half));
        let result = decode_stream(&mut input, &mut bridge_out, MAX_XZ_DECODE_CPU, || {
            err_tx.is_closed()
        })
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

/// The decoder's memory limit in KiB: the dictionary cap plus the fixed
/// per-block overhead `lzma_rust2` adds on top (its 64 KiB range-decoder
/// buffer and a few dozen KiB of state; one MiB of slack keeps a `-9` index
/// decodable without tracking the crate's exact formula).
fn xz_mem_limit_kb() -> u32 {
    let dict_kib = MAX_XZ_DICT_SIZE.get() / 1024 + 1024;
    u32::try_from(dict_kib).expect("64 MiB in KiB fits u32")
}

/// CPU time (user + system) the calling thread has consumed so far.
fn thread_cpu_time() -> io::Result<Duration> {
    let usage = getrusage(UsageWho::RUSAGE_THREAD).map_err(io::Error::from)?;
    let micros = usage.user_time().num_microseconds() + usage.system_time().num_microseconds();
    Ok(Duration::from_micros(u64::try_from(micros).unwrap_or(0)))
}

/// Pump `input` through a memory-limited [`XzStream`] into `output` until the
/// stream ends.  A truncated stream surfaces as `UnexpectedEof`.
///
/// Gives up with `TimedOut` once this thread has spent more than
/// `cpu_budget` of CPU time since the call began, and with `BrokenPipe` as
/// soon as `abandoned` reports that the consumer is gone (see the module
/// doc for why both are needed).
fn decode_stream(
    input: &mut impl io::Read,
    output: &mut impl io::Write,
    cpu_budget: Duration,
    abandoned: impl Fn() -> bool,
) -> io::Result<()> {
    // Not `XzReader`: see the module doc (its index parser allocates from the
    // untrusted record count before the count-vs-blocks check).
    let mut stream =
        XzStream::new_mem_limit(/* allow_multiple_streams = */ true, xz_mem_limit_kb());
    // Input is read in `PIPE_CAPACITY` chunks: one read per 64 KiB, not one
    // per header field.
    let mut in_buf = vec![0u8; PIPE_CAPACITY];
    let mut out_buf = vec![0u8; PIPE_CAPACITY];
    let mut in_len = 0;
    let mut in_pos = 0;
    let mut eof = false;
    let cpu_start = thread_cpu_time()?;
    let mut last_cpu_check = Instant::now();

    loop {
        if abandoned() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xz consumer went away; abandoning the decode",
            ));
        }
        let now = Instant::now();
        if now.duration_since(last_cpu_check) >= CPU_CHECK_INTERVAL {
            last_cpu_check = now;
            if thread_cpu_time()?.saturating_sub(cpu_start) > cpu_budget {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "xz stream exceeded the decoding CPU budget of {}",
                        HumanFmt::Time(cpu_budget)
                    ),
                ));
            }
        }
        if in_pos == in_len && !eof {
            in_len = input.read(&mut in_buf)?;
            in_pos = 0;
            eof = in_len == 0;
        }
        let action = if eof { Action::Finish } else { Action::Run };
        let in_end = in_len.min(in_pos + PROCESS_SLICE);
        let step = stream.process(&in_buf[in_pos..in_end], &mut out_buf, action)?;
        in_pos += step.bytes_consumed;
        output.write_all(&out_buf[..step.bytes_produced])?;
        match step.status {
            Status::StreamEnd => return Ok(()),
            Status::Ok => {}
        }
        if eof && step.bytes_consumed == 0 && step.bytes_produced == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "xz stream ended without a stream footer",
            ));
        }
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
mod tests {
    use std::io::Cursor;

    use super::*;
    use tokio::io::AsyncReadExt as _;

    /// `printf 'hello world\n' | xz -c --check=crc32` — 72 bytes.
    const HELLO_XZ: &[u8] = &[
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
        assert!(out.is_empty(), "nothing must be decoded");
    }

    /// A stream header followed straight by an index (indicator 0x00, so
    /// zero blocks) whose record count claims 2^31 records, then nothing.
    /// `XzReader`'s index parser reserves `count * 16` bytes (32 GiB) before
    /// it compares the count with the blocks it saw; the decoder must reject
    /// the mismatch from the count alone.
    const HOSTILE_INDEX_XZ: &[u8] = &[
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36, 0x00, 0x80, 0x80,
        0x80, 0x80, 0x08,
    ];

    #[tokio::test]
    async fn hostile_index_record_count_is_refused_before_allocation() {
        let mut decoder = xz_decoder(Cursor::new(HOSTILE_INDEX_XZ));
        let mut out = Vec::new();
        let err = decoder
            .read_to_end(&mut out)
            .await
            .expect_err("an index claiming records for absent blocks must be refused");
        // `InvalidData` from the count check, not `OutOfMemory` (a failed
        // reservation) or `UnexpectedEof` (a granted one, then reading the
        // records off the end of the input).
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
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
        // Corrupt input so the blocking decoder finishes with an Err in the
        // tail channel. An empty-buffer read must NOT be misread as EOF,
        // consume `tail`, and surface that error — it should behave like a
        // normal AsyncRead and return Ok(()) immediately.
        let mut bad = HELLO_XZ.to_vec();
        bad[32] ^= 0xFF;
        let mut decoder = xz_decoder(Cursor::new(bad));

        // Let the blocking task run to completion so the Err is sitting in
        // the oneshot. 100ms is ample for decoding ~70 bytes.
        tokio::time::sleep(Duration::from_millis(100)).await;

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
        // surface the decode error (or at minimum, not yield the clean output).
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
        header.extend_from_slice(&crc32(&header.clone()).to_le_bytes());
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
        index.extend_from_slice(&crc32(&index.clone()).to_le_bytes());
        let backward_size = u32::try_from(index.len() / 4 - 1).expect("small index");
        out.extend_from_slice(&index);
        let mut footer_body = backward_size.to_le_bytes().to_vec();
        footer_body.extend_from_slice(&flags);
        out.extend_from_slice(&crc32(&footer_body).to_le_bytes());
        out.extend_from_slice(&footer_body);
        out.extend_from_slice(b"YZ");
        out
    }

    /// Property byte of a 1 MiB LZMA2 dictionary: small enough to keep the
    /// tests cheap, and the per-block cost scales with it either way.
    const DICT_1MIB: u8 = 0x10;

    /// Counts the bytes the decoder pulled from its input.
    struct CountingReader<'a> {
        inner: Cursor<&'a [u8]>,
        read: usize,
    }

    impl io::Read for CountingReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = io::Read::read(&mut self.inner, buf)?;
            self.read += n;
            Ok(n)
        }
    }

    #[test]
    fn empty_blocks_decode_to_nothing_within_the_budget() {
        // The fixture itself is a valid stream: what stops the tests below
        // is the budget or the hang-up, never a malformed input.
        let xz = empty_blocks_xz(3, DICT_1MIB);
        let mut out = Vec::new();
        decode_stream(
            &mut Cursor::new(&xz[..]),
            &mut out,
            MAX_XZ_DECODE_CPU,
            || false,
        )
        .expect("three empty blocks form a valid stream");
        assert_eq!(out, [] as [u8; 0]);
    }

    #[test]
    fn empty_blocks_are_abandoned_at_the_cpu_budget() {
        // 100k empty blocks, 1.8 MB of input and no output: the output caps
        // never engage, and setting up 100k dictionaries takes far longer
        // than the budget.
        let xz = empty_blocks_xz(100_000, DICT_1MIB);
        let mut input = CountingReader {
            inner: Cursor::new(&xz[..]),
            read: 0,
        };
        let mut out = Vec::new();
        let err = decode_stream(&mut input, &mut out, Duration::from_millis(20), || false)
            .expect_err("an output-free stream must not outlive its CPU budget");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        assert_eq!(out, [] as [u8; 0]);
        assert!(
            input.read < xz.len(),
            "the decode must stop early, read {} of {} bytes",
            input.read,
            xz.len()
        );
    }

    #[test]
    fn abandoned_decode_stops_before_reading() {
        let mut input = CountingReader {
            inner: Cursor::new(HELLO_XZ),
            read: 0,
        };
        let mut out = Vec::new();
        let err = decode_stream(&mut input, &mut out, MAX_XZ_DECODE_CPU, || true)
            .expect_err("a decode nobody reads must stop");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{err}");
        assert_eq!(input.read, 0);
        assert_eq!(out, [] as [u8; 0]);
    }

    /// Wraps an input and signals when the blocking decode drops it, which
    /// it does only on its way out.
    struct DropSignal<R> {
        inner: R,
        _dropped: oneshot::Sender<()>,
    }

    impl<R: io::Read> io::Read for DropSignal<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buf)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_decoder_stops_an_output_free_decode() {
        // The blocking decode never writes, so before the hang-up check it
        // only noticed a dropped reader once the whole stream (or the CPU
        // budget) was spent.
        let (tx, rx) = oneshot::channel();
        let input = DropSignal {
            inner: Cursor::new(empty_blocks_xz(100_000, DICT_1MIB)),
            _dropped: tx,
        };
        let decoder = xz_decoder(input);
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(decoder);
        let closed = tokio::time::timeout(Duration::from_secs(10), rx).await;
        assert!(
            matches!(closed, Ok(Err(_))),
            "the blocking decode must let go of its input once the reader is dropped"
        );
    }

    #[tokio::test]
    async fn early_drop_does_not_panic() {
        // Spawn a decode, read one byte, drop the wrapper. The blocking task
        // should observe BrokenPipe on its next write and exit cleanly without
        // panicking the runtime.
        let mut decoder = xz_decoder(Cursor::new(HELLO_XZ));
        let mut one = [0u8; 1];
        let n = decoder.read(&mut one).await.expect("first byte ok");
        assert_eq!(n, 1);
        assert_eq!(one[0], b'h');
        drop(decoder);
        tokio::task::yield_now().await;
    }
}
