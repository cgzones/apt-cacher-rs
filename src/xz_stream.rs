//! Pure-Rust XZ streaming decompressor.
//!
//! Wraps `lzma_rust2::XzReader` (a synchronous `std::io::Read` adapter) in a
//! tokio blocking task feeding a `tokio::io::duplex` pipe, so callers can treat
//! it as any other `AsyncRead`. Replaces `async_compression::tokio::bufread::XzDecoder`
//! to remove the C `liblzma`/`liblzma-sys` dependency.

use std::future::Future as _;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, DuplexStream, ReadBuf};
use tokio::sync::oneshot;
use tokio_util::io::SyncIoBridge;

/// Internal pipe capacity. 64 KiB amortises copy syscalls between the blocking
/// decoder thread and the async consumer without holding meaningful state.
const PIPE_CAPACITY: usize = 64 * 1024;

/// Async wrapper over a blocking `lzma_rust2::XzReader` decode.
///
/// EOF on the inner pipe triggers a poll of `tail` to surface any terminal
/// `io::Error` the decoder produced; a clean decode reports the EOF verbatim.
pub(crate) struct XzDecoderStream {
    inner: DuplexStream,
    tail: Option<oneshot::Receiver<io::Result<()>>>,
}

/// Construct an `AsyncRead` that yields the xz-decompressed bytes of `reader`.
///
/// Multi-stream xz files are accepted (matches the `xz` CLI default and what
/// `async_compression`'s `XzDecoder` did before).
pub(crate) fn xz_decoder<R>(reader: R) -> XzDecoderStream
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (read_half, write_half) = tokio::io::duplex(PIPE_CAPACITY);
    let (err_tx, err_rx) = oneshot::channel::<io::Result<()>>();

    tokio::task::spawn_blocking(move || {
        let bridge_in = SyncIoBridge::new(reader);
        let mut bridge_out = SyncIoBridge::new(write_half);
        let mut decoder =
            lzma_rust2::XzReader::new(bridge_in, /* allow_multiple_streams = */ true);
        let result = std::io::copy(&mut decoder, &mut bridge_out).map(|_| ());
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
        let mut decoder = xz_decoder(std::io::Cursor::new(HELLO_XZ));
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .await
            .expect("decode should succeed");
        assert_eq!(&out, b"hello world\n");
    }

    #[tokio::test]
    async fn corrupt_input_surfaces_io_error() {
        // Flip a byte in the LZMA2-encoded payload region (offset 32 is well
        // inside the compressed block, past the stream header).
        let mut bad = HELLO_XZ.to_vec();
        bad[32] ^= 0xFF;
        let mut decoder = xz_decoder(std::io::Cursor::new(bad));
        let mut out = Vec::new();
        let result = decoder.read_to_end(&mut out).await;
        assert!(
            result.is_err() || out != b"hello world\n",
            "corrupt xz must either return io::Error or produce different output, got Ok with {out:?}"
        );
    }

    #[tokio::test]
    async fn empty_buffer_read_does_not_surface_tail_error() {
        // Corrupt input so the blocking decoder finishes with an Err in the
        // tail channel. An empty-buffer read must NOT be misread as EOF,
        // consume `tail`, and surface that error — it should behave like a
        // normal AsyncRead and return Ok(()) immediately.
        let mut bad = HELLO_XZ.to_vec();
        bad[32] ^= 0xFF;
        let mut decoder = xz_decoder(std::io::Cursor::new(bad));

        // Let the blocking task run to completion so the Err is sitting in
        // the oneshot. 100ms is ample for decoding ~70 bytes.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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
        let real = decoder.read_to_end(&mut out).await;
        assert!(
            real.is_err() || out != b"hello world\n",
            "tail error must still be available after empty-buf read, got Ok({out:?})"
        );
    }

    #[tokio::test]
    async fn empty_buffer_read_is_immediately_ready() {
        // Using a noop waker, a single poll with an empty ReadBuf must return
        // Ready(Ok(())). Without the fix, the wrapper polls the (still
        // pending) tail oneshot and returns Pending — which would never
        // resolve under a noop waker.
        let mut decoder = xz_decoder(std::io::Cursor::new(HELLO_XZ));

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

    #[tokio::test]
    async fn early_drop_does_not_panic() {
        // Spawn a decode, read one byte, drop the wrapper. The blocking task
        // should observe BrokenPipe on its next write and exit cleanly without
        // panicking the runtime.
        let mut decoder = xz_decoder(std::io::Cursor::new(HELLO_XZ));
        let mut one = [0u8; 1];
        let n = decoder.read(&mut one).await.expect("first byte ok");
        assert_eq!(n, 1);
        assert_eq!(one[0], b'h');
        drop(decoder);
        tokio::task::yield_now().await;
    }
}
