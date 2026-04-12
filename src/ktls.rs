//! Kernel TLS (kTLS) support for zero-copy splice from TLS sockets.
//!
//! When kTLS RX is configured on a socket, the kernel decrypts incoming TLS
//! records transparently, allowing `splice(2)` to move plaintext data without
//! ever copying it to userspace.

use std::io;
use std::io::IoSliceMut;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd};
use std::sync::OnceLock;

use log::{debug, info, warn};
use nix::libc;
use nix::sys::socket::sockopt::TlsCryptoInfo;
use nix::sys::socket::{self, ControlMessageOwned, MsgFlags, SockaddrStorage, TlsGetRecordType};
use rustls::ConnectionTrafficSecrets;
use rustls::crypto::cipher::NONCE_LEN;

use crate::error::errno_to_io_error;
use crate::{Never, static_assert, warn_once};

/// RAII wrapper around `TlsCryptoInfo` that zeroes its payload bytes on drop.
///
/// `TlsCryptoInfo` is `#[derive(Copy, Clone)]`, so each construction / move
/// leaves a copy of the key material on the stack. This wrapper owns the
/// final copy that `setsockopt(TLS_RX)` reads from and wipes it before the
/// stack frame is reused — also on panic and early return paths.
struct ZeroizingCryptoInfo(TlsCryptoInfo);

impl Drop for ZeroizingCryptoInfo {
    fn drop(&mut self) {
        match &mut self.0 {
            TlsCryptoInfo::Aes128Gcm(d) => {
                // SAFETY: `d` is a live, initialized POD struct owned by self.0;
                // `size_of_val` gives its exact byte span.
                unsafe {
                    libc::explicit_bzero(
                        core::ptr::from_mut(d).cast::<libc::c_void>(),
                        size_of_val(d),
                    );
                }
            }
            TlsCryptoInfo::Aes256Gcm(d) => {
                // SAFETY: see Aes128Gcm arm.
                unsafe {
                    libc::explicit_bzero(
                        core::ptr::from_mut(d).cast::<libc::c_void>(),
                        size_of_val(d),
                    );
                }
            }
            TlsCryptoInfo::Chacha20Poly1305(d) => {
                // SAFETY: see Aes128Gcm arm.
                unsafe {
                    libc::explicit_bzero(
                        core::ptr::from_mut(d).cast::<libc::c_void>(),
                        size_of_val(d),
                    );
                }
            }
        }
    }
}

/// Zeroize a mutable byte slice using `explicit_bzero`, which the compiler
/// is not permitted to elide. A no-op for empty slices.
#[inline]
fn zeroize_bytes(bytes: &mut [u8]) {
    if bytes.is_empty() {
        return;
    }
    // SAFETY: `bytes` is a valid writable slice of `bytes.len()` bytes.
    unsafe {
        libc::explicit_bzero(bytes.as_mut_ptr().cast::<libc::c_void>(), bytes.len());
    }
}

// Compile-time assertions: NONCE_LEN (rustls Iv size) must match
// the kernel kTLS struct field sizes for all supported ciphers.
// AES-GCM: salt (4 bytes) + iv (8 bytes) = 12
// ChaCha20-Poly1305: iv (12 bytes), no salt
static_assert!(NONCE_LEN == 12, "kTLS requires NONCE_LEN == 12");

// ---------------------------------------------------------------------------
// Availability probe (cached)
// ---------------------------------------------------------------------------

static KTLS_AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Probe kTLS availability by attempting to set the TLS ULP on a connected socket.
/// The result is cached for the lifetime of the process.
///
/// `TCP_ULP` requires a connected socket, so we create a loopback TCP pair
/// to test whether the kernel supports the `tls` ULP.
#[must_use]
pub(crate) fn is_available() -> bool {
    enum TestResult {
        Available,
        Unavailable,
        /// An error occurred during the test.
        /// A log message should have been emitted.
        Error,
    }

    fn inner() -> TestResult {
        use nix::sys::socket::{
            AddressFamily, Backlog, SockFlag, SockType, SockaddrIn, accept, bind, connect,
            getsockname, listen, setsockopt, socket, sockopt::TcpUlp,
        };
        use std::os::fd::{FromRawFd as _, OwnedFd};

        let listener: OwnedFd = match socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        ) {
            Ok(fd) => fd,
            Err(err) => {
                warn!("kTLS: available test: Failed to create listener socket:  {err}");
                return TestResult::Error;
            }
        };

        let addr = SockaddrIn::new(127, 0, 0, 1, 0);
        if let Err(err) = bind(listener.as_raw_fd(), &addr) {
            warn!("kTLS: available test: Failed to bind socket:  {err}");
            return TestResult::Error;
        }

        if let Err(err) = listen(&listener, Backlog::new(1).expect("valid backlog value")) {
            warn!("kTLS: available test: Failed to listen on socket:  {err}");
            return TestResult::Error;
        }

        // Read back the assigned port
        let sockname: SockaddrIn = match getsockname(listener.as_raw_fd()) {
            Ok(s) => s,
            Err(err) => {
                warn!("kTLS: available test: Failed to get sockname:  {err}");
                return TestResult::Error;
            }
        };

        // Connect a client socket
        let client: OwnedFd = match socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        ) {
            Ok(fd) => fd,
            Err(err) => {
                warn!("kTLS: available test: Failed to create client socket:  {err}");
                return TestResult::Error;
            }
        };

        if let Err(err) = connect(client.as_raw_fd(), &sockname) {
            warn!("kTLS: available test: Failed to connect client socket:  {err}");
            return TestResult::Error;
        }

        // Accept the server side (not needed for the probe, but completes the handshake)
        let _server = match accept(listener.as_raw_fd()) {
            Ok(fd) => {
                // SAFETY: accept succeeded so the fd is valid, and no other code owns it.
                // nix::sys::socket::accept returns a raw fd (not OwnedFd), so we wrap it
                // immediately to ensure it is closed on drop.
                unsafe { OwnedFd::from_raw_fd(fd) }
            }
            Err(err) => {
                warn!("kTLS: available test: Failed to accept client connection:  {err}");
                return TestResult::Error;
            }
        };

        drop(listener);

        // Now try TCP_ULP on the connected client socket
        match setsockopt(&client, TcpUlp::default(), b"tls") {
            Ok(()) => TestResult::Available,
            Err(nix::errno::Errno::ENOENT) => TestResult::Unavailable,
            Err(err) => {
                warn!("kTLS: available test: Failed to set TCP_ULP:  {err}");
                TestResult::Error
            }
        }
    }

    *KTLS_AVAILABLE.get_or_init(|| match inner() {
        TestResult::Available => {
            info!("kTLS: kernel TLS support detected");
            true
        }
        TestResult::Unavailable => {
            info!("kTLS: kernel TLS not available (modprobe tls?)");
            false
        }
        TestResult::Error => {
            // Log message should have been emitted.
            false
        }
    })
}

/// Resolve TLS protocol version to the kernel constant, or return an error.
fn resolve_tls_version(version: rustls::ProtocolVersion) -> io::Result<u16> {
    // TODO: static_assert!(std::mem::variant_count::<rustls::ProtocolVersion>() == 10);

    match version {
        rustls::ProtocolVersion::TLSv1_2 => Ok(libc::TLS_1_2_VERSION),
        rustls::ProtocolVersion::TLSv1_3 => Ok(libc::TLS_1_3_VERSION),
        rustls::ProtocolVersion::SSLv2
        | rustls::ProtocolVersion::SSLv3
        | rustls::ProtocolVersion::TLSv1_0
        | rustls::ProtocolVersion::TLSv1_1
        | rustls::ProtocolVersion::DTLSv1_0
        | rustls::ProtocolVersion::DTLSv1_2
        | rustls::ProtocolVersion::DTLSv1_3
        | rustls::ProtocolVersion::Unknown(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("kTLS: unknown TLS protocol version {version:#x?}"),
        )),
        // ProtocolVersion is #[non_exhaustive]; keep the catch-all separate
        // from the explicit list so a new rustls variant reads as its own
        // arm during review rather than silently merging into the list above.
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("kTLS: unsupported new TLS protocol version {version:#x?}"),
        )),
    }
}

/// Copy a fixed-size slice into an output array, returning an `InvalidData`
/// I/O error with `label` if the source length doesn't match.
fn copy_fixed<const N: usize>(src: &[u8], label: &'static str) -> io::Result<[u8; N]> {
    if src.len() != N {
        return Err(io::Error::new(io::ErrorKind::InvalidData, label));
    }

    let mut out = [0u8; N];
    out.copy_from_slice(src);
    Ok(out)
}

/// Set up kTLS RX decryption on a raw file descriptor using extracted rustls secrets.
///
/// After this call succeeds, the kernel will transparently decrypt incoming TLS
/// records on this socket, enabling `splice(2)` to read plaintext directly.
///
/// # Safety considerations
///
/// The caller must ensure `fd` is a valid, connected TCP socket with TLS ULP
/// already loaded (via [`load_ulp`]) and that the TLS secrets correspond to
/// the current connection state.
pub(crate) fn setup_rx<F: AsFd>(
    fd: &F,
    seq: u64,
    secrets: &ConnectionTrafficSecrets,
    version: rustls::ProtocolVersion,
) -> io::Result<()> {
    let tls_version = resolve_tls_version(version)?;
    let rec_seq = seq.to_be_bytes();

    // TODO: static_assert!(std::mem::variant_count::<ConnectionTrafficSecrets>() == 3);

    // Note: the kernel structs are named `tls12_crypto_info_*` but work for
    // both TLS 1.2 and 1.3 — this is a kernel naming convention, not a version check.
    //
    // All per-arm `salt` / `iv` / `key` stack locals hold raw key material.
    // They are `Copy` arrays of primitives (so still readable after being
    // moved into the crypto_info struct literal) and are explicitly
    // `zeroize_bytes`'d once the enum has been wrapped. The enum's own
    // payload is wiped by `ZeroizingCryptoInfo::drop` after setsockopt.
    let crypto = match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            // AES-GCM nonce layout: salt = iv[0..4], iv_field = iv[4..12]
            let salt_and_iv: &[u8; NONCE_LEN] = iv.as_ref().try_into().map_err(|_err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "kTLS: AES-128-GCM IV is not 12 bytes",
                )
            })?;
            let &[s0, s1, s2, s3, i0, i1, i2, i3, i4, i5, i6, i7] = salt_and_iv;
            let mut salt: [u8; 4] = [s0, s1, s2, s3];
            let mut iv: [u8; 8] = [i0, i1, i2, i3, i4, i5, i6, i7];
            let mut key: [u8; 16] =
                copy_fixed(key.as_ref(), "kTLS: AES-128-GCM key is not 16 bytes")?;

            let zci = ZeroizingCryptoInfo(TlsCryptoInfo::Aes128Gcm(
                libc::tls12_crypto_info_aes_gcm_128 {
                    info: libc::tls_crypto_info {
                        version: tls_version,
                        cipher_type: libc::TLS_CIPHER_AES_GCM_128,
                    },
                    iv,
                    key,
                    salt,
                    rec_seq,
                },
            ));

            zeroize_bytes(&mut salt);
            zeroize_bytes(&mut iv);
            zeroize_bytes(&mut key);
            zci
        }

        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            let salt_and_iv: &[u8; NONCE_LEN] = iv.as_ref().try_into().map_err(|_err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "kTLS: AES-256-GCM IV is not 12 bytes",
                )
            })?;
            let &[s0, s1, s2, s3, i0, i1, i2, i3, i4, i5, i6, i7] = salt_and_iv;
            let mut salt: [u8; 4] = [s0, s1, s2, s3];
            let mut iv: [u8; 8] = [i0, i1, i2, i3, i4, i5, i6, i7];
            let mut key: [u8; 32] =
                copy_fixed(key.as_ref(), "kTLS: AES-256-GCM key is not 32 bytes")?;

            let zci = ZeroizingCryptoInfo(TlsCryptoInfo::Aes256Gcm(
                libc::tls12_crypto_info_aes_gcm_256 {
                    info: libc::tls_crypto_info {
                        version: tls_version,
                        cipher_type: libc::TLS_CIPHER_AES_GCM_256,
                    },
                    iv,
                    key,
                    salt,
                    rec_seq,
                },
            ));

            zeroize_bytes(&mut salt);
            zeroize_bytes(&mut iv);
            zeroize_bytes(&mut key);
            zci
        }
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            // ChaCha20: full 12-byte IV, no salt split
            let mut iv: [u8; NONCE_LEN] =
                copy_fixed(iv.as_ref(), "kTLS: ChaCha20-Poly1305 IV is not 12 bytes")?;
            let mut key: [u8; 32] =
                copy_fixed(key.as_ref(), "kTLS: ChaCha20-Poly1305 key is not 32 bytes")?;

            let zci = ZeroizingCryptoInfo(TlsCryptoInfo::Chacha20Poly1305(
                libc::tls12_crypto_info_chacha20_poly1305 {
                    info: libc::tls_crypto_info {
                        version: tls_version,
                        cipher_type: libc::TLS_CIPHER_CHACHA20_POLY1305,
                    },
                    iv,
                    salt: [],
                    key,
                    rec_seq,
                },
            ));

            zeroize_bytes(&mut iv);
            zeroize_bytes(&mut key);
            zci
        }
        _ => {
            warn_once!("kTLS: unsupported cipher suite in traffic secrets");
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "kTLS: unsupported cipher suite",
            ));
        }
    };

    nix::sys::socket::setsockopt(fd, nix::sys::socket::sockopt::TcpTlsRx, &crypto.0)
        .map_err(|errno| errno_to_io_error(errno, "kTLS: failed to set TcpTlsRx"))?;

    // `crypto` drops here, zeroing the enum payload (both success and panic paths).
    drop(crypto);

    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load the TLS Upper Layer Protocol on the socket.
///
/// This must be called on a connected TCP socket (state `TCP_ESTABLISHED`)
/// before [`setup_rx`]. The kernel rejects this with `ENOTCONN`
/// if the socket is in `CLOSE_WAIT` or any other non-established state.
///
/// # Required call order
///
/// 1. [`load_ulp`] — load TLS ULP (this function)
/// 2. [`setup_rx`] — configure crypto keys
/// 3. [`drain_control_messages`] — consume non-data TLS records
///
/// Calling `setup_rx` before `load_ulp` will fail with `ENOENT`.
/// Calling `drain_control_messages` before `setup_rx` has undefined results.
pub(crate) fn load_ulp<F: AsFd>(fd: &F) -> io::Result<()> {
    nix::sys::socket::setsockopt(fd, nix::sys::socket::sockopt::TcpUlp::default(), b"tls").map_err(
        |errno| {
            warn_once!("kTLS: failed to load TLS ULP:  {errno}");
            errno_to_io_error(errno, "setsockopt TLS ULP failed")
        },
    )
}

/// Return a display name for a `ConnectionTrafficSecrets` variant.
pub(crate) fn secret_name(secrets: &ConnectionTrafficSecrets) -> &'static str {
    // TODO: static_assert!(std::mem::variant_count::<ConnectionTrafficSecrets>() == 3);

    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { .. } => "AES-128-GCM",
        ConnectionTrafficSecrets::Aes256Gcm { .. } => "AES-256-GCM",
        ConnectionTrafficSecrets::Chacha20Poly1305 { .. } => "ChaCha20-Poly1305",
        // ConnectionTrafficSecrets is #[non_exhaustive], so new variants may be added
        // by rustls in future versions. This will not cause a compile-time error, but
        // setup_direction() will return Err for unsupported ciphers before we reach here.
        _ => "unknown",
    }
}

/// Whether the caller has confirmed that data is ready on the socket
/// (e.g. via `poll(POLLIN)`) before calling `drain_control_messages`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DrainExpect {
    /// Data is known to be ready. An EAGAIN from the first peek means a
    /// non-data control record was queued but became unavailable between
    /// poll and peek — fail closed and fall back to userspace TLS rather
    /// than letting splice later trip on an EIO.
    DataReady,
    /// No data-ready guarantee. An EAGAIN just means the socket is empty,
    /// so `drain_control_messages` returns `Ok(())`.
    MaybeIdle,
}

/// Consume any pending TLS 1.3 control messages (e.g. `NewSessionTicket`) from a
/// kTLS socket.
///
/// In TLS 1.3, the server may send post-handshake messages like `NewSessionTicket`
/// encrypted with the application traffic keys. These arrive as TLS records with
/// outer content type `ApplicationData` but inner content type `Handshake`. kTLS
/// decrypts them but cannot deliver them via regular `read()`/`splice()` — only
/// via `recvmsg()` with control message (cmsg) handling. This function drains all
/// such non-data records so subsequent `splice()` calls see only application data.
///
/// Returns `Ok(())` when the next available record is application data or the
/// socket has no data ready (and `expect` is [`DrainExpect::MaybeIdle`]).
/// Returns `Err` on unexpected socket errors, and (with [`DrainExpect::DataReady`])
/// on a first-peek EAGAIN.
///
/// # Single-caller invariant
///
/// This function must only be called by one thread/task at a time for a given fd.
/// The peek-then-consume pattern assumes no concurrent consumer on the same socket.
/// `debug_assert_eq!`s on the peeked vs. consumed `recvmsg` result detect violations
/// in debug builds.
///
/// # Kernel record atomicity
///
/// `TLS-ULP` in the Linux kernel delivers one TLS record per `recvmsg()`
/// (`net/tls/tls_sw.c: tls_sw_recvmsg`): the payload length returned via
/// `msg_iov` is bounded by the current record boundary, and the record-type
/// cmsg always describes exactly that record. A partial record cannot be
/// surfaced to userspace — the kernel blocks (or returns `EAGAIN` in
/// non-blocking mode) until a full record has been decrypted. This is what
/// makes the peek-then-consume pattern sound: the consume `recvmsg` sees the
/// same record-type cmsg as the peek, not a stale type from a record that was
/// only partially in the kernel buffer during the peek. The `MSG_CTRUNC`
/// check below additionally defends against kernel-side cmsg-buffer
/// insufficiency rather than wire-level partial records.
pub(crate) fn drain_control_messages(fd: BorrowedFd<'_>, expect: DrainExpect) -> io::Result<()> {
    // Buffer for the record payload. 0x4001 (16385) is one byte more than the
    // TLS max record size (16384) to avoid EMSGSIZE on exactly-max-size records
    // during MSG_PEEK.
    #[expect(clippy::large_stack_arrays, reason = "must fit full TLS record")]
    let mut buf = [0u8; 0x4001];

    let mut first_iteration = true;

    loop {
        let mut iov = [IoSliceMut::new(&mut buf)];
        // Fresh cmsg buffer per iteration so stale bytes from a previous recvmsg
        // cannot influence extract_record_type() if the kernel writes fewer bytes.
        let mut cmsg_buf = nix::cmsg_space!(TlsGetRecordType);

        // Use recvmsg with cmsg to receive control messages that read() can't deliver.
        // kTLS only returns non-data records (NewSessionTicket, etc.) when cmsg is available.
        let recv = match socket::recvmsg::<SockaddrStorage>(
            fd.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(msg) => msg,
            Err(nix::errno::Errno::EAGAIN) => {
                if first_iteration && expect == DrainExpect::DataReady {
                    // Caller polled POLLIN and saw the socket was ready; if the
                    // kernel now tells us there's nothing there, a non-data
                    // control record may have been delivered without us seeing
                    // it (or raced with some other consumer). Fail closed so
                    // the caller falls back to userspace TLS.
                    warn!(
                        "kTLS: initial drain peek returned EAGAIN despite POLLIN; \
                         aborting kTLS setup"
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "kTLS: drain peek EAGAIN after poll-ready",
                    ));
                }
                return Ok(());
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::EMSGSIZE) => {
                // The TLS record is larger than our peek buffer. This should
                // not happen since the buffer is > max TLS record size, but
                // if it does, assume it's application data and stop draining.
                warn!("kTLS: peek buffer too small (EMSGSIZE), assuming application data");
                return Ok(());
            }
            Err(errno) => {
                debug!("kTLS: drain peek error:  {errno}");
                return Err(errno_to_io_error(errno, "recvmsg peek failed"));
            }
        };

        first_iteration = false;

        let record_type = extract_record_type(&recv);
        let peeked_bytes = recv.bytes;
        let flags = recv.flags;
        debug!("kTLS: peeked {peeked_bytes} bytes, record_type={record_type:?}, flags={flags:?}");
        drop(cmsg_buf); // Avoid accidental reuse.

        match record_type {
            Some(TlsGetRecordType::ApplicationData) => return Ok(()),
            None => {
                if flags.contains(MsgFlags::MSG_CTRUNC) {
                    // Truncated cmsg means we could not read the TLS record
                    // type; assuming application data is unsafe because a
                    // missed control message would desync the kTLS state.
                    warn!("kTLS: cmsg buffer truncated, aborting kTLS setup");
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "kTLS: cmsg buffer truncated",
                    ));
                }
                // No TLS record type reported — assume application data
                return Ok(());
            }
            Some(rt) => {
                // It's a control message (e.g., Handshake) — consume it (no MSG_PEEK).
                // Retry in a tight loop on EINTR to avoid restarting the outer
                // peek cycle for a record we already identified.
                loop {
                    let mut consume_iov = [IoSliceMut::new(&mut buf)];
                    let mut consume_cmsg = nix::cmsg_space!(TlsGetRecordType);
                    let _: Never = match socket::recvmsg::<SockaddrStorage>(
                        fd.as_raw_fd(),
                        &mut consume_iov,
                        Some(&mut consume_cmsg),
                        MsgFlags::MSG_DONTWAIT,
                    ) {
                        Ok(msg) => {
                            // Verify the consumed message matches what we peeked.
                            // This should always hold since we are the sole consumer
                            // on this fd, but verify as defense-in-depth.
                            debug_assert_eq!(
                                msg.bytes, peeked_bytes,
                                "consumed {}, but peeked {peeked_bytes} — \
                                 concurrent reader on kTLS socket?",
                                msg.bytes
                            );
                            let consumed_rt = extract_record_type(&msg);
                            debug_assert_eq!(
                                consumed_rt,
                                Some(rt),
                                "consumed record type {consumed_rt:?} differs from \
                                 peeked {rt:?} — concurrent reader on kTLS socket?"
                            );
                            debug!(
                                "kTLS: consumed control message ({} bytes, type={rt:?})",
                                msg.bytes
                            );
                            break;
                        }
                        Err(nix::errno::Errno::EWOULDBLOCK) => {
                            // EWOULDBLOCK after a successful peek means the record was
                            // consumed between the peek and the consume — leaving an
                            // unconsumed non-data record queued would desync kTLS.
                            // Fail closed so the caller falls back to userspace TLS
                            // instead of corrupting the stream.
                            warn!(
                                "kTLS: drain consume got EWOULDBLOCK after successful peek \
                                 ({peeked_bytes} bytes, type={rt:?}); aborting kTLS setup"
                            );
                            return Err(io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "kTLS: drain consume EWOULDBLOCK after peek",
                            ));
                        }
                        Err(nix::errno::Errno::EINTR) => continue,
                        Err(errno) => {
                            debug!(
                                "kTLS: drain consume error (peeked {peeked_bytes} bytes, type={rt:?}):  {errno}"
                            );
                            return Err(errno_to_io_error(errno, "kTLS: drain consume error"));
                        }
                    };
                }
            }
        }
    }
}

/// Extract the `TlsGetRecordType` from a `recvmsg()` result's control messages.
fn extract_record_type(
    recv: &socket::RecvMsg<'_, '_, SockaddrStorage>,
) -> Option<TlsGetRecordType> {
    let cmsgs = recv.cmsgs().ok()?;
    for cmsg in cmsgs {
        if let ControlMessageOwned::TlsGetRecordType(rt) = cmsg {
            return Some(rt);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Barrier};
    use std::thread::JoinHandle;

    /// Result of setting up a kTLS test: a client socket with kTLS RX configured,
    /// two barriers (start-writing, client-done-reading) and the server thread handle.
    struct KtlsTestHarness {
        tcp_client: TcpStream,
        /// Client → server: "start writing application data".
        start_barrier: Arc<Barrier>,
        /// Client → server: "I've finished reading — you may send `close_notify`".
        /// This replaces a fixed-duration sleep that was racy on slow CI runners.
        done_barrier: Arc<Barrier>,
        server_handle: JoinHandle<()>,
    }

    /// Create a self-signed cert + key pair for test TLS connections.
    fn generate_test_cert() -> (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let key_pair = rcgen::KeyPair::generate().expect("keygen");
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("cert params");
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
                std::net::Ipv4Addr::LOCALHOST,
            )));
        let cert = params.self_signed(&key_pair).expect("self-signed cert");

        let certs = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
            .expect("parse key");

        (certs, key)
    }

    /// Set up a TLS server/client pair with kTLS RX on the client side.
    ///
    /// The returned `KtlsTestHarness` carries two barriers:
    ///   * `start_barrier.wait()` — tell the server to invoke `write_fn`.
    ///   * `done_barrier.wait()` — tell the server the client has finished
    ///     reading and it may now send `close_notify`. Replaces a fixed sleep
    ///     that was flaky on contended CI runners.
    ///
    /// `write_fn` receives the server's `rustls::Stream` and should write all
    /// application data, then return.
    fn setup_ktls_test<F>(
        tls_versions: &[&'static rustls::SupportedProtocolVersion],
        write_fn: F,
    ) -> KtlsTestHarness
    where
        F: FnOnce(&mut rustls::Stream<'_, rustls::ServerConnection, &TcpStream>) + Send + 'static,
    {
        setup_ktls_test_with_provider(tls_versions, None, write_fn)
    }

    /// Like `setup_ktls_test`, but accepts an optional cipher-suite filter so
    /// tests can exercise a specific cipher (e.g. ChaCha20-Poly1305).
    fn setup_ktls_test_with_provider<F>(
        tls_versions: &[&'static rustls::SupportedProtocolVersion],
        cipher_suite_filter: Option<&[rustls::SupportedCipherSuite]>,
        write_fn: F,
    ) -> KtlsTestHarness
    where
        F: FnOnce(&mut rustls::Stream<'_, rustls::ServerConnection, &TcpStream>) + Send + 'static,
    {
        let (certs, key) = generate_test_cert();

        let build_provider = || {
            let mut provider = rustls::crypto::aws_lc_rs::default_provider();
            if let Some(filter) = cipher_suite_filter {
                provider.cipher_suites = filter.to_vec();
            }
            std::sync::Arc::new(provider)
        };

        let server_config = std::sync::Arc::new(
            rustls::ServerConfig::builder_with_provider(build_provider())
                .with_protocol_versions(tls_versions)
                .expect("server protocol versions")
                .with_no_client_auth()
                .with_single_cert(certs.clone(), key)
                .expect("server config"),
        );

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(certs[0].clone()).expect("add root cert");
        let mut client_config = rustls::ClientConfig::builder_with_provider(build_provider())
            .with_protocol_versions(tls_versions)
            .expect("client protocol versions")
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.enable_secret_extraction = true;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let start_barrier = Arc::new(Barrier::new(2));
        let done_barrier = Arc::new(Barrier::new(2));
        let server_start_barrier = Arc::clone(&start_barrier);
        let server_done_barrier = Arc::clone(&done_barrier);

        let server_handle = std::thread::spawn(move || {
            let (tcp_server, _) = listener.accept().expect("accept");
            let mut server_conn =
                rustls::ServerConnection::new(server_config).expect("server conn");
            while server_conn.is_handshaking() {
                server_conn
                    .complete_io(&mut &tcp_server)
                    .expect("server handshake");
            }

            while server_conn.wants_write() {
                server_conn
                    .write_tls(&mut &tcp_server)
                    .expect("flush post-handshake");
            }

            server_start_barrier.wait();

            let mut tcp_ref = &tcp_server;
            let mut stream = rustls::Stream::new(&mut server_conn, &mut tcp_ref);
            write_fn(&mut stream);

            server_done_barrier.wait();
            server_conn.send_close_notify();
            server_conn
                .write_tls(&mut &tcp_server)
                .expect("write close_notify");
        });

        let tcp_client = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let mut client_conn =
            rustls::ClientConnection::new(std::sync::Arc::new(client_config), server_name)
                .expect("client conn");

        let mut tcp_ref: &TcpStream = &tcp_client;
        while client_conn.is_handshaking() {
            client_conn.complete_io(&mut tcp_ref).expect("handshake io");
        }

        let version = client_conn.protocol_version().expect("protocol version");
        let secrets = client_conn
            .dangerous_extract_secrets()
            .expect("extract secrets");
        let (rx_seq, ref rx_secrets) = secrets.rx;

        load_ulp(&tcp_client).expect("load_ulp");
        setup_rx(&tcp_client, rx_seq, rx_secrets, version).expect("setup_rx");

        KtlsTestHarness {
            tcp_client,
            start_barrier,
            done_barrier,
            server_handle,
        }
    }

    /// Signal the server, poll for data, and drain kTLS control messages.
    fn signal_and_drain(harness: &KtlsTestHarness) {
        harness.start_barrier.wait();

        let pollfd =
            nix::poll::PollFd::new(harness.tcp_client.as_fd(), nix::poll::PollFlags::POLLIN);
        let nready =
            nix::poll::poll(&mut [pollfd], nix::poll::PollTimeout::from(5000u16)).expect("poll");
        assert_eq!(nready, 1, "expected 1 ready fd");

        drain_control_messages(harness.tcp_client.as_fd(), DrainExpect::DataReady)
            .expect("drain control messages");
    }

    /// Read all available data from a socket using poll + read.
    fn read_all_available(tcp: &mut TcpStream, poll_timeout_ms: u16) -> Vec<u8> {
        let mut all_data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let pollfd = nix::poll::PollFd::new(tcp.as_fd(), nix::poll::PollFlags::POLLIN);
            match nix::poll::poll(&mut [pollfd], nix::poll::PollTimeout::from(poll_timeout_ms)) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            match tcp.read(&mut buf) {
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Ok(0) | Err(_) => break,
                Ok(n) => all_data.extend_from_slice(&buf[..n]),
            }
        }
        all_data
    }

    #[test]
    fn test_is_available_is_deterministic() {
        // Calling is_available() twice must return the same cached result.
        let first = is_available();
        let second = is_available();
        assert_eq!(first, second);
    }

    /// Shared test helper: create a TLS connection, set up kTLS RX, send data,
    /// and verify decryption works with `read()`.
    #[expect(
        clippy::print_stderr,
        reason = "matched against in integration test ktls_splice_proxy_downloads_over_https()"
    )]
    fn run_ktls_read_test(tls_versions: &[&'static rustls::SupportedProtocolVersion]) {
        if !is_available() {
            eprintln!("kTLS not available, skipping");
            return;
        }

        let plaintext_msg = b"Hello from kTLS test! This is plaintext data.";

        let mut harness = setup_ktls_test(tls_versions, |stream| {
            stream.write_all(plaintext_msg).expect("write plaintext");
            stream.flush().expect("flush");
        });

        signal_and_drain(&harness);

        let mut buf = [0u8; 1024];
        let n = harness
            .tcp_client
            .read(&mut buf)
            .expect("read from kTLS socket");
        assert_eq!(
            &buf[..n],
            plaintext_msg,
            "kTLS should have decrypted the data"
        );

        harness.done_barrier.wait();
        harness.server_handle.join().expect("server thread");
    }

    /// kTLS RX decryption works with TLS 1.2.
    #[test]
    fn test_ktls_rx_tls12() {
        run_ktls_read_test(&[&rustls::version::TLS12]);
    }

    /// kTLS RX decryption works with TLS 1.3 (including `NewSessionTicket` handling).
    #[test]
    fn test_ktls_rx_tls13() {
        run_ktls_read_test(&[&rustls::version::TLS13]);
    }

    /// kTLS RX decryption works with the ChaCha20-Poly1305 cipher, which takes
    /// the IV-as-full-12-bytes / empty-salt layout in `setup_rx` — distinct
    /// from the AES-GCM split-IV path exercised by the other tests.
    #[test]
    #[expect(clippy::print_stderr, reason = "test diagnostic output")]
    fn test_ktls_rx_chacha20_poly1305() {
        if !is_available() {
            eprintln!("kTLS not available, skipping");
            return;
        }

        let plaintext_msg = b"Hello from ChaCha20-Poly1305 kTLS test!";

        let mut harness = setup_ktls_test_with_provider(
            &[&rustls::version::TLS13],
            Some(&[rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256]),
            |stream| {
                stream.write_all(plaintext_msg).expect("write plaintext");
                stream.flush().expect("flush");
            },
        );

        signal_and_drain(&harness);

        let mut buf = [0u8; 1024];
        let n = harness
            .tcp_client
            .read(&mut buf)
            .expect("read from kTLS socket");
        assert_eq!(
            &buf[..n],
            plaintext_msg,
            "kTLS with ChaCha20-Poly1305 should decrypt data"
        );

        harness.done_barrier.wait();
        harness.server_handle.join().expect("server thread");
    }

    /// TLS 1.3 sends multiple `NewSessionTicket` records (rustls sends 4 by default).
    /// Verify that `drain_control_messages` handles all of them and application data
    /// is still correctly read afterward.
    #[test]
    #[expect(clippy::print_stderr, reason = "test diagnostic output")]
    fn test_ktls_drain_multiple_session_tickets_tls13() {
        if !is_available() {
            eprintln!("kTLS not available, skipping");
            return;
        }

        let messages: Vec<&[u8]> = vec![
            b"First message after tickets",
            b"Second message after tickets",
            b"Third message to confirm stream integrity",
        ];
        let server_messages = messages.clone();

        let mut harness = setup_ktls_test(&[&rustls::version::TLS13], move |stream| {
            for msg in &server_messages {
                stream.write_all(msg).expect("write");
                stream.flush().expect("flush");
            }
        });

        signal_and_drain(&harness);

        let all_data = read_all_available(&mut harness.tcp_client, 1000);

        let expected: Vec<u8> = messages.iter().flat_map(|m| m.iter()).copied().collect();
        assert_eq!(
            all_data, expected,
            "all application data should be intact after draining multiple tickets"
        );

        harness.done_barrier.wait();
        harness.server_handle.join().expect("server thread");
    }

    /// Verify that kTLS RX works when application data arrives in multiple
    /// small TCP segments. While we can't perfectly control TCP segmentation,
    /// sending small messages with explicit flushes increases the likelihood
    /// of partial TLS records in the kernel buffer.
    #[test]
    #[expect(clippy::print_stderr, reason = "test diagnostic output")]
    fn test_ktls_rx_small_segments() {
        if !is_available() {
            eprintln!("kTLS not available, skipping");
            return;
        }

        let num_messages = 20;

        let mut harness = setup_ktls_test(&[&rustls::version::TLS13], move |stream| {
            // Each write+flush creates a separate TLS record
            for i in 0..num_messages {
                let msg = format!("msg-{i:04}|");
                stream.write_all(msg.as_bytes()).expect("write");
                stream.flush().expect("flush");
                // Small delay to encourage separate TCP segments
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });

        signal_and_drain(&harness);

        let all_data = read_all_available(&mut harness.tcp_client, 2000);

        #[expect(clippy::format_collect, reason = "permit in test")]
        let expected: String = (0..num_messages).map(|i| format!("msg-{i:04}|")).collect();
        let received = String::from_utf8_lossy(&all_data);
        assert_eq!(
            received.as_ref(),
            expected.as_str(),
            "all {num_messages} small messages should arrive intact via kTLS"
        );

        harness.done_barrier.wait();
        harness.server_handle.join().expect("server thread");
    }
}
