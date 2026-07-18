//! Kernel TLS (kTLS) support for zero-copy splice from TLS sockets.
//!
//! When kTLS RX is configured on a socket, the kernel decrypts incoming TLS
//! records transparently, allowing `splice(2)` to move plaintext data without
//! ever copying it to userspace.
//!
//! Setup pipeline (kernel-canonical order): [`attach_ulp`] right after
//! `connect(2)` → userspace TLS handshake (`TLS_BASE` passthrough) →
//! [`setup_rx`] with the extracted secrets → [`drain_control_messages`].
//!
//! # Security
//!
//! `setsockopt(SOL_TLS, TLS_RX)` copies the RX session key into kernel
//! memory for the socket's lifetime (this module configures RX only — see
//! [`setup_rx`] — and never TX). On kernels >= 5.10 the kernel allows reading
//! that key back via `getsockopt(SOL_TLS, TLS_RX)`, with no opt-out, so a
//! kTLS socket fd is a key-extraction capability until it is closed, to any
//! holder of that fd (or a ptrace-capable attacker).
//!
//! The userspace zeroization in this module ([`ZeroizingCryptoInfo`],
//! `SecureVec`-backed buffers, dropping rustls' `AeadKey`) defends only
//! against *memory disclosure* of key material transiently present in this
//! process — it does nothing about the kernel-held copy, which remains
//! readable via `getsockopt` regardless.
//!
//! What actually bounds the exposure is the one-shot design: kTLS sockets
//! are sent with `Connection: close` and are never returned to a connection
//! pool, so the kernel-held key — and the fd able to read it back — dies
//! with the socket at the end of a single transfer.

use std::io;
use std::io::IoSliceMut;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd};
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use nix::libc;
use nix::sys::socket::sockopt::TlsCryptoInfo;
use nix::sys::socket::{self, ControlMessageOwned, MsgFlags, SockaddrStorage, TlsGetRecordType};
use rustls::ConnectionTrafficSecrets;
use rustls::crypto::cipher::NONCE_LEN;
use tracing::{debug, info, warn};

use crate::error::errno_to_io_error;
use crate::{Never, static_assert, warn_once};

/// Overwrite every byte of a mutable POD value with zeros via `explicit_bzero`,
/// which the compiler is not permitted to elide.
///
/// # Safety
///
/// `val` must be a live, fully-initialised value whose entire byte span
/// (`size_of_val(val)` bytes starting at `val as *mut T`) is valid to
/// overwrite. This is trivially satisfied for any `&mut T` passed by the
/// caller where `T` contains no uninitialised bytes — all `libc` kTLS
/// crypto-info structs are plain C structs that meet this requirement.
unsafe fn zeroize_pod<T>(val: &mut T) {
    // SAFETY: Caller guarantees `val` is a live, initialised POD value.
    // `size_of_val` gives its exact byte span; `from_mut` yields a valid
    // non-null pointer to that span.
    unsafe {
        libc::explicit_bzero(
            core::ptr::from_mut(val).cast::<libc::c_void>(),
            size_of_val(val),
        );
    }
}

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
                // SAFETY: AES-128-GCM kTLS crypto-info is a live, initialised
                // POD struct; satisfies `zeroize_pod`'s safety contract.
                unsafe { zeroize_pod(d) }
            }
            TlsCryptoInfo::Aes256Gcm(d) => {
                // SAFETY: AES-256-GCM kTLS crypto-info is a live, initialised
                // POD struct; satisfies `zeroize_pod`'s safety contract.
                unsafe { zeroize_pod(d) }
            }
            TlsCryptoInfo::Chacha20Poly1305(d) => {
                // SAFETY: ChaCha20-Poly1305 kTLS crypto-info is a live,
                // initialised POD struct; satisfies `zeroize_pod`'s safety
                // contract.
                unsafe { zeroize_pod(d) }
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

/// Cached probe result: definitive outcomes (available / unavailable) are
/// latched for the process lifetime; probe *errors* are not, so a transient
/// startup failure (e.g. ephemeral-port exhaustion) does not permanently
/// disable kTLS.
const KTLS_PROBE_UNKNOWN: u8 = 0;
const KTLS_PROBE_AVAILABLE: u8 = 1;
const KTLS_PROBE_UNAVAILABLE: u8 = 2;

static KTLS_AVAILABLE: AtomicU8 = AtomicU8::new(KTLS_PROBE_UNKNOWN);

/// Bitmask of kernel-supported `(TLS version, cipher)` RX combos, indexed by
/// [`combo_bit`]. Populated by [`is_available`]'s probe *before*
/// [`KTLS_AVAILABLE`] latches AVAILABLE, and read by [`rx_supported`] to gate
/// `setup_rx`. A value of 0 means "never populated" — [`rx_supported`] then
/// defers to `setup_rx` so the gate can never make things worse.
static KTLS_RX_SUPPORT: AtomicU32 = AtomicU32::new(0);

/// The six `(TLS version, cipher)` combos the RX probe tests, with display
/// names for the support-summary log line. Kept as the single source of the
/// probe order and the combo naming.
const PROBE_COMBOS: [(u16, u16, &str); 6] = [
    (
        libc::TLS_1_2_VERSION,
        libc::TLS_CIPHER_AES_GCM_128,
        "TLSv1.2+AES-128-GCM",
    ),
    (
        libc::TLS_1_2_VERSION,
        libc::TLS_CIPHER_AES_GCM_256,
        "TLSv1.2+AES-256-GCM",
    ),
    (
        libc::TLS_1_2_VERSION,
        libc::TLS_CIPHER_CHACHA20_POLY1305,
        "TLSv1.2+ChaCha20-Poly1305",
    ),
    (
        libc::TLS_1_3_VERSION,
        libc::TLS_CIPHER_AES_GCM_128,
        "TLSv1.3+AES-128-GCM",
    ),
    (
        libc::TLS_1_3_VERSION,
        libc::TLS_CIPHER_AES_GCM_256,
        "TLSv1.3+AES-256-GCM",
    ),
    (
        libc::TLS_1_3_VERSION,
        libc::TLS_CIPHER_CHACHA20_POLY1305,
        "TLSv1.3+ChaCha20-Poly1305",
    ),
];

/// Map a kernel `(TLS version, cipher_type)` pair to its distinct bit index in
/// [`KTLS_RX_SUPPORT`], or `None` for an unrecognised version or cipher.
fn combo_bit(tls_version: u16, cipher_type: u16) -> Option<u8> {
    let version_index = if tls_version == libc::TLS_1_2_VERSION {
        0u8
    } else if tls_version == libc::TLS_1_3_VERSION {
        1u8
    } else {
        return None;
    };
    let cipher_index = if cipher_type == libc::TLS_CIPHER_AES_GCM_128 {
        0u8
    } else if cipher_type == libc::TLS_CIPHER_AES_GCM_256 {
        1u8
    } else if cipher_type == libc::TLS_CIPHER_CHACHA20_POLY1305 {
        2u8
    } else {
        return None;
    };
    Some(version_index * 3 + cipher_index)
}

/// Map a rustls `ConnectionTrafficSecrets` variant to its kernel `cipher_type`
/// constant, or `None` for a cipher kTLS does not support. Single source of the
/// secrets->cipher mapping shared by [`rx_supported`].
fn kernel_cipher_type(secrets: &ConnectionTrafficSecrets) -> Option<u16> {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { .. } => Some(libc::TLS_CIPHER_AES_GCM_128),
        ConnectionTrafficSecrets::Aes256Gcm { .. } => Some(libc::TLS_CIPHER_AES_GCM_256),
        ConnectionTrafficSecrets::Chacha20Poly1305 { .. } => {
            Some(libc::TLS_CIPHER_CHACHA20_POLY1305)
        }
        // ConnectionTrafficSecrets is #[non_exhaustive]; an unknown cipher is
        // simply not kTLS-capable here.
        _ => None,
    }
}

/// Build a shape-correct kTLS crypto-info struct with zeroed key material for
/// the availability probe. The kernel validates the version/cipher/struct
/// shape, not key content, so a zeroed struct is enough to test whether the
/// combo's `TLS_RX` setsockopt is accepted. `None` for an unknown cipher.
fn dummy_crypto_info(tls_version: u16, cipher_type: u16) -> Option<TlsCryptoInfo> {
    let info = libc::tls_crypto_info {
        version: tls_version,
        cipher_type,
    };
    if cipher_type == libc::TLS_CIPHER_AES_GCM_128 {
        Some(TlsCryptoInfo::Aes128Gcm(
            libc::tls12_crypto_info_aes_gcm_128 {
                info,
                iv: [0u8; 8],
                key: [0u8; 16],
                salt: [0u8; 4],
                rec_seq: [0u8; 8],
            },
        ))
    } else if cipher_type == libc::TLS_CIPHER_AES_GCM_256 {
        Some(TlsCryptoInfo::Aes256Gcm(
            libc::tls12_crypto_info_aes_gcm_256 {
                info,
                iv: [0u8; 8],
                key: [0u8; 32],
                salt: [0u8; 4],
                rec_seq: [0u8; 8],
            },
        ))
    } else if cipher_type == libc::TLS_CIPHER_CHACHA20_POLY1305 {
        Some(TlsCryptoInfo::Chacha20Poly1305(
            libc::tls12_crypto_info_chacha20_poly1305 {
                info,
                iv: [0u8; NONCE_LEN],
                salt: [],
                key: [0u8; 32],
                rec_seq: [0u8; 8],
            },
        ))
    } else {
        None
    }
}

/// Human-readable list of the supported combos in a [`KTLS_RX_SUPPORT`] mask,
/// for the support-summary log line.
fn describe_rx_support(mask: u32) -> String {
    PROBE_COMBOS
        .iter()
        .filter(|&&(version, cipher, _)| {
            combo_bit(version, cipher).is_some_and(|bit| mask & (1u32 << bit) != 0)
        })
        .map(|&(_, _, name)| name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Latch kTLS unavailable for the rest of the process; [`is_available`]
/// short-circuits to `false` from then on. Single owner of the
/// unavailable-latch store so every latch site is greppable.
fn latch_unavailable() {
    KTLS_AVAILABLE.store(KTLS_PROBE_UNAVAILABLE, Ordering::Relaxed);
}

/// Erroring probe attempts so far. Once `MAX_PROBE_ERRORS` is reached the
/// probe latches unavailable, bounding per-request probe work and log noise
/// on persistently broken environments.
static KTLS_PROBE_ERRORS: AtomicU32 = AtomicU32::new(0);

/// Probe kTLS availability by attempting to set the TLS ULP on a connected socket.
/// A definitive result (available / unavailable) is cached for the lifetime of
/// the process; an errored probe is retried on the next call, up to
/// `MAX_PROBE_ERRORS` attempts.
///
/// `TCP_ULP` requires a connected socket, so we create a loopback TCP pair
/// to test whether the kernel supports the `tls` ULP.
#[must_use]
pub(crate) fn is_available() -> bool {
    enum TestResult {
        /// ULP attach succeeded; the payload is the [`KTLS_RX_SUPPORT`] bitmask
        /// of combos whose `TLS_RX` setsockopt was accepted (0 = none).
        Available(u32),
        Unavailable,
        /// An error occurred during the test.
        /// A log message should have been emitted.
        Error,
    }

    fn inner() -> TestResult {
        use nix::sys::socket::{
            AddressFamily, Backlog, SockFlag, SockType, SockaddrIn, accept4, bind, connect,
            getsockname, listen, setsockopt, socket,
            sockopt::{TcpTlsRx, TcpUlp},
        };
        use std::os::fd::{FromRawFd as _, OwnedFd};

        let listener: OwnedFd = match socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        ) {
            Ok(fd) => fd,
            Err(err) => {
                warn!("kTLS: availability test: failed to create listener socket:  {err}");
                return TestResult::Error;
            }
        };

        let addr = SockaddrIn::new(127, 0, 0, 1, 0);
        if let Err(err) = bind(listener.as_raw_fd(), &addr) {
            warn!("kTLS: availability test: failed to bind socket:  {err}");
            return TestResult::Error;
        }

        if let Err(err) = listen(&listener, Backlog::new(1).expect("valid backlog value")) {
            warn!("kTLS: availability test: failed to listen on socket:  {err}");
            return TestResult::Error;
        }

        // Read back the assigned port
        let sockname: SockaddrIn = match getsockname(listener.as_raw_fd()) {
            Ok(s) => s,
            Err(err) => {
                warn!("kTLS: availability test: failed to get sockname:  {err}");
                return TestResult::Error;
            }
        };

        // Create a fresh connected loopback pair. TLS_RX can be set only once
        // per socket (EBUSY on the second set), so every combo probe needs its
        // own pair. The listener stays alive across all pairs.
        let make_pair = || -> nix::Result<(OwnedFd, OwnedFd)> {
            let client = socket(
                AddressFamily::Inet,
                SockType::Stream,
                SockFlag::SOCK_CLOEXEC,
                None,
            )?;
            connect(client.as_raw_fd(), &sockname)?;
            let server_raw = accept4(listener.as_raw_fd(), SockFlag::SOCK_CLOEXEC)?;
            // SAFETY: accept4 returned a valid fd that no other code owns; wrap
            // it immediately so it is closed on drop.
            let server = unsafe { OwnedFd::from_raw_fd(server_raw) };
            Ok((client, server))
        };

        // First pair: the ULP attach test (unchanged behavior).
        let (probe_client, probe_server) = match make_pair() {
            Ok(pair) => pair,
            Err(err) => {
                warn!("kTLS: availability test: failed to create loopback pair:  {err}");
                return TestResult::Error;
            }
        };
        match setsockopt(&probe_client, TcpUlp::default(), b"tls") {
            Ok(()) => {}
            Err(nix::errno::Errno::ENOENT) => return TestResult::Unavailable,
            Err(err) => {
                warn!("kTLS: availability test: failed to set TCP_ULP:  {err}");
                return TestResult::Error;
            }
        }
        drop((probe_client, probe_server));

        // The ULP is present. Probe each supported (version, cipher) combo on a
        // fresh pair to discover per-cipher/version kernel gaps up front,
        // instead of a wasted upstream request + a per-host block later.
        let mut mask: u32 = 0;
        for &(version, cipher, name) in &PROBE_COMBOS {
            let (client, _server) = match make_pair() {
                Ok(pair) => pair,
                Err(err) => {
                    warn!(
                        "kTLS: availability test: failed to create probe pair for {name}:  {err}"
                    );
                    return TestResult::Error;
                }
            };
            if let Err(err) = setsockopt(&client, TcpUlp::default(), b"tls") {
                warn!("kTLS: availability test: failed to attach ULP for {name}:  {err}");
                return TestResult::Error;
            }
            let (Some(bit), Some(crypto)) = (
                combo_bit(version, cipher),
                dummy_crypto_info(version, cipher),
            ) else {
                // PROBE_COMBOS entries always map; defensive skip only.
                continue;
            };
            match setsockopt(&client, TcpTlsRx, &crypto) {
                Ok(()) => mask |= 1u32 << bit,
                Err(errno) => {
                    debug!("kTLS: availability test: {name} TLS_RX unsupported:  {errno}");
                }
            }
        }

        TestResult::Available(mask)
    }

    /// Give up and latch unavailable after this many erroring probe attempts.
    const MAX_PROBE_ERRORS: u32 = 3;

    match KTLS_AVAILABLE.load(Ordering::Relaxed) {
        KTLS_PROBE_AVAILABLE => return true,
        KTLS_PROBE_UNAVAILABLE => return false,
        _ => {}
    }

    // Concurrent probes are benign: the loopback test is idempotent and both
    // callers store the same definitive outcome.
    match inner() {
        TestResult::Available(mask) => {
            if mask == 0 {
                // ULP present but no cipher/version combo has a usable TLS_RX
                // (e.g. 4.13-4.16 kernels with no RX support at all).
                info!(
                    "kTLS: kernel TLS ULP present but TLS_RX unusable for every supported cipher"
                );
                latch_unavailable();
                return false;
            }
            // The Release store of KTLS_AVAILABLE below is paired with the
            // Acquire load in rx_supported, so a thread observing AVAILABLE
            // also observes the fully-published matrix.
            KTLS_RX_SUPPORT.store(mask, Ordering::Relaxed);
            info!(
                "kTLS: kernel TLS support detected (RX ciphers: {})",
                describe_rx_support(mask)
            );
            KTLS_AVAILABLE.store(KTLS_PROBE_AVAILABLE, Ordering::Release);
            true
        }
        TestResult::Unavailable => {
            info!("kTLS: kernel TLS not available (modprobe tls?)");
            latch_unavailable();
            false
        }
        TestResult::Error => {
            // A log message was emitted by inner(). Do not latch: the error
            // may be transient and the next call retries the probe.
            let errors = KTLS_PROBE_ERRORS.fetch_add(1, Ordering::Relaxed) + 1;
            if errors >= MAX_PROBE_ERRORS {
                warn!(
                    "kTLS: availability probe failed {errors} times; disabling kTLS for this run"
                );
                latch_unavailable();
            }
            false
        }
    }
}

/// Whether this kernel's `TLS_RX` accepts the given TLS version + cipher,
/// according to the matrix built by [`is_available`]'s probe.
///
/// The gate in `splice_conn.rs` calls this before `setup_rx` so an unsupported
/// combo fails fast (deterministic `KtlsSetupFailed`) instead of wasting a full
/// upstream request. An unknown version/cipher returns `false`. If the matrix
/// isn't published yet (not AVAILABLE), or was never populated (mask 0 —
/// should not happen once AVAILABLE), this returns `true` and lets `setup_rx`
/// decide, so the gate can never make things worse.
pub(crate) fn rx_supported(
    version: rustls::ProtocolVersion,
    secrets: &ConnectionTrafficSecrets,
) -> bool {
    let Ok(tls_version) = resolve_tls_version(version) else {
        return false;
    };
    let Some(cipher_type) = kernel_cipher_type(secrets) else {
        return false;
    };
    let Some(bit) = combo_bit(tls_version, cipher_type) else {
        return false;
    };
    // Acquire-paired with the Release store in is_available: observing
    // AVAILABLE here guarantees the matrix below is fully published.
    if KTLS_AVAILABLE.load(Ordering::Acquire) != KTLS_PROBE_AVAILABLE {
        return true;
    }
    let mask = KTLS_RX_SUPPORT.load(Ordering::Relaxed);
    if mask == 0 {
        return true;
    }
    mask & (1u32 << bit) != 0
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
        | rustls::ProtocolVersion::DTLSv1_3 => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("kTLS: unsupported TLS protocol version {version:#x?}"),
        )),
        rustls::ProtocolVersion::Unknown(_) => Err(io::Error::new(
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
/// The caller must ensure `fd` is a valid TCP socket with the TLS ULP
/// already attached (via [`attach_ulp`]) and that the TLS secrets correspond
/// to the current connection state.
///
/// Unlike the ULP attach, the kernel's `TLS_RX` setsockopt has **no**
/// `TCP_ESTABLISHED` check: it succeeds on a `CLOSE_WAIT` socket, and
/// ciphertext queued before or after the peer's FIN stays decryptable. This
/// is what makes the attach-at-connect order robust against upstreams that
/// honor `Connection: close` aggressively.
///
/// For TLS 1.3, once `TLS_RX` is set this also best-effort enables
/// `TLS_RX_EXPECT_NO_PAD` (see [`enable_rx_expect_no_pad`]) — a kernel >= 6.0
/// speculative-decrypt fast path. Failure there is non-fatal.
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

    if version == rustls::ProtocolVersion::TLSv1_3 {
        enable_rx_expect_no_pad(fd);
    }

    Ok(())
}

/// Best-effort: authorize the kernel's TLS 1.3 speculative "no padding"
/// decrypt fast path (`setsockopt(SOL_TLS, TLS_RX_EXPECT_NO_PAD, 1)`,
/// kernel >= 6.0), letting it decrypt directly into the final destination
/// without a padding scan.
///
/// Per <https://docs.kernel.org/networking/tls.html>: "If the record
/// decrypted turns out to had been padded or is not a data record it will be
/// decrypted again into a kernel buffer without zero copy." — a padded
/// record after this is set is transparently re-decrypted with no
/// user-visible error (counted in the `TlsDecryptRetry` /
/// `TlsRxNoPadViolation` stats), so enabling this is correctness-safe.
///
/// Older kernels reject the option (`ENOPROTOOPT`/`EINVAL`); that failure is
/// non-fatal, this is a pure optimization.
fn enable_rx_expect_no_pad<F: AsFd>(fd: &F) {
    let value: libc::c_int = 1;
    let value_len =
        libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("c_int size fits socklen_t");

    // SAFETY: `fd` is a valid open socket for the lifetime of this call
    // (borrowed via `AsFd`); `value` is a live `c_int` and `value_len` is its
    // exact byte size, passed together and correctly to `setsockopt(2)`.
    let ret = unsafe {
        libc::setsockopt(
            fd.as_fd().as_raw_fd(),
            libc::SOL_TLS,
            libc::TLS_RX_EXPECT_NO_PAD,
            std::ptr::from_ref(&value).cast::<libc::c_void>(),
            value_len,
        )
    };

    if ret != 0 {
        let errno = nix::errno::Errno::last();
        debug!("kTLS: TLS_RX_EXPECT_NO_PAD not supported (kernel < 6.0):  {errno}");
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Classified failure of [`attach_ulp`].
///
/// Classification happens here because [`errno_to_io_error`] wraps the errno
/// in a custom payload; callers cannot recover it via `raw_os_error()`.
#[derive(Debug)]
pub(crate) enum UlpAttachError {
    /// `ENOENT` (kernel tls module gone — the availability probe should have
    /// caught this) or `EPERM` (an LSM policy denying the ULP attach, which is
    /// process-wide, not per-host). The global availability latch has already
    /// been flipped to unavailable by [`attach_ulp`], so this fires at most
    /// once per process.
    Unavailable(io::Error),
    /// `ENOTCONN` — the socket left `TCP_ESTABLISHED` between `connect(2)`
    /// and the attach (peer FIN/RST raced the connect). Transient.
    Transient(io::Error),
    /// Any other errno. Persistent (per-host block only).
    Persistent(io::Error),
}

/// Attach the TLS Upper Layer Protocol to the socket.
///
/// Call this immediately after `connect(2)` succeeds, **before any bytes are
/// exchanged** — the kernel-canonical order (Documentation/networking/tls.rst;
/// OpenSSL attaches at BIO creation). `TCP_ULP` requires `TCP_ESTABLISHED`;
/// attaching after the handshake races the upstream's FIN (a `Connection:
/// close` response moves the socket to `CLOSE_WAIT`, rejected with
/// `ENOTCONN`). With the ULP attached but no crypto configured the kernel
/// context is in `TLS_BASE` mode: `sendmsg`/`recvmsg` pass through to TCP
/// unchanged, so the userspace TLS handshake runs unmodified.
///
/// The attach is irrevocable: the socket must never be pooled or reused for
/// plaintext protocols afterwards.
///
/// # Required call order
///
/// 1. [`attach_ulp`] — attach TLS ULP right after connect (this function)
/// 2. userspace TLS handshake (`TLS_BASE` passthrough)
/// 3. [`setup_rx`] — configure crypto keys
/// 4. [`drain_control_messages`] — consume non-data TLS records
///
/// Calling `setup_rx` without the ULP attached fails with `ENOPROTOOPT`.
/// Calling `drain_control_messages` before `setup_rx` has undefined results.
pub(crate) fn attach_ulp<F: AsFd>(fd: &F) -> Result<(), UlpAttachError> {
    // No logging here: the caller logs the returned error (with host context)
    // and decides between transient fallback and a kTLS block for the mirror.
    match nix::sys::socket::setsockopt(fd, nix::sys::socket::sockopt::TcpUlp::default(), b"tls") {
        Ok(()) => Ok(()),
        Err(errno) => {
            let err = errno_to_io_error(errno, "kTLS: setsockopt TLS ULP failed");
            Err(
                if errno == nix::errno::Errno::ENOENT || errno == nix::errno::Errno::EPERM {
                    // EPERM is almost certainly an LSM denying the ULP attach
                    // process-wide; latch unavailable rather than block per host.
                    latch_unavailable();
                    UlpAttachError::Unavailable(err)
                } else if errno == nix::errno::Errno::ENOTCONN {
                    UlpAttachError::Transient(err)
                } else {
                    UlpAttachError::Persistent(err)
                },
            )
        }
    }
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
        // setup_rx() will return Err for unsupported ciphers before we reach here.
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

/// What `drain_control_messages` should do with a peeked TLS record.
/// Pure function of the record type; the cmsg-truncation case
/// (`MSG_CTRUNC`) is handled separately because it indicates the
/// record-type cmsg itself could not be trusted.
#[derive(Debug, PartialEq, Eq)]
enum DrainAction {
    /// `ApplicationData` reached (or no record-type cmsg returned with the
    /// cmsg buffer intact) -- the drain is complete.
    Done,
    /// Expected post-handshake control message (`NewSessionTicket`,
    /// `KeyUpdate`); consume silently and continue the drain loop.
    ConsumeHandshake,
    /// Post-handshake `ChangeCipherSpec`. RFC 8446 section 5 only tolerates
    /// CCS during the handshake; `drain_control_messages` runs only after
    /// the handshake completes, so this can only mean an attacker-crafted
    /// record or a TLS 1.2 renegotiation attempt (rustls does not support
    /// renegotiation). Fail-closed, record left on the socket.
    AbortChangeCipherSpec,
    /// TLS `Alert` record. Could be a fatal alert (`bad_record_mac`,
    /// `handshake_failure`); we cannot inspect severity from the cmsg
    /// alone. Fail-closed so the caller falls back to userspace TLS,
    /// which can decrypt the payload and react properly.
    AbortAlert,
    /// Unrecognised TLS record type. Kernel parser anomaly, server
    /// protocol violation, or future TLS extension we don't know about.
    /// Fail-closed.
    AbortUnknown,
}

fn classify_drain_action(record_type: Option<TlsGetRecordType>) -> DrainAction {
    // TODO: static_assert!(std::mem::variant_count::<TlsGetRecordType>() == 5);
    match record_type {
        Some(TlsGetRecordType::ApplicationData) | None => DrainAction::Done,
        Some(TlsGetRecordType::Handshake) => DrainAction::ConsumeHandshake,
        Some(TlsGetRecordType::ChangeCipherSpec) => DrainAction::AbortChangeCipherSpec,
        Some(TlsGetRecordType::Alert) => DrainAction::AbortAlert,
        // Catches both TlsGetRecordType::Unknown(_) (unrecognised numeric
        // record types) and any future nix variants added after this code
        // was written (TlsGetRecordType is #[non_exhaustive]).
        Some(_) => DrainAction::AbortUnknown,
    }
}

/// TLS `Alert` record fields (RFC 8446 section 6): a 2-byte payload of
/// `[AlertLevel, AlertDescription]`. `close_notify` is the peer's clean
/// end-of-stream signal at warning level.
const TLS_ALERT_LEVEL_WARNING: u8 = 1;
const TLS_ALERT_DESC_CLOSE_NOTIFY: u8 = 0;

/// Whether a peeked alert payload is a clean warning-level `close_notify` that
/// the given drain context may treat as end-of-stream instead of failing
/// closed.
///
/// Only the post-`setup_rx` [`DrainExpect::MaybeIdle`] drain accepts it: there,
/// the alert being frontmost proves all application data was already consumed
/// into `extra_body` (kTLS delivers records in order), so a clean close is the
/// expected end, not a fault. The [`DrainExpect::DataReady`] splice-loop drain
/// still fails closed -- a `close_notify` seen there means the peer closed
/// *before* delivering data we polled for (truncation), which must surface as
/// an error. Fatal alerts (level 2) and non-`close_notify` warnings never match.
fn alert_is_clean_close(expect: DrainExpect, payload: &[u8]) -> bool {
    expect == DrainExpect::MaybeIdle
        && matches!(
            payload,
            [TLS_ALERT_LEVEL_WARNING, TLS_ALERT_DESC_CLOSE_NOTIFY]
        )
}

/// Whether a TLS Handshake record payload contains a `KeyUpdate` message.
///
/// Walks the handshake-message framing (1-byte type + 3-byte big-endian
/// length) covering the case where the kernel coalesced several
/// consecutive handshake records (e.g. `NewSessionTicket`s) into one
/// delivery. Stops without error on a truncated tail (a fragmented
/// message continues in the next record); detection is best-effort by
/// design -- an undetected `KeyUpdate` still fails later as EBADMSG.
fn handshake_contains_key_update(payload: &[u8]) -> bool {
    /// RFC 8446 `HandshakeType.key_update`.
    const HANDSHAKE_TYPE_KEY_UPDATE: u8 = 24;

    let mut rest = payload;
    while let [msg_type, len_hi, len_mid, len_lo, tail @ ..] = rest {
        if *msg_type == HANDSHAKE_TYPE_KEY_UPDATE {
            return true;
        }
        let len = u32::from_be_bytes([0, *len_hi, *len_mid, *len_lo]) as usize;
        let Some(remainder) = tail.get(len..) else {
            return false;
        };
        rest = remainder;
    }
    false
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
/// Release-mode fail-closed checks on the peeked vs. consumed `recvmsg` result detect
/// violations of that invariant.
///
/// # Kernel record atomicity
///
/// `TLS-ULP` in the Linux kernel never mixes record *types* within a single
/// `recvmsg()` delivery (`net/tls/tls_sw.c: tls_sw_recvmsg`): the record-type
/// cmsg always describes the type of every byte returned via `msg_iov` for
/// that call. It may, however, coalesce multiple *consecutive same-type*
/// records (e.g. a burst of `NewSessionTicket`s) into one delivery. A partial
/// record cannot be surfaced to userspace — the kernel blocks (or returns
/// `EAGAIN` in non-blocking mode) until a full record has been decrypted.
/// This is what makes the peek-then-consume pattern sound: the consume
/// `recvmsg` sees the same record-type cmsg as the peek, not a stale type
/// from a record that was only partially in the kernel buffer during the
/// peek, and both calls see the same coalescing horizon. The `MSG_CTRUNC`
/// check below additionally defends against kernel-side cmsg-buffer
/// insufficiency rather than wire-level partial records.
pub(crate) fn drain_control_messages(fd: BorrowedFd<'_>, expect: DrainExpect) -> io::Result<()> {
    // Buffer for the record payload. 0x4001 (16385) holds the largest legal
    // record payload (16384 bytes) plus slack, so a whole record is
    // peeked/consumed in one recvmsg() call and the peek/consume pair stays
    // symmetric.
    /// Cap on consumed control records per drain. Real servers send a small
    /// burst of post-handshake messages (rustls-facing servers emit at most
    /// ~4 `NewSessionTicket`s); a peer streaming control records without end
    /// would otherwise pin a worker in this loop at network rate.
    const MAX_DRAIN_RECORDS: u32 = 16;

    #[expect(clippy::large_stack_arrays, reason = "must fit full TLS record")]
    let mut buf = [0u8; 0x4001];

    let mut first_iteration = true;
    let mut consumed_records = 0u32;

    // cmsg buffers are allocated once and zero-filled before every recvmsg so
    // stale bytes from a previous call cannot influence extract_record_type()
    // if the kernel writes fewer bytes.
    let mut cmsg_buf = nix::cmsg_space!(TlsGetRecordType);
    let mut consume_cmsg = nix::cmsg_space!(TlsGetRecordType);

    loop {
        let mut iov = [IoSliceMut::new(&mut buf)];
        cmsg_buf.fill(0);

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
                warn!("kTLS: oversized TLS record from peer (EMSGSIZE); aborting kTLS setup");
                return Err(errno_to_io_error(
                    nix::errno::Errno::EMSGSIZE,
                    "kTLS: recvmsg peek EMSGSIZE (oversized record)",
                ));
            }
            Err(errno) => {
                debug!("kTLS: drain peek error:  {errno}");
                return Err(errno_to_io_error(errno, "kTLS: recvmsg peek failed"));
            }
        };

        first_iteration = false;

        let record_type = match extract_record_type(&recv) {
            Ok(rt) => rt,
            Err(err) => {
                warn!("kTLS: drain peek cmsg decode failed; aborting kTLS setup:  {err}");
                return Err(err);
            }
        };
        let peeked_bytes = recv.bytes;
        let flags = recv.flags;
        debug!("kTLS: peeked {peeked_bytes} bytes, record_type={record_type:?}, flags={flags:?}");

        // MSG_CTRUNC is orthogonal to record-type classification: it
        // indicates the cmsg buffer was truncated, so we cannot trust
        // record_type even when present. Fail closed whenever the flag is
        // set rather than letting a possibly-stale ApplicationData type
        // pass through classify_drain_action as safe.
        if flags.contains(MsgFlags::MSG_CTRUNC) {
            warn!("kTLS: cmsg buffer truncated (record_type={record_type:?}); aborting kTLS setup");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kTLS: cmsg buffer truncated",
            ));
        }

        let rt_to_consume = match classify_drain_action(record_type) {
            DrainAction::Done => return Ok(()),
            DrainAction::AbortAlert => {
                if alert_is_clean_close(expect, buf.get(..peeked_bytes).unwrap_or_default()) {
                    // Peer's clean end-of-stream. All application data already
                    // sits in extra_body (this alert is frontmost, so no data
                    // records precede it); serve that and let the connection
                    // drop with the alert unread. A short body is still caught
                    // downstream by the Content-Length check, same as any
                    // truncated response.
                    debug!(
                        "kTLS: peer sent warning close_notify during post-setup drain \
                         ({peeked_bytes} bytes); treating as clean end-of-stream"
                    );
                    return Ok(());
                }
                warn!(
                    "kTLS: peeked TLS Alert record ({peeked_bytes} bytes, left on socket); \
                     aborting kTLS setup so userspace TLS can read and decode it"
                );
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "kTLS: alert in drain",
                ));
            }
            DrainAction::AbortUnknown => {
                warn!(
                    "kTLS: peeked unknown TLS record ({peeked_bytes} bytes, \
                     record_type={record_type:?}, left on socket); aborting kTLS setup"
                );
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "kTLS: unknown record type in drain",
                ));
            }
            DrainAction::AbortChangeCipherSpec => {
                warn!(
                    "kTLS: peeked post-handshake ChangeCipherSpec record ({peeked_bytes} bytes, \
                     left on socket); aborting kTLS setup"
                );
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "kTLS: post-handshake ChangeCipherSpec",
                ));
            }
            DrainAction::ConsumeHandshake => TlsGetRecordType::Handshake,
        };

        // A TLS 1.3 KeyUpdate arrives as a generic Handshake control
        // record. Rekey is impossible in this design (rustls has been
        // consumed; the traffic secret needed to derive the next key was
        // handed to the kernel), so detect it here and abort immediately
        // with a clear error rather than let every later record fail with
        // sticky EBADMSG.
        if handshake_contains_key_update(&buf[..peeked_bytes]) {
            warn!(
                "kTLS: peer sent KeyUpdate ({peeked_bytes} bytes, left on socket); \
                 kernel TLS cannot rekey; aborting kTLS setup"
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kTLS: peer sent KeyUpdate",
            ));
        }

        consumed_records += 1;
        if consumed_records > MAX_DRAIN_RECORDS {
            warn!(
                "kTLS: more than {MAX_DRAIN_RECORDS} control records queued without \
                 reaching application data; aborting kTLS setup"
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kTLS: too many control records in drain",
            ));
        }

        // Consume the peeked record (no MSG_PEEK). Retry tightly on EINTR
        // to avoid restarting the outer peek cycle for a record we already
        // identified.
        loop {
            let mut consume_iov = [IoSliceMut::new(&mut buf)];
            consume_cmsg.fill(0);
            let _: Never = match socket::recvmsg::<SockaddrStorage>(
                fd.as_raw_fd(),
                &mut consume_iov,
                Some(&mut consume_cmsg),
                MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(msg) => {
                    // A truncated cmsg buffer means the control data (and thus
                    // the record type read from it below) cannot be trusted;
                    // check this before anything else that relies on it.
                    if msg.flags.contains(MsgFlags::MSG_CTRUNC) {
                        warn!(
                            "kTLS: cmsg buffer truncated on consume ({} bytes); aborting \
                             kTLS setup",
                            msg.bytes
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "kTLS: cmsg buffer truncated on consume",
                        ));
                    }
                    // Fewer bytes than peeked means a concurrent consumer took
                    // part of the record between peek and consume -- the
                    // sole-consumer invariant broke. (Strictly `<`, not `!=`:
                    // MORE bytes than peeked is legal when an additional
                    // same-type record was coalesced in between the two calls.)
                    if msg.bytes < peeked_bytes {
                        warn!(
                            "kTLS: consumed {} bytes, but peeked {peeked_bytes} -- \
                             concurrent reader on kTLS socket?; aborting kTLS setup",
                            msg.bytes
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "kTLS: consumed fewer bytes than peeked",
                        ));
                    }
                    let consumed_rt = match extract_record_type(&msg) {
                        Ok(rt) => rt,
                        Err(err) => {
                            warn!(
                                "kTLS: drain consume cmsg decode failed; aborting kTLS setup:  {err}"
                            );
                            return Err(err);
                        }
                    };
                    // Record-type mismatch between peek and consume means a
                    // concurrent reader interleaved with us -- the
                    // sole-consumer invariant broke.
                    if consumed_rt != Some(rt_to_consume) {
                        warn!(
                            "kTLS: consumed record type {consumed_rt:?} differs from peeked \
                             {rt_to_consume:?} -- concurrent reader on kTLS socket?; aborting \
                             kTLS setup"
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "kTLS: consumed record type {consumed_rt:?} differs from \
                                 peeked {rt_to_consume:?}"
                            ),
                        ));
                    }
                    let consumed_bytes = msg.bytes;
                    // The consume recvmsg can coalesce in a KeyUpdate record
                    // that arrived after the peek; check the payload we just
                    // consumed too. The record is already off the socket, but
                    // the connection is doomed anyway (kernel TLS cannot
                    // rekey), so abort here as well.
                    if handshake_contains_key_update(&buf[..consumed_bytes]) {
                        warn!(
                            "kTLS: consumed control record contained KeyUpdate \
                             ({consumed_bytes} bytes); kernel TLS cannot rekey; \
                             aborting kTLS setup"
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "kTLS: peer sent KeyUpdate",
                        ));
                    }
                    debug!(
                        "kTLS: consumed control message ({consumed_bytes} bytes, type={rt_to_consume:?})",
                    );
                    break;
                }
                Err(nix::errno::Errno::EAGAIN) => {
                    // EAGAIN after a successful peek means the record
                    // was consumed between the peek and the consume --
                    // leaving an unconsumed non-data record queued would
                    // desync kTLS. Fail closed so the caller falls back to
                    // userspace TLS instead of corrupting the stream.
                    warn!(
                        "kTLS: drain consume got EAGAIN after successful peek \
                         ({peeked_bytes} bytes, type={rt_to_consume:?}); aborting kTLS setup"
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "kTLS: drain consume EAGAIN after peek",
                    ));
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(errno) => {
                    debug!(
                        "kTLS: drain consume error (peeked {peeked_bytes} bytes, type={rt_to_consume:?}):  {errno}"
                    );
                    return Err(errno_to_io_error(errno, "kTLS: drain consume error"));
                }
            };
        }
    }
}

/// Extract the `TlsGetRecordType` from a `recvmsg()` result's control messages.
///
/// Returns `Ok(None)` when the cmsg buffer decodes cleanly but carries no
/// record-type entry (the kernel's signal for plain application data). A cmsg
/// *decode* error is surfaced as `Err` so callers fail closed instead of
/// misclassifying an undecodable record as application data.
fn extract_record_type(
    recv: &socket::RecvMsg<'_, '_, SockaddrStorage>,
) -> io::Result<Option<TlsGetRecordType>> {
    let cmsgs = recv
        .cmsgs()
        .map_err(|errno| errno_to_io_error(errno, "kTLS: cmsg decode failed"))?;
    for cmsg in cmsgs {
        if let ControlMessageOwned::TlsGetRecordType(rt) = cmsg {
            return Ok(Some(rt));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Barrier};
    use std::thread::JoinHandle;

    #[test]
    fn classify_drain_action_application_data_is_done() {
        assert_eq!(
            classify_drain_action(Some(TlsGetRecordType::ApplicationData)),
            DrainAction::Done,
        );
    }

    #[test]
    fn classify_drain_action_missing_cmsg_is_done() {
        // No record-type cmsg means the cmsg buffer came back intact with
        // no TlsGetRecordType entry — treat as ApplicationData (drain
        // complete) rather than failing closed.
        assert_eq!(classify_drain_action(None), DrainAction::Done);
    }

    #[test]
    fn classify_drain_action_handshake_consumes() {
        assert_eq!(
            classify_drain_action(Some(TlsGetRecordType::Handshake)),
            DrainAction::ConsumeHandshake,
        );
    }

    #[test]
    fn classify_drain_action_change_cipher_spec_aborts() {
        assert_eq!(
            classify_drain_action(Some(TlsGetRecordType::ChangeCipherSpec)),
            DrainAction::AbortChangeCipherSpec,
        );
    }

    #[test]
    fn classify_drain_action_alert_aborts() {
        assert_eq!(
            classify_drain_action(Some(TlsGetRecordType::Alert)),
            DrainAction::AbortAlert,
        );
    }

    #[test]
    fn classify_drain_action_unknown_aborts() {
        // Both the explicit Unknown(_) variant (recognised numeric type
        // outside the four named cases) and any future #[non_exhaustive]
        // variant must take the fail-closed path.
        assert_eq!(
            classify_drain_action(Some(TlsGetRecordType::Unknown(99))),
            DrainAction::AbortUnknown,
        );
    }

    #[test]
    fn alert_clean_close_only_close_notify_in_maybe_idle() {
        // Warning close_notify in the post-setup drain: the one accepted case.
        assert!(alert_is_clean_close(DrainExpect::MaybeIdle, &[1, 0]));
        // Same alert in the data-ready splice-loop drain must still abort so a
        // mid-stream truncation surfaces as an error.
        assert!(!alert_is_clean_close(DrainExpect::DataReady, &[1, 0]));
        // Fatal alerts (level 2) must reach userspace TLS, even a fatal record
        // carrying the close_notify description byte.
        assert!(!alert_is_clean_close(DrainExpect::MaybeIdle, &[2, 0]));
        // Warning-level but not close_notify (e.g. user_canceled = 90).
        assert!(!alert_is_clean_close(DrainExpect::MaybeIdle, &[1, 90]));
        // Malformed payload lengths never match the exact 2-byte pattern.
        assert!(!alert_is_clean_close(DrainExpect::MaybeIdle, &[]));
        assert!(!alert_is_clean_close(DrainExpect::MaybeIdle, &[1]));
        assert!(!alert_is_clean_close(DrainExpect::MaybeIdle, &[1, 0, 0]));
    }

    #[test]
    fn handshake_contains_key_update_lone_message() {
        // type=24 (key_update), len=1, body=[0] (key_update_requested).
        assert!(handshake_contains_key_update(&[24, 0, 0, 1, 0]));
    }

    #[test]
    fn handshake_contains_key_update_new_session_ticket_only() {
        // type=4 (new_session_ticket), len=2, body=[0xAA, 0xBB].
        assert!(!handshake_contains_key_update(&[4, 0, 0, 2, 0xAA, 0xBB]));
    }

    #[test]
    fn handshake_contains_key_update_coalesced_after_new_session_ticket() {
        // A NewSessionTicket followed by a KeyUpdate coalesced into one
        // recvmsg delivery -- the KeyUpdate must still be found.
        let mut payload = vec![4, 0, 0, 2, 0xAA, 0xBB];
        payload.extend_from_slice(&[24, 0, 0, 1, 0]);
        assert!(handshake_contains_key_update(&payload));
    }

    #[test]
    fn handshake_contains_key_update_truncated_tail_is_false() {
        // Header claims a 10-byte body but only 1 byte follows -- a
        // fragmented message continuing in the next record, not an error.
        assert!(!handshake_contains_key_update(&[4, 0, 0, 10, 0xAA]));
    }

    #[test]
    fn handshake_contains_key_update_empty_payload_is_false() {
        assert!(!handshake_contains_key_update(&[]));
    }

    #[test]
    fn handshake_contains_key_update_short_of_header_is_false() {
        // Fewer than 4 bytes: not enough for even the message header.
        assert!(!handshake_contains_key_update(&[24, 0, 0]));
    }

    #[test]
    fn combo_bit_maps_all_six_combos_to_distinct_bits() {
        let bits: Vec<u8> = PROBE_COMBOS
            .iter()
            .map(|&(version, cipher, _)| {
                combo_bit(version, cipher).expect("PROBE_COMBOS entry must map to a bit")
            })
            .collect();
        assert_eq!(bits.len(), 6, "there must be six probe combos");
        for &bit in &bits {
            assert!(bit < 6, "bit {bit} out of the 0..6 range");
        }
        for i in 0..bits.len() {
            for j in (i + 1)..bits.len() {
                assert_ne!(
                    bits[i], bits[j],
                    "combos {i} and {j} collide on bit {}",
                    bits[i]
                );
            }
        }
    }

    #[test]
    fn combo_bit_unknown_cipher_or_version_is_none() {
        // 0 is not a valid kernel cipher_type constant.
        assert_eq!(combo_bit(libc::TLS_1_3_VERSION, 0), None);
        // 0 is not a valid kernel TLS version constant.
        assert_eq!(combo_bit(0, libc::TLS_CIPHER_AES_GCM_128), None);
    }

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

    /// Build a matching server/client TLS config pair for loopback tests,
    /// with secret extraction enabled on the client.
    fn build_tls_configs(
        tls_versions: &[&'static rustls::SupportedProtocolVersion],
        cipher_suite_filter: Option<&[rustls::SupportedCipherSuite]>,
    ) -> (std::sync::Arc<rustls::ServerConfig>, rustls::ClientConfig) {
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

        (server_config, client_config)
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
        let (server_config, client_config) = build_tls_configs(tls_versions, cipher_suite_filter);

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
        // Attach the ULP before the handshake, mirroring production: the
        // kernel context is TLS_BASE passthrough until setup_rx, so the
        // buffered complete_io handshake below is unaffected.
        attach_ulp(&tcp_client).expect("attach_ulp");
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

        // rx_supported must predict the setup_rx outcome: the probe reported
        // this combo usable, and setup_rx below proves it. Asserting both here
        // pins the gate and the probe to the same truth.
        assert!(
            rx_supported(version, rx_secrets),
            "rx_supported must agree with setup_rx for {} {version:?}",
            secret_name(rx_secrets)
        );

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

    /// Regression test for the FIN-before-setup shape: the server writes its
    /// data, sends `close_notify`, and closes the connection before the
    /// client configures kTLS RX — modelling an upstream that honors
    /// `Connection: close` aggressively. With the ULP attached at connect
    /// time, `setup_rx` succeeds on the `CLOSE_WAIT` socket and the queued
    /// records stay decryptable. Under the old post-handshake attach order
    /// the `TCP_ULP` setsockopt at this point failed with `ENOTCONN`.
    #[expect(
        clippy::print_stderr,
        reason = "skip message when the kernel lacks the tls module"
    )]
    fn run_ktls_setup_rx_after_server_fin(
        tls_versions: &[&'static rustls::SupportedProtocolVersion],
    ) {
        if !is_available() {
            eprintln!("kTLS not available, skipping");
            return;
        }

        let plaintext_msg = b"kTLS after FIN: data queued before setup_rx";

        let (server_config, client_config) = build_tls_configs(tls_versions, None);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let start_barrier = Arc::new(Barrier::new(2));
        let server_start_barrier = Arc::clone(&start_barrier);

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
            stream.write_all(plaintext_msg).expect("write plaintext");
            stream.flush().expect("flush");
            server_conn.send_close_notify();
            server_conn
                .write_tls(&mut &tcp_server)
                .expect("write close_notify");
            // tcp_server drops on return -> FIN.
        });

        let mut tcp_client = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
        attach_ulp(&tcp_client).expect("attach_ulp");
        let server_name =
            rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let mut client_conn =
            rustls::ClientConnection::new(std::sync::Arc::new(client_config), server_name)
                .expect("client conn");
        let mut tcp_ref: &TcpStream = &tcp_client;
        while client_conn.is_handshaking() {
            client_conn.complete_io(&mut tcp_ref).expect("handshake io");
        }

        // Let the server write everything and exit; joining guarantees its
        // FIN is on the wire before kTLS RX is configured.
        start_barrier.wait();
        server_handle.join().expect("server thread");

        // Wait until the kernel has processed the FIN: POLLRDHUP is only
        // reported once the peer's shutdown reached this socket, making
        // "socket is in CLOSE_WAIT" deterministic rather than sleep-based.
        // nix 0.31 does not expose POLLRDHUP, so use the raw libc poll.
        let mut pfd = nix::libc::pollfd {
            fd: tcp_client.as_raw_fd(),
            events: nix::libc::POLLIN | nix::libc::POLLRDHUP,
            revents: 0,
        };
        // SAFETY: `pfd` is a valid pollfd for an open socket, nfds is 1.
        let nready = unsafe { nix::libc::poll(&raw mut pfd, 1, 5000) };
        assert_eq!(nready, 1, "expected socket readable after server exit");
        assert!(
            pfd.revents & nix::libc::POLLRDHUP != 0,
            "expected POLLRDHUP after server FIN, got {:#x}",
            pfd.revents
        );

        // The regression assertion: configuring RX on the CLOSE_WAIT socket
        // must succeed (the ULP is already attached).
        let version = client_conn.protocol_version().expect("protocol version");
        let secrets = client_conn
            .dangerous_extract_secrets()
            .expect("extract secrets");
        let (rx_seq, ref rx_secrets) = secrets.rx;
        setup_rx(&tcp_client, rx_seq, rx_secrets, version).expect("setup_rx on CLOSE_WAIT socket");

        // Data is provably queued (POLLIN above), so DataReady is correct.
        drain_control_messages(tcp_client.as_fd(), DrainExpect::DataReady)
            .expect("drain control messages");

        let mut buf = [0u8; 1024];
        let n = tcp_client.read(&mut buf).expect("read from kTLS socket");
        assert_eq!(
            &buf[..n],
            plaintext_msg,
            "kTLS should decrypt data queued before the FIN"
        );
        // Do not read past the payload: the queued close_notify alert
        // surfaces as EIO on a plain kTLS read; alert semantics are out of
        // scope here.
    }

    /// `setup_rx` succeeds after the server's FIN with TLS 1.2.
    #[test]
    fn test_ktls_setup_rx_after_server_fin_tls12() {
        run_ktls_setup_rx_after_server_fin(&[&rustls::version::TLS12]);
    }

    /// `setup_rx` succeeds after the server's FIN with TLS 1.3 (the queued
    /// `NewSessionTicket`s are drained as control records first).
    #[test]
    fn test_ktls_setup_rx_after_server_fin_tls13() {
        run_ktls_setup_rx_after_server_fin(&[&rustls::version::TLS13]);
    }

    /// A warning-level `close_notify` at the head of the kTLS receive queue is
    /// the peer's clean end-of-stream, not a fault. The post-setup `MaybeIdle`
    /// drain must accept it (so kTLS setup completes and the already-buffered
    /// body is served instead of forcing a userspace-TLS refetch), while the
    /// mid-stream `DataReady` drain must still fail closed so a truncated
    /// response cannot pass as complete. Exercises the real kernel-decrypted
    /// alert record, not just the pure `alert_is_clean_close` classifier.
    #[expect(
        clippy::print_stderr,
        reason = "skip message when the kernel lacks the tls module"
    )]
    fn run_ktls_drain_close_notify(tls_versions: &[&'static rustls::SupportedProtocolVersion]) {
        if !is_available() {
            eprintln!("kTLS not available, skipping");
            return;
        }

        let plaintext_msg = b"kTLS close_notify drain: body before the alert";

        let mut harness = setup_ktls_test(tls_versions, |stream| {
            stream.write_all(plaintext_msg).expect("write plaintext");
            stream.flush().expect("flush");
        });

        // Drain post-handshake control records and read the body, leaving the
        // server's close_notify as the frontmost queued record.
        signal_and_drain(&harness);
        let mut buf = [0u8; 1024];
        let n = harness.tcp_client.read(&mut buf).expect("read body");
        assert_eq!(&buf[..n], plaintext_msg, "kTLS should decrypt the body");

        // Release the server to send close_notify, then FIN. Joining
        // guarantees the alert record is on the wire before we drain.
        harness.done_barrier.wait();
        harness.server_handle.join().expect("server thread");

        // Wait until the queued close_notify is readable.
        let pollfd =
            nix::poll::PollFd::new(harness.tcp_client.as_fd(), nix::poll::PollFlags::POLLIN);
        let nready =
            nix::poll::poll(&mut [pollfd], nix::poll::PollTimeout::from(5000u16)).expect("poll");
        assert_eq!(nready, 1, "expected close_notify to be readable");

        // MaybeIdle (post-setup) accepts the clean close as end-of-stream. The
        // peek does not consume the record, so it stays queued for the next
        // drain below.
        drain_control_messages(harness.tcp_client.as_fd(), DrainExpect::MaybeIdle)
            .expect("MaybeIdle drain must accept a clean close_notify");

        // DataReady (mid-stream splice loop) must still fail closed on the same
        // record so a truncated response cannot pass as complete.
        let err = drain_control_messages(harness.tcp_client.as_fd(), DrainExpect::DataReady)
            .expect_err("DataReady drain must reject a close_notify");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// Clean `close_notify` handling in the post-setup drain, TLS 1.2.
    #[test]
    fn test_ktls_drain_close_notify_tls12() {
        run_ktls_drain_close_notify(&[&rustls::version::TLS12]);
    }

    /// Clean `close_notify` handling in the post-setup drain, TLS 1.3.
    #[test]
    fn test_ktls_drain_close_notify_tls13() {
        run_ktls_drain_close_notify(&[&rustls::version::TLS13]);
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
