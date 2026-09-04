//! Low-level helpers for the unbuffered rustls handshake loop used by the
//! splice proxy's kTLS path.
//!
//! These routines manipulate the incoming/outgoing TLS buffers and the rustls
//! `UnbufferedClientConnection` state machine. They are kept here (rather than
//! inline in `splice/ktls_path.rs`) so that the orchestration of
//! `unbuffered_ktls_request` stays readable.

use std::io::{self, ErrorKind};

use rustls::{
    client::ClientConnectionData,
    unbuffered::{EncodeError, EncodeTlsData},
};

use crate::secure_vec::SecureVec;
use crate::warn_once;

/// Shift `discard` processed bytes out of the front of `buf[..used]`.
pub(crate) fn discard_incoming(buf: &mut [u8], used: &mut usize, discard: usize) {
    debug_assert!(
        discard <= *used,
        "discard ({discard}) exceeds used ({used})",
        used = *used
    );
    if discard > *used {
        // Release builds compile the debug_assert out, and zeroing `used`
        // here drops unprocessed ciphertext *and* defeats the `incoming_used
        // != 0` guard that stops kTLS being configured with a stale record
        // sequence -- the resulting garbage decrypts as a peer error later.
        warn_once!(
            "kTLS: rustls asked to discard {discard} bytes but only {} are buffered; dropping the buffer",
            *used
        );
        *used = 0;
    } else if discard == *used {
        // All data consumed — skip the copy_within entirely
        *used = 0;
    } else if discard > 0 {
        buf.copy_within(discard..*used, 0);
        *used -= discard;
    }
}

/// Try to grow the incoming buffer if full, returning an error if the
/// maximum size is exceeded.
pub(crate) fn grow_incoming(
    buf: &mut SecureVec,
    used: usize,
    phase: &'static str,
) -> io::Result<()> {
    /// Maximum incoming buffer size (2 MiB). Prevents unbounded growth if a
    /// server sends many TLS records without completing the handshake.
    const MAX_INCOMING_BUF: usize = 2 * 1024 * 1024;

    let buf_len = buf.len();

    if used >= buf_len {
        let new_size = if buf_len == 0 {
            1024
        } else {
            buf_len
                .checked_mul(2)
                .filter(|&n| n <= MAX_INCOMING_BUF)
                .ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        format!("kTLS: incoming buffer exceeded 2 MiB during {phase} (used={used}, cap={buf_len})"),
                    )
                })?
        };

        buf.resize(new_size, 0);
    }

    Ok(())
}

/// Encode pending TLS data into the outgoing buffer, resizing as needed.
pub(crate) fn encode_tls_data(
    etd: &mut EncodeTlsData<'_, ClientConnectionData>,
    outgoing: &mut SecureVec,
    outgoing_used: &mut usize,
) {
    loop {
        match etd.encode(&mut outgoing[*outgoing_used..]) {
            Ok(n) => {
                *outgoing_used += n;
                break;
            }
            Err(EncodeError::InsufficientSize(isz)) => {
                outgoing.resize(isz.required_size + *outgoing_used, 0);
            }
            Err(EncodeError::AlreadyEncoded) => {
                // Unreachable today (the caller encodes once per state, and
                // `InsufficientSize` does not set rustls' encoded flag).
                // Breaking here leaves `outgoing_used` unadvanced, so the
                // following TransmitTlsData sends nothing and the handshake
                // stalls into a round-cap or http_timeout error that points
                // at the network instead of the state machine.
                warn_once!(
                    "kTLS: rustls reported handshake data already encoded; no bytes queued for transmit, so the handshake stalls and falls back to userspace TLS for this request"
                );
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grow_incoming_seeds_an_empty_buffer() {
        let mut buf = SecureVec::new(0);
        grow_incoming(&mut buf, 0, "test").expect("seeding an empty buffer must succeed");
        assert_eq!(buf.len(), 1024, "an empty buffer starts at 1 KiB");
    }

    #[test]
    fn grow_incoming_doubles_only_once_the_buffer_is_full() {
        let mut buf = SecureVec::new(1024);
        grow_incoming(&mut buf, 1023, "test").expect("a buffer with room must succeed");
        assert_eq!(buf.len(), 1024, "a buffer with room must not grow");

        grow_incoming(&mut buf, 1024, "test").expect("a full buffer must grow");
        assert_eq!(buf.len(), 2048, "a full buffer doubles");
    }

    /// The growth cap is what stops a server that ships TLS records without
    /// ever completing the handshake from growing this buffer without bound.
    #[test]
    fn grow_incoming_refuses_to_grow_past_two_mib() {
        const MAX: usize = 2 * 1024 * 1024;

        let mut buf = SecureVec::new(MAX);
        let err = grow_incoming(&mut buf, MAX, "test").expect_err("the cap must be enforced");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(
            buf.len(),
            MAX,
            "a refused growth must leave the buffer as-is"
        );
    }
}
