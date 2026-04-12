//! Low-level helpers for the unbuffered rustls handshake loop used by the
//! splice proxy's kTLS path.
//!
//! These routines manipulate the incoming/outgoing TLS buffers and the rustls
//! `UnbufferedClientConnection` state machine. They are kept here (rather than
//! inline in `splice_conn.rs`) so that the orchestration of
//! `unbuffered_ktls_request` stays readable.

use std::io::{self, ErrorKind};

use rustls::{
    client::ClientConnectionData,
    unbuffered::{EncodeError, EncodeTlsData},
};

use crate::secure_vec::SecureVec;

/// Shift `discard` processed bytes out of the front of `buf[..used]`.
pub(crate) fn discard_incoming(buf: &mut [u8], used: &mut usize, discard: usize) {
    debug_assert!(
        discard <= *used,
        "discard ({discard}) exceeds used ({used})",
        used = *used
    );
    if discard >= *used {
        // All data consumed — skip the copy_within entirely
        *used = 0;
    } else if discard > 0 {
        buf.copy_within(discard..*used, 0);
        *used -= discard;
    }
}

/// Try to grow the incoming buffer if full, returning an error if the
/// maximum size is exceeded.
pub(crate) fn grow_incoming(buf: &mut SecureVec, used: usize, phase: &str) -> io::Result<()> {
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
                        format!("kTLS: incoming buffer exceeded 2 MiB during {phase}"),
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
            Err(EncodeError::AlreadyEncoded) => break,
        }
    }
}
