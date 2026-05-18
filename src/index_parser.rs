//! Shared parsing primitives for Debian `Packages` stanzas: the `Filename:`
//! field, hex-encoded `SHA256:` / `SHA512:` digests, and the small helpers
//! that derive cache lookup keys from a stanza's relative path.
//!
//! Used by `task_cleanup`'s 24h sweep (and its tests). The cold path is
//! currently the only consumer; the helpers stay free of hot-path-specific
//! coupling so they can be reused if a future call site needs them.

use std::path::Path;

/// Extract the `Filename:` field's relative-path value from a Debian
/// `Packages` stanza line. Returns the path verbatim.
///
/// **Security**: rejects empty values, absolute paths, NUL bytes, backslash,
/// and any segment equal to `..` or `.`. An attacker-controlled upstream
/// `Packages` stanza could otherwise inject a traversal sequence; rejecting
/// here keeps downstream `HashMap` keys and filesystem joins honest.
pub(crate) fn parse_filename_field(line: &str) -> Option<&str> {
    let line = line.trim();
    let filepath = line.strip_prefix("Filename: ")?.trim_start();
    if !is_safe_filename_relpath(filepath) {
        return None;
    }
    Some(filepath)
}

/// `true` iff `s` is a safe relative path: non-empty, no leading `/`, no
/// backslash, no ASCII control character (`< 0x20`, plus `0x7f` DEL), and
/// every `/`-separated segment is non-empty and not `.` or `..`.
pub(crate) fn is_safe_filename_relpath(s: &str) -> bool {
    if s.is_empty() || s.starts_with('/') {
        return false;
    }
    if s.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'\\') {
        return false;
    }
    s.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Derive the on-disk cache key for a structured-pool entry: the `.deb`
/// basename. Borrows from `relpath` to avoid allocating a fresh `String` per
/// matched stanza (the returned key borrows the input — the caller's source
/// string must outlive it).
pub(crate) fn structured_lookup_key(relpath: &str) -> Option<&str> {
    Path::new(relpath).file_name().and_then(|n| n.to_str())
}

/// Decode `hex` into exactly `N` bytes. `None` on wrong length / non-hex.
/// Accepts upper- and lower-case.
pub(crate) fn hex_decode_exact<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        let hi = hex_digit(bytes[2 * i])?;
        let lo = hex_digit(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(out)
}

const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse a stanza line of the form `"<prefix><hex>"` into `N` bytes.
pub(crate) fn parse_hex_field<const N: usize>(line: &str, prefix: &str) -> Option<[u8; N]> {
    let rest = line.trim().strip_prefix(prefix)?.trim_start();
    hex_decode_exact::<N>(rest)
}

/// Lowercase-hex encoding suitable for log messages.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(HEX[(*b >> 4) as usize]));
        out.push(char::from(HEX[(*b & 0x0f) as usize]));
    }
    out
}

/// Hash algorithm accepted from Debian indices. SHA256 is the modern default;
/// SHA512 is the fallback.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum HashAlgo {
    Sha256,
    Sha512,
}

impl HashAlgo {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// Accumulated state of the current Debian `Packages` stanza.
#[derive(Debug)]
pub(crate) struct Stanza {
    pub(crate) filename: Option<String>,
    pub(crate) sha256: Option<[u8; 32]>,
    pub(crate) sha512: Option<[u8; 64]>,
}

impl Stanza {
    pub(crate) const fn new() -> Self {
        Self {
            filename: None,
            sha256: None,
            sha512: None,
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.filename.is_none() && self.sha256.is_none() && self.sha512.is_none()
    }

    pub(crate) fn reset(&mut self) {
        self.filename = None;
        self.sha256 = None;
        self.sha512 = None;
    }

    pub(crate) fn ingest(&mut self, line: &str) {
        if self.filename.is_none()
            && let Some(name) = parse_filename_field(line)
        {
            self.filename = Some(name.to_owned());
            return;
        }
        if self.sha256.is_none()
            && let Some(h) = parse_hex_field::<32>(line, "SHA256: ")
        {
            self.sha256 = Some(h);
            return;
        }
        if self.sha512.is_none()
            && let Some(h) = parse_hex_field::<64>(line, "SHA512: ")
        {
            self.sha512 = Some(h);
        }
    }

    /// Preferred `(algo, expected-digest)` pair: SHA256 wins, SHA512 fallback.
    pub(crate) fn chosen(&self) -> Option<(HashAlgo, &[u8])> {
        self.sha256
            .as_ref()
            .map(|h| (HashAlgo::Sha256, h.as_slice()))
            .or_else(|| {
                self.sha512
                    .as_ref()
                    .map(|h| (HashAlgo::Sha512, h.as_slice()))
            })
    }
}

/// Hash the contents of an open file. Synchronous; blocks the current thread.
pub(crate) fn hash_open_file<D: sha2::Digest>(
    file: &mut std::fs::File,
) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut hasher = D::new();
    #[expect(clippy::large_stack_arrays, reason = "ensure efficient file hashing")]
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_field_sha256() {
        let hash = [0x11u8; 32];
        let line = format!("SHA256: {}\n", hex_encode(&hash));
        assert_eq!(parse_hex_field::<32>(&line, "SHA256: "), Some(hash));
    }

    #[test]
    fn stanza_ingest_collects_filename_and_sha256() {
        let mut s = Stanza::new();
        s.ingest("Filename: pool/main/a/abc/abc_1.0_amd64.deb\n");
        s.ingest(&format!("SHA256: {}\n", hex_encode(&[0xab; 32])));
        assert_eq!(
            s.filename.as_deref(),
            Some("pool/main/a/abc/abc_1.0_amd64.deb"),
        );
        assert_eq!(s.chosen(), Some((HashAlgo::Sha256, [0xab; 32].as_slice())));
    }

    #[test]
    fn stanza_chosen_prefers_sha256_over_sha512() {
        let mut s = Stanza::new();
        s.sha256 = Some([0x11u8; 32]);
        s.sha512 = Some([0x22u8; 64]);
        assert_eq!(
            s.chosen(),
            Some((HashAlgo::Sha256, [0x11u8; 32].as_slice()))
        );
    }
}
