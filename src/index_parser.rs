//! Shared parsing primitives for Debian `Packages` stanzas: the `Filename:`
//! field, hex-encoded `SHA256:` / `SHA512:` digests, and the small helpers
//! that derive cache lookup keys from a stanza's relative path.
//!
//! Used by `integrity.rs` (post-commit registry ingest/verify) and
//! `task_cleanup`'s 24h sweep (and its tests). Cold-path only; the helpers
//! stay free of hot-path-specific coupling.

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

/// Decode a `by-hash` URL's digest filename against the algorithm taken from
/// the URL's `<algo>` path segment (see `integrity::byhash_algo_from_uri_path`).
///
/// A `/by-hash/SHA256/<hex>` (or `/SHA512/<hex>`) URL embeds the digest in the
/// path component, so the filename *is* the expected digest -- but the
/// authoritative algorithm is the `<algo>` segment, not the digest length. The
/// hex length must match `algo` (64 for SHA256, 128 for SHA512); a length/algo
/// mismatch or non-hex input returns `None`, so verification treats the
/// resource as unverifiable rather than hashing with the wrong algorithm.
pub(crate) fn byhash_digest_for_algo(algo: HashAlgo, filename: &str) -> Option<Vec<u8>> {
    match algo {
        HashAlgo::Sha256 => hex_decode_exact::<32>(filename).map(|d| d.to_vec()),
        HashAlgo::Sha512 => hex_decode_exact::<64>(filename).map(|d| d.to_vec()),
    }
}

/// Discriminator for `Packages`/`Filename` parsing rules: structured
/// (pool-based) repositories versus flat-repo layouts. Replaces the
/// previous `is_flat: bool` parameter so the call sites self-document and
/// no impossible "neither" state can be constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IndexFormat {
    Structured,
    Flat,
}

/// Map a `Packages` stanza `Filename:` value to the registry key used to look
/// it up at `.deb` download time.
///
/// - structured repos: the cache flattens `pool/.../<deb>` to the basename, so
///   the key is the basename (`structured_lookup_key`).
/// - flat repos: the URL path is the on-disk path verbatim, so the key is the
///   validated relpath itself.
///
/// Returns `None` when the relpath fails `is_safe_filename_relpath`.
pub(crate) fn registry_key_from_filename_field(
    filename_field: &str,
    format: IndexFormat,
) -> Option<String> {
    if !is_safe_filename_relpath(filename_field) {
        return None;
    }
    match format {
        IndexFormat::Flat => Some(filename_field.to_owned()),
        IndexFormat::Structured => structured_lookup_key(filename_field).map(str::to_owned),
    }
}

/// Iterate the `(repo-relative path, SHA256 digest)` entries from a Debian
/// `Release` / `InRelease` file's `SHA256:` section.
///
/// Handles the `InRelease` clearsigned wrapper by stopping at the PGP
/// signature boundary. Entry lines are indented with one or more spaces or
/// tabs followed by `<hex> <size> <path>`; the section ends at the first
/// non-indented line. Paths failing `is_safe_filename_relpath` are skipped.
pub(crate) fn parse_release_checksums(
    content: &str,
) -> impl Iterator<Item = (String, [u8; 32])> + '_ {
    let mut in_sha256_section = false;
    content.lines().filter_map(move |line| {
        if line.starts_with("-----BEGIN PGP SIGNATURE-----") {
            in_sha256_section = false;
            return None;
        }
        // A non-indented, non-empty line ends the current section. Section
        // headers ("SHA256:", "MD5Sum:", ...) are themselves non-indented.
        // Debian uses spaces but accept tabs too so non-canonical mirrors
        // that emit `\t`-indented entries still ingest.
        let indented = line.starts_with(' ') || line.starts_with('\t');
        if !indented && !line.is_empty() {
            in_sha256_section = line.trim_end() == "SHA256:";
            return None;
        }
        if !in_sha256_section {
            return None;
        }
        // Indented entry: " <hex> <size> <path>"
        let mut parts = line.split_whitespace();
        let hex = parts.next()?;
        let _size = parts.next()?;
        let path = parts.next()?;
        // Debian repo paths do not contain spaces; if a 4th token exists the
        // path had a space - reject.
        if parts.next().is_some() {
            return None;
        }
        let digest = hex_decode_exact::<32>(hex)?;
        if !is_safe_filename_relpath(path) {
            return None;
        }
        Some((path.to_owned(), digest))
    })
}

/// Map a `.deb` download's request to the same registry key.
///
/// `debname` is `ConnectionDetails::debname` (already the basename for a
/// structured pool file). For structured pool the key is `debname` directly.
/// Flat-pool layer-B verification is deferred (see the plan's deferred list),
/// so this is currently only used for the structured-pool path.
pub(crate) fn registry_key_for_download(debname: &str) -> String {
    debname.to_owned()
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

    #[test]
    fn byhash_digest_sha256() {
        let hex = "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba";
        let digest = byhash_digest_for_algo(HashAlgo::Sha256, hex).expect("valid sha256 hex");
        assert_eq!(digest.len(), 32);
        assert_eq!(hex_encode(&digest), hex);
    }

    #[test]
    fn byhash_digest_sha512() {
        let hex = &"a".repeat(128);
        let digest = byhash_digest_for_algo(HashAlgo::Sha512, hex).expect("valid sha512 hex");
        assert_eq!(digest.len(), 64);
        assert_eq!(hex_encode(&digest), *hex);
    }

    #[test]
    fn byhash_digest_rejects_bad_input() {
        assert!(byhash_digest_for_algo(HashAlgo::Sha256, "").is_none());
        assert!(byhash_digest_for_algo(HashAlgo::Sha256, "deadbeef").is_none()); // too short
        assert!(byhash_digest_for_algo(HashAlgo::Sha256, &"z".repeat(64)).is_none()); // non-hex
        // Length/algo mismatch: a 128-hex digest under a SHA256 URL segment (or
        // a 64-hex one under SHA512) must be rejected, never hashed as the other
        // algorithm.
        assert!(byhash_digest_for_algo(HashAlgo::Sha256, &"a".repeat(128)).is_none());
        assert!(byhash_digest_for_algo(HashAlgo::Sha512, &"a".repeat(64)).is_none());
    }

    #[test]
    fn registry_key_for_structured_pool_uses_basename() {
        assert_eq!(
            registry_key_from_filename_field(
                "pool/main/f/foo/foo_1.0_amd64.deb",
                IndexFormat::Structured,
            ),
            Some("foo_1.0_amd64.deb".to_string())
        );
    }

    #[test]
    fn registry_key_for_flat_uses_relpath_verbatim() {
        assert_eq!(
            registry_key_from_filename_field("amd64/foo_1.0_amd64.deb", IndexFormat::Flat),
            Some("amd64/foo_1.0_amd64.deb".to_string())
        );
    }

    #[test]
    fn registry_key_rejects_unsafe_relpath() {
        assert_eq!(
            registry_key_from_filename_field("../etc/passwd", IndexFormat::Structured),
            None
        );
        assert_eq!(
            registry_key_from_filename_field("", IndexFormat::Flat),
            None
        );
    }

    #[test]
    fn parse_release_detached() {
        let release = "\
Origin: Debian
Suite: sid
MD5Sum:
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1234 main/binary-amd64/Packages
SHA256:
 1111111111111111111111111111111111111111111111111111111111111111 1234 main/binary-amd64/Packages
 2222222222222222222222222222222222222222222222222222222222222222 567 main/binary-amd64/Packages.xz
SHA512:
 3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333 1234 main/binary-amd64/Packages
";
        let entries: Vec<_> = parse_release_checksums(release).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "main/binary-amd64/Packages");
        assert_eq!(entries[0].1, [0x11u8; 32]);
        assert_eq!(entries[1].0, "main/binary-amd64/Packages.xz");
        assert_eq!(entries[1].1, [0x22u8; 32]);
    }

    #[test]
    fn parse_release_inrelease_clearsigned() {
        let inrelease = "\
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Origin: Debian
SHA256:
 1111111111111111111111111111111111111111111111111111111111111111 1234 main/binary-amd64/Packages
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAd...
-----END PGP SIGNATURE-----
";
        let entries: Vec<_> = parse_release_checksums(inrelease).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "main/binary-amd64/Packages");
    }

    #[test]
    fn parse_release_rejects_unsafe_path() {
        let release = "\
SHA256:
 1111111111111111111111111111111111111111111111111111111111111111 1 ../../etc/passwd
";
        assert!(parse_release_checksums(release).next().is_none());
    }

    #[test]
    fn hex_decode_exact_rejects_truncated() {
        assert!(hex_decode_exact::<32>("deadbeef").is_none());
    }

    #[test]
    fn hex_decode_exact_rejects_oversize() {
        let oversize = "a".repeat(128);
        assert!(hex_decode_exact::<32>(&oversize).is_none());
    }

    #[test]
    fn hex_decode_exact_rejects_odd_length() {
        let odd = "a".repeat(63);
        assert!(hex_decode_exact::<32>(&odd).is_none());
    }

    #[test]
    fn byhash_digest_rejects_non_hex_with_correct_length() {
        let bad = "g".repeat(64);
        assert!(byhash_digest_for_algo(HashAlgo::Sha256, &bad).is_none());
    }
}
