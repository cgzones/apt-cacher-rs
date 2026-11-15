//! Shared parsing primitives for Debian `Packages` stanzas: the `Filename:`
//! field, hex-encoded `SHA256:` / `SHA512:` digests, and the small helpers
//! that derive cache lookup keys from a stanza's relative path.

use std::{borrow::Cow, io, str::Utf8Error};

use tokio::io::AsyncBufRead;

use crate::{
    limits::{CappedLine, MAX_METADATA_LINE_LEN, read_line_capped},
    sticky, warn_once, warn_once_or_debug,
};

/// Split one stanza line into its deb822 field name and trimmed value.
///
/// **Security**: `None` for a continuation line (leading space or tab). A
/// package maintainer writes such lines verbatim into a long `Description:`,
/// so reading `  SHA256: <hex>` there as a field would let any maintainer
/// override the digest the registry expects for any deb (a persistent
/// checksum-mismatch denial of service).
///
/// Splits bytes: a `Packages` line need be UTF-8 only where a tracked value
/// is decoded ([`field_text`]).
fn split_field(line: &[u8]) -> Option<(&[u8], &[u8])> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return None;
    }
    let colon = memchr::memchr(b':', line)?;
    Some((&line[..colon], line[colon + 1..].trim_ascii()))
}

/// A tracked field that is not UTF-8 fails the whole index read: a consumer
/// acting on part of an index (cleanup's reference set) must not mistake it
/// for the whole. Other fields are never decoded, so a Latin-1
/// `Description:` is harmless.
fn field_text(value: &[u8]) -> io::Result<&str> {
    std::str::from_utf8(value).map_err(|_err @ Utf8Error { .. }| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata line is not valid UTF-8",
        )
    })
}

/// Gate a `Filename:` field value; `Err` carries the rejected value for the
/// log.
///
/// **Security**: an attacker-controlled upstream `Packages` stanza could
/// otherwise inject a traversal sequence into downstream `HashMap` keys and
/// filesystem joins.
fn filename_value(value: &str) -> Result<&str, &str> {
    let filepath = strip_leading_dot_segments(value);
    if is_safe_filename_relpath(filepath) {
        Ok(filepath)
    } else {
        Err(filepath)
    }
}

/// `apt-ftparchive packages .` (and `apt-ftparchive release .`) writes the
/// directory argument verbatim, so whole flat archives publish every
/// `Filename:` as `./<deb>`, while the cleanup candidate map and the
/// checksum registry are keyed by the path relative to the mirror root.
///
/// Leading-only: no generator emits an interior `.` segment, and those (like
/// `..` anywhere) still fail [`is_safe_filename_relpath`].
fn strip_leading_dot_segments(mut s: &str) -> &str {
    while let Some(rest) = s.strip_prefix("./") {
        s = rest;
    }
    s
}

fn is_safe_filename_relpath(s: &str) -> bool {
    if s.is_empty() || s.starts_with('/') {
        return false;
    }
    if s.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'\\') {
        return false;
    }
    s.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// The on-disk cache key for a structured-pool entry: the `.deb` basename.
///
/// `relpath` must have passed [`is_safe_filename_relpath`]: with no empty,
/// `.` or `..` segment, the last segment is exactly `Path::file_name`.
pub(crate) fn structured_lookup_key(relpath: &str) -> &str {
    debug_assert!(is_safe_filename_relpath(relpath), "{relpath:?}");
    relpath.rsplit_once('/').map_or(relpath, |(_, name)| name)
}

/// `None` on wrong length / non-hex; accepts upper- and lower-case.
///
/// `const_hex` decodes with SIMD, which matters for the ~10^5 digests of a
/// full `Packages` ingest. It also strips an optional `0x` prefix; the exact
/// length check comes first, so a prefixed input has too few digits and the
/// decode rejects it.
pub(crate) fn hex_decode_exact<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 {
        return None;
    }
    const_hex::decode_to_array(hex).ok()
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const_hex::encode(bytes)
}

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

    /// Length of the digest in hexadecimal characters.
    pub(crate) const fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }

    pub(crate) fn matches_digest(self, digest: &str) -> bool {
        digest.len() == self.digest_len() && digest.bytes().all(|b| b.is_ascii_hexdigit())
    }

    pub(crate) fn for_digest(digest: &str) -> Option<Self> {
        [Self::Sha256, Self::Sha512]
            .into_iter()
            .find(|algo| algo.matches_digest(digest))
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "SHA256" => Some(Self::Sha256),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// Boxed to keep async state compact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Digest {
    Sha256(Box<[u8; 32]>),
    Sha512(Box<[u8; 64]>),
}

impl Digest {
    pub(crate) const fn algo(&self) -> HashAlgo {
        match self {
            Self::Sha256(_) => HashAlgo::Sha256,
            Self::Sha512(_) => HashAlgo::Sha512,
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Sha256(digest) => digest.as_slice(),
            Self::Sha512(digest) => digest.as_slice(),
        }
    }

    pub(crate) fn from_bytes(algo: HashAlgo, bytes: &[u8]) -> Option<Self> {
        match algo {
            HashAlgo::Sha256 => bytes
                .try_into()
                .ok()
                .map(|value| Self::Sha256(Box::new(value))),
            HashAlgo::Sha512 => bytes
                .try_into()
                .ok()
                .map(|value| Self::Sha512(Box::new(value))),
        }
    }
}

impl std::ops::Deref for Digest {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// The stanza fields [`Stanza`] reads; a stanza may carry each at most once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrackedField {
    Filename,
    Sha256,
    Sha512,
}

impl TrackedField {
    fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"Filename" => Some(Self::Filename),
            b"SHA256" => Some(Self::Sha256),
            b"SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Filename => "Filename",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Filename => 1,
            Self::Sha256 => 2,
            Self::Sha512 => 4,
        }
    }
}

/// Accumulated state of the current Debian `Packages` stanza.
#[derive(Debug)]
pub(crate) struct Stanza {
    /// Empty until a `Filename:` is seen. A `String` kept across
    /// [`Self::reset`] rather than an `Option<String>`, so a stream of stanzas
    /// reuses one allocation.
    filename: String,
    pub(crate) sha256: Option<[u8; 32]>,
    pub(crate) sha512: Option<[u8; 64]>,
    /// [`TrackedField::bit`]s of the fields seen so far, valid or not: a
    /// field is repeated by its name, not by a second value that parsed.
    seen: u8,
    /// The first tracked field this stanza carried twice. Such a stanza is
    /// malformed deb822 and ambiguous about which value is meant, so
    /// [`StanzaStream`] drops it whole rather than picking one.
    repeated: Option<TrackedField>,
    /// `false` for the registry ingest, which only reads `sha256` and so
    /// skips the 128-char hex decode per stanza. A repeated `SHA512:` still
    /// rejects the stanza.
    want_sha512: bool,
    /// Which index these stanzas came from (`<host>/<mirror_path>/<file>`),
    /// for the log lines only. `None` in tests.
    source: Option<String>,
}

impl Stanza {
    pub(crate) const fn new() -> Self {
        Self {
            filename: String::new(),
            sha256: None,
            sha512: None,
            seen: 0,
            repeated: None,
            want_sha512: true,
            source: None,
        }
    }

    /// A stanza whose consumer only reads SHA256 (see `want_sha512`).
    pub(crate) const fn new_sha256_only() -> Self {
        let mut stanza = Self::new();
        stanza.want_sha512 = false;
        stanza
    }

    #[must_use]
    pub(crate) fn with_source(mut self, source: String) -> Self {
        self.source = Some(source);
        self
    }

    fn source_label(&self) -> &str {
        self.source.as_deref().unwrap_or("<unknown index>")
    }

    pub(crate) fn filename(&self) -> Option<&str> {
        (!self.filename.is_empty()).then_some(self.filename.as_str())
    }

    /// The structured registry key: the cache flattens `pool/.../<deb>` to
    /// its basename. `None` past Linux's `NAME_MAX`, since no cache file can
    /// have a longer name; this also bounds pending key storage.
    pub(crate) fn registry_key(&self) -> Option<&str> {
        let key = structured_lookup_key(self.filename()?);
        (key.len() <= MAX_REGISTRY_KEY_COMPONENT_LEN).then_some(key)
    }

    fn reset(&mut self) {
        self.filename.clear();
        self.sha256 = None;
        self.sha512 = None;
        self.seen = 0;
        self.repeated = None;
    }

    /// `Err` for a tracked field whose value is not UTF-8, repeated or not.
    fn ingest(&mut self, line: &[u8]) -> io::Result<()> {
        let Some((name, value)) = split_field(line) else {
            return Ok(());
        };
        let Some(field) = TrackedField::from_name(name) else {
            return Ok(());
        };
        let value = field_text(value)?;
        if self.seen & field.bit() != 0 {
            self.repeated.get_or_insert(field);
            return Ok(());
        }
        self.seen |= field.bit();
        match field {
            TrackedField::Filename => match filename_value(value) {
                Ok(name) => self.filename.push_str(name),
                Err(bad) => {
                    warn_once!(
                        "Rejecting unsafe Filename value `{}` in a Packages stanza from {}; the package it names loses checksum verification and its cleanup reference",
                        bad.escape_debug(),
                        self.source_label()
                    );
                }
            },
            TrackedField::Sha256 => self.sha256 = hex_decode_exact::<32>(value),
            // `chosen` prefers SHA256, so once it is known a SHA512 would
            // never be read: skip its 128-digit decode (the field still
            // counts as seen, so a repeat still rejects the stanza).
            TrackedField::Sha512 => {
                if self.want_sha512 && self.sha256.is_none() {
                    self.sha512 = hex_decode_exact::<64>(value);
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn ingest_text(&mut self, line: &str) {
        self.ingest(line.as_bytes()).expect("a `str` is UTF-8");
    }

    /// The digest fields this stanza's consumer can use, for the digest-less
    /// warn: a SHA512-only index is digest-less to a SHA256-only consumer.
    const fn usable_digests(&self) -> &'static str {
        if self.want_sha512 {
            "SHA256/SHA512"
        } else {
            "SHA256"
        }
    }

    pub(crate) fn chosen_digest(&self) -> Option<Digest> {
        let (algo, digest) = self.chosen()?;
        Digest::from_bytes(algo, digest)
    }

    /// SHA256 wins, SHA512 is the fallback.
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

/// Streams the stanzas of a (decoded) Debian `Packages` index, one complete
/// stanza per [`Self::next`].
///
/// Pull-style rather than a `for_each_stanza(sink)` visitor: cleanup's
/// per-stanza work is async and its tasks are spawned, and an `AsyncFnMut`
/// sink's call future cannot be bounded `Send` on stable.
///
/// Yields only stanzas with a `Filename:`; one without a consumer-usable
/// digest is still yielded (cleanup retains the file without verification)
/// after a once-gated warn. A stanza repeating a tracked field is not
/// yielded at all: which of two values a consumer would pick is exactly what
/// a crafted index relies on, so neither is trusted.
///
/// A line over [`MAX_METADATA_LINE_LEN`] counts as non-blank (multi-kilobyte
/// `Provides:`/`Depends:` fields are legitimate) so the stanza is not
/// flushed prematurely; a trailing stanza without a closing blank line is
/// flushed at EOF. A blank line is one of `u8::is_ascii_whitespace` bytes
/// only, which excludes vertical tab.
pub(crate) struct StanzaStream<R> {
    reader: R,
    stanza: Stanza,
    line_buf: Vec<u8>,
    done: sticky::Bool,
}

impl<R: AsyncBufRead + Unpin> StanzaStream<R> {
    pub(crate) fn new(reader: R, stanza: Stanza) -> Self {
        Self {
            reader,
            stanza,
            line_buf: Vec::with_capacity(128),
            done: sticky::Bool::new(),
        }
    }

    /// `Ok(None)` at EOF. A read error (size/line limit, a tracked field that
    /// is not UTF-8, I/O) ends the stream.
    pub(crate) async fn next(&mut self) -> io::Result<Option<&Stanza>> {
        if self.done.get() {
            return Ok(None);
        }
        // The stanza handed out by the previous call is consumed.
        self.stanza.reset();
        loop {
            let read =
                read_line_capped(&mut self.reader, &mut self.line_buf, MAX_METADATA_LINE_LEN).await;
            match read {
                Ok(CappedLine::Eof) => {
                    self.done.set();
                    return Ok(self.accept().then_some(&self.stanza));
                }
                Ok(CappedLine::Skipped) => {}
                Ok(CappedLine::Line(line)) => {
                    if !line.trim_ascii().is_empty() {
                        if let Err(err) = self.stanza.ingest(line) {
                            self.done.set();
                            return Err(err);
                        }
                    } else if self.accept() {
                        return Ok(Some(&self.stanza));
                    } else {
                        // A blank run, a stanza without `Filename:` or a
                        // rejected one: nothing either consumer acts on.
                        self.stanza.reset();
                    }
                }
                Err(err) => {
                    self.done.set();
                    return Err(err);
                }
            }
        }
    }

    /// Whether to hand out the accumulated stanza.
    fn accept(&self) -> bool {
        let Some(filename) = self.stanza.filename() else {
            return false;
        };
        if let Some(field) = self.stanza.repeated {
            // A malformed (or hostile) index repeats the fault in every
            // stanza, so only the first occurrence warns.
            warn_once_or_debug!(
                "Packages stanza for `{}` from {} repeats its {} field; ignoring the stanza, so the package it names is exempt from checksum verification and loses its cleanup reference",
                filename.escape_debug(),
                self.stanza.source_label(),
                field.as_str()
            );
            return false;
        }
        if self.stanza.chosen().is_none() {
            // Fires per stanza on a digest-less index, so degrade after the
            // first.
            warn_once_or_debug!(
                "Packages stanza for `{}` from {} advertises no {} digest; the package it names is exempt from checksum verification",
                filename.escape_debug(),
                self.stanza.source_label(),
                self.stanza.usable_digests()
            );
        }
        true
    }
}

/// Decode a `by-hash` URL's digest filename. The authoritative algorithm is
/// the URL's `<algo>` segment, not the digest length: a length/algo mismatch
/// returns `None`, so the resource is unverifiable rather than hashed with
/// the wrong algorithm.
pub(crate) fn byhash_digest_for_algo(algo: HashAlgo, filename: &str) -> Option<Digest> {
    match algo {
        HashAlgo::Sha256 => hex_decode_exact::<32>(filename).map(|d| Digest::Sha256(Box::new(d))),
        HashAlgo::Sha512 => hex_decode_exact::<64>(filename).map(|d| Digest::Sha512(Box::new(d))),
    }
}

/// Linux's `NAME_MAX`.
const MAX_REGISTRY_KEY_COMPONENT_LEN: usize = 255;

/// Iterate the `(section, hex, path)` triples of every indented
/// `<hex> <size> <path>` entry inside a `SHA256:`/`SHA512:` section of a
/// Debian `Release`/`InRelease` file.
///
/// Stops at the `-----BEGIN PGP SIGNATURE-----` boundary: nothing past it is
/// signed, so a section header in the signature block must not re-open a
/// section. Entry lines are indented with spaces or tabs (tabs for
/// non-canonical mirrors). A non-field line ending a supported section emits
/// an error before switching out, so strict cleanup rejects incomplete
/// references while tolerant ingestion recovers. Field names follow deb822
/// syntax, including its ban on initial `#` and `-`. A 4th token means the
/// path contained a space, so the entry is rejected. Validates the unsigned
/// `<size>`; callers validate the algorithm/length of `hex`.
fn release_hash_entries(
    content: &str,
) -> impl Iterator<Item = Result<(HashAlgo, &str, &str), &'static str>> + '_ {
    let mut section: Option<HashAlgo> = None;
    content
        .lines()
        .take_while(|line| !line.starts_with("-----BEGIN PGP SIGNATURE-----"))
        .filter_map(move |line| {
            if line.trim_ascii().is_empty() {
                return None;
            }
            let indented = line.starts_with(' ') || line.starts_with('\t');
            if !indented {
                let malformed = section.is_some()
                    && !split_field(line.as_bytes()).is_some_and(|(name, _)| {
                        !matches!(name.first(), None | Some(b'#' | b'-'))
                            && name.iter().all(u8::is_ascii_graphic)
                    });
                section = match line.trim_end() {
                    "SHA256:" => Some(HashAlgo::Sha256),
                    "SHA512:" => Some(HashAlgo::Sha512),
                    _ => None,
                };
                return malformed.then_some(Err("unindented checksum entry or malformed field"));
            }
            let section = section?;
            let mut parts = line.split_ascii_whitespace();
            let hex = parts.next()?; // Blank lines are harmless.
            let Some(size) = parts.next() else {
                return Some(Err("missing checksum size"));
            };
            let Some(path) = parts.next() else {
                return Some(Err("missing checksum path"));
            };
            if parts.next().is_some() {
                return Some(Err("extra checksum fields"));
            }
            if !size.bytes().all(|byte| byte.is_ascii_digit()) || size.parse::<u64>().is_err() {
                return Some(Err("invalid checksum size"));
            }
            Some(Ok((section, hex, path)))
        })
}

/// Iterate the `(repo-relative path, SHA256 digest)` entries of a `Release`
/// / `InRelease` file's `SHA256:` section whose path `wanted` accepts.
///
/// Leading `./` segments are stripped so the key matches the request's URI
/// path; unsafe paths are skipped. `wanted` sees the stripped, validated
/// path and runs before the digest is decoded: the registry ingest keeps
/// only the `Packages` leaves, about a fifth of a Debian `InRelease`.
pub(crate) fn parse_release_checksums<'a>(
    content: &'a str,
    mut wanted: impl FnMut(&str) -> bool + 'a,
) -> impl Iterator<Item = (&'a str, [u8; 32])> + 'a {
    release_hash_entries(content).filter_map(move |entry| {
        // Integrity ingestion tolerates bad rows; destructive cleanup does not.
        let Ok((section, hex, path)) = entry else {
            return None;
        };
        if section != HashAlgo::Sha256 {
            return None;
        }
        let path = strip_leading_dot_segments(path);
        if !is_safe_filename_relpath(path) || !wanted(path) {
            return None;
        }
        Some((path, hex_decode_exact::<32>(hex)?))
    })
}

/// The dates in a `Release`/`InRelease` header paragraph, as unix seconds:
/// `Date:` (when the archive generated it) and `Valid-Until:` (after which
/// apt refuses it). Either is `None` when missing or unparsable.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReleaseHeader {
    pub(crate) date: Option<i64>,
    pub(crate) valid_until: Option<i64>,
}

/// Reads the header paragraph only (it ends at the first checksum section).
/// The first occurrence of each field counts.
pub(crate) fn parse_release_header(content: &str) -> ReleaseHeader {
    let mut header = ReleaseHeader::default();
    let (mut date_seen, mut valid_until_seen) = (false, false);
    for line in content.lines() {
        if matches!(line, "MD5Sum:" | "SHA1:" | "SHA256:" | "SHA512:")
            || line.starts_with("-----BEGIN PGP SIGNATURE")
        {
            break;
        }
        if let Some(value) = line.strip_prefix("Date:")
            && !date_seen
        {
            date_seen = true;
            header.date = parse_release_timestamp(value);
        } else if let Some(value) = line.strip_prefix("Valid-Until:")
            && !valid_until_seen
        {
            valid_until_seen = true;
            header.valid_until = parse_release_timestamp(value);
        }
        if date_seen && valid_until_seen {
            break;
        }
    }
    header
}

/// A `Release` date field's value as unix seconds. Debian writes the zone as
/// `UTC`, which RFC 2822 lacks, so a trailing `UTC` is read as `+0000`.
fn parse_release_timestamp(value: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc2822;
    let value = value.trim();
    let normalized = value
        .strip_suffix(" UTC")
        .map_or(Cow::Borrowed(value), |head| {
            Cow::Owned(format!("{head} +0000"))
        });
    time::OffsetDateTime::parse(&normalized, &Rfc2822)
        .ok()
        .map(time::OffsetDateTime::unix_timestamp)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ByHashRef {
    Sha256([u8; 32]),
    Sha512([u8; 64]),
}

/// Algorithms with at least one successfully decoded Release checksum.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReleaseHashCoverage {
    pub(crate) sha256: bool,
    pub(crate) sha512: bool,
}

/// The by-hash digests referenced by a `Release`/`InRelease`, from both the
/// `SHA256:` and `SHA512:` sections.
///
/// Unlike [`parse_release_checksums`], deliberately path-agnostic: every
/// listed resource (`Packages`, `Contents-*`, `Translation-*`, ...) has a
/// by-hash file, and only the digest is content-addressed.
///
/// The sink may receive a valid prefix before an error; callers must discard
/// their accumulated result if parsing fails.
pub(crate) fn parse_release_byhash_digests(
    content: &str,
    mut on_digest: impl FnMut(ByHashRef),
) -> Result<ReleaseHashCoverage, &'static str> {
    let mut parsed = ReleaseHashCoverage {
        sha256: false,
        sha512: false,
    };
    for entry in release_hash_entries(content) {
        let (section, hex, _path) = entry?;
        let digest = match section {
            HashAlgo::Sha256 => {
                let digest = hex_decode_exact::<32>(hex).ok_or("invalid SHA256 digest")?;
                parsed.sha256 = true;
                ByHashRef::Sha256(digest)
            }
            HashAlgo::Sha512 => {
                let digest = hex_decode_exact::<64>(hex).ok_or("invalid SHA512 digest")?;
                parsed.sha512 = true;
                ByHashRef::Sha512(digest)
            }
        };
        on_digest(digest);
    }
    if !parsed.sha256 && !parsed.sha512 {
        return Err("no usable SHA256 or SHA512 checksum entries");
    }
    Ok(parsed)
}

/// What a download's [`StreamHasher`] computed. The verifier trusts the
/// digest only if its algorithm is the one the expected digest uses and
/// `bytes` equals the size of the finished file; otherwise it re-reads the
/// file.
///
/// Not gated on the `splice` feature even though only that backend produces
/// one: `integrity::VerifyInput` carries the `Option` in every build.
pub(crate) struct StreamedDigest {
    pub(crate) digest: Digest,
    /// Bytes fed through `StreamHasher::update`. The caller must hash
    /// exactly what it writes to the cache file, so this is the size the
    /// finished file must have.
    pub(crate) bytes: u64,
}

/// A [`HashAlgo`]-dispatched incremental digest, for hashing a download's
/// bytes as they are written instead of re-reading the finished file.
///
/// Only the splice backend hashes a download as it writes it: the other
/// backends have no single site every cache byte passes through, so they
/// re-read the finished file at commit time ([`hash_open_file`]).
///
/// Both digests are boxed: a `Sha512` carries a 128-byte block buffer plus
/// its chaining state inline, and this type is held in `splice::CacheTarget`
/// across every await of a download (`clippy::large_futures`).
pub(crate) struct StreamHasher {
    state: StreamHasherState,
    bytes: u64,
}

enum StreamHasherState {
    Sha256(Box<sha2::Sha256>),
    Sha512(Box<sha2::Sha512>),
}

impl StreamHasher {
    #[must_use]
    pub(crate) fn new(algo: HashAlgo) -> Self {
        use sha2::Digest as _;
        let state = match algo {
            HashAlgo::Sha256 => StreamHasherState::Sha256(Box::new(sha2::Sha256::new())),
            HashAlgo::Sha512 => StreamHasherState::Sha512(Box::new(sha2::Sha512::new())),
        };
        Self { state, bytes: 0 }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        use sha2::Digest as _;
        match &mut self.state {
            StreamHasherState::Sha256(h) => h.update(bytes),
            StreamHasherState::Sha512(h) => h.update(bytes),
        }
        self.bytes += bytes.len() as u64;
    }

    #[must_use]
    pub(crate) fn finalize(self) -> StreamedDigest {
        use sha2::Digest as _;
        let Self { state, bytes } = self;
        let digest = match state {
            StreamHasherState::Sha256(h) => Digest::Sha256(Box::new(h.finalize().into())),
            StreamHasherState::Sha512(h) => Digest::Sha512(Box::new(h.finalize().into())),
        };
        StreamedDigest { digest, bytes }
    }
}

/// Hashes from the file's current position to its end. Synchronous; blocks
/// the current thread. `size_hint` only sizes the read buffer.
pub(crate) fn hash_open_file(
    algo: HashAlgo,
    file: &mut impl io::Read,
    size_hint: u64,
) -> io::Result<Digest> {
    /// 1 MiB rather than the kernel's default readahead window: cleanup
    /// hashes the whole cache and commit hashes every download, so this is
    /// the read-syscall count for both.
    const MAX_READ_BUFFER: usize = 1024 * 1024;
    /// Smallest read buffer: a small index is still read in one call, and
    /// no 1 MiB buffer is zeroed for it.
    const MIN_READ_BUFFER: usize = 64 * 1024;

    let len = usize::try_from(size_hint).map_or(MAX_READ_BUFFER, |size| {
        size.clamp(MIN_READ_BUFFER, MAX_READ_BUFFER)
    });
    let mut hasher = StreamHasher::new(algo);
    let mut buf = vec![0u8; len];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_filename_field(line: &str) -> Option<&str> {
        match split_field(line.as_bytes())? {
            (b"Filename", value) => filename_value(field_text(value).ok()?).ok(),
            _ => None,
        }
    }

    #[test]
    fn parse_filename_field_strips_the_line_terminator() {
        for (line, expected) in [
            (
                "Filename: pool/main/a/abc/abc_1.0_amd64.deb\n",
                "pool/main/a/abc/abc_1.0_amd64.deb",
            ),
            (
                "Filename: pool/main/a/abc/abc_1.0_amd64.deb\r\n",
                "pool/main/a/abc/abc_1.0_amd64.deb",
            ),
            (
                "Filename: pool/main/a/abc/abc_1.0_amd64.deb",
                "pool/main/a/abc/abc_1.0_amd64.deb",
            ),
            (
                "Filename: pool/main/i/inst/inst_1.0_amd64.udeb\n",
                "pool/main/i/inst/inst_1.0_amd64.udeb",
            ),
        ] {
            assert_eq!(parse_filename_field(line), Some(expected), "{line:?}");
        }
    }

    #[test]
    fn parse_filename_field_returns_nested_relpath_for_flat() {
        // Flat repos cite paths relative to the repo root; cleanup needs
        // to disambiguate same-basename debs across sub-directories.
        assert_eq!(
            parse_filename_field("Filename: amd64/twilio-cli_5.0.0_amd64.deb\n"),
            Some("amd64/twilio-cli_5.0.0_amd64.deb"),
        );
    }

    #[test]
    fn parse_filename_field_skips_other_keys() {
        assert_eq!(parse_filename_field("Package: stub\n"), None);
        assert_eq!(parse_filename_field("\n"), None);
        assert_eq!(parse_filename_field(""), None);
    }

    #[test]
    fn parse_filename_field_rejects_traversal() {
        assert_eq!(
            parse_filename_field("Filename: ../../../etc/passwd\n"),
            None,
        );
        assert_eq!(parse_filename_field("Filename: pool/../escape.deb\n"), None);
        assert_eq!(parse_filename_field("Filename: /etc/shadow\n"), None);
        assert_eq!(parse_filename_field("Filename: a//b.deb\n"), None);
        // A leading `./` is not traversal; a `..` behind it still is.
        assert_eq!(
            parse_filename_field("Filename: ./foo.deb\n"),
            Some("foo.deb"),
        );
        assert_eq!(parse_filename_field("Filename: ./../escape.deb\n"), None);
        assert_eq!(
            parse_filename_field("Filename: pool\\main\\evil.deb\n"),
            None,
        );
        assert_eq!(parse_filename_field("Filename: pool/x\0y.deb\n"), None,);
        assert_eq!(parse_filename_field("Filename: pool/x\ty.deb\n"), None);
        assert_eq!(parse_filename_field("Filename: pool/x\x0by.deb\n"), None);
        assert_eq!(parse_filename_field("Filename: pool/x\x7fy.deb\n"), None);
    }

    #[test]
    fn structured_lookup_key_extracts_basename() {
        assert_eq!(
            structured_lookup_key("pool/main/a/abc/abc_1.0_amd64.deb"),
            "abc_1.0_amd64.deb",
        );
        assert_eq!(
            structured_lookup_key("abc_1.0_amd64.deb"),
            "abc_1.0_amd64.deb",
        );
    }

    #[test]
    fn hex_decode_exact_rejects_wrong_length() {
        assert_eq!(hex_decode_exact::<4>("deadbe"), None); // too short
        assert_eq!(hex_decode_exact::<4>("deadbeef00"), None); // too long
        assert_eq!(hex_decode_exact::<4>("deadbee"), None); // odd
    }

    #[test]
    fn stanza_chosen_prefers_sha256_and_falls_back_to_sha512() {
        let mut s = Stanza::new();
        assert_eq!(s.chosen(), None);
        s.sha512 = Some([0x22u8; 64]);
        assert_eq!(
            s.chosen(),
            Some((HashAlgo::Sha512, [0x22u8; 64].as_slice()))
        );
        s.sha256 = Some([0x11u8; 32]);
        assert_eq!(
            s.chosen(),
            Some((HashAlgo::Sha256, [0x11u8; 32].as_slice()))
        );
    }

    #[test]
    fn stanza_ingest_ignores_unrelated_lines() {
        let mut s = Stanza::new();
        s.ingest_text("Package: stub\n");
        s.ingest_text("Description: a stub\n");
        s.ingest_text(" continued description text\n");
        assert_eq!(s.filename(), None);
        assert_eq!(s.chosen(), None);
    }

    #[test]
    fn hash_open_file_matches_one_shot_across_buffer_boundaries() {
        use sha2::Digest as _;

        // Larger than the 1 MiB read buffer, and not a multiple of it.
        let payload: Vec<u8> = (0..(1024 * 1024 + 4096))
            .map(|i: u32| u8::try_from(i % 251).expect("i % 251 is in 0..251, fits in u8"))
            .collect();

        // The real size (1 MiB reads), and an understated one (64 KiB reads):
        // the hint sizes the buffer, never the read.
        for size_hint in [payload.len() as u64, 0] {
            let mut file = io::Cursor::new(&payload);
            let streamed = hash_open_file(HashAlgo::Sha256, &mut file, size_hint).expect("hash");
            assert_eq!(
                streamed.as_slice(),
                sha2::Sha256::digest(&payload).to_vec(),
                "{size_hint}"
            );
        }

        let mut file = io::Cursor::new(&payload);
        let streamed = hash_open_file(HashAlgo::Sha512, &mut file, 0).expect("hash");
        assert_eq!(streamed.as_slice(), sha2::Sha512::digest(&payload).to_vec());
    }

    #[test]
    fn stanza_ingest_accepts_sha512_whitespace_and_crlf() {
        let mut stanza = Stanza::new();
        let hash = [0x22u8; 64];
        stanza.ingest_text(&format!("SHA512:  {}\r\n", hex_encode(&hash)));
        assert_eq!(stanza.sha512, Some(hash));
    }

    #[test]
    fn stanza_ingest_ignores_unrecognized_digest_fields() {
        let mut stanza = Stanza::new();
        stanza.ingest_text(&format!("MD5sum: {}\n", hex_encode(&[0u8; 32])));
        assert_eq!(stanza.chosen(), None);
    }

    #[test]
    fn stanza_ingest_rejects_a_short_sha256() {
        let mut stanza = Stanza::new();
        stanza.ingest_text(&format!("SHA256: {}\n", "0".repeat(63)));
        assert_eq!(stanza.sha256, None);
    }

    #[test]
    fn stanza_ingest_collects_filename_and_sha256() {
        let mut s = Stanza::new();
        s.ingest_text("Filename: pool/main/a/abc/abc_1.0_amd64.deb\n");
        s.ingest_text(&format!("SHA256: {}\n", hex_encode(&[0xab; 32])));
        assert_eq!(s.filename(), Some("pool/main/a/abc/abc_1.0_amd64.deb"),);
        assert_eq!(s.chosen(), Some((HashAlgo::Sha256, [0xab; 32].as_slice())));
    }

    #[test]
    fn stanza_ingest_strips_leading_dot_slash() {
        // E.g. NVIDIA's CUDA repos publish every `Filename:` as `./<deb>`.
        let mut s = Stanza::new();
        s.ingest_text("Filename: ./collectx-bringup_1.22.1-1_amd64.deb\n");
        assert_eq!(s.filename(), Some("collectx-bringup_1.22.1-1_amd64.deb"),);
    }

    #[test]
    fn filename_field_strips_repeated_leading_dot_segments() {
        assert_eq!(
            parse_filename_field("Filename: .././a.deb\n"),
            None,
            "a `..` segment survives the leading-dot strip and stays rejected"
        );
        assert_eq!(
            parse_filename_field("Filename: ././pool/a.deb\n"),
            Some("pool/a.deb"),
        );
        assert_eq!(
            parse_filename_field("Filename: pool/./a.deb\n"),
            None,
            "an interior `.` segment would need an allocation to normalise"
        );
        assert_eq!(parse_filename_field("Filename: ./\n"), None);
        assert_eq!(parse_filename_field("Filename: .\n"), None);
    }

    #[test]
    fn stanza_ingest_skips_sha512_once_sha256_is_known() {
        let sha512 = format!("SHA512: {}", hex_encode(&[0x22; 64]));
        let mut s = Stanza::new();
        s.ingest_text(&format!("SHA256: {}", hex_encode(&[0x11; 32])));
        s.ingest_text(&sha512);
        assert_eq!(s.sha512, None, "never read: `chosen` prefers SHA256");
        assert_eq!(s.chosen(), Some((HashAlgo::Sha256, [0x11; 32].as_slice())));

        // A SHA512 listed first is kept, and SHA256 still wins.
        let mut s = Stanza::new();
        s.ingest_text(&sha512);
        s.ingest_text(&format!("SHA256: {}", hex_encode(&[0x11; 32])));
        assert_eq!(s.sha512, Some([0x22; 64]));
        assert_eq!(s.chosen(), Some((HashAlgo::Sha256, [0x11; 32].as_slice())));
    }

    #[test]
    fn stanza_reset_reuses_the_filename_buffer() {
        let mut s = Stanza::new();
        s.ingest_text("Filename: pool/main/a/abc/abc_1.0_amd64.deb");
        let capacity = s.filename.capacity();
        s.reset();
        assert_eq!(s.filename(), None);
        s.ingest_text("Filename: pool/b.deb");
        assert_eq!(s.filename(), Some("pool/b.deb"));
        assert_eq!(s.filename.capacity(), capacity);
    }

    async fn collect_stanzas(input: &[u8], stanza: Stanza) -> Vec<(String, Option<HashAlgo>)> {
        let mut stream = StanzaStream::new(input, stanza);
        let mut out = Vec::new();
        while let Some(s) = stream.next().await.expect("readable") {
            out.push((
                s.filename()
                    .expect("only stanzas with a Filename are yielded")
                    .to_owned(),
                s.chosen().map(|(algo, _)| algo),
            ));
        }
        out
    }

    #[tokio::test]
    async fn stanza_stream_yields_named_stanzas_and_flushes_at_eof() {
        let input = format!(
            "Package: a\nFilename: pool/a.deb\nSHA256: {}\n\n\
             Package: skipped\nVersion: 1\n\n\n\
             Package: b\nFilename: pool/b.deb\nSHA512: {}\n\n\
             Package: c\nFilename: pool/c.deb\n",
            hex_encode(&[0x11; 32]),
            hex_encode(&[0x22; 64]),
        );
        let got = collect_stanzas(input.as_bytes(), Stanza::new()).await;
        assert_eq!(
            got,
            vec![
                ("pool/a.deb".to_owned(), Some(HashAlgo::Sha256)),
                ("pool/b.deb".to_owned(), Some(HashAlgo::Sha512)),
                ("pool/c.deb".to_owned(), None),
            ]
        );
    }

    #[tokio::test]
    async fn stanza_stream_sha256_only_consumer_ignores_sha512() {
        let input = format!(
            "Filename: pool/b.deb\nSHA512: {}\n",
            hex_encode(&[0x22; 64]),
        );
        let got = collect_stanzas(input.as_bytes(), Stanza::new_sha256_only()).await;
        assert_eq!(got, vec![("pool/b.deb".to_owned(), None)]);
    }

    #[tokio::test]
    async fn stanza_stream_overlong_line_does_not_split_a_stanza() {
        let long = "x".repeat(MAX_METADATA_LINE_LEN + 1);
        let input = format!(
            "Filename: pool/a.deb\nProvides: {long}\nSHA256: {}\n\n",
            hex_encode(&[0x11; 32]),
        );
        let got = collect_stanzas(input.as_bytes(), Stanza::new()).await;
        assert_eq!(got, vec![("pool/a.deb".to_owned(), Some(HashAlgo::Sha256))]);
    }

    #[tokio::test]
    async fn stanza_stream_handles_crlf_line_endings() {
        let input = format!(
            "Package: a\r\nFilename: pool/a.deb\r\nSHA256: {}\r\n\r\n\
             Package: b\r\nFilename: pool/b.deb\r\n",
            hex_encode(&[0x11; 32]),
        );
        let got = collect_stanzas(input.as_bytes(), Stanza::new()).await;
        assert_eq!(
            got,
            vec![
                ("pool/a.deb".to_owned(), Some(HashAlgo::Sha256)),
                ("pool/b.deb".to_owned(), None),
            ]
        );
    }

    #[tokio::test]
    async fn stanza_stream_flushes_on_a_whitespace_only_line() {
        let input = b"Filename: pool/a.deb\n \t \nFilename: pool/b.deb\n";
        let got = collect_stanzas(&input[..], Stanza::new()).await;
        assert_eq!(
            got,
            vec![
                ("pool/a.deb".to_owned(), None),
                ("pool/b.deb".to_owned(), None),
            ]
        );
    }

    /// Vertical tab is not whitespace to `trim_ascii`: the two stanzas around
    /// the line merge, and the repeated `Filename:` rejects the result.
    #[tokio::test]
    async fn stanza_stream_vertical_tab_line_does_not_separate() {
        let input = b"Filename: pool/a.deb\n\x0b\nFilename: pool/b.deb\n";
        let got = collect_stanzas(&input[..], Stanza::new()).await;
        assert_eq!(got, vec![]);
    }

    #[test]
    fn stanza_ingest_ignores_indented_continuation_lines() {
        let mut s = Stanza::new();
        s.ingest_text(" Filename: pool/evil.deb\n");
        s.ingest_text(&format!("\tSHA256: {}\n", hex_encode(&[0xee; 32])));
        s.ingest_text(&format!("  SHA512: {}\n", hex_encode(&[0xee; 64])));
        assert_eq!(s.filename(), None);
        assert_eq!(s.chosen(), None);
    }

    #[tokio::test]
    async fn stanza_stream_takes_the_real_digest_over_a_continuation_payload() {
        let input = format!(
            "Package: a\nDescription: harmless\n SHA256: {evil}\n .\n\tFilename: pool/evil.deb\n\
             Filename: pool/a.deb\nSHA256: {real}\n\n",
            evil = hex_encode(&[0xee; 32]),
            real = hex_encode(&[0x11; 32]),
        );
        let mut stream = StanzaStream::new(input.as_bytes(), Stanza::new());
        let stanza = stream.next().await.expect("readable").expect("one stanza");
        assert_eq!(stanza.filename(), Some("pool/a.deb"));
        assert_eq!(
            stanza.chosen(),
            Some((HashAlgo::Sha256, [0x11u8; 32].as_slice()))
        );
        assert!(stream.next().await.expect("readable").is_none());
    }

    #[tokio::test]
    async fn stanza_stream_rejects_a_stanza_repeating_a_tracked_field() {
        let h256 = |b| hex_encode(&[b; 32]);
        let h512 = |b| hex_encode(&[b; 64]);
        for (label, repeated, stanza) in [
            (
                "Filename",
                format!(
                    "Filename: pool/x.deb\nSHA256: {}\nFilename: pool/y.deb\n",
                    h256(0x22)
                ),
                Stanza::new(),
            ),
            (
                "SHA256",
                format!(
                    "Filename: pool/x.deb\nSHA256: {}\nSHA256: {}\n",
                    h256(0x22),
                    h256(0x33)
                ),
                Stanza::new(),
            ),
            (
                "SHA512",
                format!(
                    "Filename: pool/x.deb\nSHA512: {}\nSHA512: {}\n",
                    h512(0x22),
                    h512(0x33)
                ),
                Stanza::new(),
            ),
            (
                "SHA512 for a SHA256-only consumer",
                format!(
                    "Filename: pool/x.deb\nSHA256: {}\nSHA512: {}\nSHA512: {}\n",
                    h256(0x22),
                    h512(0x22),
                    h512(0x33)
                ),
                Stanza::new_sha256_only(),
            ),
            (
                "an unparsable SHA256 followed by a valid one",
                format!(
                    "Filename: pool/x.deb\nSHA256: nothex\nSHA256: {}\n",
                    h256(0x33)
                ),
                Stanza::new(),
            ),
        ] {
            let input =
                format!("Filename: pool/before.deb\n\n{repeated}\nFilename: pool/after.deb\n");
            let got = collect_stanzas(input.as_bytes(), stanza).await;
            assert_eq!(
                got,
                vec![
                    ("pool/before.deb".to_owned(), None),
                    ("pool/after.deb".to_owned(), None),
                ],
                "repeated {label}"
            );
        }
        // The same at EOF, without a closing blank line.
        let input = format!(
            "Filename: pool/x.deb\nSHA256: {}\nSHA256: {}\n",
            h256(0x22),
            h256(0x33)
        );
        assert_eq!(
            collect_stanzas(input.as_bytes(), Stanza::new()).await,
            [] as [(String, Option<HashAlgo>); 0]
        );
    }

    /// A stanza whose `Filename:` fails the traversal gate is dropped whole:
    /// it must not inherit the next stanza's name or leak its digest into it.
    #[tokio::test]
    async fn stanza_stream_drops_a_stanza_with_an_unsafe_filename() {
        let input = format!(
            "Filename: ../../etc/passwd\nSHA256: {}\n\nFilename: pool/ok.deb\n\n",
            hex_encode(&[0x33; 32]),
        );
        let got = collect_stanzas(input.as_bytes(), Stanza::new()).await;
        assert_eq!(got, vec![("pool/ok.deb".to_owned(), None)]);
    }

    #[tokio::test]
    async fn stanza_stream_empty_input_and_early_exit() {
        let mut stream = StanzaStream::new(&b""[..], Stanza::new());
        assert!(stream.next().await.expect("readable").is_none());
        assert!(stream.next().await.expect("readable").is_none());

        let input = b"Filename: pool/a.deb\n\nFilename: pool/b.deb\n\n";
        let mut stream = StanzaStream::new(&input[..], Stanza::new());
        let first = stream.next().await.expect("readable").expect("first");
        assert_eq!(first.filename(), Some("pool/a.deb"));
        // Leaving the loop here is the early exit; nothing else is read.
        drop(stream);
    }

    /// A tracked field that is not UTF-8 fails the read, whether it comes
    /// first, as the value of a repeat, or as a digest.
    #[tokio::test]
    async fn stanza_stream_fails_on_a_non_utf8_tracked_field_and_ends() {
        let digest = hex_encode(&[0x11; 32]);
        for input in [
            b"Filename: pool/\xff\xfe.deb\n".to_vec(),
            b"Filename: pool/a.deb\nFilename: pool/\xff.deb\n".to_vec(),
            [
                format!("Filename: pool/a.deb\nSHA256: {digest}\nSHA512: ").as_bytes(),
                b"\xff\n",
            ]
            .concat(),
        ] {
            let mut stream = StanzaStream::new(&input[..], Stanza::new());
            let err = stream.next().await.expect_err("not UTF-8");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{input:?}");
            assert_eq!(err.to_string(), "metadata line is not valid UTF-8");
            assert!(stream.next().await.expect("ended").is_none());
        }
    }

    #[tokio::test]
    async fn stanza_stream_ignores_non_utf8_bytes_outside_tracked_fields() {
        let mut input =
            b"Package: \xe9t\xe9\nDescription: \xe9t\xe9 cr\xe8me\n na\xefve\n".to_vec();
        input.extend_from_slice(b"X-\xff: 1\n\xfe\n");
        input.extend_from_slice(
            format!(
                "Filename: pool/a.deb\nSHA256: {}\n\nFilename: pool/b.deb\n",
                hex_encode(&[0x11; 32])
            )
            .as_bytes(),
        );
        let got = collect_stanzas(&input, Stanza::new()).await;
        assert_eq!(
            got,
            vec![
                ("pool/a.deb".to_owned(), Some(HashAlgo::Sha256)),
                ("pool/b.deb".to_owned(), None),
            ]
        );
    }

    #[test]
    fn byhash_digest_decodes_each_algorithm() {
        for (algo, hex) in [
            (
                HashAlgo::Sha256,
                "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba".to_owned(),
            ),
            (HashAlgo::Sha512, "a".repeat(128)),
        ] {
            let digest = byhash_digest_for_algo(algo, &hex).expect("valid hex");
            assert_eq!(digest.algo(), algo);
            assert_eq!(hex_encode(&digest), hex);
        }
    }

    #[test]
    fn byhash_digest_rejects_bad_input() {
        assert!(byhash_digest_for_algo(HashAlgo::Sha256, "").is_none());
        assert!(byhash_digest_for_algo(HashAlgo::Sha256, "deadbeef").is_none()); // too short
        assert!(byhash_digest_for_algo(HashAlgo::Sha256, &"z".repeat(64)).is_none()); // non-hex
        // Length/algo mismatch.
        assert!(byhash_digest_for_algo(HashAlgo::Sha256, &"a".repeat(128)).is_none());
        assert!(byhash_digest_for_algo(HashAlgo::Sha512, &"a".repeat(64)).is_none());
    }

    fn collect_release_byhash_digests(
        content: &str,
    ) -> Result<(Vec<ByHashRef>, ReleaseHashCoverage), &'static str> {
        let mut digests = Vec::new();
        let coverage = parse_release_byhash_digests(content, |digest| digests.push(digest))?;
        Ok((digests, coverage))
    }

    #[test]
    fn strict_release_parser_rejects_malformed_entries_but_ingestion_keeps_valid_rows() {
        let good = format!(
            " {} 1 main/binary-amd64/Packages\n",
            hex_encode(&[0xaa; 32])
        );
        for bad in [
            " bad 1 Packages\n",
            " bad\n",
            " bad -1 Packages\n",
            " bad 18446744073709551616 Packages\n",
            " bad 1 Packages extra\n",
        ] {
            let content = format!("SHA256:\n{good}{bad}");
            assert!(parse_release_byhash_digests(&content, |_| {}).is_err());
            assert_eq!(
                parse_release_checksums(&content, |_| true).collect::<Vec<_>>(),
                [("main/binary-amd64/Packages", [0xaa; 32])]
            );
        }
    }

    #[test]
    fn strict_release_parser_rejects_unindented_rows_without_changing_tolerant_recovery() {
        for (algorithm, width) in [("SHA256", 32), ("SHA512", 64)] {
            let first = hex_encode(&vec![0xaa; width]);
            let second = hex_encode(&vec![0xbb; width]);
            let third = hex_encode(&vec![0xcc; width]);
            for malformed in [
                format!("{second} 2 second/Packages"),
                format!("{second} 2 colon:path/Packages"),
                "not a field".to_owned(),
                "Bad field: value".to_owned(),
                ": empty field name".to_owned(),
                "-broken: value".to_owned(),
                "#broken: value".to_owned(),
            ] {
                let content = format!(
                    "{algorithm}:\n {first} 1 first/Packages\n{malformed}\n {third} 3 third/Packages\nSHA256:\n {} 4 recovered/Packages\n",
                    hex_encode(&[0xdd; 32]),
                );
                assert!(parse_release_byhash_digests(&content, |_| {}).is_err());
                let mut expected = Vec::new();
                if algorithm == "SHA256" {
                    expected.push(("first/Packages", [0xaa; 32]));
                }
                expected.push(("recovered/Packages", [0xdd; 32]));
                assert_eq!(
                    parse_release_checksums(&content, |_| true).collect::<Vec<_>>(),
                    expected,
                    "tolerant ingestion resumes at the next supported section"
                );
            }
        }
    }

    #[test]
    fn release_checksum_sections_allow_real_fields_and_ascii_blank_lines() {
        let digest = hex_encode(&[0xaa; 32]);
        let content = format!(
            "SHA256:\n {digest} 1 first/Packages\n\t \x0c\n\x0c\n {digest} 2 second/Packages\nX-Description#1: extension field\n continuation\nMD5Sum:\n ignored 1 Packages\nSHA512:\n {} 3 third/Packages\n-----BEGIN PGP SIGNATURE-----\nnot a field\n",
            hex_encode(&[0xbb; 64]),
        );
        let (digests, coverage) =
            collect_release_byhash_digests(&content).expect("valid field transitions");
        assert!(coverage.sha256 && coverage.sha512);
        assert_eq!(digests.len(), 3);
    }

    #[test]
    fn release_byhash_digests_sha256_only_ignores_md5() {
        // Debian's `InRelease` carries `MD5Sum:` + `SHA256:` (no SHA512).
        let a = hex_encode(&[0xaa; 32]);
        let b = hex_encode(&[0xbb; 32]);
        let content = format!(
            "Origin: Debian\n\
             MD5Sum:\n \
             {md5} 111 main/binary-amd64/Packages\n\
             SHA256:\n \
             {a} 222 main/binary-amd64/Packages\n \
             {b} 333 main/Contents-amd64\n",
            md5 = hex_encode(&[0xcc; 16]),
        );
        let got: Vec<ByHashRef> = collect_release_byhash_digests(&content)
            .expect("valid Release")
            .0;
        assert_eq!(
            got,
            vec![ByHashRef::Sha256([0xaa; 32]), ByHashRef::Sha256([0xbb; 32])]
        );
    }

    #[test]
    fn release_byhash_digests_both_algos() {
        let s256 = hex_encode(&[0x11; 32]);
        let s512 = hex_encode(&[0x22; 64]);
        let content = format!(
            "SHA256:\n {s256} 10 main/binary-amd64/Packages\n\
             SHA512:\n {s512} 10 main/binary-amd64/Packages\n",
        );
        let got: Vec<ByHashRef> = collect_release_byhash_digests(&content)
            .expect("valid Release")
            .0;
        assert_eq!(
            got,
            vec![ByHashRef::Sha256([0x11; 32]), ByHashRef::Sha512([0x22; 64])]
        );
    }

    #[test]
    fn release_byhash_digests_stops_at_pgp_signature() {
        let inside = hex_encode(&[0x33; 32]);
        let after = hex_encode(&[0x44; 32]);
        let content = format!(
            "SHA256:\n {inside} 10 main/binary-amd64/Packages\n\
             -----BEGIN PGP SIGNATURE-----\n\
             SHA256:\n {after} 10 evil/Packages\n\
             -----END PGP SIGNATURE-----\n",
        );
        let got: Vec<ByHashRef> = collect_release_byhash_digests(&content)
            .expect("valid Release")
            .0;
        assert_eq!(got, vec![ByHashRef::Sha256([0x33; 32])]);
    }

    #[test]
    fn release_byhash_digests_accepts_tab_indent() {
        let d = hex_encode(&[0x55; 32]);
        let content = format!("SHA256:\n\t{d} 10 main/binary-amd64/Packages\n");
        let got: Vec<ByHashRef> = collect_release_byhash_digests(&content)
            .expect("valid Release")
            .0;
        assert_eq!(got, vec![ByHashRef::Sha256([0x55; 32])]);
    }

    #[test]
    fn release_byhash_digests_rejects_space_in_path() {
        let d = hex_encode(&[0x66; 32]);
        let content = format!("SHA256:\n {d} 10 main/with space/Packages\n");
        assert!(parse_release_byhash_digests(&content, |_| {}).is_err());
    }

    #[test]
    fn release_entries_split_on_ascii_whitespace_only() {
        // A no-break space is not a separator: the path keeps it and stays
        // the 3rd token.
        let d = hex_encode(&[0x77; 32]);
        let content = format!("SHA256:\n {d} 10 main/a\u{a0}b/Packages\n");
        assert_eq!(
            collect_release_byhash_digests(&content)
                .expect("valid Release")
                .0,
            vec![ByHashRef::Sha256([0x77; 32])]
        );
    }

    fn stanza_with_filename(filename: &str) -> Stanza {
        let mut stanza = Stanza::new();
        stanza.ingest_text(&format!("Filename: {filename}"));
        stanza
    }

    #[test]
    fn registry_key_for_structured_pool_uses_basename() {
        assert_eq!(
            stanza_with_filename("pool/main/f/foo/foo_1.0_amd64.deb").registry_key(),
            Some("foo_1.0_amd64.deb")
        );
    }

    #[test]
    fn registry_key_strips_leading_dot_slash() {
        assert_eq!(
            stanza_with_filename("./foo_1.0_amd64.deb").registry_key(),
            Some("foo_1.0_amd64.deb")
        );
    }

    #[test]
    fn registry_key_rejects_unsafe_relpath() {
        assert_eq!(stanza_with_filename("../etc/passwd").registry_key(), None);
        assert_eq!(stanza_with_filename("").registry_key(), None);
    }

    #[test]
    fn registry_key_rejects_names_no_cache_file_can_have() {
        let at_cap = "a".repeat(MAX_REGISTRY_KEY_COMPONENT_LEN);
        let over_cap = "a".repeat(MAX_REGISTRY_KEY_COMPONENT_LEN + 1);
        // Only the basename becomes a structured key, so a long directory
        // part does not matter...
        let long_dir = format!("pool/{}{at_cap}", "d/".repeat(1000));
        assert_eq!(
            stanza_with_filename(&long_dir).registry_key(),
            Some(at_cap.as_str())
        );
        // ... but a basename past NAME_MAX, up to the 8 KiB line cap, does.
        for name in [
            over_cap,
            "a".repeat(MAX_METADATA_LINE_LEN - "Filename: pool/".len()),
        ] {
            assert_eq!(
                stanza_with_filename(&format!("pool/{name}")).registry_key(),
                None,
                "{} byte basename",
                name.len()
            );
        }
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
        let entries: Vec<_> = parse_release_checksums(release, |_| true).collect();
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
        let entries: Vec<_> = parse_release_checksums(inrelease, |_| true).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "main/binary-amd64/Packages");
    }

    #[test]
    fn parse_release_rejects_unsafe_path() {
        let release = "\
SHA256:
 1111111111111111111111111111111111111111111111111111111111111111 1 ../../etc/passwd
";
        assert!(parse_release_checksums(release, |_| true).next().is_none());
    }

    #[test]
    fn parse_release_strips_leading_dot_slash() {
        // Flat-repo `Release` files from the same generator prefix their
        // entries the same way; the key must match the request's URI path.
        let release = "\
SHA256:
 1111111111111111111111111111111111111111111111111111111111111111 10 ./Packages
 2222222222222222222222222222222222222222222222222222222222222222 10 ../evil
";
        let entries: Vec<_> = parse_release_checksums(release, |_| true).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "Packages");
        assert_eq!(entries[0].1, [0x11u8; 32]);
    }

    #[test]
    fn parse_release_checksums_filters_on_the_stripped_path() {
        let release = "\
SHA256:
 1111111111111111111111111111111111111111111111111111111111111111 10 ./main/binary-amd64/Packages.xz
 2222222222222222222222222222222222222222222222222222222222222222 10 main/Contents-amd64
 3333333333333333333333333333333333333333333333333333333333333333 10 ../main/binary-amd64/Packages
";
        let mut seen = Vec::new();
        let entries: Vec<_> = parse_release_checksums(release, |path| {
            seen.push(path.to_owned());
            path.ends_with("/Packages.xz")
        })
        .collect();
        assert_eq!(
            entries,
            vec![("main/binary-amd64/Packages.xz", [0x11u8; 32])]
        );
        // An unsafe path never reaches the filter.
        assert_eq!(
            seen,
            ["main/binary-amd64/Packages.xz", "main/Contents-amd64"]
        );
    }

    #[test]
    fn parse_release_checksums_stops_at_pgp_signature() {
        // A `SHA256:` block after the (unsigned) signature boundary must not
        // inject entries into the integrity registry.
        let inrelease = "\
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

SHA256:
 1111111111111111111111111111111111111111111111111111111111111111 10 main/binary-amd64/Packages
-----BEGIN PGP SIGNATURE-----
SHA256:
 2222222222222222222222222222222222222222222222222222222222222222 10 evil/Packages
-----END PGP SIGNATURE-----
";
        let entries: Vec<_> = parse_release_checksums(inrelease, |_| true).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "main/binary-amd64/Packages");
        assert_eq!(entries[0].1, [0x11u8; 32]);
    }

    #[test]
    fn release_date_is_parsed_from_the_header_paragraph() {
        let date = |content| parse_release_header(content).date;
        let release = "Origin: Debian\nDate: Sun, 20 Sep 2026 08:53:33 UTC\nSHA256:\n 00 1 main/binary-amd64/Packages\n";
        assert_eq!(date(release), Some(1_789_894_413));
        let offset = "Date: Sun, 20 Sep 2026 08:53:33 +0000\n";
        assert_eq!(date(offset), Some(1_789_894_413));
        let inrelease = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Debian\nDate: Sun, 20 Sep 2026 08:53:33 UTC\nSHA256:\n";
        assert_eq!(date(inrelease), Some(1_789_894_413));
        assert_eq!(date("Origin: Debian\nSHA256:\n"), None);
        assert_eq!(date("Date: yesterday\n"), None);
        // A `Date:` after a checksum section header is not the header
        // paragraph's; unindented, so only the section cutoff rejects it.
        assert_eq!(date("SHA256:\nDate: Sun, 20 Sep 2026 08:53:33 UTC\n"), None);
    }

    #[test]
    fn valid_until_is_parsed_beside_the_date() {
        let release = "Origin: Debian\nDate: Sun, 20 Sep 2026 08:53:33 UTC\nValid-Until: Sun, 27 Sep 2026 08:53:33 UTC\nSHA256:\n 00 1 main/binary-amd64/Packages\n";
        assert_eq!(
            parse_release_header(release),
            ReleaseHeader {
                date: Some(1_789_894_413),
                valid_until: Some(1_789_894_413 + 7 * 86_400),
            }
        );
        // Clearsigned, the field before the date.
        let inrelease = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nValid-Until: Sun, 27 Sep 2026 08:53:33 +0000\nDate: Sun, 20 Sep 2026 08:53:33 UTC\nSHA256:\n";
        assert_eq!(
            parse_release_header(inrelease).valid_until,
            Some(1_789_894_413 + 7 * 86_400)
        );
        // Absent, and after the checksum section: not the header's.
        assert_eq!(
            parse_release_header("Date: Sun, 20 Sep 2026 08:53:33 UTC\n").valid_until,
            None
        );
        assert_eq!(
            parse_release_header(
                "Date: Sun, 20 Sep 2026 08:53:33 UTC\nSHA256:\nValid-Until: Sun, 27 Sep 2026 08:53:33 UTC\n"
            )
            .valid_until,
            None
        );
        // Unparsable: absent, without hiding the date.
        let bad = parse_release_header("Date: Sun, 20 Sep 2026 08:53:33 UTC\nValid-Until: soon\n");
        assert_eq!((bad.date, bad.valid_until), (Some(1_789_894_413), None));
    }

    #[test]
    fn hex_decode_exact_matches_a_per_digit_reference_on_every_byte() {
        let reference = |b: u8| char::from(b).to_digit(16);
        for b in 0..=u8::MAX {
            // One odd byte among valid digits, at either nibble.
            for input in [[b, b'0'], [b'f', b]] {
                let expected = match (reference(input[0]), reference(input[1])) {
                    (Some(hi), Some(lo)) => {
                        Some([u8::try_from((hi << 4) | lo).expect("two nibbles fit a byte")])
                    }
                    _ => None,
                };
                // Non-ASCII bytes are not a `str` on their own; the
                // decoder only ever sees the bytes.
                let Ok(text) = std::str::from_utf8(&input) else {
                    continue;
                };
                assert_eq!(hex_decode_exact::<1>(text), expected, "{input:?}");
            }
        }
        // A multi-byte character of the right byte length.
        let text = format!("{}\u{e9}", "a".repeat(62));
        assert_eq!(text.len(), 64);
        assert_eq!(hex_decode_exact::<32>(&text), None);
        assert_eq!(
            hex_decode_exact::<4>("0aF9c3E7"),
            Some([0x0a, 0xf9, 0xc3, 0xe7])
        );
        // `const_hex` accepts a `0x` prefix; at the exact length it leaves
        // too few digits and must still be rejected.
        assert_eq!(hex_decode_exact::<4>("0x0aF9c3"), None);
        assert_eq!(hex_decode_exact::<3>("0x0aF9c3"), None);
    }
}
