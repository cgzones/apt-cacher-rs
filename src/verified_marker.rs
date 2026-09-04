//! The `cleanup_verified` xattr marker: the memo that says "this exact file
//! (inode, size) already matched this expected digest", so a cleanup cycle
//! can skip re-hashing it.
//!
//! The marker has two writers — `integrity.rs` stamps it at commit, on the
//! temp file it just hashed and is about to rename, and `cleanup/verify.rs`
//! stamps it after its own verification — and one reader,
//! `cleanup/verify.rs`. It lives here so the `(ino, size, algo, digest)`
//! contract has a single owner: a field added to `CleanupMarker` is then a
//! compile error at both writers rather than a silent divergence.

use std::borrow::Cow;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use crate::index_parser::{HashAlgo, byhash_digest_for_algo, hex_encode};
use crate::xattr_helpers::{self, XattrValue};

/// Xattr recording a successful cleanup digest verification, persisted as
/// `user.apt_cacher_rs.cleanup_verified` = `"{ino}:{size}:{algo}:{digest-hex}"`.
///
/// A later cycle skips re-hashing when inode, size, algorithm, and expected
/// digest all still match — the daily full-cache re-read otherwise scales
/// with total cache size instead of churn. Binding the expected digest
/// means an index update that changes the expected content invalidates the
/// marker automatically; binding `(ino, size)` means any re-download
/// (temp file + rename, so a fresh inode) invalidates it too.
///
/// A by-hash download verified with SHA-512 leaves a SHA-512 marker while
/// cleanup compares against the registry's SHA-256 expectation, so that file
/// is re-hashed once — a missed optimisation, not a correctness gap.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CleanupMarker {
    ino: u64,
    size: u64,
    algo: HashAlgo,
    digest: Vec<u8>,
}

impl CleanupMarker {
    /// `expected` must be the digest `algo` produces: [`Self::parse`] decodes
    /// through `byhash_digest_for_algo`, which cross-checks the length, so a
    /// marker built from a mismatched pair renders a value that never parses
    /// back and silently disables the memo. Both writers pass the digest they
    /// just compared against, so the pairing is structural today.
    pub(crate) fn new(ino: u64, size: u64, algo: HashAlgo, expected: &[u8]) -> Self {
        debug_assert_eq!(
            expected.len(),
            match algo {
                HashAlgo::Sha256 => 32,
                HashAlgo::Sha512 => 64,
            },
            "a marker's digest length must match its algorithm, or `parse` rejects what `render` wrote"
        );
        Self {
            ino,
            size,
            algo,
            digest: expected.to_vec(),
        }
    }

    /// Whether the marker was stamped for exactly this file identity and
    /// expected digest.
    pub(crate) fn matches(&self, ino: u64, size: u64, algo: HashAlgo, expected: &[u8]) -> bool {
        let Self {
            ino: my_ino,
            size: my_size,
            algo: my_algo,
            digest,
        } = self;
        *my_ino == ino && *my_size == size && *my_algo == algo && digest == expected
    }
}

impl XattrValue for CleanupMarker {
    const KEY: &'static str = "user.apt_cacher_rs.cleanup_verified";
    const LABEL: &'static str = "cleanup verification marker";
    // Without any log a per-file stamp failure is indistinguishable from
    // working memoization, and every cycle silently re-hashes the whole cache.
    const WRITE_FAILURE_CONSEQUENCE: &'static str =
        "digest verification is not memoized and every cleanup cycle re-hashes this file";

    fn discard_gate() -> &'static AtomicBool {
        static GATE: AtomicBool = AtomicBool::new(false);
        &GATE
    }

    fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.split(':');
        let ino = parts.next()?.parse().ok()?;
        let size = parts.next()?.parse().ok()?;
        let algo = HashAlgo::parse(parts.next()?)?;
        let digest = byhash_digest_for_algo(algo, parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            ino,
            size,
            algo,
            digest,
        })
    }

    fn render(&self) -> Cow<'_, str> {
        let Self {
            ino,
            size,
            algo,
            digest,
        } = self;
        Cow::Owned(format!(
            "{ino}:{size}:{}:{}",
            algo.as_str(),
            hex_encode(digest)
        ))
    }
}

/// Whether `file` carries a verified marker matching the current identity
/// and expected digest. Any read failure or mismatch counts as "not
/// verified" (the caller re-hashes and re-stamps); a malformed marker is
/// scrubbed by the xattr layer.
pub(crate) fn has_valid_marker(
    file: &std::fs::File,
    path: &Path,
    ino: u64,
    size: u64,
    algo: HashAlgo,
    expected: &[u8],
) -> bool {
    xattr_helpers::read::<CleanupMarker>(file, path)
        .is_some_and(|marker| marker.matches(ino, size, algo, expected))
}

/// Stamp the verified marker after a successful digest match. Best-effort:
/// a failure (logged once by the xattr layer, e.g. a filesystem without
/// xattr support) just means the next cycle re-hashes.
pub(crate) fn stamp(
    file: &std::fs::File,
    path: &Path,
    ino: u64,
    size: u64,
    algo: HashAlgo,
    expected: &[u8],
) {
    xattr_helpers::write(file, path, &CleanupMarker::new(ino, size, algo, expected));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_marker_parse_and_render() {
        let digest = [0xabu8; 32];
        let marker = CleanupMarker::new(42, 1234, HashAlgo::Sha256, &digest);
        let rendered = marker.render();
        assert_eq!(rendered, format!("42:1234:SHA256:{}", hex_encode(&digest)));
        assert_eq!(CleanupMarker::parse(&rendered), Some(marker));

        let sha512 = [0x11u8; 64];
        let marker = CleanupMarker::new(7, 0, HashAlgo::Sha512, &sha512);
        assert_eq!(
            CleanupMarker::parse(&marker.render()).as_ref(),
            Some(&marker)
        );
        assert!(marker.matches(7, 0, HashAlgo::Sha512, &sha512));
        assert!(!marker.matches(8, 0, HashAlgo::Sha512, &sha512));
        assert!(!marker.matches(7, 1, HashAlgo::Sha512, &sha512));
        assert!(!marker.matches(7, 0, HashAlgo::Sha256, &sha512));
        assert!(!marker.matches(7, 0, HashAlgo::Sha512, &[0x22u8; 64]));

        let hex = hex_encode(&digest);
        assert!(CleanupMarker::parse("").is_none());
        assert!(CleanupMarker::parse("42:1234:SHA256").is_none());
        assert!(CleanupMarker::parse(&format!("x:1234:SHA256:{hex}")).is_none());
        assert!(CleanupMarker::parse(&format!("42:1234:MD5:{hex}")).is_none());
        // Digest length must match the algorithm.
        assert!(CleanupMarker::parse(&format!("42:1234:SHA512:{hex}")).is_none());
        assert!(CleanupMarker::parse(&format!("42:1234:SHA256:{hex}:extra")).is_none());
    }

    #[test]
    fn cleanup_marker_round_trips_every_algorithm() {
        // `render` -> `parse` must be lossless for both algorithms, or a
        // stamped marker is scrubbed on the next read and every cleanup cycle
        // re-hashes the file it was supposed to memoize.
        for (algo, digest) in [
            (HashAlgo::Sha256, vec![0x5au8; 32]),
            (HashAlgo::Sha512, vec![0xa5u8; 64]),
        ] {
            let marker = CleanupMarker::new(9, 4096, algo, &digest);
            assert_eq!(
                CleanupMarker::parse(&marker.render()).as_ref(),
                Some(&marker),
                "{} marker must survive a render/parse round trip",
                algo.as_str()
            );
        }
    }

    #[test]
    fn cleanup_marker_scrubs_malformed_and_round_trips() {
        use crate::xattr_helpers::tests::assert_scrubs_malformed_and_round_trips;

        let marker = CleanupMarker::new(42, 1234, HashAlgo::Sha256, &[0xcdu8; 32]);
        assert_scrubs_malformed_and_round_trips(b"42:1234:SHA256:nothex", &marker);
    }
}
