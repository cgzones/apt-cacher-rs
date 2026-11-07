//! The `cleanup_verified` xattr marker: the memo that says "this exact file
//! (inode, size, mtime) already matched this expected digest", so a cleanup
//! cycle can skip re-hashing it.
//!
//! The marker has two writers — `integrity.rs` stamps it at commit, on the
//! temp file it just hashed and is about to rename, and `cleanup/verify.rs`
//! stamps it after its own verification — and one reader,
//! `cleanup/verify.rs`. It lives here so the `(identity, algo, digest)`
//! contract has a single owner: both writers build the identity through
//! [`FileIdentity::of`], so a field added there reaches every stamp and every
//! comparison rather than silently diverging.

use std::borrow::Cow;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use crate::index_parser::{Digest, HashAlgo, byhash_digest_for_algo, hex_encode};
use crate::xattr_helpers::{self, XattrValue};

/// The on-disk identity a marker is bound to: inode, size and modification
/// time, all taken from one stat.
///
/// The inode catches a re-download (temp file + rename), the size and mtime
/// an in-place rewrite through `write(2)`. Committed cache files are never
/// re-timestamped (`fs_open::touch_volatile_mtime` only renews volatile
/// indexes, which cleanup does not verify), and neither `rename(2)` nor an
/// xattr write moves the mtime, so an unchanged file keeps its identity.
/// ctime would be stricter but is unusable: writing the marker itself bumps
/// it.
///
/// Not covered: bit rot (no metadata changes), a deliberate `utimensat(2)`
/// restoring the old mtime, and a same-size rewrite landing within the same
/// filesystem timestamp tick as the stamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    ino: u64,
    size: u64,
    mtime_secs: i64,
    mtime_nanos: i64,
}

impl FileIdentity {
    /// The identity of the file `meta` was taken from.
    #[must_use]
    pub(crate) fn of(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            ino: meta.ino(),
            size: meta.len(),
            mtime_secs: meta.mtime(),
            mtime_nanos: meta.mtime_nsec(),
        }
    }

    #[cfg(test)]
    const fn new(ino: u64, size: u64, mtime_secs: i64, mtime_nanos: i64) -> Self {
        Self {
            ino,
            size,
            mtime_secs,
            mtime_nanos,
        }
    }
}

/// What a stored marker was bound to.
#[derive(Debug, PartialEq, Eq)]
enum MarkerIdentity {
    /// Stamped by this version: the full [`FileIdentity`].
    Bound(FileIdentity),
    /// Stamped by a version that bound only `(ino, size)`, so it cannot
    /// vouch for the content (an in-place same-size rewrite keeps both).
    /// Parsed rather than rejected because a rejected value is scrubbed with
    /// a "malformed" WARN, which this is not; it never matches, so the file
    /// is re-hashed once and re-stamped in the current form.
    Legacy { ino: u64, size: u64 },
}

/// Xattr recording a successful cleanup digest verification, persisted as
/// `user.apt_cacher_rs.cleanup_verified` =
/// `"{ino}:{size}:{mtime_secs}.{mtime_nanos}:{algo}:{digest-hex}"`.
///
/// A later cycle skips re-hashing when the [`FileIdentity`], algorithm and
/// expected digest all still match — the daily full-cache re-read otherwise
/// scales with total cache size instead of churn. Binding the expected
/// digest means an index update that changes the expected content
/// invalidates the marker automatically; binding the identity means a
/// re-download (a fresh inode) or an in-place rewrite (a new mtime)
/// invalidates it too.
///
/// A by-hash download verified with SHA-512 leaves a SHA-512 marker while
/// cleanup compares against the registry's SHA-256 expectation, so that file
/// is re-hashed once — a missed optimisation, not a correctness gap.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CleanupMarker {
    identity: MarkerIdentity,
    digest: Digest,
}

impl CleanupMarker {
    fn new(identity: FileIdentity, digest: Digest) -> Self {
        Self {
            identity: MarkerIdentity::Bound(identity),
            digest,
        }
    }

    /// Whether the marker was stamped for exactly this file identity and
    /// expected digest. A legacy marker never matches.
    fn matches(&self, identity: FileIdentity, expected: &Digest) -> bool {
        let Self {
            identity: stamped,
            digest,
        } = self;
        let identity_matches = match stamped {
            MarkerIdentity::Bound(stamped) => *stamped == identity,
            MarkerIdentity::Legacy { ino: _, size: _ } => false,
        };
        identity_matches && digest == expected
    }
}

/// Parse `"{sec}.{nsec}"`; `nsec` must be a valid nanosecond count.
fn parse_mtime(raw: &str) -> Option<(i64, i64)> {
    let (sec, nsec) = raw.split_once('.')?;
    let sec = sec.parse().ok()?;
    let nsec = nsec.parse().ok()?;
    (0..1_000_000_000).contains(&nsec).then_some((sec, nsec))
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
        let (ino, rest) = raw.split_once(':')?;
        let (size, rest) = rest.split_once(':')?;
        let (prefix, digest) = rest.rsplit_once(':')?;
        let (mtime, algo) = prefix
            .split_once(':')
            .map_or((None, prefix), |(mtime, algo)| (Some(mtime), algo));
        let ino = ino.parse().ok()?;
        let size = size.parse().ok()?;
        let identity = match mtime {
            Some(mtime) => {
                let (mtime_secs, mtime_nanos) = parse_mtime(mtime)?;
                MarkerIdentity::Bound(FileIdentity {
                    ino,
                    size,
                    mtime_secs,
                    mtime_nanos,
                })
            }
            None => MarkerIdentity::Legacy { ino, size },
        };
        let algo = HashAlgo::parse(algo)?;
        let digest = byhash_digest_for_algo(algo, digest)?;
        Some(Self { identity, digest })
    }

    fn render(&self) -> Cow<'_, str> {
        let Self { identity, digest } = self;
        let algo = digest.algo().as_str();
        let digest = hex_encode(digest);
        Cow::Owned(match identity {
            MarkerIdentity::Bound(FileIdentity {
                ino,
                size,
                mtime_secs,
                mtime_nanos,
            }) => format!("{ino}:{size}:{mtime_secs}.{mtime_nanos:09}:{algo}:{digest}"),
            MarkerIdentity::Legacy { ino, size } => format!("{ino}:{size}:{algo}:{digest}"),
        })
    }
}

/// Whether `file` carries a verified marker matching `identity` and the
/// expected digest. Any read failure or mismatch counts as "not verified"
/// (the caller re-hashes and re-stamps); a malformed marker is scrubbed by
/// the xattr layer.
pub(crate) fn has_valid_marker(
    file: &std::fs::File,
    path: &Path,
    identity: FileIdentity,
    expected: &Digest,
) -> bool {
    xattr_helpers::read::<CleanupMarker>(file, path)
        .is_some_and(|marker| marker.matches(identity, expected))
}

/// Stamp the verified marker after a successful digest match. Best-effort:
/// a failure (logged once by the xattr layer, e.g. a filesystem without
/// xattr support) just means the next cycle re-hashes.
pub(crate) fn stamp(file: &std::fs::File, path: &Path, identity: FileIdentity, expected: &Digest) {
    xattr_helpers::write(file, path, &CleanupMarker::new(identity, expected.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: FileIdentity = FileIdentity::new(42, 1234, 1_789_900_000, 123_456_789);

    #[test]
    fn cleanup_marker_parse_and_render() {
        let digest = [0xabu8; 32];
        let marker = CleanupMarker::new(
            ID,
            Digest::from_bytes(HashAlgo::Sha256, &digest).expect("matching digest length"),
        );
        let rendered = marker.render();
        assert_eq!(
            rendered,
            format!(
                "42:1234:1789900000.123456789:SHA256:{}",
                hex_encode(&digest)
            )
        );
        assert_eq!(CleanupMarker::parse(&rendered), Some(marker));

        let sha512 = [0x11u8; 64];
        let id = FileIdentity::new(7, 0, 5, 0);
        let marker = CleanupMarker::new(
            id,
            Digest::from_bytes(HashAlgo::Sha512, &sha512).expect("matching digest length"),
        );
        assert_eq!(
            marker.render(),
            format!("7:0:5.000000000:SHA512:{}", hex_encode(&sha512))
        );
        assert_eq!(
            CleanupMarker::parse(&marker.render()).as_ref(),
            Some(&marker)
        );
        assert!(marker.matches(
            id,
            &Digest::from_bytes(HashAlgo::Sha512, &sha512).expect("matching digest length")
        ));
        assert!(!marker.matches(
            FileIdentity::new(8, 0, 5, 0),
            &Digest::from_bytes(HashAlgo::Sha512, &sha512).expect("matching digest length")
        ));
        assert!(!marker.matches(
            FileIdentity::new(7, 1, 5, 0),
            &Digest::from_bytes(HashAlgo::Sha512, &sha512).expect("matching digest length")
        ));
        assert!(!marker.matches(id, &Digest::Sha256(Box::new([0u8; 32]))));
        assert!(!marker.matches(
            id,
            &Digest::from_bytes(HashAlgo::Sha512, &[0x22u8; 64]).expect("matching digest length")
        ));

        let hex = hex_encode(&digest);
        assert!(CleanupMarker::parse("").is_none());
        assert!(CleanupMarker::parse("42:1234:SHA256").is_none());
        assert!(CleanupMarker::parse(&format!("x:1234:1.0:SHA256:{hex}")).is_none());
        assert!(CleanupMarker::parse(&format!("42:1234:1.0:MD5:{hex}")).is_none());
        // Digest length must match the algorithm.
        assert!(CleanupMarker::parse(&format!("42:1234:1.0:SHA512:{hex}")).is_none());
        assert!(CleanupMarker::parse(&format!("42:1234:1.0:SHA256:{hex}:extra")).is_none());
        // The mtime needs both halves and a nanosecond count below one second.
        assert!(CleanupMarker::parse(&format!("42:1234:1:SHA256:{hex}")).is_none());
        assert!(CleanupMarker::parse(&format!("42:1234:1.:SHA256:{hex}")).is_none());
        assert!(CleanupMarker::parse(&format!("42:1234:1.1000000000:SHA256:{hex}")).is_none());
        assert!(CleanupMarker::parse(&format!("42:1234:1.-1:SHA256:{hex}")).is_none());
    }

    /// A same-size rewrite in place keeps inode and size; only the mtime
    /// tells it apart, so the marker must not match it.
    #[test]
    fn cleanup_marker_rejects_an_mtime_only_change() {
        let digest = [0x5au8; 32];
        let marker = CleanupMarker::new(
            ID,
            Digest::from_bytes(HashAlgo::Sha256, &digest).expect("matching digest length"),
        );
        assert!(marker.matches(
            ID,
            &Digest::from_bytes(HashAlgo::Sha256, &digest).expect("matching digest length")
        ));
        for rewritten in [
            FileIdentity::new(42, 1234, 1_789_900_001, 123_456_789),
            FileIdentity::new(42, 1234, 1_789_900_000, 123_456_790),
        ] {
            assert!(
                !marker.matches(
                    rewritten,
                    &Digest::from_bytes(HashAlgo::Sha256, &digest).expect("matching digest length")
                ),
                "an mtime change must invalidate the marker: {rewritten:?}"
            );
        }
    }

    /// Pre-epoch mtimes are representable and round-trip.
    #[test]
    fn cleanup_marker_round_trips_a_negative_mtime() {
        let digest = [0x01u8; 32];
        let id = FileIdentity::new(3, 9, -86_400, 1);
        let marker = CleanupMarker::new(
            id,
            Digest::from_bytes(HashAlgo::Sha256, &digest).expect("matching digest length"),
        );
        assert_eq!(
            marker.render(),
            format!("3:9:-86400.000000001:SHA256:{}", hex_encode(&digest))
        );
        assert_eq!(CleanupMarker::parse(&marker.render()), Some(marker));
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
            let marker = CleanupMarker::new(
                FileIdentity::new(9, 4096, 1, 2),
                Digest::from_bytes(algo, &digest).expect("matching digest length"),
            );
            assert_eq!(
                CleanupMarker::parse(&marker.render()).as_ref(),
                Some(&marker),
                "{} marker must survive a render/parse round trip",
                algo.as_str()
            );
        }
    }

    /// A marker an earlier version stamped (`ino:size:algo:digest`) is
    /// accepted -- so the xattr layer neither scrubs it nor warns -- but
    /// vouches for nothing, even when inode and size still agree.
    #[test]
    fn cleanup_marker_accepts_a_legacy_marker_that_never_matches() {
        let digest = [0xabu8; 32];
        let raw = format!("42:1234:SHA256:{}", hex_encode(&digest));
        let marker = CleanupMarker::parse(&raw).expect("a legacy marker parses");
        assert_eq!(
            marker.identity,
            MarkerIdentity::Legacy {
                ino: 42,
                size: 1234
            }
        );
        assert_eq!(
            marker.render(),
            raw,
            "a legacy marker renders back verbatim"
        );
        assert!(!marker.matches(
            ID,
            &Digest::from_bytes(HashAlgo::Sha256, &digest).expect("matching digest length")
        ));
    }

    #[test]
    fn cleanup_marker_scrubs_malformed_and_round_trips() {
        use crate::xattr_helpers::tests::assert_scrubs_malformed_and_round_trips;

        let marker = CleanupMarker::new(
            ID,
            Digest::from_bytes(HashAlgo::Sha256, &[0xcdu8; 32]).expect("matching digest length"),
        );
        assert_scrubs_malformed_and_round_trips(b"42:1234:1.0:SHA256:nothex", &marker);
    }

    /// The legacy form survives a real xattr read: present, not scrubbed,
    /// nothing logged -- and still not valid.
    #[test]
    fn legacy_marker_is_kept_on_disk_but_not_valid() {
        use crate::test_support::levels_during;
        use crate::xattr_helpers::tests::{plant_raw, raw_present};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pkg.deb");
        std::fs::write(&path, b"payload").expect("write");
        let file = std::fs::File::open(&path).expect("open");
        let digest = [0x77u8; 32];
        let raw = format!("1:7:SHA256:{}", hex_encode(&digest));
        if !plant_raw::<CleanupMarker>(&file, raw.as_bytes()) {
            // The filesystem under the temp dir has no user xattrs.
            return;
        }
        let identity = FileIdentity::of(&file.metadata().expect("stat"));
        let levels = levels_during(|| {
            assert!(!has_valid_marker(
                &file,
                &path,
                identity,
                &Digest::from_bytes(HashAlgo::Sha256, &digest).expect("matching digest length")
            ));
        });
        assert!(
            levels.is_empty(),
            "reading a legacy marker must be silent, logged {levels:?}"
        );
        assert!(
            raw_present::<CleanupMarker>(&file),
            "a legacy marker is not malformed and must not be scrubbed"
        );
    }
}
