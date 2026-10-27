use std::ffi::{OsStr, OsString};
use std::io;
use std::num::NonZero;
use std::path::Path;

use hashbrown::HashMap;
use tracing::{debug, error, warn};

use crate::{
    cache_layout::CacheLayout,
    deb_mirror::Mirror,
    error::ErrorReport,
    index_parser::{Stanza, StanzaStream, hex_encode, structured_lookup_key},
    limits::{PackagesCompression, check_packages_file_size, decompressed_limit, packages_reader},
    metrics,
    mirror_health::{self, MirrorFault},
};

use super::engine::{SpanClass, UnitStats};
use super::fetch::FetchedPackages;
use super::sweep::invalidate_metadata_for;
use super::verify::{Verdict, verify_cache_file};

/// How a `Filename:` value from a Packages stanza maps to a key in the
/// scanned candidate map.
#[derive(Clone, Copy)]
pub(super) enum KeyMapper<'a> {
    /// Structured pool: the cache flattens to basename.
    Basename,
    /// Flat repo, Packages co-located with the mirror root: key = relpath.
    Relpath,
    /// Flat repo, Packages fetched from an ancestor: `Filename:` values are
    /// relative to that ancestor. Keep only entries under `prefix` (which
    /// carries a trailing `/`); strip it. Entries outside the subtree map to
    /// `None` (they belong to a sibling).
    RelpathUnderPrefix { prefix: &'a str },
}

impl KeyMapper<'_> {
    pub(super) fn map<'a>(&self, filename: &'a str) -> Option<&'a str> {
        match self {
            Self::Basename => Some(structured_lookup_key(filename)),
            Self::Relpath => Some(filename),
            Self::RelpathUnderPrefix { prefix } => filename.strip_prefix(prefix),
        }
    }
}

/// Per-call context for [`reduce_file_list`]: needed to invalidate
/// per-file `cache_metadata` entries and to attribute checksum-mismatch
/// removals back to the per-mirror `CleanupDone` totals.
pub(super) struct ReduceContext<'a> {
    /// Tree root the candidate keys are relative to; a matched key is rejoined
    /// onto it to reach the cached file.
    pub(super) root: &'a Path,
    pub(super) mirror: &'a Mirror,
    pub(super) layout: CacheLayout,
    /// The unit's running tally; checksum-mismatch evictions are accounted
    /// straight into it, so deletions performed before a mid-cascade group
    /// failure are never lost.
    pub(super) tally: &'a mut UnitStats,
    /// Derives the lookup key from a `Filename:` relpath.
    pub(super) keymap: KeyMapper<'a>,
}

/// Process one stanza: if its `Filename:` value resolves to a candidate
/// cached file, verify the file content and either retain it (match), warn-
/// and-retain it (no usable hash advertised, transient error, or concurrent
/// rename race), or warn-and-evict it (genuine digest mismatch).
///
/// The `Filename:` field is a full relative path from the repo root.  For
/// structured archives the on-disk cache flattens that to the basename, so
/// the lookup key is the basename portion.  For flat archives the URL path
/// is the on-disk path verbatim, so the lookup key is the relpath itself.
async fn process_stanza(
    stanza: &Stanza,
    file_list: &mut HashMap<OsString, SpanClass>,
    ctx: &mut ReduceContext<'_>,
) {
    let Some(filename) = stanza.filename() else {
        return;
    };

    let Some(lookup_key) = ctx.keymap.map(filename) else {
        return;
    };

    // Every path below drops the entry from the reference set, so take it out
    // once rather than looking it up again per exit.
    if file_list.remove(OsStr::new(lookup_key)).is_none() {
        return;
    }
    let Some((algo, expected)) = stanza.chosen() else {
        // Retained without verification; `StanzaStream` already warned about
        // the digest-less stanza.
        return;
    };
    let path = ctx.root.join(lookup_key);

    // No pre-verify stat: `verify_file_sync` opens the file `O_NOFOLLOW |
    // O_NONBLOCK` and `fstat`s the descriptor it actually hashed, so it detects
    // a concurrent type swap without a second syscall (and without the
    // lstat-then-open race an extra stat would only narrow).
    match verify_cache_file(path.clone(), algo, expected.to_vec()).await {
        Verdict::Match => {}
        Verdict::NonRegular => {
            warn!(
                "Cache file `{}` changed to non-regular between cleanup-collect and verify (concurrent swap); retaining without verification",
                path.display(),
            );
        }
        Verdict::Mismatch {
            computed,
            size: pre_size,
        } => {
            warn!(
                "Cache file `{}` failed {} verification (expected {}, computed {}); removing it",
                path.display(),
                algo.as_str(),
                hex_encode(expected),
                hex_encode(&computed),
            );
            if let Err(err) = tokio::fs::remove_file(&path).await {
                ctx.tally.io_failures += 1;
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to remove checksum-mismatched cache file `{}`; retaining it:  {}",
                    path.display(),
                    ErrorReport(&err)
                );
            } else {
                invalidate_metadata_for(&path, ctx.mirror, ctx.layout);
                metrics::CLEANUP_CHECKSUM_MISMATCHES.increment();
                mirror_health::record(ctx.mirror, MirrorFault::Checksum);
                ctx.tally.record_mismatch(pre_size);
            }
        }
        Verdict::Vanished => {
            debug!(
                "Cache entry `{}` vanished before it could be verified; skipping it",
                path.display(),
            );
        }
        Verdict::Raced => {
            warn!(
                "Cache file `{}` changed during {} verification; retaining (concurrent re-cache)",
                path.display(),
                algo.as_str(),
            );
        }
        Verdict::IoError(err) => {
            ctx.tally.io_failures += 1;
            error!(
                "Failed to verify cache file `{}` against its {} digest; retaining it:  {}",
                path.display(),
                algo.as_str(),
                ErrorReport(&err),
            );
        }
    }
}

/// Why a fetched `Packages` index could not be reduced against the candidate
/// set.  Carries the cause only: the resolver receiving it decides the
/// consequence (bail the mirror, continue with the next index source, fall
/// back to age-based retention) and logs the one line, with this rendered
/// through `ErrorReport` after it.  `filename` is the fetched index's
/// [`FetchedPackages::name`], which identifies the origin's index.
#[derive(Debug, thiserror::Error)]
pub(super) enum ReduceError {
    /// A gzip/xz index of zero bytes is malformed (both formats need at least
    /// a header), never "no stanzas" - only a raw index may be empty.
    #[error("compressed Packages index `{filename}` is zero bytes")]
    ZeroSizeCompressed { filename: String },
    /// Larger than `limits::packages_file_cap` allows; refused undecoded.
    #[error("Packages index `{filename}` is too large to decode")]
    TooLarge {
        filename: String,
        #[source]
        source: io::Error,
    },
    /// Decode/read failure, including the decompressed-size and line caps
    /// and a decompression bomb.
    #[error("failed to read Packages index `{filename}` (may exceed the size or line limit)")]
    Read {
        filename: String,
        #[source]
        source: io::Error,
    },
}

/// Stream a (possibly compressed) Debian `Packages` file stanza by stanza,
/// reducing the candidate `file_list` by basename and verifying matched
/// cache files against the stanza's `SHA256:`/`SHA512:` digest.
///
/// Cleanup is conservative about an index it cannot read in full: an unreadable
/// or malformed file bails the mirror this cycle rather than reconciling against
/// a partial reference set (which would grace-sweep still-referenced debs). That
/// is the deliberate difference from `integrity::ingest_packages_file`, which
/// shares the decode ladder via [`packages_reader`] and the stanza loop via
/// [`StanzaStream`] but degrades to a less-populated registry instead.  The
/// `Err` is the cause alone; the resolver logs it with its consequence.
pub(super) async fn reduce_file_list(
    index: FetchedPackages,
    file_list: &mut HashMap<OsString, SpanClass>,
    ctx: &mut ReduceContext<'_>,
    buffer_size: usize,
) -> Result<(), ReduceError> {
    debug_assert!(!file_list.is_empty(), "avoid unnecessary work");

    let FetchedPackages {
        compression,
        name: filename,
        file,
        len,
    } = index;

    check_packages_file_size(compression, len).map_err(|source| ReduceError::TooLarge {
        filename: filename.clone(),
        source,
    })?;

    let Some(compressed_size) = NonZero::new(len) else {
        return match compression {
            // A raw Packages file with zero stanzas is legal (e.g.
            // a freshly-created component with no published debs); the
            // read loop would hit EOF immediately and treat
            // file_list as the empty reference set, which is the
            // correct cleanup behaviour. Avoid turning that into a
            // mirror-cleanup failure.
            PackagesCompression::Raw => Ok(()),
            // For compressed formats an empty file is malformed:
            // both gzip and xz require at least a header.
            PackagesCompression::Gz | PackagesCompression::Xz => {
                Err(ReduceError::ZeroSizeCompressed { filename })
            }
        };
    };

    let reader = packages_reader(
        file,
        compression,
        decompressed_limit(Some(compressed_size)),
        buffer_size,
    )
    .await;

    // `filename` is the synthetic memfd name, so name the mirror as well.
    let mut stanzas = StanzaStream::new(
        reader,
        Stanza::new().with_source(format!("mirror {} index `{filename}`", ctx.mirror)),
    );
    loop {
        match stanzas.next().await {
            Ok(Some(stanza)) => {
                process_stanza(stanza, file_list, ctx).await;
                // Every candidate is referenced: nothing left to reduce.
                if file_list.is_empty() {
                    return Ok(());
                }
            }
            Ok(None) => return Ok(()),
            Err(source) => {
                return Err(ReduceError::Read { filename, source });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    const BUFFER_SIZE: usize = 32 * 1024;

    use super::*;

    use crate::{
        config::ClientHost,
        deb_mirror::MirrorKind,
        index_parser::{HashAlgo, hex_decode_exact, parse_filename_field},
        limits::{MAX_COMPRESSED_PACKAGES_SIZE, MAX_METADATA_LINE_LEN},
        test_support::structured_mirror,
    };

    /// A test fixture as the fetch would hand it over: the whole file,
    /// sized by a stat.
    async fn fetched(
        compression: PackagesCompression,
        file: tokio::fs::File,
        name: &str,
    ) -> FetchedPackages {
        let len = file.metadata().await.expect("stat fixture").len();
        FetchedPackages {
            compression,
            name: name.to_owned(),
            file,
            len,
        }
    }

    /// A candidate map for the reduce tests: every entry is `Deb`-class and
    /// keyed by its path relative to the `ReduceContext` root.
    fn cands(keys: &[&str]) -> HashMap<OsString, SpanClass> {
        keys.iter()
            .map(|k| (OsString::from(*k), SpanClass::Deb))
            .collect()
    }

    #[test]
    fn key_mapper_maps_each_layout() {
        // Structured: basename of the relpath.
        assert_eq!(
            KeyMapper::Basename.map("pool/main/a/abc/abc_1.0_amd64.deb"),
            Some("abc_1.0_amd64.deb"),
        );
        // Flat co-located: relpath verbatim.
        assert_eq!(
            KeyMapper::Relpath.map("amd64/twilio-cli_5.0.0_amd64.deb"),
            Some("amd64/twilio-cli_5.0.0_amd64.deb"),
        );
        // Flat walk-up: strip the prefix, drop siblings outside it.
        let km = KeyMapper::RelpathUnderPrefix { prefix: "amd64/" };
        assert_eq!(km.map("amd64/pkg.deb"), Some("pkg.deb"));
        assert_eq!(km.map("arm64/sibling.deb"), None);
    }

    #[test]
    fn parse_filename_field_strips_lf() {
        assert_eq!(
            parse_filename_field("Filename: pool/main/a/abc/abc_1.0_amd64.deb\n"),
            Some("pool/main/a/abc/abc_1.0_amd64.deb"),
        );
    }

    #[test]
    fn parse_filename_field_strips_crlf() {
        assert_eq!(
            parse_filename_field("Filename: pool/main/a/abc/abc_1.0_amd64.deb\r\n"),
            Some("pool/main/a/abc/abc_1.0_amd64.deb"),
        );
    }

    #[test]
    fn parse_filename_field_no_terminator() {
        assert_eq!(
            parse_filename_field("Filename: pool/main/a/abc/abc_1.0_amd64.deb"),
            Some("pool/main/a/abc/abc_1.0_amd64.deb"),
        );
    }

    #[test]
    fn parse_filename_field_handles_udeb_extension() {
        assert_eq!(
            parse_filename_field("Filename: pool/main/i/inst/inst_1.0_amd64.udeb\n"),
            Some("pool/main/i/inst/inst_1.0_amd64.udeb"),
        );
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
        // Path-traversal hardening: an attacker-controlled upstream
        // Packages stanza must not be able to inject `..` segments or
        // absolute paths that could later be joined to a filesystem path.
        assert_eq!(
            parse_filename_field("Filename: ../../../etc/passwd\n"),
            None,
        );
        assert_eq!(parse_filename_field("Filename: pool/../escape.deb\n"), None);
        assert_eq!(parse_filename_field("Filename: /etc/shadow\n"), None);
        assert_eq!(parse_filename_field("Filename: a//b.deb\n"), None);
        // A leading `./` is NOT traversal and is normalised away rather than
        // rejected (flat archives publish every stanza that way); a `..`
        // behind it still is.
        assert_eq!(
            parse_filename_field("Filename: ./foo.deb\n"),
            Some("foo.deb"),
        );
        assert_eq!(parse_filename_field("Filename: ./../escape.deb\n"), None);
        assert_eq!(
            parse_filename_field("Filename: pool\\main\\evil.deb\n"),
            None,
        );
        // NUL byte rejection — Rust strings allow `\0`; rust source uses
        // an explicit escape to materialise the test input.
        assert_eq!(parse_filename_field("Filename: pool/x\0y.deb\n"), None,);
        // Other ASCII control characters (tab, vertical tab, bare CR/LF
        // embedded mid-segment, etc.) are likewise rejected so they can
        // never reach a downstream HashMap lookup or future filesystem
        // join.
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
    fn hex_decode_exact_round_trip_lowercase() {
        let bytes: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let s = hex_encode(&bytes);
        assert_eq!(s, "deadbeef");
        assert_eq!(hex_decode_exact::<4>(&s), Some(bytes));
    }

    #[test]
    fn hex_decode_exact_accepts_uppercase() {
        assert_eq!(
            hex_decode_exact::<4>("DEADBEEF"),
            Some([0xde, 0xad, 0xbe, 0xef])
        );
    }

    #[test]
    fn hex_decode_exact_rejects_wrong_length() {
        assert_eq!(hex_decode_exact::<4>("deadbe"), None); // too short
        assert_eq!(hex_decode_exact::<4>("deadbeef00"), None); // too long
    }

    #[test]
    fn hex_decode_exact_rejects_non_hex() {
        assert_eq!(hex_decode_exact::<4>("deadbeeg"), None);
        assert_eq!(hex_decode_exact::<4>("deadbe!f"), None);
    }

    #[test]
    fn stanza_chosen_falls_back_to_sha512() {
        let mut s = Stanza::new();
        s.sha512 = Some([0x33u8; 64]);
        assert_eq!(
            s.chosen(),
            Some((HashAlgo::Sha512, [0x33u8; 64].as_slice()))
        );
    }

    #[test]
    fn stanza_chosen_returns_none_without_hash() {
        let s = Stanza::new();
        assert_eq!(s.chosen(), None);
    }

    #[test]
    fn stanza_ingest_ignores_unrelated_lines() {
        let mut s = Stanza::new();
        s.ingest("Package: stub\n");
        s.ingest("Description: a stub\n");
        s.ingest(" continued description text\n");
        assert_eq!(s.filename(), None);
        assert_eq!(s.chosen(), None);
    }

    #[tokio::test]
    async fn process_stanza_flat_prefix_strips_in_subtree_and_drops_siblings() {
        // Regression guard for the walk-up flat-cleanup case: when a flat
        // mirror at `apt/amd64` reuses a Packages index fetched at the
        // ancestor `apt/`, `Filename:` values are relative to `apt/`. The
        // process_stanza prefix logic must (a) ignore sibling-subtree
        // entries (`arm64/*`), and (b) strip the `amd64/` prefix to find
        // the basename-keyed entry inside our subtree.
        use std::num::NonZero;

        let mut file_list = cands(&["pkg.deb", "other.deb"]);

        let mirror = Mirror::new(
            ClientHost::new("example.com").expect("valid host"),
            None::<NonZero<u16>>,
            "apt/amd64".to_owned(),
            MirrorKind::Flat,
        );
        let mut tally = UnitStats::default();

        // Sibling subtree: `arm64/sibling.deb` does not start with the
        // `amd64/` prefix — must be a no-op on file_list.
        {
            let mut ctx = ReduceContext {
                root: Path::new("/tmp/cache"),
                mirror: &mirror,
                layout: CacheLayout::Flat,
                tally: &mut tally,
                keymap: KeyMapper::RelpathUnderPrefix { prefix: "amd64/" },
            };
            let mut stanza = Stanza::new();
            stanza.ingest("Filename: arm64/sibling.deb\n");
            process_stanza(&stanza, &mut file_list, &mut ctx).await;
        }
        assert_eq!(file_list.len(), 2);
        assert!(file_list.contains_key(OsStr::new("pkg.deb")));
        assert!(file_list.contains_key(OsStr::new("other.deb")));

        // In-subtree: `amd64/pkg.deb` strips to `pkg.deb`; with no SHA
        // advertised, the stanza warn-retains and removes the lookup key.
        {
            let mut ctx = ReduceContext {
                root: Path::new("/tmp/cache"),
                mirror: &mirror,
                layout: CacheLayout::Flat,
                tally: &mut tally,
                keymap: KeyMapper::RelpathUnderPrefix { prefix: "amd64/" },
            };
            let mut stanza = Stanza::new();
            stanza.ingest("Filename: amd64/pkg.deb\n");
            process_stanza(&stanza, &mut file_list, &mut ctx).await;
        }
        assert!(!file_list.contains_key(OsStr::new("pkg.deb")));
        assert!(file_list.contains_key(OsStr::new("other.deb")));
    }

    #[tokio::test]
    async fn reduce_file_list_rejects_decompression_bomb() {
        use std::num::NonZero;

        use async_compression::tokio::write::GzipEncoder;
        use tokio::io::AsyncWriteExt as _;

        // 4 MiB of newlines compresses to a few KiB -- a ratio far above the cap.
        let raw = vec![b'\n'; 4 * 1024 * 1024];
        let mut encoder = GzipEncoder::new(Vec::new());
        encoder.write_all(&raw).await.expect("gzip write");
        encoder.shutdown().await.expect("gzip finish");
        let compressed = encoder.into_inner();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages.gz");
        tokio::fs::write(&path, &compressed)
            .await
            .expect("write fixture");
        let file = tokio::fs::File::open(&path).await.expect("open fixture");

        // Mirror the EXACT Mirror / ReduceContext construction used by the
        // existing process_stanza_flat_prefix_strips_in_subtree_and_drops_siblings
        // test in this module.
        let mirror = Mirror::new(
            ClientHost::new("example.com").expect("valid host"),
            None::<NonZero<u16>>,
            "apt/amd64".to_owned(),
            MirrorKind::Flat,
        );
        // A non-matching entry keeps `file_list` non-empty so the reducer
        // streams the whole (bomb) input instead of early-returning.
        let mut file_list = cands(&["never-matched.deb"]);
        let mut tally = UnitStats::default();
        let mut ctx = ReduceContext {
            root: Path::new("/tmp"),
            mirror: &mirror,
            layout: CacheLayout::Flat,
            tally: &mut tally,
            keymap: KeyMapper::RelpathUnderPrefix { prefix: "amd64/" },
        };

        let result = reduce_file_list(
            fetched(PackagesCompression::Gz, file, "Packages.gz").await,
            &mut file_list,
            &mut ctx,
            BUFFER_SIZE,
        )
        .await;
        let err = result.expect_err("a decompression bomb must abort reduce_file_list");
        assert!(
            matches!(err, ReduceError::Read { ref filename, .. } if filename == "Packages.gz"),
            "a decompression bomb is a read failure of the named index, got {err:?}"
        );
    }

    /// A compressed index past `MAX_COMPRESSED_PACKAGES_SIZE` is refused on
    /// its size, before the decoder sees a byte (the sparse fixture holds no
    /// valid xz header, so a decode attempt would fail differently).
    #[tokio::test]
    async fn reduce_file_list_refuses_an_oversized_compressed_index_unread() {
        use std::num::NonZero;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages.xz");
        let std_file = std::fs::File::create(&path).expect("create fixture");
        std_file
            .set_len(MAX_COMPRESSED_PACKAGES_SIZE.get() + 1)
            .expect("extend sparse");
        drop(std_file);
        let file = tokio::fs::File::open(&path).await.expect("open fixture");

        let mirror = Mirror::new(
            ClientHost::new("example.com").expect("valid host"),
            None::<NonZero<u16>>,
            "apt/amd64".to_owned(),
            MirrorKind::Flat,
        );
        let mut file_list = cands(&["never-matched.deb"]);
        let mut tally = UnitStats::default();
        let mut ctx = ReduceContext {
            root: Path::new("/tmp"),
            mirror: &mirror,
            layout: CacheLayout::Flat,
            tally: &mut tally,
            keymap: KeyMapper::RelpathUnderPrefix { prefix: "amd64/" },
        };

        let err = reduce_file_list(
            fetched(PackagesCompression::Xz, file, "Packages.xz").await,
            &mut file_list,
            &mut ctx,
            BUFFER_SIZE,
        )
        .await
        .expect_err("an oversized compressed index must bail the mirror");
        assert!(
            matches!(err, ReduceError::TooLarge { ref filename, .. } if filename == "Packages.xz"),
            "got {err:?}"
        );
        assert_eq!(file_list.len(), 1, "the candidates must be left untouched");
    }

    /// A zero-byte compressed index is malformed (gzip needs at least a
    /// header): the mirror bails with `ZeroSizeCompressed` and the candidate
    /// list is left untouched rather than reconciled against nothing.
    #[tokio::test]
    async fn reduce_file_list_rejects_empty_compressed_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages.gz");
        tokio::fs::write(&path, b"").await.expect("write empty");
        let file = tokio::fs::File::open(&path).await.expect("open empty");

        let mirror = structured_mirror("example.com", "debian");
        let mut file_list = cands(&["keep-me.deb"]);
        let mut tally = UnitStats::default();
        let mut ctx = ReduceContext {
            root: Path::new("/tmp"),
            mirror: &mirror,
            layout: CacheLayout::StructuredPool,
            tally: &mut tally,
            keymap: KeyMapper::Basename,
        };

        let err = reduce_file_list(
            fetched(PackagesCompression::Gz, file, "Packages.gz").await,
            &mut file_list,
            &mut ctx,
            BUFFER_SIZE,
        )
        .await
        .expect_err("an empty compressed index must bail the mirror");
        assert!(
            matches!(err, ReduceError::ZeroSizeCompressed { ref filename } if filename == "Packages.gz"),
            "got {err:?}"
        );
        assert_eq!(file_list.len(), 1);
        assert!(
            file_list.contains_key(OsStr::new("keep-me.deb")),
            "a rejected index must leave the candidate list untouched"
        );
    }

    #[tokio::test]
    async fn reduce_file_list_skips_overlong_line_and_keeps_parsing() {
        use sha2::{Digest as _, Sha256};

        use crate::index_parser::hex_encode;

        // Pre-compute SHA256(b"payload") so the stanza yields a `Match`
        // verdict — the `Mismatch` path would call into the cache_metadata
        // singleton which isn't initialized under `cargo test`.
        let deb_body: &[u8] = b"payload";
        let deb_hash: [u8; 32] = Sha256::digest(deb_body).into();

        // Build a stanza whose `Provides:` field is far longer than the
        // per-line cap (mirroring the real `experimental_main` layout where
        // packages like `librust-ruma` carry ~19 KiB Provides lists) — the
        // parser must skip the line and still extract Filename+SHA256.
        let mut raw = Vec::new();
        raw.extend_from_slice(b"Package: dummy\n");
        raw.extend_from_slice(b"Filename: pool/d/dummy/dummy_1.0_amd64.deb\n");
        raw.extend_from_slice(b"Provides: ");
        raw.resize(raw.len() + MAX_METADATA_LINE_LEN + 1024, b'a');
        raw.push(b'\n');
        let sha_line = format!("SHA256: {}\n", hex_encode(&deb_hash));
        raw.extend_from_slice(sha_line.as_bytes());
        raw.extend_from_slice(b"\n");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages");
        tokio::fs::write(&path, &raw).await.expect("write fixture");
        let file = tokio::fs::File::open(&path).await.expect("open fixture");

        let mirror = structured_mirror("example.com", "debian");
        // `dummy_1.0_amd64.deb` is the structured-lookup-key (basename) of
        // the Filename: above; reaching `StanzaStream::complete` with the stanza
        // intact removes the entry from the candidate list, proving the
        // parser kept its place through the oversize line.
        tokio::fs::write(dir.path().join("dummy_1.0_amd64.deb"), deb_body)
            .await
            .expect("write deb");
        let mut file_list = cands(&["dummy_1.0_amd64.deb", "keep-me.deb"]);
        let mut tally = UnitStats::default();
        let mut ctx = ReduceContext {
            root: dir.path(),
            mirror: &mirror,
            layout: CacheLayout::StructuredPool,
            tally: &mut tally,
            keymap: KeyMapper::Basename,
        };

        reduce_file_list(
            fetched(PackagesCompression::Raw, file, "Packages").await,
            &mut file_list,
            &mut ctx,
            BUFFER_SIZE,
        )
        .await
        .expect("oversize lines must be skipped, not aborted");

        assert!(
            !file_list.contains_key(OsStr::new("dummy_1.0_amd64.deb")),
            "matching stanza after a skipped line must still remove the file"
        );
        assert!(
            file_list.contains_key(OsStr::new("keep-me.deb")),
            "unrelated entries must be left in place"
        );
    }

    /// A zero-length raw `Packages` file is a valid empty stanza set
    /// (e.g. a freshly-created component with no published debs) and
    /// must not abort the per-mirror cleanup.
    #[tokio::test]
    async fn reduce_file_list_accepts_empty_raw_packages() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages");
        tokio::fs::write(&path, b"").await.expect("write empty");
        let file = tokio::fs::File::open(&path).await.expect("open empty");

        let mirror = structured_mirror("example.com", "debian");
        let mut file_list = cands(&["keep-me.deb"]);
        let mut tally = UnitStats::default();
        let mut ctx = ReduceContext {
            root: Path::new("/tmp"),
            mirror: &mirror,
            layout: CacheLayout::StructuredPool,
            tally: &mut tally,
            keymap: KeyMapper::Basename,
        };

        reduce_file_list(
            fetched(PackagesCompression::Raw, file, "Packages").await,
            &mut file_list,
            &mut ctx,
            BUFFER_SIZE,
        )
        .await
        .expect("an empty raw Packages file must be treated as zero stanzas");

        assert!(
            file_list.contains_key(OsStr::new("keep-me.deb")),
            "empty Packages must leave the candidate list untouched"
        );
    }
}
