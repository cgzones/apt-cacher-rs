//! One directory walker for every pass over the cache tree.
//!
//! The startup / post-cleanup size scan (`task_cache_scan`), the dashboard
//! size walk (`web`) and every cleanup unit (`cleanup/`) used to
//! each hand-roll a `read_dir` / `next_entry` / `file_type` loop, and with it
//! the "Failed to read / iterate / inspect" error lines, the
//! `CACHE_IO_FAILURE` bumps and the anomaly taxonomy:
//!
//! - A `read_dir` / `next_entry` failure is an `error!` + `CACHE_IO_FAILURE`;
//!   [`DirFailure`] says whether the walk ends or carries on.
//! - A vanished entry or directory (`NotFound` after it was listed) is a
//!   concurrent removal, not an I/O failure: `debug!`, no counter.
//! - A symlink / FIFO / socket / device is reported on sight (at the walk's
//!   [`AnomalyLevel`] + `CACHE_NON_REGULAR`) and still handed to the caller
//!   as [`EntryKind::NonRegular`] so cleanup can unlink it.
//! - A directory or regular file is *classified* by the caller: what is a
//!   stray entry depends on where the walk is (a `dists/` directory is fine
//!   in a mirror root, not in a pool).  The caller reports one via
//!   [`Entry::report_unexpected`], which owns the `CACHE_DIRECTORY_UNEXPECTED`
//!   / `CACHE_UNEXPECTED_REGULAR` bump and the wording.
//!
//! The walker is a pull-style iterative DFS rather than a visitor callback:
//! `while let Some(entry) = walker.next().await { ... }`.  Callers keep their
//! natural loop shape (`continue`, `?`, early `return`), and no `AsyncFnMut`
//! bound is needed - the call future of an async closure cannot be bounded
//! `Send` on stable, which the tokio-spawned cleanup tasks require.  A
//! directory is descended into only when the caller asks
//! ([`Entry::descend`]); a per-directory `Copy` tag rides along so a caller
//! can remember what a subtree means (`dists/` vs `by-hash/` vs flat) without
//! re-deriving it from the path on every entry.
//!
//! Entries are classified from the directory listing's `d_type`, so a walk
//! that only needs names and kinds costs no per-entry syscall; sizes and
//! timestamps are fetched on demand through [`Entry::metadata`] (lstat, so a
//! planted symlink is seen as itself and never followed; relative to the
//! open directory, like the listing, so it costs no full-path walk and
//! follows the entry if an ancestor is renamed mid-walk).
//!
//! A directory is listed in batches of [`LIST_BATCH`] entries, one
//! blocking-pool hop per batch (the first rides along with the `opendir`).
//! A walk that only tallies sizes (the startup / reconcile scan, the
//! dashboard) opts in with [`Walker::stat_files`]: the lstat of each
//! regular file then runs inside the listing hop, relative to the open
//! directory, instead of costing one hop per file, and [`Entry::metadata`]
//! hands out that result - including a failure, reported exactly as an
//! on-demand one would be, when the caller asks.  The stat is then as old
//! as the batch, not as the caller's use of it, so a walk that acts on the
//! file afterwards (cleanup's reaps, which report a failed unlink) keeps
//! the on-demand stat.  Name-only walks never set it and so still stat
//! nothing.

use std::{
    collections::VecDeque,
    ffi::{OsStr, OsString},
    fs::{DirEntry, FileType, Metadata, ReadDir},
    io::{self, ErrorKind},
    path::{Path, PathBuf},
    sync::Arc,
};

use tracing::{debug, error, warn};

use crate::{error::ErrorReport, log_once::Logged, metrics};

/// Wording and failure policy of one walk.  Every field is a fragment of the
/// walker's fixed sentences; the caller supplies only the *consequence*
/// clauses.
#[derive(Debug)]
pub(crate) struct WalkContext {
    /// Noun (with article) naming the tree in every line: `"the cache
    /// directory"`, `"a mirror directory"`, `"a by-hash directory"`.  Reads
    /// as `Failed to read {what} <path>` and `Unrecognized symlink entry
    /// <path> in {what}; ...`.
    pub(crate) what: &'static str,
    /// What a failed `read_dir` / `next_entry` does to the walk, carrying
    /// the consequence clause of its error line.
    pub(crate) dir_failure: DirFailure,
    /// Consequence clause when one entry drops out of the walk because its
    /// file type or metadata could not be read (`"excluding it from the
    /// cache size"`, `"retaining it and excluding it from cleanup"`).
    pub(crate) entry_failure: &'static str,
    /// Consequence clause of the warn for a symlink / FIFO / socket /
    /// device, which the walker reports on sight (`"not counting it towards
    /// the cache size"`, `"removing it"`).
    pub(crate) non_regular: &'static str,
    /// Level of the anomaly lines: a non-regular entry and
    /// [`Entry::report_unexpected`].
    pub(crate) anomalies: AnomalyLevel,
}

/// Level of a walk's anomaly lines (`docs/logging.md`, "Flood control"):
/// a plain `warn!` per artifact is earned only by a walk whose rate no
/// client drives.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AnomalyLevel {
    /// A walk run once per startup scan or cleanup cycle: each line names
    /// one artifact, bounded by cache contents.
    Warn,
    /// A walk a client re-triggers (the dashboard, on every refresh past
    /// its cache TTL): it restates facts the scan and cleanup already
    /// warned about.
    Debug,
}

/// Policy for a directory that cannot be read or iterated.
#[derive(Clone, Copy, Debug)]
pub(crate) enum DirFailure {
    /// Log, then end the walk: [`Walker::next`] yields nothing further and
    /// [`Walker::finish`] returns [`WalkOutcome::Aborted`].
    Abort(&'static str),
    /// Log, then carry on with the next directory; the unread remainder of
    /// the failed directory is skipped.
    Continue(&'static str),
}

impl DirFailure {
    const fn consequence(self) -> &'static str {
        match self {
            Self::Abort(c) | Self::Continue(c) => c,
        }
    }
}

/// Policy for a root directory that does not exist.
#[derive(Clone, Copy, Debug)]
pub(crate) enum OnMissing {
    /// An absent root is an empty tree: nothing is logged, and
    /// [`Walker::finish`] reports [`WalkOutcome::RootMissing`] so a caller
    /// can add its own line.
    Tolerate,
    /// An absent root is a read failure like any other, handled per
    /// [`WalkContext::dir_failure`].
    Fail,
}

/// How a walk ended, from [`Walker::finish`].
#[derive(Debug)]
pub(crate) enum WalkOutcome {
    /// Every reachable directory was read (a [`DirFailure::Continue`] skip
    /// still counts as complete - it was logged where it happened).
    Complete,
    /// The root does not exist and the walk was [`OnMissing::Tolerate`].
    RootMissing,
    /// A [`DirFailure::Abort`] fired.  `logged` proves the failure was
    /// logged and counted where it happened (the walker's one directory-
    /// failure line), so a caller maps it silently - cleanup's
    /// `CleanupUnitError` carries the proof.  `err` is for a caller that has
    /// to classify the failure or fold it into a typed error of its own
    /// (`task_cache_scan`), never for a second line.
    Aborted { logged: Logged, err: io::Error },
}

/// What an entry is, by `lstat` semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EntryKind {
    File,
    Dir,
    /// Symlink, FIFO, socket or device: never legitimate in the cache tree.
    /// Already reported (+ `CACHE_NON_REGULAR`) when yielded.
    NonRegular,
}

/// A directory waiting to be opened.
#[derive(Debug)]
struct Frame<T> {
    path: PathBuf,
    /// Path relative to the walk root; empty for the root itself.
    rel: PathBuf,
    tag: T,
}

/// Entries listed per blocking-pool hop.  Bounds the memory a huge pool
/// directory holds in flight (a few hundred bytes per entry with its
/// metadata) while cutting its hops by that factor.
const LIST_BATCH: usize = 256;

/// One listed entry, as read inside the blocking hop.
#[derive(Debug)]
struct Listed {
    name: OsString,
    /// The listing's entry, holding the open directory: the on-demand
    /// [`Entry::metadata`] lstats relative to it (`DirEntry::metadata`, a
    /// `statx`/`fstatat` on the directory descriptor) rather than walking
    /// the entry's full path again.
    listing: Arc<DirEntry>,
    /// The listing's `d_type`, or an lstat where the filesystem leaves it
    /// unknown.
    file_type: io::Result<FileType>,
    /// The lstat of a regular file, taken in the same hop when the walk
    /// asked for it ([`Walker::stat_files`]); `None` otherwise.
    metadata: Option<io::Result<Metadata>>,
}

/// A directory's listing so far, as one blocking hop returns it.
#[derive(Debug)]
struct Batch {
    entries: VecDeque<Listed>,
    /// The open handle while entries remain unread; `None` once the end of
    /// the directory or `failed` was reached.
    reader: Option<ReadDir>,
    /// Iteration failed after `entries`; reported once they are yielded.
    failed: Option<io::Error>,
}

impl Batch {
    /// Read up to [`LIST_BATCH`] entries from `reader`.  Blocking.
    fn read(mut reader: ReadDir, stat_files: bool) -> Self {
        let mut entries = VecDeque::with_capacity(LIST_BATCH);
        while entries.len() < LIST_BATCH {
            match reader.next() {
                Some(Ok(dir_entry)) => {
                    let file_type = dir_entry.file_type();
                    // `DirEntry::metadata` is an lstat relative to the open
                    // directory, like the on-demand one.
                    let metadata = (stat_files && file_type.as_ref().is_ok_and(FileType::is_file))
                        .then(|| dir_entry.metadata());
                    entries.push_back(Listed {
                        name: dir_entry.file_name(),
                        listing: Arc::new(dir_entry),
                        file_type,
                        metadata,
                    });
                }
                None => {
                    return Self {
                        entries,
                        reader: None,
                        failed: None,
                    };
                }
                Some(Err(err)) => {
                    return Self {
                        entries,
                        reader: None,
                        failed: Some(err),
                    };
                }
            }
        }
        Self {
            entries,
            reader: Some(reader),
            failed: None,
        }
    }
}

/// The directory currently being iterated.
#[derive(Debug)]
struct Open<T> {
    frame: Frame<T>,
    batch: Batch,
}

/// The entry most recently yielded, kept so the [`Entry`] handed out can
/// borrow it.
#[derive(Debug)]
struct Yielded {
    name: OsString,
    listing: Arc<DirEntry>,
    kind: EntryKind,
    metadata: Option<io::Result<Metadata>>,
}

/// An iterative depth-first walk over one cache tree.  See the module doc.
#[derive(Debug)]
pub(crate) struct Walker<T> {
    ctx: &'static WalkContext,
    missing: OnMissing,
    /// Set by [`Walker::stat_files`].
    stat_files: bool,
    pending: Vec<Frame<T>>,
    current: Option<Open<T>>,
    yielded: Option<Yielded>,
    /// Set by [`Entry::descend`]; consumed at the start of the next
    /// [`Walker::next`] call, when the yielded entry is known to be a dir.
    descend: Option<T>,
    root_missing: bool,
    aborted: Option<(Logged, io::Error)>,
}

impl<T: Copy + Send + Sync> Walker<T> {
    /// Prepare a walk of `root`; nothing is read until the first
    /// [`Walker::next`].  `root_tag` is handed back on every entry of the
    /// root directory itself.
    #[must_use]
    pub(crate) fn new(
        root: &Path,
        ctx: &'static WalkContext,
        missing: OnMissing,
        root_tag: T,
    ) -> Self {
        Self {
            ctx,
            missing,
            stat_files: false,
            pending: vec![Frame {
                path: root.to_path_buf(),
                rel: PathBuf::new(),
                tag: root_tag,
            }],
            current: None,
            yielded: None,
            descend: None,
            root_missing: false,
            aborted: None,
        }
    }

    /// Lstat every regular file while its directory is listed, in the
    /// listing's blocking hop, so [`Entry::metadata`] costs no hop of its
    /// own.  For a walk that only tallies (nearly) every regular file's
    /// size; not for one that skips files by name before the stat, or acts
    /// on a file after it (see the module doc).
    #[must_use]
    pub(crate) const fn stat_files(mut self) -> Self {
        self.stat_files = true;
        self
    }

    /// Yield the next entry, or `None` once every directory the caller
    /// descended into has been read (or the walk aborted).
    pub(crate) async fn next(&mut self) -> Option<Entry<'_, T>> {
        if let Some(tag) = self.descend.take()
            && let (Some(open), Some(yielded)) = (&self.current, &self.yielded)
        {
            self.pending.push(Frame {
                path: open.frame.path.join(&yielded.name),
                rel: open.frame.rel.join(&yielded.name),
                tag,
            });
        }
        self.yielded = None;

        let yielded = loop {
            if self.aborted.is_some() {
                return None;
            }
            let Some(open) = self.current.as_mut() else {
                let frame = self.pending.pop()?;
                self.open(frame).await;
                continue;
            };
            if let Some(listed) = open.batch.entries.pop_front() {
                let Listed {
                    name,
                    listing,
                    file_type,
                    metadata,
                } = listed;
                if let Some(kind) = classify(self.ctx, &open.frame.path, &name, file_type) {
                    break Yielded {
                        name,
                        listing,
                        kind,
                        metadata,
                    };
                }
            } else if let Some(err) = open.batch.failed.take() {
                let open = self.current.take()?;
                self.dir_failed("iterate", &open.frame.path, err);
            } else if let Some(reader) = open.batch.reader.take() {
                let stat_files = self.stat_files;
                open.batch = match tokio::task::spawn_blocking(move || {
                    Batch::read(reader, stat_files)
                })
                .await
                {
                    Ok(batch) => batch,
                    // The hop panicked: the reader went with it, so the
                    // rest of the directory is unreadable.
                    Err(err) => Batch {
                        entries: VecDeque::new(),
                        reader: None,
                        failed: Some(io::Error::other(err)),
                    },
                };
            } else {
                self.current = None;
            }
        };

        self.yielded = Some(yielded);
        let Yielded {
            name,
            listing,
            kind,
            metadata,
        } = self.yielded.as_ref()?;
        let open = self.current.as_ref()?;
        Some(Entry {
            ctx: self.ctx,
            dir: &open.frame.path,
            name,
            listing,
            rel_dir: &open.frame.rel,
            tag: open.frame.tag,
            kind: *kind,
            prefetched: metadata.as_ref(),
            descend: &mut self.descend,
        })
    }

    /// Report how the walk ended.  Dropping the walker instead is fine for a
    /// caller that cannot abort and does not care whether the root existed.
    #[must_use]
    pub(crate) fn finish(self) -> WalkOutcome {
        if let Some((logged, err)) = self.aborted {
            WalkOutcome::Aborted { logged, err }
        } else if self.root_missing {
            WalkOutcome::RootMissing
        } else {
            WalkOutcome::Complete
        }
    }

    /// Open `frame`'s directory and read its first batch in the same hop.
    async fn open(&mut self, frame: Frame<T>) {
        let is_root = frame.rel.as_os_str().is_empty();
        let path = frame.path.clone();
        let stat_files = self.stat_files;
        let opened = tokio::task::spawn_blocking(move || {
            std::fs::read_dir(path).map(|reader| Batch::read(reader, stat_files))
        })
        .await
        .unwrap_or_else(|err| Err(io::Error::other(err)));
        match opened {
            Ok(batch) => self.current = Some(Open { frame, batch }),
            Err(err) if err.kind() == ErrorKind::NotFound && is_root => match self.missing {
                OnMissing::Tolerate => self.root_missing = true,
                OnMissing::Fail => self.dir_failed("read", &frame.path, err),
            },
            Err(err) if err.kind() == ErrorKind::NotFound => {
                debug!(
                    "Directory `{}` vanished before it could be read; skipping it",
                    frame.path.display()
                );
            }
            Err(err) => self.dir_failed("read", &frame.path, err),
        }
    }

    /// The one site logging and counting a directory-level failure.
    fn dir_failed(&mut self, verb: &'static str, path: &Path, err: io::Error) {
        let logged = Logged::cache_io_failure(format_args!(
            "Failed to {verb} {} `{}`; {}:  {}",
            self.ctx.what,
            path.display(),
            self.ctx.dir_failure.consequence(),
            ErrorReport(&err)
        ));
        self.current = None;
        if let DirFailure::Abort(_) = self.ctx.dir_failure {
            self.pending.clear();
            self.aborted = Some((logged, err));
        }
    }
}

/// Classify one listed entry of directory `dir`, reporting a non-regular
/// one on sight.  `None` means the entry dropped out of the walk (vanished,
/// or its type could not be read - logged and counted here).
fn classify(
    ctx: &'static WalkContext,
    dir: &Path,
    name: &OsStr,
    file_type: io::Result<FileType>,
) -> Option<EntryKind> {
    match file_type {
        Ok(ft) if ft.is_file() => Some(EntryKind::File),
        Ok(ft) if ft.is_dir() => Some(EntryKind::Dir),
        Ok(ft) => {
            metrics::CACHE_NON_REGULAR.increment();
            let kind = if ft.is_symlink() {
                "symlink"
            } else {
                "non-regular"
            };
            let path = dir.join(name);
            match ctx.anomalies {
                AnomalyLevel::Warn => warn!(
                    "Unrecognized {kind} entry `{}` in {}; {}",
                    path.display(),
                    ctx.what,
                    ctx.non_regular
                ),
                AnomalyLevel::Debug => debug!(
                    "Unrecognized {kind} entry `{}` in {}; {}",
                    path.display(),
                    ctx.what,
                    ctx.non_regular
                ),
            }
            Some(EntryKind::NonRegular)
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            debug!(
                "Cache entry `{}` vanished before it could be inspected; skipping it",
                dir.join(name).display()
            );
            None
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to get the file type of `{}`; {}:  {}",
                dir.join(name).display(),
                ctx.entry_failure,
                ErrorReport(&err)
            );
            None
        }
    }
}

/// One listed entry, borrowed from the [`Walker`] until the next
/// [`Walker::next`] call.
#[derive(Debug)]
pub(crate) struct Entry<'w, T> {
    ctx: &'static WalkContext,
    /// Full path of the directory holding the entry.
    dir: &'w Path,
    name: &'w OsStr,
    /// The listing's entry, for the on-demand lstat (see [`Listed`]).
    listing: &'w Arc<DirEntry>,
    rel_dir: &'w Path,
    tag: T,
    kind: EntryKind,
    /// The lstat taken while listing, in a [`Walker::stat_files`] walk.
    prefetched: Option<&'w io::Result<Metadata>>,
    descend: &'w mut Option<T>,
}

impl<T: Copy + Send + Sync> Entry<'_, T> {
    #[must_use]
    pub(crate) const fn kind(&self) -> EntryKind {
        self.kind
    }

    /// The entry's file name, verbatim (may not be UTF-8).
    #[must_use]
    pub(crate) fn name(&self) -> &OsStr {
        self.name
    }

    /// The tag of the directory holding this entry.
    #[must_use]
    pub(crate) const fn tag(&self) -> T {
        self.tag
    }

    /// Full path of the entry.
    #[must_use]
    pub(crate) fn path(&self) -> PathBuf {
        self.dir.join(self.name)
    }

    /// Path of the entry relative to the walk root (`"a.deb"` for a root
    /// entry, `"amd64/a.deb"` one level down); rejoining it onto the root
    /// gives [`Entry::path`].
    #[must_use]
    pub(crate) fn rel_path(&self) -> PathBuf {
        self.rel_dir.join(self.name)
    }

    /// Ask the walker to read this directory's contents (after the current
    /// directory), tagging every entry in it with `tag`.  Ignored for
    /// anything but a directory.
    pub(crate) fn descend(&mut self, tag: T) {
        debug_assert!(
            self.kind == EntryKind::Dir,
            "only a directory can be descended into"
        );
        if self.kind == EntryKind::Dir {
            *self.descend = Some(tag);
        }
    }

    /// Report a directory or regular file the caller's layout does not
    /// allow here: bumps `CACHE_DIRECTORY_UNEXPECTED` /
    /// `CACHE_UNEXPECTED_REGULAR` and logs at the walk's [`AnomalyLevel`]
    /// with the caller's consequence clause (`"not counting it or its contents towards the cache size"`,
    /// `"retaining it and excluding its contents from cleanup"`).  A
    /// non-regular entry was already reported when it was yielded, so this
    /// is a no-op for one.
    pub(crate) fn report_unexpected(&self, consequence: &'static str) {
        let kind = match self.kind {
            EntryKind::Dir => {
                metrics::CACHE_DIRECTORY_UNEXPECTED.increment();
                "directory"
            }
            EntryKind::File => {
                metrics::CACHE_UNEXPECTED_REGULAR.increment();
                "regular file"
            }
            EntryKind::NonRegular => return,
        };
        let path = self.path();
        match self.ctx.anomalies {
            AnomalyLevel::Warn => warn!(
                "Unrecognized {kind} entry `{}` in {}; {consequence}",
                path.display(),
                self.ctx.what
            ),
            AnomalyLevel::Debug => debug!(
                "Unrecognized {kind} entry `{}` in {}; {consequence}",
                path.display(),
                self.ctx.what
            ),
        }
    }

    /// `lstat` the entry, or hand out the lstat a [`Walker::stat_files`]
    /// walk took while listing it.  `None` means it dropped out of the walk:
    /// it vanished or changed type since it was listed (`debug!`), or the
    /// stat failed (`error!` + `CACHE_IO_FAILURE`, with the walk's
    /// [`WalkContext::entry_failure`] clause).
    pub(crate) async fn metadata(&self) -> Option<Metadata> {
        let on_demand;
        let result = if let Some(prefetched) = self.prefetched {
            prefetched.as_ref()
        } else {
            let listing = Arc::clone(self.listing);
            on_demand = tokio::task::spawn_blocking(move || listing.metadata())
                .await
                .unwrap_or_else(|err| Err(io::Error::other(err)));
            on_demand.as_ref()
        };
        match result {
            Ok(meta) => {
                let same_kind = match self.kind {
                    EntryKind::File => meta.is_file(),
                    EntryKind::Dir => meta.is_dir(),
                    EntryKind::NonRegular => !meta.is_file() && !meta.is_dir(),
                };
                if same_kind {
                    Some(meta.clone())
                } else {
                    debug!(
                        "Cache entry `{}` changed type before it could be inspected; skipping it",
                        self.path().display()
                    );
                    None
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                debug!(
                    "Cache entry `{}` vanished before it could be inspected; skipping it",
                    self.path().display()
                );
                None
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to get metadata of `{}`; {}:  {}",
                    self.path().display(),
                    self.ctx.entry_failure,
                    ErrorReport(&err)
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsStr,
        os::unix::{ffi::OsStrExt as _, fs::PermissionsExt as _},
        path::{Path, PathBuf},
    };

    use super::*;

    static CONTINUE: WalkContext = WalkContext {
        what: "a test directory",
        dir_failure: DirFailure::Continue("skipping its unread entries"),
        entry_failure: "skipping it",
        non_regular: "noting it",
        anomalies: AnomalyLevel::Warn,
    };

    static ABORT: WalkContext = WalkContext {
        what: "a test directory",
        dir_failure: DirFailure::Abort("abandoning the test walk"),
        entry_failure: "skipping it",
        non_regular: "noting it",
        anomalies: AnomalyLevel::Warn,
    };

    /// Drive a walk to completion, descending into every directory named in
    /// `descend_into`, and collect the `(relative path, kind, tag)` events
    /// sorted by path.
    async fn collect(
        root: &Path,
        ctx: &'static WalkContext,
        missing: OnMissing,
        descend_into: &[&str],
    ) -> (Vec<(PathBuf, EntryKind, u8)>, WalkOutcome) {
        let mut events = Vec::new();
        let mut walker = Walker::new(root, ctx, missing, 0u8);
        while let Some(mut entry) = walker.next().await {
            events.push((entry.rel_path(), entry.kind(), entry.tag()));
            assert_eq!(root.join(entry.rel_path()), entry.path());
            if entry.kind() == EntryKind::Dir
                && entry
                    .name()
                    .to_str()
                    .is_some_and(|n| descend_into.contains(&n))
            {
                let depth = entry.tag() + 1;
                entry.descend(depth);
            }
        }
        events.sort_unstable();
        (events, walker.finish())
    }

    #[tokio::test]
    async fn yields_root_entries_and_descends_only_on_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a"), b"abc").expect("a");
        std::fs::create_dir(dir.path().join("d")).expect("d");
        std::fs::write(dir.path().join("d/b"), b"x").expect("d/b");
        std::fs::create_dir(dir.path().join("e")).expect("e");
        std::fs::write(dir.path().join("e/c"), b"x").expect("e/c");

        let (events, outcome) = collect(dir.path(), &CONTINUE, OnMissing::Fail, &["d"]).await;
        assert!(matches!(outcome, WalkOutcome::Complete), "{outcome:?}");
        assert_eq!(
            events,
            vec![
                (PathBuf::from("a"), EntryKind::File, 0),
                (PathBuf::from("d"), EntryKind::Dir, 0),
                (PathBuf::from("d/b"), EntryKind::File, 1),
                (PathBuf::from("e"), EntryKind::Dir, 0),
            ]
        );
    }

    #[tokio::test]
    async fn metadata_is_lstat_and_carries_the_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a"), b"abcde").expect("a");

        let mut walker = Walker::new(dir.path(), &CONTINUE, OnMissing::Fail, ());
        {
            let entry = walker.next().await.expect("one entry");
            assert_eq!(entry.kind(), EntryKind::File);
            let meta = entry.metadata().await.expect("stat");
            assert_eq!(meta.len(), 5);
            assert!(meta.is_file());
        }
        assert!(walker.next().await.is_none());
    }

    #[tokio::test]
    async fn descend_carries_its_tag_and_relative_path_down_the_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("a/b")).expect("a/b");
        std::fs::write(dir.path().join("a/shallow"), b"x").expect("shallow");
        std::fs::write(dir.path().join("a/b/deep"), b"x").expect("deep");

        let (events, outcome) = collect(dir.path(), &CONTINUE, OnMissing::Fail, &["a", "b"]).await;
        assert!(matches!(outcome, WalkOutcome::Complete), "{outcome:?}");
        assert_eq!(
            events,
            vec![
                (PathBuf::from("a"), EntryKind::Dir, 0),
                (PathBuf::from("a/b"), EntryKind::Dir, 1),
                (PathBuf::from("a/b/deep"), EntryKind::File, 2),
                (PathBuf::from("a/shallow"), EntryKind::File, 1),
            ],
            "each entry carries the tag of the directory holding it"
        );
    }

    /// A directory larger than one listing batch is read across several
    /// hops without losing or repeating an entry, in either mode.
    #[tokio::test]
    async fn a_directory_spanning_several_batches_is_listed_completely() {
        let dir = tempfile::tempdir().expect("tempdir");
        let count = LIST_BATCH * 2 + 7;
        for i in 0..count {
            std::fs::write(dir.path().join(format!("f{i}")), vec![b'x'; i % 5]).expect("file");
        }
        let expected_bytes = u64::try_from((0..count).map(|i| i % 5).sum::<usize>()).unwrap();

        for stat_files in [false, true] {
            let walker = Walker::new(dir.path(), &CONTINUE, OnMissing::Fail, ());
            let mut walker = if stat_files {
                walker.stat_files()
            } else {
                walker
            };
            let mut names = Vec::new();
            let mut bytes = 0;
            while let Some(entry) = walker.next().await {
                assert_eq!(entry.kind(), EntryKind::File);
                bytes += entry.metadata().await.expect("stat").len();
                names.push(entry.name().to_os_string());
            }
            assert!(matches!(walker.finish(), WalkOutcome::Complete));
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), count, "stat_files: {stat_files}");
            assert_eq!(bytes, expected_bytes, "stat_files: {stat_files}");
        }
    }

    /// A `stat_files` walk lstats regular files in the listing hop:
    /// `metadata` hands out that result, so it no longer sees a removal
    /// after the listing, and it still lstats a non-file on demand.
    #[tokio::test]
    async fn stat_files_serves_the_lstat_taken_while_listing() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a"), b"abcde").expect("a");
        std::fs::create_dir(dir.path().join("d")).expect("d");

        let mut walker = Walker::new(dir.path(), &CONTINUE, OnMissing::Fail, ()).stat_files();
        let mut seen = 0;
        while let Some(entry) = walker.next().await {
            seen += 1;
            match entry.kind() {
                EntryKind::File => {
                    std::fs::remove_file(entry.path()).expect("unlink");
                    let meta = entry.metadata().await.expect("prefetched stat");
                    assert_eq!(meta.len(), 5);
                    assert!(meta.is_file());
                }
                EntryKind::Dir | EntryKind::NonRegular => {
                    assert_eq!(entry.kind(), EntryKind::Dir, "no non-regular entry exists");
                    assert!(entry.metadata().await.expect("on-demand stat").is_dir());
                }
            }
        }
        assert_eq!(seen, 2);
    }

    /// `metadata` is the walker's only per-entry syscall and runs after the
    /// listing, so it has to absorb both races the listing cannot see.
    #[tokio::test]
    async fn metadata_skips_an_entry_that_vanished_or_changed_type() {
        let gone_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(gone_dir.path().join("gone"), b"x").expect("gone");
        {
            let mut walker = Walker::new(gone_dir.path(), &CONTINUE, OnMissing::Fail, ());
            let entry = walker.next().await.expect("one entry");
            std::fs::remove_file(entry.path()).expect("unlink");
            assert!(
                entry.metadata().await.is_none(),
                "an entry that vanished after the listing drops out of the walk"
            );
        }

        let swapped_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(swapped_dir.path().join("swapped"), b"x").expect("swapped");
        let mut walker = Walker::new(swapped_dir.path(), &CONTINUE, OnMissing::Fail, ());
        let entry = walker.next().await.expect("one entry");
        assert_eq!(entry.kind(), EntryKind::File);
        std::fs::remove_file(entry.path()).expect("unlink");
        std::fs::create_dir(entry.path()).expect("mkdir");
        assert!(
            entry.metadata().await.is_none(),
            "an entry whose type changed after the listing drops out of the walk"
        );
    }

    /// The on-demand lstat is relative to the listed directory, as the
    /// listing itself is: it neither re-walks the entry's full path nor
    /// loses the entry when an ancestor is renamed mid-walk.
    #[tokio::test]
    async fn metadata_is_anchored_to_the_listed_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(root.path().join("sub")).expect("sub");
        std::fs::write(root.path().join("sub").join("f"), b"abc").expect("f");

        let mut walker = Walker::new(root.path(), &CONTINUE, OnMissing::Fail, ());
        {
            let mut entry = walker.next().await.expect("sub");
            assert_eq!(entry.kind(), EntryKind::Dir);
            entry.descend(());
        }
        let entry = walker.next().await.expect("f");
        assert_eq!(entry.name(), "f");
        std::fs::rename(root.path().join("sub"), root.path().join("moved")).expect("rename sub");
        let meta = entry
            .metadata()
            .await
            .expect("the lstat follows the open directory, not the stale path");
        assert_eq!(meta.len(), 3);
    }

    #[tokio::test]
    async fn non_regular_entries_are_yielded_and_counted_on_sight() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink("/nonexistent", dir.path().join("link")).expect("symlink");
        nix::unistd::mkfifo(
            &dir.path().join("fifo"),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .expect("mkfifo");

        // The counter is process-global and other unit tests in this binary
        // bump it concurrently, so assert the delta as a lower bound.
        let before = metrics::CACHE_NON_REGULAR.get();
        let (events, outcome) = collect(dir.path(), &CONTINUE, OnMissing::Fail, &[]).await;
        assert!(matches!(outcome, WalkOutcome::Complete), "{outcome:?}");
        assert_eq!(
            events,
            vec![
                (PathBuf::from("fifo"), EntryKind::NonRegular, 0),
                (PathBuf::from("link"), EntryKind::NonRegular, 0),
            ]
        );
        assert!(metrics::CACHE_NON_REGULAR.get() >= before + 2);
    }

    #[tokio::test]
    async fn report_unexpected_bumps_the_counter_of_the_kind() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("f"), b"x").expect("f");
        std::fs::create_dir(dir.path().join("d")).expect("d");
        std::os::unix::fs::symlink("/nonexistent", dir.path().join("l")).expect("symlink");

        let dirs_before = metrics::CACHE_DIRECTORY_UNEXPECTED.get();
        let files_before = metrics::CACHE_UNEXPECTED_REGULAR.get();
        let mut walker = Walker::new(dir.path(), &CONTINUE, OnMissing::Fail, ());
        let mut seen = 0;
        while let Some(entry) = walker.next().await {
            entry.report_unexpected("noting it");
            seen += 1;
        }
        assert_eq!(seen, 3);
        assert!(metrics::CACHE_DIRECTORY_UNEXPECTED.get() > dirs_before);
        assert!(metrics::CACHE_UNEXPECTED_REGULAR.get() > files_before);
    }

    #[tokio::test]
    async fn non_utf8_names_are_yielded_verbatim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let name = OsStr::from_bytes(b"bad\xffname");
        std::fs::write(dir.path().join(name), b"x").expect("file");

        let mut walker = Walker::new(dir.path(), &CONTINUE, OnMissing::Fail, ());
        let entry = walker.next().await.expect("one entry");
        assert_eq!(entry.name(), name);
        assert!(entry.name().to_str().is_none());
        assert_eq!(entry.rel_path(), PathBuf::from(name));
        assert_eq!(entry.path(), dir.path().join(name));
    }

    #[tokio::test]
    async fn missing_root_is_tolerated_or_failed_per_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let absent = dir.path().join("absent");

        let (events, outcome) = collect(&absent, &ABORT, OnMissing::Tolerate, &[]).await;
        assert_eq!(events, Vec::new());
        assert!(matches!(outcome, WalkOutcome::RootMissing), "{outcome:?}");

        let before = metrics::CACHE_IO_FAILURE.get();
        let (events, outcome) = collect(&absent, &ABORT, OnMissing::Fail, &[]).await;
        assert_eq!(events, Vec::new());
        assert!(
            matches!(outcome, WalkOutcome::Aborted { .. }),
            "expected Aborted, got {outcome:?}"
        );
        let err = if let WalkOutcome::Aborted { logged: _, err } = outcome {
            Some(err)
        } else {
            None
        };
        let err = err.expect("asserted above");
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert!(metrics::CACHE_IO_FAILURE.get() > before);

        // `Fail` with a `Continue` policy: logged, then the (empty) walk
        // completes.
        let (events, outcome) = collect(&absent, &CONTINUE, OnMissing::Fail, &[]).await;
        assert_eq!(events, Vec::new());
        assert!(matches!(outcome, WalkOutcome::Complete), "{outcome:?}");
    }

    #[tokio::test]
    async fn unreadable_subdirectory_follows_the_dir_failure_policy() {
        if nix::unistd::Uid::effective().is_root() {
            // root ignores mode bits, so the directory would be readable.
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).expect("locked");
        std::fs::write(locked.join("hidden"), b"x").expect("hidden");
        std::fs::write(dir.path().join("visible"), b"x").expect("visible");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let before = metrics::CACHE_IO_FAILURE.get();
        let (events, outcome) = collect(dir.path(), &CONTINUE, OnMissing::Fail, &["locked"]).await;
        assert!(matches!(outcome, WalkOutcome::Complete), "{outcome:?}");
        assert_eq!(
            events,
            vec![
                (PathBuf::from("locked"), EntryKind::Dir, 0),
                (PathBuf::from("visible"), EntryKind::File, 0),
            ]
        );
        assert!(metrics::CACHE_IO_FAILURE.get() > before);

        let (events, outcome) = collect(dir.path(), &ABORT, OnMissing::Fail, &["locked"]).await;
        assert!(
            matches!(outcome, WalkOutcome::Aborted { .. }),
            "{outcome:?}"
        );
        // The root was fully listed before the subdirectory was opened.
        assert_eq!(events.len(), 2);

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
}
