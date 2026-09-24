//! Ownership of the deterministic `.partial` paths, shared between the
//! downloads that write them and cleanup's `tmp/` reap.
//!
//! A kept partial is accounted in the disk quota (`cache_quota`'s module doc)
//! and its bytes are released exactly once: by cleanup's reap, through the
//! reconcile's `removed`, when no download uses it; or by the download that
//! takes it over, whose reservation adopts the bytes and keeps what the
//! partial holds when it ends. Cleanup used to decide from its walk and
//! unlink by path, so it could reap a partial a download had already opened:
//! the download wrote into an unlinked inode and failed its rename, its
//! reservation found nothing left to keep and released the adopted bytes, and
//! the reap released them again. Both sides therefore meet on one
//! process-wide set of claimed paths:
//!
//! - A download claims its partial path ([`PartialClaim::acquire`], in
//!   `partial_file::prepare_partial_resume`) before it first opens, stats or
//!   creates it, fresh or resumed alike. The claim rides in both holders that
//!   may still touch the path -- the kept partial's `TempPath` guard and the
//!   quota reservation's `ReservedPartial`, whose drop measures the file --
//!   and the path is released when the later of the two is gone.
//! - Cleanup unlinks a stale partial only through [`reap_unclaimed`], which
//!   holds the set's lock across the claim check, a fresh `lstat(2)` (the
//!   inode the walk judged, still stale) and the `unlink(2)`, and counts the
//!   bytes of that `lstat`. A claim taken meanwhile waits for at most that
//!   unlink.
//!
//! A partial is thus either reaped and released by cleanup, or used and
//! released by its download, never both.
//!
//! The active-downloads registry serialises originators per cache entry, but
//! it retires an entry before a failed or declined download has dropped its
//! partial guard and reservation, so a new originator can still find the
//! path claimed by the previous one's tail. It then downloads into a scratch
//! file instead of resuming (`prepare_partial_resume`), which touches the
//! partial not at all.

use std::{
    fs::Metadata,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
};

use hashbrown::HashSet;

/// The partial paths some download currently owns. Held across cleanup's
/// whole check-and-unlink, so it is a sync mutex taken for syscall-short
/// sections only, never across an `.await`.
static CLAIMED: LazyLock<parking_lot::Mutex<HashSet<PathBuf>>> =
    LazyLock::new(|| parking_lot::Mutex::new(HashSet::new()));

/// A download's ownership of its `.partial` path; see the module doc.
///
/// Cloning shares the one claim: the path is released when the last clone
/// drops.
#[derive(Clone)]
pub(crate) struct PartialClaim(Arc<Claimed>);

struct Claimed {
    path: PathBuf,
}

impl PartialClaim {
    /// Claim `path`, or `None` when another download still owns it.
    ///
    /// Blocks for at most one of cleanup's unlinks ([`reap_unclaimed`]).
    #[must_use]
    pub(crate) fn acquire(path: PathBuf) -> Option<Self> {
        if !CLAIMED.lock().insert(path.clone()) {
            return None;
        }
        Some(Self(Arc::new(Claimed { path })))
    }

    /// The claimed partial path.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.0.path
    }
}

impl std::fmt::Debug for PartialClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(claimed) = self;
        f.debug_tuple("PartialClaim").field(&claimed.path).finish()
    }
}

impl Drop for Claimed {
    fn drop(&mut self) {
        let released = CLAIMED.lock().remove(&self.path);
        debug_assert!(released, "a live claim is in the set");
    }
}

/// The identity of the file a walk judged: an unlink by path must hit that
/// inode, not one created at the same path since.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileId {
    dev: u64,
    ino: u64,
}

impl FileId {
    #[must_use]
    pub(crate) fn of(mdata: &Metadata) -> Self {
        Self {
            dev: mdata.dev(),
            ino: mdata.ino(),
        }
    }
}

/// What [`reap_unclaimed`] did with a partial the walk judged stale.
#[derive(Debug)]
pub(crate) enum Reap {
    /// Unlinked; `len` is its length as the final `lstat(2)` read it.
    Removed { len: u64 },
    /// A download owns it; left alone.
    Claimed,
    /// Gone, replaced by another file, or no longer stale since the walk;
    /// left alone.
    Changed,
    /// The fresh `lstat(2)` failed; left alone.
    StatFailed(std::io::Error),
    /// The `unlink(2)` failed.
    RemoveFailed(std::io::Error),
}

/// Unlink the stale partial at `path` unless a download claims it: the one
/// way cleanup removes a partial (see the module doc).
///
/// Under the claim-set lock the path is `lstat`ed again and removed only if
/// it is still the regular file `walked` identified and `still_stale`
/// accepts its fresh metadata -- the walk's verdict may be stale by now.
///
/// Blocking: two short syscalls under a sync mutex. An async caller wraps it
/// in `block_in_place`.
pub(crate) fn reap_unclaimed(
    path: &Path,
    walked: FileId,
    still_stale: impl FnOnce(&Metadata) -> bool,
) -> Reap {
    let claimed = CLAIMED.lock();
    if claimed.contains(path) {
        return Reap::Claimed;
    }
    let mdata = match std::fs::symlink_metadata(path) {
        Ok(mdata) => mdata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Reap::Changed,
        Err(err) => return Reap::StatFailed(err),
    };
    if !mdata.file_type().is_file() || FileId::of(&mdata) != walked || !still_stale(&mdata) {
        return Reap::Changed;
    }
    let reaped = match std::fs::remove_file(path) {
        Ok(()) => Reap::Removed { len: mdata.len() },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Reap::Changed,
        Err(err) => Reap::RemoveFailed(err),
    };
    drop(claimed);
    reaped
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stale file planted at `name` under `dir`, and its identity.
    fn plant(dir: &tempfile::TempDir, name: &str) -> (PathBuf, FileId) {
        let path = dir.path().join(name);
        std::fs::write(&path, b"resume state").expect("write partial");
        let id = FileId::of(&std::fs::symlink_metadata(&path).expect("stat"));
        (path, id)
    }

    #[test]
    fn a_claimed_path_is_not_reaped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, id) = plant(&dir, "a.partial");
        let claim = PartialClaim::acquire(path.clone()).expect("unclaimed");

        assert!(matches!(reap_unclaimed(&path, id, |_| true), Reap::Claimed));
        assert!(path.exists(), "a download owns it");

        // A clone keeps the claim alive; the last one releases it.
        let clone = claim.clone();
        drop(claim);
        assert!(matches!(reap_unclaimed(&path, id, |_| true), Reap::Claimed));
        drop(clone);
        assert!(matches!(
            reap_unclaimed(&path, id, |_| true),
            Reap::Removed { len: 12 }
        ));
        assert!(!path.exists());
    }

    #[test]
    fn a_path_is_claimed_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("b.partial");
        let claim = PartialClaim::acquire(path.clone()).expect("unclaimed");
        assert!(
            PartialClaim::acquire(path.clone()).is_none(),
            "a second claim is refused, not a panic"
        );
        drop(claim);
        assert!(PartialClaim::acquire(path).is_some(), "released on drop");
    }

    /// The walk's verdict describes the inode it saw: a partial a download
    /// recreated at the same path since is somebody else's file.
    #[test]
    fn a_replaced_file_is_not_reaped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, walked) = plant(&dir, "c.partial");
        // Held open, so the new file cannot reuse the old inode number.
        let old = std::fs::File::open(&path).expect("open old");
        std::fs::remove_file(&path).expect("unlink old");
        std::fs::write(&path, b"new").expect("recreate");

        assert!(matches!(
            reap_unclaimed(&path, walked, |_| true),
            Reap::Changed
        ));
        assert!(path.exists(), "the new file is kept");
        drop(old);
    }

    #[test]
    fn a_file_no_longer_stale_or_gone_is_not_reaped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, id) = plant(&dir, "d.partial");
        assert!(matches!(
            reap_unclaimed(&path, id, |_| false),
            Reap::Changed
        ));
        assert!(path.exists());

        std::fs::remove_file(&path).expect("unlink");
        assert!(matches!(reap_unclaimed(&path, id, |_| true), Reap::Changed));
    }
}
