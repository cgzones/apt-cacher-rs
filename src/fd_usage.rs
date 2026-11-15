//! The descriptors this process holds against its soft `RLIMIT_NOFILE`, for
//! the dashboard's Capacity section.
//!
//! Sampled off the hot path, never per accept: by every dashboard render
//! and by [`sampler`]. A burst between two samples is missed unless it
//! reached the cap, which the accept loop reports through
//! [`note_exhausted`]. Only this process's descriptors count; the
//! system-wide table (`ENFILE`) is not tracked.

use std::{os::unix::fs::MetadataExt as _, path::Path, time::Duration};

use crate::{error::ErrorReport, metrics, warn_once_or_debug};

pub(crate) const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

const PROC_SELF_FD: &str = "/proc/self/fd";

/// Linux 6.2 and later report the count as the directory's size, one
/// `stat(2)`; an older kernel reports 0 there, and the listing is counted
/// instead.
#[must_use]
fn open_fds() -> Option<u64> {
    let dir = Path::new(PROC_SELF_FD);
    match std::fs::metadata(dir) {
        Ok(mdata) if mdata.size() > 0 => Some(mdata.size()),
        Ok(_) => listed_fds(dir),
        Err(err) => {
            warn_once_or_debug!(
                "Failed to stat `{PROC_SELF_FD}`; the dashboard reports the open file descriptors as N/A:  {}",
                ErrorReport(&err)
            );
            None
        }
    }
}

/// The descriptors in `dir` (a `/proc/<pid>/fd` listing), not counting the
/// one the listing itself holds open while it runs.
fn listed_fds(dir: &Path) -> Option<u64> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            warn_once_or_debug!(
                "Failed to list `{}`; the dashboard reports the open file descriptors as N/A:  {}",
                dir.display(),
                ErrorReport(&err)
            );
            return None;
        }
    };
    // A descriptor closed between the listing and its entry's read errors
    // out; it is gone, so it is not counted.
    let listed = entries.flatten().count() as u64;
    Some(listed.saturating_sub(1))
}

/// The soft and hard `RLIMIT_NOFILE`, `None` for either when unlimited or
/// unreadable. The daemon never raises its own soft limit.
#[must_use]
pub(crate) fn nofile_limit() -> (Option<u64>, Option<u64>) {
    match nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE) {
        Ok((soft, hard)) => {
            let finite = |limit| Some(limit).filter(|&l| l != nix::sys::resource::RLIM_INFINITY);
            (finite(soft), finite(hard))
        }
        Err(_errno) => (None, None),
    }
}

/// Read the descriptor count into the peak, returning it.
#[must_use]
pub(crate) fn sample() -> Option<u64> {
    let open = open_fds()?;
    metrics::OPEN_FDS_PEAK.update(open);
    Some(open)
}

/// `accept(2)` failed with `EMFILE`: the process is at its soft limit right
/// now, a peak the periodic samples may never catch.
pub(crate) fn note_exhausted() {
    if let (Some(soft), _hard) = nofile_limit() {
        metrics::OPEN_FDS_PEAK.update(soft);
    }
}

pub(crate) async fn sampler() {
    let mut interval = tokio::time::interval(SAMPLE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    #[expect(
        clippy::infinite_loop,
        reason = "a runtime-lifetime task: the main loop's return drops the runtime and the task with it"
    )]
    loop {
        interval.tick().await;
        // An unreadable `/proc` is logged once and leaves the peak alone.
        let _open_fds = sample();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_count_follows_the_descriptors_opened() {
        let before = open_fds().expect("/proc/self/fd is readable");
        // stdin/stdout/stderr at least.
        assert!(before >= 3, "{before}");
        let dir = tempfile::tempdir().expect("tempdir");
        let files: Vec<std::fs::File> = (0..8)
            .map(|i| std::fs::File::create(dir.path().join(i.to_string())).expect("create"))
            .collect();
        let after = open_fds().expect("/proc/self/fd is readable");
        assert!(after >= before + 8, "{before} -> {after}");
        drop(files);
    }

    #[test]
    fn the_listing_fallback_counts_like_the_stat() {
        let listed = listed_fds(Path::new(PROC_SELF_FD)).expect("listable");
        let stat = std::fs::metadata(PROC_SELF_FD).expect("stat").size();
        if stat > 0 {
            assert_eq!(listed, stat);
        }
        assert!(listed >= 3, "{listed}");
    }

    #[test]
    fn exhaustion_raises_the_peak_to_the_soft_limit() {
        let (soft, _) = nofile_limit();
        let soft = soft.expect("a finite soft limit on a test runner");
        note_exhausted();
        assert!(metrics::OPEN_FDS_PEAK.get() >= soft);
    }
}
