//! Memory figures for the dashboard's Memory section: the process's
//! resident set from `/proc/self/status`, the allocator's own account of
//! the heap (glibc builds), SQLite's heap, and the estimated footprint of
//! each process-local store.
//!
//! A store's [`Footprint`] is an estimate computed from capacities and
//! element sizes, never a measurement: no allocator attributes its blocks to
//! a table. It counts a table's allocation as hashbrown reports it (the
//! bucket count rounded up to a power of two, a control byte per bucket,
//! and the buckets deletions leave behind until the next rebuild), a ring
//! or deque's whole capacity, and the heap blocks the entries own, and
//! ignores the allocator's per-block rounding and headers, so it reads
//! somewhat under the truth. The process figures beside it are measured,
//! which is what makes the gap between them readable: the heap the stores
//! do not account for is connection buffers, TLS sessions, SQLite, the
//! runtime and allocator slack.
//!
//! Every reader here runs on a dashboard render only, never on a request
//! path; the store footprints take each store's lock briefly, so none of
//! them may iterate a large table (the checksum registry's reads only its
//! per-scope capacities for that reason).

use std::ops::{Add, AddAssign};

use crate::{error::ErrorReport, warn_once_or_debug};

/// Entries and estimated heap bytes of one in-memory store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Footprint {
    pub(crate) entries: usize,
    pub(crate) bytes: usize,
}

impl Add for Footprint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            entries: self.entries.saturating_add(rhs.entries),
            bytes: self.bytes.saturating_add(rhs.bytes),
        }
    }
}

impl AddAssign for Footprint {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

/// Heap bytes of a hashbrown table (`HashMap`, `HashSet`, `HashTable`)
/// reporting `capacity` for buckets of `bucket` bytes: the bucket count is
/// the power of two at or above 8/7 of the capacity, and each bucket costs
/// one control byte on top of its payload, plus one trailing control group.
#[must_use]
pub(crate) const fn table_bytes(capacity: usize, bucket: usize) -> usize {
    if capacity == 0 {
        return 0;
    }
    let buckets = capacity.saturating_mul(8).div_ceil(7).next_power_of_two();
    buckets.saturating_mul(bucket + 1).saturating_add(16)
}

/// Heap bytes of a `Vec`/`VecDeque` with `capacity` slots of `elem` bytes.
#[must_use]
pub(crate) const fn buffer_bytes(capacity: usize, elem: usize) -> usize {
    capacity.saturating_mul(elem)
}

/// The two reference counts an `Arc` allocation carries in front of its
/// value.
pub(crate) const ARC_HEADER: usize = 2 * size_of::<usize>();

/// What `/proc/self/status` says about the process's memory, in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProcessMemory {
    /// `VmRSS`: resident pages, the figure `top` and `systemd` show.
    pub(crate) resident: u64,
    /// `RssAnon`: heap, thread stacks and other private pages.
    pub(crate) anonymous: u64,
    /// `RssFile`: the binary and the shared libraries it maps.
    pub(crate) file_backed: u64,
    /// `RssShmem`: tmpfs and System V shared memory; a shared mapping of a
    /// regular file (SQLite's WAL index) counts as file-backed instead.
    pub(crate) shared: u64,
    /// `VmHWM`: the most resident the process has been.
    pub(crate) peak_resident: u64,
    /// `VmSize`: the address space, reserved or not.
    pub(crate) virtual_size: u64,
}

const PROC_SELF_STATUS: &str = "/proc/self/status";

/// The process's memory now, `None` when `/proc` cannot say.
#[must_use]
pub(crate) fn process_memory() -> Option<ProcessMemory> {
    match std::fs::read_to_string(PROC_SELF_STATUS) {
        Ok(status) => parse_status(&status),
        Err(err) => {
            warn_once_or_debug!(
                "Failed to read `{PROC_SELF_STATUS}`; the dashboard reports the process memory as N/A:  {}",
                ErrorReport(&err)
            );
            None
        }
    }
}

/// The memory lines of a `/proc/<pid>/status` listing; `None` without a
/// `VmRSS` line. The per-kind `Rss*` lines exist since Linux 4.5 and read
/// as zero before that.
fn parse_status(status: &str) -> Option<ProcessMemory> {
    let mut memory = ProcessMemory::default();
    let mut saw_resident = false;
    for line in status.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let field = match key {
            "VmRSS" => {
                saw_resident = true;
                &mut memory.resident
            }
            "RssAnon" => &mut memory.anonymous,
            "RssFile" => &mut memory.file_backed,
            "RssShmem" => &mut memory.shared,
            "VmHWM" => &mut memory.peak_resident,
            "VmSize" => &mut memory.virtual_size,
            _ => continue,
        };
        // `    1234 kB`
        let kib = value
            .trim()
            .strip_suffix("kB")?
            .trim()
            .parse::<u64>()
            .ok()?;
        *field = kib.saturating_mul(1024);
    }
    saw_resident.then_some(memory)
}

/// glibc malloc's account of the heap, in bytes. Only glibc keeps one: the
/// musl build runs mimalloc, which exposes none.
#[cfg(target_env = "gnu")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AllocatorStats {
    /// Bytes handed out and not yet freed, arena blocks and mmapped blocks
    /// alike.
    pub(crate) in_use: u64,
    /// Bytes free inside the arenas: blocks freed and kept for reuse, which
    /// stay resident, and the untouched remainder at each arena's top,
    /// which was never resident. The allocator gives memory back by itself
    /// only from an arena's top.
    pub(crate) retained: u64,
    /// The part of `in_use` served by its own `mmap(2)` (blocks above the
    /// mmap threshold), returned to the kernel the moment it is freed.
    pub(crate) mmapped: u64,
}

/// The allocator's figures now. Walks every arena under its lock, so this
/// is a dashboard reader, not a hot-path one.
#[cfg(target_env = "gnu")]
#[must_use]
pub(crate) fn allocator_stats() -> AllocatorStats {
    // SAFETY: `mallinfo2(3)` takes no arguments, has no preconditions and
    // returns a plain struct by value; it only reads the allocator's own
    // state under the arena locks.
    let info = unsafe { nix::libc::mallinfo2() };
    let bytes = |value: nix::libc::size_t| value as u64;
    AllocatorStats {
        in_use: bytes(info.uordblks).saturating_add(bytes(info.hblkhd)),
        retained: bytes(info.fordblks),
        mmapped: bytes(info.hblkhd),
    }
}

/// SQLite's heap, in bytes: the page caches of the pool's connections, their
/// prepared statements and schema copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SqliteMemory {
    pub(crate) used: u64,
    /// The most it has held since the process started.
    pub(crate) peak: u64,
}

#[must_use]
pub(crate) fn sqlite_memory() -> SqliteMemory {
    let bytes = |value: i64| u64::try_from(value).unwrap_or(0);
    // SAFETY: both functions take no pointer, have no preconditions and read
    // counters SQLite keeps under its own mutex; `0` asks the high-water
    // mark not to be reset.
    let used = unsafe { libsqlite3_sys::sqlite3_memory_used() };
    // SAFETY: as above.
    let peak = unsafe { libsqlite3_sys::sqlite3_memory_highwater(0) };
    SqliteMemory {
        used: bytes(used),
        peak: bytes(peak),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_listing_parses_into_bytes() {
        let status = "Name:\tapt-cacher-rs\nVmPeak:\t  123456 kB\nVmSize:\t  120000 kB\nVmHWM:\t   50000 kB\nVmRSS:\t   40000 kB\nRssAnon:\t   30000 kB\nRssFile:\t   9000 kB\nRssShmem:\t   1000 kB\nThreads:\t17\n";
        assert_eq!(
            parse_status(status),
            Some(ProcessMemory {
                resident: 40_000 * 1024,
                anonymous: 30_000 * 1024,
                file_backed: 9_000 * 1024,
                shared: 1_000 * 1024,
                peak_resident: 50_000 * 1024,
                virtual_size: 120_000 * 1024,
            })
        );
    }

    /// A kernel without the per-kind lines (before 4.5) still yields the
    /// total; a listing without `VmRSS` yields nothing.
    #[test]
    fn missing_lines_read_as_zero_but_the_resident_set_is_required() {
        let parsed = parse_status("VmRSS:\t 2048 kB\n").expect("VmRSS suffices");
        assert_eq!(parsed.resident, 2 * 1024 * 1024);
        assert_eq!(parsed.anonymous, 0);
        assert_eq!(parse_status("VmSize:\t 2048 kB\n"), None);
        assert_eq!(parse_status("VmRSS:\t lots\n"), None, "a malformed value");
    }

    #[test]
    fn the_live_process_reports_a_resident_set() {
        let memory = process_memory().expect("/proc/self/status is readable");
        assert!(memory.resident > 0);
        assert!(memory.peak_resident >= memory.resident);
        assert!(memory.virtual_size >= memory.resident);
        assert!(memory.anonymous + memory.file_backed + memory.shared <= memory.resident + 4096);
    }

    /// The estimate follows hashbrown's bucket rounding: the reported
    /// capacity is 7/8 of a power-of-two bucket count.
    #[test]
    fn table_bytes_follows_the_bucket_rounding() {
        assert_eq!(table_bytes(0, 64), 0);
        // 7 usable of 8 buckets: 8 payloads, 8 control bytes, one group.
        assert_eq!(table_bytes(7, 64), 8 * 65 + 16);
        // 14 of 16.
        assert_eq!(table_bytes(14, 64), 16 * 65 + 16);
        // 896 of 1024; 897 needs 2048.
        assert_eq!(table_bytes(896, 8), 1024 * 9 + 16);
        assert_eq!(table_bytes(897, 8), 2048 * 9 + 16);
        let map: hashbrown::HashMap<u64, u64> = (0..1000).map(|i| (i, i)).collect();
        assert_eq!(
            table_bytes(map.capacity(), 16),
            2048 * 17 + 16,
            "capacity {}",
            map.capacity()
        );
    }

    #[cfg(target_env = "gnu")]
    #[test]
    fn the_allocator_accounts_for_a_live_block() {
        let before = allocator_stats();
        let block = vec![1u8; 1 << 20];
        let during = allocator_stats();
        assert!(
            during.in_use >= before.in_use + (1 << 20),
            "{before:?} -> {during:?}"
        );
        drop(block);
    }

    #[test]
    fn sqlite_reports_its_heap() {
        let memory = sqlite_memory();
        assert!(memory.peak >= memory.used);
    }
}
