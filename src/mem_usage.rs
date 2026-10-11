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

/// The least mmap threshold [`tune_allocator`] pins: blocks of this size
/// and above come straight from `mmap(2)` and go back to the kernel the
/// moment they are freed. Above every table the daemon keeps around and the
/// default transfer buffer; below an LZMA dictionary, a `Packages` buffer
/// and a registry scope's slot log once it holds a few tens of thousands of
/// entries.
#[cfg(target_env = "gnu")]
const MIN_MMAP_THRESHOLD: usize = if MAX_MMAP_THRESHOLD < 1024 * 1024 {
    MAX_MMAP_THRESHOLD
} else {
    1024 * 1024
};

/// The most glibc accepts, half its arena heap size: 32 MiB on 64-bit,
/// which is also where its dynamic threshold stops rising, and 512 KiB on
/// 32-bit.
#[cfg(all(target_env = "gnu", target_pointer_width = "64"))]
const MAX_MMAP_THRESHOLD: usize = 32 * 1024 * 1024;
#[cfg(all(target_env = "gnu", not(target_pointer_width = "64")))]
const MAX_MMAP_THRESHOLD: usize = 512 * 1024;

/// Slack between the largest buffer and the pin. glibc compares the
/// threshold with the chunk it allocates, the request plus a header rounded
/// up to 16 bytes, so a block of exactly the buffer's size would sit above a
/// pin one byte beyond it; a page covers the header and the rounding.
#[cfg(target_env = "gnu")]
const BUFFER_HEADROOM: usize = 4096;

/// What [`tune_allocator`] did, for [`Self::log`] once logging is up.
#[cfg(target_env = "gnu")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllocatorTuning {
    Pinned(usize),
    /// glibc refused the value, so its dynamic threshold stays.
    Rejected(usize),
}

#[cfg(target_env = "gnu")]
impl AllocatorTuning {
    pub(crate) fn log(self) {
        match self {
            Self::Pinned(threshold) => {
                tracing::debug!("Allocator mmap threshold pinned at {threshold} bytes");
            }
            Self::Rejected(threshold) => {
                tracing::warn!(
                    "Failed to set the allocator's mmap threshold to {threshold} bytes; freed index buffers may stay resident"
                );
            }
        }
    }
}

/// The pin for a process whose largest per-connection buffer is
/// `largest_buffer` bytes: [`BUFFER_HEADROOM`] above it, within glibc's
/// range.
#[cfg(target_env = "gnu")]
const fn pinned_threshold(largest_buffer: usize) -> usize {
    let threshold = largest_buffer.saturating_add(BUFFER_HEADROOM);
    if threshold < MIN_MMAP_THRESHOLD {
        MIN_MMAP_THRESHOLD
    } else if threshold > MAX_MMAP_THRESHOLD {
        MAX_MMAP_THRESHOLD
    } else {
        threshold
    }
}

/// Pin glibc's mmap threshold just above `largest_buffer`, the biggest block
/// a connection allocates, and at [`MIN_MMAP_THRESHOLD`] at least.
///
/// By default the threshold starts at 128 KiB and rises to the size of
/// every larger block freed, up to 32 MiB: the first freed 8 MiB LZMA
/// dictionary moves every later dictionary, every `Packages` buffer and
/// every reallocation of a growing table into the arenas, where a freed
/// block only leaves if it sits at the arena's top. Measured on nine Debian
/// indexes: 85 MB freed but retained next to 85 MB in use, the retained
/// part never returned. Pinned, those blocks are mapped on their own and
/// unmapped on free; the arenas keep the small blocks they are good at.
///
/// The per-connection buffers stay below the pin whatever `buffer_size`
/// says (up to glibc's ceiling, past which the dynamic threshold would have
/// mapped them too): a buffer per connection through `mmap(2)` would be a
/// mapping and a round of page faults per transfer.
///
/// Call it once the configuration is loaded and before the process starts
/// a second thread: glibc lists `mallopt(3)` as MT-unsafe, its parameter
/// writes being unsynchronised with allocations on other threads. The
/// outcome is returned for logging because logging is not up yet at that
/// point. It overrides a `GLIBC_TUNABLES=glibc.malloc.mmap_threshold=` the
/// operator may have set.
///
/// mimalloc (the musl build's allocator) returns freed memory itself, so
/// there is nothing to tune there.
#[cfg(target_env = "gnu")]
#[must_use]
pub(crate) fn tune_allocator(largest_buffer: usize) -> AllocatorTuning {
    let threshold = pinned_threshold(largest_buffer);
    let value = nix::libc::c_int::try_from(threshold).expect("at most 32 MiB");
    // SAFETY: `mallopt(3)` takes two integers and only writes the
    // allocator's parameters; the caller keeps every other thread from
    // allocating meanwhile (see above).
    let ok = unsafe { nix::libc::mallopt(nix::libc::M_MMAP_THRESHOLD, value) };
    if ok == 1 {
        AllocatorTuning::Pinned(threshold)
    } else {
        AllocatorTuning::Rejected(threshold)
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

    #[cfg(target_env = "gnu")]
    #[test]
    fn the_pin_sits_above_the_largest_buffer_within_glibc_s_range() {
        assert_eq!(pinned_threshold(0), MIN_MMAP_THRESHOLD);
        // The largest buffer the headroom still fits above; on 32-bit the
        // floor and the ceiling coincide and the pin is the ceiling.
        let largest = MAX_MMAP_THRESHOLD - BUFFER_HEADROOM;
        assert_eq!(pinned_threshold(largest), MAX_MMAP_THRESHOLD);
        assert!(
            pinned_threshold(largest) > largest + 16,
            "the chunk header must fit below the pin"
        );
        assert_eq!(pinned_threshold(usize::MAX), MAX_MMAP_THRESHOLD);
    }

    /// The pin exists so that a per-connection buffer is never a mapping of
    /// its own; one of exactly the largest size must come from the arena
    /// while a larger block is mapped and returned on free. Runs in its own
    /// process under nextest, so the pin affects no other test.
    #[cfg(all(target_env = "gnu", target_pointer_width = "64"))]
    #[test]
    fn a_block_of_the_largest_buffer_s_size_stays_in_the_arena() {
        let largest = 4 * 1024 * 1024;
        assert_eq!(
            tune_allocator(largest),
            AllocatorTuning::Pinned(largest + BUFFER_HEADROOM)
        );
        let before = allocator_stats().mmapped;
        let buffer: Vec<u8> = Vec::with_capacity(largest);
        std::hint::black_box(&buffer);
        assert_eq!(
            allocator_stats().mmapped,
            before,
            "a block of the buffer's size must come from the arena"
        );
        let bigger: Vec<u8> = Vec::with_capacity(2 * largest);
        std::hint::black_box(&bigger);
        assert!(
            allocator_stats().mmapped > before,
            "a block above the pin is mapped on its own"
        );
        drop(bigger);
        assert_eq!(allocator_stats().mmapped, before, "and unmapped on free");
        drop(buffer);
    }

    #[test]
    fn sqlite_reports_its_heap() {
        let memory = sqlite_memory();
        assert!(memory.peak >= memory.used);
    }
}
