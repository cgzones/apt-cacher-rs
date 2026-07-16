//! RAII buffers that zeroize their contents on drop.
//!
//! Used for buffers that hold TLS key material or partially-decrypted data
//! to reduce the window during which secrets remain in memory.
//!
//! Each buffer is backed by its own anonymous memory mapping instead of the
//! global heap: `mlock(2)` and `madvise(2)` operate on whole pages without
//! reference counting, so heap-backed buffers sharing a page with unrelated
//! allocations would lose their protection as soon as a neighbour releases
//! it. A dedicated mapping makes the protection page-exact, and `munmap(2)`
//! on drop tears it down with the pages — no munlock/`MADV_DODUMP` restore
//! step exists to get wrong. A small process-wide pool recycles the hot
//! buffer sizes (the kTLS handshake's 32 KiB incoming / 8 KiB outgoing
//! buffers) to avoid per-connection mmap/mlock churn.

use std::alloc::{Layout, handle_alloc_error};
use std::num::NonZero;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, OnceLock};

use hashbrown::HashMap;
use nix::libc;
use tracing::{debug, error};

use crate::{nonzero, warn_once_or_debug};

/// Whether buffers are pinned in RAM via `mlock(2)` — config
/// `ktls_memory_lock`, stored here by `main()` so this module never touches
/// `global_config()` and stays unit-testable. Locking is best-effort either
/// way; zeroize-on-drop and `MADV_DONTDUMP` are unconditional.
static LOCK_ENABLED: AtomicBool = AtomicBool::new(true);

/// Set from `main()` after config parsing (config option `ktls_memory_lock`).
pub(crate) fn set_lock_enabled(enabled: bool) {
    LOCK_ENABLED.store(enabled, Ordering::Relaxed);
}

/// A `Vec<u8>`-like buffer that zeroizes its contents on drop, pins its
/// backing pages in RAM via `mlock(2)` to prevent the kernel from paging
/// secrets to swap, and excludes them from core dumps via
/// `madvise(MADV_DONTDUMP)`.
pub(crate) struct SecureVec {
    /// Start of the dedicated mapping; dangling iff `map_len == 0`.
    ptr: NonNull<u8>,
    /// Logical length. Invariants: `len <= map_len`, and bytes in
    /// `[len, map_len)` are always zero (fresh mappings are kernel
    /// zero-filled, `resize` zeroizes on shrink, and the pool only parks
    /// fully zeroized regions).
    len: usize,
    /// Size of the mapping in bytes; a whole number of pages, or 0 for the
    /// empty buffer (no mapping).
    map_len: usize,
}

// SAFETY: the region is exclusively owned (a fresh anonymous private mapping,
// or one handed out by the pool to exactly one owner) and carries no thread
// affinity; `u8` is `Send`. Required because the kTLS handshake holds
// `SecureVec` locals across `.await` points on a work-stealing runtime.
unsafe impl Send for SecureVec {}

impl SecureVec {
    #[must_use]
    pub(crate) fn new(size: usize) -> Self {
        if size == 0 {
            return Self {
                ptr: NonNull::dangling(),
                len: 0,
                map_len: 0,
            };
        }

        let lock = LOCK_ENABLED.load(Ordering::Relaxed);
        let map_len = page_round_up(size);
        let ptr = if let Some(ptr) = pool_checkout(map_len) {
            if lock {
                // Re-lock on checkout: a no-op for already-locked pages, and
                // it heals regions whose creation-time mlock failed.
                // SAFETY: live mapping of `map_len` bytes.
                unsafe { try_mlock(ptr.as_ptr(), map_len) };
            }
            ptr
        } else {
            let ptr = map_region(map_len);
            if lock {
                // SAFETY: live mapping of `map_len` bytes.
                unsafe { try_mlock(ptr.as_ptr(), map_len) };
            }
            // SAFETY: `ptr` is the page-aligned start of a live mapping of
            // `map_len` bytes.
            unsafe { try_madvise_dontdump(ptr.as_ptr(), map_len) };
            ptr
        };

        Self {
            ptr,
            len: size,
            map_len,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn resize(&mut self, new_len: usize, value: u8) {
        let old_len = self.len;

        if new_len <= old_len {
            // SAFETY: `new_len <= old_len <= map_len`, so the offset stays
            // within the mapping (or is the dangling pointer with offset 0
            // for the empty buffer).
            let tail = unsafe { self.ptr.as_ptr().add(new_len) };
            // SAFETY: `[new_len, old_len)` lies within the live mapping.
            unsafe { zeroize(tail, old_len - new_len) };
            self.len = new_len;
        } else if new_len <= self.map_len {
            // Fits into the existing mapping. Bytes in `[old_len, map_len)`
            // are zero by invariant; overwrite the grown range with `value`
            // (Vec::resize semantics).
            self.len = new_len;
            self[old_len..].fill(value);
        } else {
            // Mapping too small. Build the replacement as a SecureVec so
            // that a panic between here and the swap automatically zeroizes
            // the in-flight buffer via its Drop impl.
            let mut new_sv = Self::new(new_len);
            new_sv[..old_len].copy_from_slice(&self[..old_len]);
            new_sv[old_len..].fill(value);
            // Swap: self becomes the new (populated) buffer; new_sv holds
            // the old one, whose Drop will zeroize and recycle it.
            std::mem::swap(self, &mut new_sv);
        }
    }
}

impl std::fmt::Debug for SecureVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecureVec")
            .field(&format_args!("<{}/{} bytes>", self.len, self.map_len))
            .finish()
    }
}

impl std::ops::Deref for SecureVec {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: `ptr` is valid for `len` initialized bytes (mappings are
        // kernel zero-filled, later writes happen only through `&mut [u8]`);
        // dangling + length 0 is a valid empty slice.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl std::ops::DerefMut for SecureVec {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `deref`; `&mut self` guarantees exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for SecureVec {
    fn drop(&mut self) {
        if self.map_len == 0 {
            return;
        }
        // Zeroize the full mapping — the pool's zero-content invariant
        // depends on it. No munlock/MADV_DODUMP restore is needed: the
        // mapping is exclusively ours, so parking it keeps the protection
        // and unmapping removes it together with the pages.
        // SAFETY: live mapping of `map_len` bytes.
        unsafe { zeroize(self.ptr.as_ptr(), self.map_len) };
        pool_checkin(self.ptr, self.map_len);
    }
}

// ---------------------------------------------------------------------------
// Region pool
// ---------------------------------------------------------------------------

/// Only regions up to this size are recycled: covers the hot kTLS handshake
/// classes (8 KiB outgoing / 32 KiB incoming plus moderate growth). Rarer
/// large growth regions (up to 2 MiB) are unmapped directly on drop.
const POOL_MAX_REGION_LEN: usize = 64 * 1024;

/// Cap on total parked bytes — also the bound on how much locked memory the
/// pool retains indefinitely. Enforced under the pool lock, so parked bytes
/// never exceed it.
const POOL_MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024;

/// A zeroized region parked in the pool. The mapping keeps its mlock /
/// `MADV_DONTDUMP` state while parked; its content is all zeros. There is no
/// Drop impl: regions leave the pool via checkout, or are unmapped at
/// checking when over cap; the pool itself lives until process exit.
struct ParkedRegion(NonNull<u8>);

// SAFETY: an exclusively-owned anonymous mapping with no thread affinity;
// parked regions are only handled under the pool mutex.
unsafe impl Send for ParkedRegion {}

struct SecurePool {
    /// Sum of the mapping sizes of all parked regions;
    /// `<= POOL_MAX_TOTAL_BYTES`.
    total_bytes: usize,
    /// Free lists keyed by mapping size (a page multiple).
    regions: HashMap<usize, Vec<ParkedRegion>>,
}

static SECURE_POOL: OnceLock<parking_lot::Mutex<SecurePool>> = OnceLock::new();

fn secure_pool() -> &'static parking_lot::Mutex<SecurePool> {
    SECURE_POOL.get_or_init(|| {
        parking_lot::Mutex::new(SecurePool {
            total_bytes: 0,
            regions: HashMap::new(),
        })
    })
}

/// Take a parked region of exactly `map_len` bytes out of the pool.
fn pool_checkout(map_len: usize) -> Option<NonNull<u8>> {
    let region = {
        let mut pool = secure_pool().lock();
        let region = pool.regions.get_mut(&map_len)?.pop()?;
        pool.total_bytes -= map_len;
        region
    };

    #[cfg(debug_assertions)]
    {
        // SAFETY: parked regions are live mappings of exactly `map_len` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(region.0.as_ptr(), map_len) };
        debug_assert!(
            bytes.iter().all(|&b| b == 0),
            "pooled secure region was not zeroized"
        );
    }

    Some(region.0)
}

/// Park a fully zeroized region in the pool, or unmap it when it is larger
/// than the pooled classes or the pool is at capacity.
fn pool_checkin(ptr: NonNull<u8>, map_len: usize) {
    if map_len <= POOL_MAX_REGION_LEN {
        // Scope the pool guard so it drops before the unmap syscall below.
        let parked = {
            let mut pool = secure_pool().lock();
            if pool.total_bytes + map_len <= POOL_MAX_TOTAL_BYTES {
                pool.total_bytes += map_len;
                pool.regions
                    .entry(map_len)
                    .or_default()
                    .push(ParkedRegion(ptr));
                true
            } else {
                false
            }
        };
        if parked {
            return;
        }
    }

    // SAFETY: `ptr`/`map_len` come from our own successful `map_region` call
    // and this is the region's sole owner; it is unmapped exactly once (here,
    // or never while parked).
    unsafe { unmap_region(ptr, map_len) };
}

#[cfg(test)]
fn pool_parked_bytes() -> usize {
    secure_pool().lock().total_bytes
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

static PAGE_SIZE: LazyLock<Option<NonZero<usize>>> =
    LazyLock::new(
        || match nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE) {
            Ok(Some(size))
                if let Ok(size) = usize::try_from(size)
                    && let Some(size) = NonZero::new(size) =>
            {
                debug!("Page size: {size} bytes");
                Some(size)
            }
            Ok(Some(size)) => {
                error!("Invalid page size of {size} bytes");
                None
            }
            Ok(None) => {
                error!("Page size is not available");
                None
            }

            Err(errno) => {
                error!("Failed to get page size:  {errno}");
                None
            }
        },
    );

/// Effective page size for sizing mappings: the runtime value when available,
/// 4 KiB otherwise. `mmap`/`munmap`/`madvise` round lengths internally, so a
/// wrong fallback only affects pool keying granularity, not correctness.
fn page_size() -> NonZero<usize> {
    (*PAGE_SIZE).unwrap_or(nonzero!(4096))
}

fn round_up(a: usize, b: NonZero<usize>) -> Option<usize> {
    let rem = a % b.get();
    if rem == 0 {
        return Some(a);
    }
    a.checked_add(b.get() - rem)
}

/// Round `size` up to a whole number of pages for mapping.
fn page_round_up(size: usize) -> usize {
    match round_up(size, page_size()) {
        Some(len) => len,
        None => secure_alloc_failure(size),
    }
}

/// Abort with allocation-failure semantics, matching the previous infallible
/// `vec![0u8; size]` backing (`panic!` is denied by lint policy, and aborting
/// is the established behavior for allocation failure).
#[cold]
fn secure_alloc_failure(size: usize) -> ! {
    let layout = Layout::from_size_align(size, 1).unwrap_or(Layout::new::<u8>());
    handle_alloc_error(layout)
}

/// Create a dedicated anonymous mapping of `map_len` bytes (page-aligned,
/// kernel zero-filled — no memset needed). Aborts on failure.
fn map_region(map_len: usize) -> NonNull<u8> {
    debug_assert!(map_len > 0, "empty buffers must not allocate a mapping");

    // SAFETY: plain anonymous private mapping request (no fd, no address
    // hint); `map_len` is non-zero.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        error!(
            "mmap({map_len}) failed:  {}",
            std::io::Error::last_os_error()
        );
        secure_alloc_failure(map_len);
    }
    match NonNull::new(ptr.cast::<u8>()) {
        Some(ptr) => ptr,
        // Unreachable in practice: a successful mmap without MAP_FIXED never
        // returns the zero page.
        None => secure_alloc_failure(map_len),
    }
}

/// Unmap a region previously created by [`map_region`].
///
/// # Safety
///
/// `ptr` and `map_len` must come from a successful `map_region(map_len)`
/// call, and the region must not have been unmapped before.
unsafe fn unmap_region(ptr: NonNull<u8>, map_len: usize) {
    // SAFETY: guaranteed by the caller.
    let rc = unsafe { libc::munmap(ptr.as_ptr().cast::<libc::c_void>(), map_len) };
    if rc != 0 {
        error!(
            "munmap({map_len}) failed:  {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Zeroize memory using `explicit_bzero`, which is guaranteed not to be
/// optimized away by the compiler.
///
/// # Safety
///
/// The caller must ensure `ptr` points to a valid allocation of at least `len` bytes.
// TODO: use contracts: https://github.com/rust-lang/rust/issues/128044
unsafe fn zeroize(ptr: *mut u8, len: usize) {
    if len == 0 {
        return;
    }

    // SAFETY: ptr points to `len` bytes of a valid allocation guaranteed by the caller.
    unsafe { libc::explicit_bzero(ptr.cast(), len) };
}

/// Best-effort `mlock(2)`. Failure (typically `RLIMIT_MEMLOCK` exhaustion
/// for unprivileged processes) is logged once at warn level (debug thereafter) and ignored —
/// zeroization on drop remains the primary defense.
///
/// # Safety
///
/// The caller must ensure `ptr` points to a valid allocation of at least `len` bytes.
// TODO: use contracts: https://github.com/rust-lang/rust/issues/128044
unsafe fn try_mlock(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }

    // SAFETY: ptr points to `len` bytes of a valid allocation guaranteed by the caller.
    let rc = unsafe { libc::mlock(ptr.cast(), len) };
    if rc != 0 {
        warn_once_or_debug!("mlock({len}) failed:  {}", std::io::Error::last_os_error());
    }
}

/// Best-effort `madvise(MADV_DONTDUMP)`. Excludes the range from core dumps.
/// Failure is logged once at warn level (debug thereafter) and ignored.
///
/// # Safety
///
/// `ptr` must be the page-aligned start of a live mapping of at least `len`
/// bytes (the kernel extends `len` to page granularity).
unsafe fn try_madvise_dontdump(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }

    // SAFETY: guaranteed by the caller.
    let rc = unsafe {
        libc::madvise(
            ptr.cast_mut().cast::<libc::c_void>(),
            len,
            libc::MADV_DONTDUMP,
        )
    };
    if rc != 0 {
        warn_once_or_debug!(
            "madvise(MADV_DONTDUMP, {len}) failed:  {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_asserts_for_indexing,
    reason = "tests assert exact len via assert_eq! before indexing"
)]
mod tests {
    use super::*;

    #[test]
    fn new_zero_size() {
        let sv = SecureVec::new(0);
        assert_eq!(sv.len(), 0, "zero-sized SecureVec must have len 0");
        assert!(sv.is_empty(), "zero-sized SecureVec must be empty");
        assert_eq!(&*sv, b"", "zero-sized SecureVec must deref to empty slice");
    }

    #[test]
    fn new_zero_initialized() {
        let sv = SecureVec::new(64);
        assert_eq!(sv.len(), 64, "len should match requested size");
        assert!(
            sv.iter().all(|&b| b == 0),
            "newly constructed SecureVec must be zeroed"
        );
    }

    #[test]
    fn new_page_sized() {
        // Larger than a typical page so mlock spans multiple pages.
        let sv = SecureVec::new(16 * 4096);
        assert_eq!(sv.len(), 16 * 4096);
        assert!(sv.iter().all(|&b| b == 0));
    }

    #[test]
    fn deref_mut_allows_write() {
        let mut sv = SecureVec::new(8);
        sv.copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&*sv, &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn resize_truncate() {
        let mut sv = SecureVec::new(10);
        sv.copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        sv.resize(5, 0xff);
        assert_eq!(sv.len(), 5, "len should shrink");
        assert_eq!(&*sv, &[1, 2, 3, 4, 5], "leading bytes preserved");
    }

    #[test]
    fn resize_truncate_to_zero() {
        let mut sv = SecureVec::new(10);
        sv[0] = 0xab;
        sv[9] = 0xcd;
        sv.resize(0, 0);
        assert_eq!(sv.len(), 0);
        assert_eq!(&*sv, b"");
    }

    #[test]
    fn resize_same_length_noop() {
        // new_len == self.len exercises the truncate branch with a
        // zero-length zeroize (one-past-the-end pointer + len 0).
        let mut sv = SecureVec::new(8);
        sv.copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        sv.resize(8, 0);
        assert_eq!(sv.len(), 8);
        assert_eq!(&*sv, &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn resize_zero_to_zero() {
        // Both branches use len 0 — verify nothing panics when zeroizing an
        // empty buffer without a mapping.
        let mut sv = SecureVec::new(0);
        sv.resize(0, 0xff);
        assert_eq!(sv.len(), 0);
    }

    #[test]
    fn resize_grow_within_capacity() {
        let mut sv = SecureVec::new(10);
        sv[0..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        sv.resize(5, 0);
        assert_eq!(sv.len(), 5);
        sv.resize(8, 0xaa);
        assert_eq!(sv.len(), 8);
        assert_eq!(&*sv, &[1, 2, 3, 4, 5, 0xaa, 0xaa, 0xaa]);
    }

    #[test]
    fn resize_grow_beyond_capacity() {
        let mut sv = SecureVec::new(4);
        sv.copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        sv.resize(16, 0xcc);
        assert_eq!(sv.len(), 16);
        assert_eq!(
            &sv[0..4],
            &[0xde, 0xad, 0xbe, 0xef],
            "existing bytes copied to new allocation"
        );
        assert_eq!(&sv[4..16], &[0xcc; 12], "new bytes filled with value");
    }

    #[test]
    fn resize_grow_beyond_page_reallocs() {
        // Growth past the mapping size takes the new-mapping + copy + swap
        // path (in-page growth is handled in place since the capacity is
        // page-rounded).
        let mut sv = SecureVec::new(4096);
        sv.fill(0xdb);
        sv.resize(2 * 4096 + 1, 0x7e);
        assert_eq!(sv.len(), 2 * 4096 + 1);
        assert_eq!(&sv[..4096], &[0xdb; 4096], "existing bytes preserved");
        assert_eq!(&sv[4096..], &[0x7e; 4097], "grown bytes filled with value");
    }

    #[test]
    fn resize_grow_from_empty() {
        // old_len == 0 exercises the grow-path copy with an empty source.
        let mut sv = SecureVec::new(0);
        sv.resize(8, 0x42);
        assert_eq!(sv.len(), 8);
        assert_eq!(&*sv, &[0x42; 8]);
    }

    #[test]
    fn resize_realloc_uses_truncated_len() {
        // After truncation the grow path must copy `old_len` (=3), not the
        // original size (=8); otherwise stale bytes would leak through.
        let mut sv = SecureVec::new(8);
        sv.copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        sv.resize(3, 0);
        assert_eq!(&*sv, &[1, 2, 3]);
        sv.resize(20, 9);
        assert_eq!(sv.len(), 20);
        assert_eq!(&sv[0..3], &[1, 2, 3]);
        assert_eq!(&sv[3..20], &[9; 17]);
    }

    #[test]
    fn resize_multiple_reallocations() {
        let mut sv = SecureVec::new(2);
        sv.copy_from_slice(&[1, 2]);
        sv.resize(8, 3);
        assert_eq!(&*sv, &[1, 2, 3, 3, 3, 3, 3, 3]);
        sv.resize(32, 4);
        assert_eq!(sv.len(), 32);
        assert_eq!(&sv[..8], &[1, 2, 3, 3, 3, 3, 3, 3]);
        assert_eq!(&sv[8..32], &[4; 24]);
        sv.resize(2, 0);
        assert_eq!(&*sv, &[1, 2]);
        sv.resize(128, 5);
        assert_eq!(sv.len(), 128);
        assert_eq!(&sv[..2], &[1, 2]);
        assert_eq!(&sv[2..128], &[5; 126]);
    }

    #[test]
    fn resize_grow_within_capacity_after_truncation_overwrites_zeroed_tail() {
        // Truncation zeroizes the tail; growing back within capacity must
        // overwrite it with `value` (Vec::resize semantics).
        let mut sv = SecureVec::new(16);
        sv.copy_from_slice(&[0xaa; 16]);
        sv.resize(4, 0);
        sv.resize(16, 0x55);
        assert_eq!(&sv[..4], &[0xaa; 4]);
        assert_eq!(&sv[4..], &[0x55; 12]);
    }

    #[test]
    fn drop_zero_size_does_not_panic() {
        // The empty buffer has no mapping; Drop must short-circuit.
        let sv = SecureVec::new(0);
        drop(sv);
    }

    #[test]
    fn drop_after_resize_to_zero_does_not_panic() {
        let mut sv = SecureVec::new(16);
        sv.resize(0, 0);
        drop(sv);
    }

    #[test]
    fn drop_after_realloc_does_not_panic() {
        // After growth past the mapping size the original region was already
        // zeroized and recycled; the new buffer must be freed cleanly on drop.
        let mut sv = SecureVec::new(4);
        sv.copy_from_slice(&[1, 2, 3, 4]);
        sv.resize(2 * 4096, 0);
        drop(sv);
    }

    #[test]
    fn debug_format_redacts_contents() {
        let mut sv = SecureVec::new(8);
        sv.copy_from_slice(b"secret!!");
        let s = format!("{sv:?}");
        assert!(s.contains("SecureVec"), "type name should appear: {s}");
        assert!(s.contains('8'), "length should appear: {s}");
        assert!(
            !s.contains("secret"),
            "raw contents must not appear in Debug output: {s}"
        );
    }

    #[test]
    fn secure_vec_is_send() {
        // Compile-time assertion: the kTLS handshake holds SecureVec across
        // `.await` points on a work-stealing runtime.
        fn assert_send<T: Send>() {}
        assert_send::<SecureVec>();
    }

    // The pool tests below each use a size class no other test allocates, so
    // parallel test threads cannot steal each other's parked regions.

    #[test]
    fn pool_reuses_region() {
        let first = SecureVec::new(48 * 1024);
        let first_ptr = first.as_ptr();
        drop(first);
        let second = SecureVec::new(48 * 1024);
        assert_eq!(
            second.as_ptr(),
            first_ptr,
            "region should be reused from the pool"
        );
    }

    #[test]
    fn pool_checkout_is_zeroed() {
        let mut sv = SecureVec::new(44 * 1024);
        sv.fill(0xa5);
        drop(sv);
        let sv = SecureVec::new(44 * 1024);
        assert!(
            sv.iter().all(|&b| b == 0),
            "pooled region must be zeroized on checkout"
        );
    }

    #[test]
    fn oversize_region_not_pooled() {
        let sv = SecureVec::new(128 * 1024);
        let map_len = sv.map_len;
        assert!(map_len > POOL_MAX_REGION_LEN, "test premise");
        drop(sv);
        assert!(
            pool_checkout(map_len).is_none(),
            "regions above POOL_MAX_REGION_LEN must not be pooled"
        );
    }

    #[test]
    fn pool_cap_bounds_parked_bytes() {
        // Park far more than the cap; checking must unmap the excess. The cap
        // is enforced under the pool lock, so this holds even with other
        // tests parking concurrently.
        let bufs: Vec<SecureVec> = std::iter::repeat_with(|| SecureVec::new(60 * 1024))
            .take(40)
            .collect();
        drop(bufs);
        assert!(
            pool_parked_bytes() <= POOL_MAX_TOTAL_BYTES,
            "parked bytes must never exceed POOL_MAX_TOTAL_BYTES"
        );
    }

    #[test]
    fn lock_disabled_smoke() {
        // Locking is best-effort and invisible to assertions; concurrent
        // tests allocating while it is disabled merely skip the mlock,
        // which is harmless.
        set_lock_enabled(false);
        let mut sv = SecureVec::new(52 * 1024);
        sv.fill(0x5c);
        assert!(sv.iter().all(|&b| b == 0x5c));
        drop(sv);
        set_lock_enabled(true);
    }

    #[test]
    fn test_round_up() {
        assert_eq!(round_up(10, nonzero!(12)), Some(12));
        assert_eq!(round_up(10, nonzero!(7)), Some(14));
        assert_eq!(round_up(10, nonzero!(3)), Some(12));
        assert_eq!(round_up(10, nonzero!(2)), Some(10));
        assert_eq!(round_up(10, nonzero!(1)), Some(10));
    }
}
