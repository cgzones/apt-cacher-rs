//! RAII buffers that zeroize their contents on drop.
//!
//! Used for buffers that hold TLS key material or partially-decrypted data
//! to reduce the window during which secrets remain in memory.

use nix::libc;

use crate::warn_once_or_debug;

/// A `Vec<u8>` wrapper that zeroizes its contents on drop, pins its
/// backing pages in RAM via `mlock(2)` to prevent the kernel from paging
/// secrets to swap, and excludes them from core dumps via
/// `madvise(MADV_DONTDUMP)`.
pub(crate) struct SecureVec(Vec<u8>);

impl SecureVec {
    pub(crate) fn new(size: usize) -> Self {
        let v = vec![0u8; size];

        // SAFETY: the passed pointer is valid for the given length.
        unsafe { try_mlock(v.as_ptr(), v.capacity()) };
        // SAFETY: the passed pointer is valid for the given length.
        unsafe { try_madvise_dontdump(v.as_ptr(), v.capacity()) };

        Self(v)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn resize(&mut self, new_len: usize, value: u8) {
        let old_len = self.0.len();

        if new_len <= old_len {
            // SAFETY: the passed pointer is valid for the given length.
            unsafe { zeroize(self.0[new_len..].as_mut_ptr(), old_len - new_len) };

            self.0.truncate(new_len);
        } else if new_len > self.0.capacity() {
            // Reallocation needed. Build the replacement as a SecureVec so
            // that a panic between here and the swap automatically zeroizes
            // and munlocks the in-flight buffer via its Drop impl.
            let mut new_sv = Self::new(new_len);
            new_sv[..old_len].copy_from_slice(&self[..old_len]);
            new_sv[old_len..].fill(value);
            // Swap: self becomes the new (populated) buffer; new_sv holds
            // the old buffer whose Drop will zeroize + munlock it.
            std::mem::swap(self, &mut new_sv);
        } else {
            // Fits in existing capacity, no reallocation
            self.0.resize(new_len, value);
        }
    }
}

impl std::fmt::Debug for SecureVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecureVec")
            .field(&format_args!(
                "<{}/{} bytes>",
                self.0.len(),
                self.0.capacity()
            ))
            .finish()
    }
}

impl std::ops::Deref for SecureVec {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::DerefMut for SecureVec {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for SecureVec {
    fn drop(&mut self) {
        // SAFETY: the passed pointer is valid for the given length.
        unsafe { zeroize(self.0.as_mut_ptr(), self.0.capacity()) };
        // Restore the default dump policy so the allocator can reuse these
        // pages for non-sensitive allocations without silently hiding them.
        // SAFETY: the passed pointer is valid for the given length.
        unsafe { try_madvise_dodump(self.0.as_ptr(), self.0.capacity()) };
        // SAFETY: the passed pointer is valid for the given length.
        unsafe { try_munlock(self.0.as_ptr(), self.0.capacity()) };
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
/// for unprivileged processes) is logged at debug level and ignored —
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

/// Best-effort `munlock(2)`. Failure is logged at debug level and ignored.
///
/// # Safety
///
/// The caller must ensure `ptr` points to a valid allocation of at least `len` bytes.
// TODO: use contracts: https://github.com/rust-lang/rust/issues/128044
unsafe fn try_munlock(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }

    // SAFETY: ptr points to `len` bytes of a valid allocation guaranteed by the caller.
    let rc = unsafe { libc::munlock(ptr.cast(), len) };
    if rc != 0 {
        warn_once_or_debug!(
            "munlock({len}) failed:  {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Best-effort `madvise(MADV_DONTDUMP)`. Excludes the range from core dumps.
/// Failure is logged at debug level and ignored.
///
/// # Safety
///
/// The caller must ensure `ptr` points to a valid allocation of at least `len` bytes.
// TODO: use contracts: https://github.com/rust-lang/rust/issues/128044
unsafe fn try_madvise_dontdump(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }

    // SAFETY: ptr points to `len` bytes of a valid allocation guaranteed by the caller.
    let rc = unsafe { libc::madvise(ptr.cast_mut().cast(), len, libc::MADV_DONTDUMP) };
    if rc != 0 {
        warn_once_or_debug!(
            "madvise(MADV_DONTDUMP, {len}) failed:  {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Best-effort `madvise(MADV_DODUMP)`. Restores the default core-dump policy
/// for the range. Called before freeing so the allocator can reuse the pages
/// for non-sensitive allocations without silently hiding them from dumps.
/// Failure is logged at debug level and ignored.
///
/// # Safety
///
/// The caller must ensure `ptr` points to a valid allocation of at least `len` bytes.
// TODO: use contracts: https://github.com/rust-lang/rust/issues/128044
unsafe fn try_madvise_dodump(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }

    // SAFETY: ptr points to `len` bytes of a valid allocation guaranteed by the caller.
    let rc = unsafe { libc::madvise(ptr.cast_mut().cast(), len, libc::MADV_DODUMP) };
    if rc != 0 {
        warn_once_or_debug!(
            "madvise(MADV_DODUMP, {len}) failed:  {}",
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
    use super::SecureVec;

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
        // new_len == self.0.len() exercises the truncate branch with a
        // zero-length zeroize (one-past-the-end pointer + len 0).
        let mut sv = SecureVec::new(8);
        sv.copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        sv.resize(8, 0);
        assert_eq!(sv.len(), 8);
        assert_eq!(&*sv, &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn resize_zero_to_zero() {
        // Both branches use len 0 — verify nothing panics when zeroizing /
        // unlocking an empty buffer.
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
    fn resize_grow_from_empty() {
        // old_len == 0 exercises copy_nonoverlapping with len 0.
        let mut sv = SecureVec::new(0);
        sv.resize(8, 0x42);
        assert_eq!(sv.len(), 8);
        assert_eq!(&*sv, &[0x42; 8]);
    }

    #[test]
    fn resize_realloc_uses_truncated_len() {
        // After truncation the realloc path must copy `old_len` (=3), not the
        // original capacity (=8); otherwise stale bytes would leak through.
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
        // mlock/munlock/zeroize must short-circuit on len 0.
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
        // After realloc the original buffer was already zeroized + munlocked;
        // the new buffer must be freed cleanly on drop.
        let mut sv = SecureVec::new(4);
        sv.copy_from_slice(&[1, 2, 3, 4]);
        sv.resize(4096, 0);
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
}
