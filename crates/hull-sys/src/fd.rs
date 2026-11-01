//! File-descriptor hygiene.
//!
//! In 2024 runc shipped CVE-2024-21626 ("Leaky Vessels"): a file descriptor to a host directory
//! leaked into the container, and setting the container's working directory to
//! `/proc/self/fd/<N>` put the process *outside* its root filesystem. The structural fix is to make
//! sure no inherited descriptor survives `execve` unless it was explicitly requested.

use std::io;

const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;

/// Mark every file descriptor numbered `first` or higher as close-on-exec.
///
/// This only sets a flag, so it cannot invalidate an `OwnedFd` held elsewhere in the program.
/// That is why it is safe, unlike closing a range of descriptors outright.
pub fn set_cloexec_from(first: u32) -> io::Result<()> {
    // SAFETY: close_range with CLOSE_RANGE_CLOEXEC only changes descriptor flags. It never closes a
    // descriptor, so it cannot violate I/O safety.
    let ret = unsafe {
        libc::syscall(libc::SYS_close_range, first, libc::c_uint::MAX, CLOSE_RANGE_CLOEXEC)
    };
    crate::cvt(ret).map(drop)
}
