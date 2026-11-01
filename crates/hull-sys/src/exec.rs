//! `execve(2)` and `_exit(2)`.

use std::ffi::{CStr, CString};
use std::io;

/// Replace the current process image. Returns only if `execve` failed.
///
/// `path` must already be resolved: this function does no `PATH` search, because the search has
/// to use the *container's* `PATH` and filesystem, not ours.
pub fn execve(path: &CStr, argv: &[CString], envp: &[CString]) -> io::Error {
    let argv_ptrs: Vec<*const libc::c_char> =
        argv.iter().map(|a| a.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();
    let envp_ptrs: Vec<*const libc::c_char> =
        envp.iter().map(|e| e.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();

    // SAFETY: `path` and every element of `argv`/`envp` are valid NUL-terminated strings borrowed
    // for the whole call. Both pointer arrays are NULL-terminated as execve requires. On success
    // execve never returns, so nothing observes the borrowed memory afterwards.
    unsafe {
        libc::execve(path.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
    }
    io::Error::last_os_error()
}

/// Terminate the process immediately with `code`, without running `atexit` handlers or flushing
/// stdio buffers.
///
/// A forked child shares copies of the parent's userspace buffers. Calling `exit` there could
/// flush the parent's half-written output a second time. `_exit` is the correct way out.
pub fn exit_immediately(code: i32) -> ! {
    // SAFETY: `_exit` is always safe to call. It terminates the process and never returns.
    unsafe { libc::_exit(code) }
}
