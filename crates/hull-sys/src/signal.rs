//! Signal masks, `signalfd(2)`, and resetting signal dispositions.
//!
//! Two lessons are encoded here:
//!
//! 1. **The signal mask survives `execve`.** The runtime blocks signals so it can read them from a
//!    signalfd. The container's process inherits that mask unless the child explicitly unblocks
//!    everything before `execve`. A container whose `SIGTERM` is blocked cannot be stopped
//!    gracefully, and nothing reports why.
//! 2. **Ignored signals survive `execve`.** Handlers are reset to the default on `execve`, but
//!    `SIG_IGN` is not. The Rust standard library sets `SIGPIPE` to `SIG_IGN` before `main` runs.
//!    Without [`reset_dispositions`], every container started by a Rust runtime would ignore
//!    `SIGPIPE`, and pipelines such as `yes | head -1` would behave differently than under Docker.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// A set of signals (`sigset_t`).
#[derive(Clone, Copy)]
pub struct SigSet(libc::sigset_t);

impl std::fmt::Debug for SigSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let members: Vec<i32> = (1..=64).filter(|&s| self.contains(s)).collect();
        f.debug_tuple("SigSet").field(&members).finish()
    }
}

impl SigSet {
    /// The empty set.
    pub fn empty() -> Self {
        // SAFETY: an all-zero sigset_t is a valid value, and sigemptyset fully initializes it.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: `set` is a valid, writable sigset_t.
        unsafe { libc::sigemptyset(&raw mut set) };
        Self(set)
    }

    /// A set containing `signals`. Invalid signal numbers are ignored.
    pub fn of(signals: &[i32]) -> Self {
        let mut set = Self::empty();
        for &sig in signals {
            set.add(sig);
        }
        set
    }

    /// Add `sig` to the set. Invalid signal numbers are ignored.
    pub fn add(&mut self, sig: i32) {
        // SAFETY: `self.0` is a valid sigset_t. sigaddset validates `sig` and returns -1 for
        // invalid numbers without touching the set.
        unsafe { libc::sigaddset(&raw mut self.0, sig) };
    }

    /// Whether `sig` is in the set.
    pub fn contains(&self, sig: i32) -> bool {
        // SAFETY: `self.0` is a valid sigset_t; sigismember only reads it.
        unsafe { libc::sigismember(&raw const self.0, sig) == 1 }
    }
}

fn sigprocmask(how: libc::c_int, set: &SigSet) -> io::Result<SigSet> {
    let mut old = SigSet::empty();
    // SAFETY: both pointers refer to valid sigset_t values that outlive the call.
    let ret = unsafe { libc::sigprocmask(how, &raw const set.0, &raw mut old.0) };
    crate::cvt(ret.into()).map(|_| old)
}

/// Add `set` to the blocked-signal mask. Returns the previous mask.
pub fn block(set: &SigSet) -> io::Result<SigSet> {
    sigprocmask(libc::SIG_BLOCK, set)
}

/// Replace the blocked-signal mask with `set`. Returns the previous mask.
pub fn set_mask(set: &SigSet) -> io::Result<SigSet> {
    sigprocmask(libc::SIG_SETMASK, set)
}

/// Create a signalfd that becomes readable when a signal in `set` is pending.
///
/// The signals must also be *blocked*, or they are delivered normally instead of being queued.
pub fn signalfd(set: &SigSet) -> io::Result<OwnedFd> {
    // SAFETY: `set.0` is a valid sigset_t. -1 asks for a new fd.
    let fd = unsafe { libc::signalfd(-1, &raw const set.0, libc::SFD_CLOEXEC) };
    crate::cvt(fd.into())?;
    // SAFETY: signalfd returned a new open fd that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Read one pending signal from a signalfd and return its number.
pub fn read_signalfd(fd: BorrowedFd<'_>) -> io::Result<i32> {
    // SAFETY: an all-zero signalfd_siginfo is a valid value.
    let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::signalfd_siginfo>();
    // SAFETY: `info` is a writable buffer of exactly `size` bytes.
    let n = unsafe { libc::read(fd.as_raw_fd(), (&raw mut info).cast(), size) };
    let n = crate::cvt(n.try_into().unwrap_or(-1))?;
    if usize::try_from(n).ok() != Some(size) {
        return Err(io::Error::other("short read from signalfd"));
    }
    i32::try_from(info.ssi_signo).map_err(|_| io::Error::other("bad signal number"))
}

/// Reset every catchable signal to its default disposition.
///
/// Signal numbers the C library reserves for itself (glibc uses 32 and 33) are skipped
/// silently, as are `SIGKILL` and `SIGSTOP`, whose dispositions cannot be changed.
pub fn reset_dispositions() {
    for sig in 1..=64 {
        if sig == libc::SIGKILL || sig == libc::SIGSTOP {
            continue;
        }
        // SAFETY: an all-zero sigaction with sa_sigaction = SIG_DFL is the default disposition.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        // SAFETY: `action` is valid for the call; a null old-action pointer is allowed. Errors
        // (EINVAL for reserved signals) are expected and deliberately ignored.
        unsafe { libc::sigaction(sig, &raw const action, std::ptr::null_mut()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigset_membership() {
        let set = SigSet::of(&[libc::SIGTERM, libc::SIGINT]);
        assert!(set.contains(libc::SIGTERM));
        assert!(set.contains(libc::SIGINT));
        assert!(!set.contains(libc::SIGHUP));
        assert!(!SigSet::empty().contains(libc::SIGTERM));
    }
}
