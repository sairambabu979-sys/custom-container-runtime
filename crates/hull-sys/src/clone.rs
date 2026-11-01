//! `clone3(2)`: create the container's first process directly inside new namespaces.
//!
//! # Why `clone3` and not `fork` + `unshare`
//!
//! `unshare(CLONE_NEWPID)` does not move the caller into a new PID namespace. It only decides
//! where the caller's *future children* go. Using it means forking twice. `clone3` creates every
//! namespace at the moment the child is born, so the child is PID 1 right away.
//!
//! When `CLONE_NEWUSER` is combined with other `CLONE_NEW*` flags in one call, the kernel creates
//! the user namespace first and makes it the owner of all the others (see `user_namespaces(7)`).
//! That ordering is what later lets the child mount `/proc` and set a hostname with capabilities
//! that only exist inside its user namespace.
//!
//! `clone3` also gives us two things old `clone` cannot:
//!
//! - `CLONE_PIDFD`: a file descriptor that refers to the child process itself. Signals sent
//!   through it can never hit an unrelated process that happened to reuse the PID.
//! - `CLONE_INTO_CGROUP` (Linux 5.7): the child is born inside its cgroup, so it never runs for
//!   even a moment without resource limits. (Used from milestone M3.)

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use bitflags::bitflags;
use rustix::process::Pid;

use crate::thread::{ThreadCheckError, ensure_single_threaded};

bitflags! {
    /// The namespaces a new process should be created in.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct Namespaces: u64 {
        /// Mount namespace (`CLONE_NEWNS`): a private copy of the mount table.
        const MOUNT = libc::CLONE_NEWNS as u64;
        /// Cgroup namespace (`CLONE_NEWCGROUP`): `/proc/self/cgroup` is relative to the container.
        const CGROUP = libc::CLONE_NEWCGROUP as u64;
        /// UTS namespace (`CLONE_NEWUTS`): private hostname and NIS domain name.
        const UTS = libc::CLONE_NEWUTS as u64;
        /// IPC namespace (`CLONE_NEWIPC`): private System V IPC and POSIX message queues.
        const IPC = libc::CLONE_NEWIPC as u64;
        /// User namespace (`CLONE_NEWUSER`): private UID/GID ranges and capabilities.
        const USER = libc::CLONE_NEWUSER as u64;
        /// PID namespace (`CLONE_NEWPID`): the child becomes PID 1.
        const PID = libc::CLONE_NEWPID as u64;
        /// Network namespace (`CLONE_NEWNET`): private interfaces, routes and firewall.
        const NET = libc::CLONE_NEWNET as u64;
        /// Time namespace (`CLONE_NEWTIME`, Linux 5.6): private monotonic and boot-time clocks.
        const TIME = 0x80;
    }
}

/// The `struct clone_args` ABI from `<linux/sched.h>`.
///
/// Defined here instead of taken from `libc` because `libc` only provides it on some targets, and
/// because the kernel versions this struct by its size. We pass the full v2 layout (with `cgroup`).
#[repr(C)]
#[derive(Default)]
struct RawCloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

const CLONE_PIDFD: u64 = 0x1000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// Arguments for [`clone3`].
#[derive(Debug, Default)]
pub struct CloneArgs<'a> {
    /// Namespaces to create for the child.
    pub namespaces: Namespaces,
    /// A cgroup v2 directory fd. If set, the child is born inside that cgroup.
    pub cgroup: Option<BorrowedFd<'a>>,
}

/// The parent's view of a newly created child.
#[derive(Debug)]
pub struct ChildProcess {
    /// The child's PID as seen from the parent's PID namespace.
    pub pid: Pid,
    /// A pidfd referring to the child. Use it for signals and waiting.
    pub pidfd: OwnedFd,
}

/// Which side of the fork we are on.
#[derive(Debug)]
pub enum Forked {
    /// We are the new child. This branch must never return into the parent's code paths.
    Child,
    /// We are the original process.
    Parent(ChildProcess),
}

/// Error returned by [`clone3`].
#[derive(Debug)]
pub enum CloneError {
    /// The single-thread precondition does not hold.
    Threads(ThreadCheckError),
    /// The syscall failed.
    Syscall(io::Error),
}

impl std::fmt::Display for CloneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Threads(e) => write!(f, "refusing to clone3: {e}"),
            Self::Syscall(e) => write!(f, "clone3: {e}"),
        }
    }
}

impl std::error::Error for CloneError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Threads(e) => Some(e),
            Self::Syscall(e) => Some(e),
        }
    }
}

/// Create a child process the way `fork(2)` does, but inside new namespaces.
///
/// This function is safe to call because it *checks* its precondition: it refuses to run unless
/// the process has exactly one thread. With a single thread, no lock can be held by a thread that
/// does not exist in the child, so the child may use the allocator and the standard library.
///
/// Callers must still treat [`Forked::Child`] as a one-way door: the child must end in `execve` or
/// [`crate::exec::exit_immediately`], and never return into the parent's logic (whose destructors
/// would, for example, delete state that belongs to the parent).
pub fn clone3(args: &CloneArgs<'_>) -> Result<Forked, CloneError> {
    ensure_single_threaded().map_err(CloneError::Threads)?;

    let mut pidfd: libc::c_int = -1;
    let mut raw = RawCloneArgs {
        flags: args.namespaces.bits() | CLONE_PIDFD,
        pidfd: std::ptr::addr_of_mut!(pidfd) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..RawCloneArgs::default()
    };
    if let Some(cgroup) = args.cgroup {
        raw.flags |= CLONE_INTO_CGROUP;
        // The kernel reads this as a file descriptor number. Non-negative by construction.
        raw.cgroup = u64::try_from(cgroup.as_raw_fd()).unwrap_or_default();
    }

    // SAFETY: `raw` is a correctly laid-out `struct clone_args` that lives across the call, and
    // `pidfd` outlives the call so the kernel can write the new pidfd into it. `stack` is 0, which
    // makes clone3 behave like fork: the child continues on a copy-on-write copy of our stack. The
    // single-thread precondition that makes this sound was checked above.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            std::ptr::addr_of_mut!(raw),
            std::mem::size_of::<RawCloneArgs>(),
        )
    };
    match crate::cvt(ret).map_err(CloneError::Syscall)? {
        0 => Ok(Forked::Child),
        pid => {
            let pid = i32::try_from(pid)
                .ok()
                .and_then(Pid::from_raw)
                .ok_or_else(|| CloneError::Syscall(io::Error::other("clone3 returned bad pid")))?;
            // SAFETY: on success with CLONE_PIDFD, the kernel stored a new, open file descriptor
            // in `pidfd` that nothing else owns. We take ownership exactly once.
            let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
            Ok(Forked::Parent(ChildProcess { pid, pidfd }))
        }
    }
}
