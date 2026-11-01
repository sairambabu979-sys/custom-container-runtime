//! The unsafe boundary of hull.
//!
//! Every `unsafe` block in the project lives in this crate. Each one carries a `// SAFETY:`
//! comment, and each is wrapped in a function whose signature makes misuse impossible (or, where
//! that is not possible, checks the precondition at runtime).
//!
//! We use [`rustix`] wherever it already offers a safe API. This crate only fills the gaps:
//!
//! | Module | Syscalls | Why rustix is not enough |
//! |---|---|---|
//! | [`clone`] | `clone3` | Fork-like process creation is outside rustix's scope |
//! | [`exec`] | `execve`, `_exit` | rustix exposes these only behind an unstable feature |
//! | [`signal`] | `sigprocmask`, `signalfd`, `sigaction` | Same |
//! | [`mount`] | `mount_setattr` | Not wrapped by rustix 1.1 |
//! | [`fd`] | `close_range` | Not wrapped by rustix 1.1 |
//! | [`thread`] | (reads `/proc/self/task`) | Safety precondition for [`clone::clone3`] |

#![allow(unsafe_code)] // This is the one crate that is allowed to use it. See the module docs.

pub mod clone;
pub mod exec;
pub mod fd;
pub mod mount;
pub mod signal;
pub mod thread;

/// Convert a raw libc return value into an [`std::io::Result`], reading `errno` on `-1`.
fn cvt(ret: libc::c_long) -> std::io::Result<libc::c_long> {
    if ret == -1 { Err(std::io::Error::last_os_error()) } else { Ok(ret) }
}
