//! Filesystem primitives that an untrusted root filesystem cannot trick.
//!
//! # The problem
//!
//! A container image is attacker-controlled data. Suppose an image ships `/etc` as a symlink to
//! `/host-etc`, and the runtime naively joins paths:
//!
//! ```text
//! rootfs = "/var/lib/hull/abc/rootfs"
//! target = rootfs + "/etc/resolv.conf"   // the runtime wants to bind-mount over this
//!        = "/var/lib/hull/abc/rootfs/etc/resolv.conf"
//! ```
//!
//! The kernel follows the `etc -> /host-etc` symlink *relative to the host's root*, and the bind
//! mount lands on the host's `/host-etc/resolv.conf`. This class of bug has produced several runc
//! CVEs, including CVE-2021-30465, which won the race by swapping a symlink in at the right moment.
//!
//! # The fix
//!
//! [`SafeRoot`] resolves every path with `openat2(2)` and `RESOLVE_IN_ROOT`, which makes the
//! kernel treat the rootfs directory as `/` for the whole lookup: absolute symlinks resolve inside
//! it and `..` cannot climb out of it. The result is a file descriptor, not a string, so nothing
//! can be swapped between the check and the use. Callers then operate on that descriptor (for
//! mounts, via `move_mount` onto the fd).

#![forbid(unsafe_code)]

mod atomic;
mod path;
mod root;

pub use atomic::atomic_write;
pub use path::clean_absolute;
pub use root::SafeRoot;
